//! Inbound SMTP listeners on compio (io_uring).
//!
//! Inbound socket I/O runs on dedicated compio runtime threads, one io_uring
//! ring per thread, with SO_REUSEPORT spreading accepts across them.
//! Everything downstream of the session (log-queue writers, delivery
//! workers, DNS, HTTP) stays on the tokio runtime. Each compio thread enters
//! the tokio runtime handle so tokio timers and channels used by the
//! callbacks keep working; sessions themselves are thread-local compio tasks
//! (their streams are bound to the thread's ring and are not Send).
//!
//! The smtp crate's stream abstraction is runtime-agnostic, so sessions run
//! on native compio streams (owned-buffer ops, no adapter copies); TLS goes
//! through compio_tls over the same rustls ServerConfig the tokio path used.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use miette::{Context, IntoDiagnostic, Result};
use smtp::compio_stream::{CompioTcpStream, TlsAcceptor};
use smtp::{SmtpServer, SmtpStream};
use tokio::sync::Semaphore;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};

use crate::config;

/// One configured inbound listener: address plus TLS posture.
#[derive(Clone)]
pub struct ListenerSpec {
    pub addr: String,
    pub tls_config: Option<Arc<rustls::ServerConfig>>,
    pub tls_mode: config::TlsMode,
}

/// Number of inbound io_uring threads: HEDWIG_INBOUND_THREADS overrides,
/// otherwise one per logical CPU (matching tokio's default worker count on
/// the main branch, for a fair benchmark).
pub fn inbound_thread_count() -> usize {
    std::env::var("HEDWIG_INBOUND_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&n| n > 0)
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(|n| n.get())
                .unwrap_or(1)
        })
}

/// Binds every listener address once per thread with SO_REUSEPORT and starts
/// the inbound threads. Bind errors surface here, before any thread spawns.
#[allow(clippy::too_many_arguments)]
pub fn spawn_inbound_threads(
    specs: Vec<ListenerSpec>,
    server: SmtpServer,
    conn_semaphore: Arc<Semaphore>,
    shutdown: CancellationToken,
    cmd_timeout: Duration,
    threads: usize,
    tokio_handle: tokio::runtime::Handle,
) -> Result<Vec<std::thread::JoinHandle<()>>> {
    let mut handles = Vec::with_capacity(threads);
    for t in 0..threads {
        let mut listeners = Vec::with_capacity(specs.len());
        for spec in &specs {
            let std_listener = bind_reuseport(&spec.addr)
                .wrap_err_with(|| format!("Failed to bind to address: {}", spec.addr))?;
            listeners.push((std_listener, spec.clone()));
        }
        let server = server.clone();
        let semaphore = Arc::clone(&conn_semaphore);
        let shutdown = shutdown.clone();
        let tokio_handle = tokio_handle.clone();
        let handle = std::thread::Builder::new()
            .name(format!("smtp-inbound-{t}"))
            .spawn(move || {
                // Keeps tokio::time / tokio::spawn usable from this thread
                // for the lifetime of the compio runtime.
                let _tokio = tokio_handle.enter();
                let rt = match compio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(e) => {
                        error!("failed to create compio runtime: {e}");
                        return;
                    }
                };
                rt.block_on(async move {
                    let mut loops = Vec::new();
                    for (std_listener, spec) in listeners {
                        match compio::net::TcpListener::from_std(std_listener) {
                            Ok(listener) => loops.push(accept_loop(
                                listener,
                                spec,
                                server.clone(),
                                Arc::clone(&semaphore),
                                shutdown.clone(),
                                cmd_timeout,
                            )),
                            Err(e) => error!("failed to adopt listener into compio: {e}"),
                        }
                    }
                    futures::future::join_all(loops).await;
                });
                // Runtime drops here; in-flight sessions on this thread are
                // torn down, matching the tokio path where main's return
                // kills session tasks.
            })
            .into_diagnostic()?;
        handles.push(handle);
    }
    Ok(handles)
}

fn bind_reuseport(addr: &str) -> Result<std::net::TcpListener> {
    let addr: SocketAddr = addr.parse().into_diagnostic()?;
    let domain = socket2::Domain::for_address(addr);
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
        .into_diagnostic()?;
    socket.set_reuse_address(true).into_diagnostic()?;
    socket.set_reuse_port(true).into_diagnostic()?;
    socket.bind(&addr.into()).into_diagnostic()?;
    socket.listen(1024).into_diagnostic()?;
    socket.set_nonblocking(true).into_diagnostic()?;
    Ok(socket.into())
}

async fn accept_loop(
    listener: compio::net::TcpListener,
    spec: ListenerSpec,
    server: SmtpServer,
    semaphore: Arc<Semaphore>,
    shutdown: CancellationToken,
    cmd_timeout: Duration,
) {
    let listener_addr = spec.addr.clone();
    let acceptor = spec.tls_config.map(TlsAcceptor::from);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => {
                info!(%listener_addr, "listener shutting down");
                break;
            }
            accept_result = listener.accept() => {
                let (socket, _) = match accept_result {
                    Ok(conn) => conn,
                    Err(e) => {
                        error!(%listener_addr, "Error accepting tcp connection: {:#}", e);
                        continue;
                    }
                };

                // Replies are small and written one batch per read; Nagle
                // would sit on them waiting for the delayed ACK.
                if let Err(e) = socket.set_nodelay(true) {
                    debug!(%listener_addr, "could not set TCP_NODELAY: {}", e);
                }

                // Enforce the connection limit. At capacity, reject
                // immediately (plaintext, as on the tokio path).
                let permit = match semaphore.clone().try_acquire_owned() {
                    Ok(permit) => permit,
                    Err(_) => {
                        warn!(%listener_addr, "max connections reached, rejecting");
                        compio::runtime::spawn(async move {
                            let mut stream = CompioTcpStream::plain(socket, None);
                            let _ = stream
                                .write_all(b"421 4.7.0 Too many connections, try again later\r\n")
                                .await;
                        })
                        .detach();
                        continue;
                    }
                };

                debug!("Accepted connection");
                let server = server.clone();
                let acceptor = acceptor.clone();
                let tls_mode = spec.tls_mode;

                compio::runtime::spawn(async move {
                    // Hold the permit for the lifetime of this connection.
                    let _permit = permit;

                    let mut stream = match acceptor {
                        // Implicit TLS: the handshake happens before any SMTP
                        // traffic. Bounded so a silent client can't hold a
                        // connection permit forever.
                        Some(acceptor) if tls_mode == config::TlsMode::Implicit => {
                            match compio::time::timeout(cmd_timeout, acceptor.accept(socket)).await
                            {
                                Ok(Ok(tls_stream)) => CompioTcpStream::tls(tls_stream),
                                Ok(Err(e)) => {
                                    if e.kind() == std::io::ErrorKind::UnexpectedEof {
                                        debug!("TLS handshake failed: {}", e);
                                    } else {
                                        error!("TLS handshake failed: {}", e);
                                    }
                                    return;
                                }
                                Err(_) => {
                                    debug!("TLS handshake timed out");
                                    return;
                                }
                            }
                        }
                        // STARTTLS: start in plaintext, upgrade on request.
                        Some(acceptor) => CompioTcpStream::plain(socket, Some(acceptor)),
                        None => CompioTcpStream::plain(socket, None),
                    };

                    if let Err(e) = server.handle_client(&mut stream).await {
                        error!("Error handling client: {:#}", e);
                    }
                })
                .detach();
            }
        }
    }
    info!(%listener_addr, "listener stopped");
}
