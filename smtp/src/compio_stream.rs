//! [`SmtpStream`] implementations for compio / io_uring (feature `compio`).
//!
//! Reads are native owned-buffer completion ops straight into the session's
//! `BytesMut` — no adapter layer, no extra copy. compio ops write from the
//! start of the buffer view, so the filled prefix is split off for the
//! duration of the op and merged back after (same allocation, zero copy).
//! TLS goes through `compio_tls` (rustls); its streams buffer internally, so
//! `write_all` always finishes with a flush (a no-op on plain TCP).

use std::time::Duration;

use bytes::BytesMut;
use compio::buf::BufResult;
use compio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use compio::net::TcpStream;
pub use compio::tls::TlsAcceptor;
use compio::tls::TlsStream;
use miette::{bail, IntoDiagnostic, Result, WrapErr};

use crate::stream::SmtpStream;

/// Grow the read buffer in these increments once spare capacity runs low.
const READ_CHUNK: usize = 64 * 1024;
const MIN_SPARE: usize = 4 * 1024;

/// Ciphertext-side buffer for the compat stream under rustls. compio_tls's
/// default is 8KB (half a TLS record per op); 64KB moves ~4 records per op,
/// which matters for large messages.
const TLS_COMPAT_BUF: usize = 64 * 1024;

/// Accepts a TLS connection with [`TLS_COMPAT_BUF`]-sized buffers instead of
/// compio_tls's default. Used for both implicit-TLS accepts and STARTTLS
/// upgrades.
pub async fn accept_tls(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
) -> std::io::Result<TlsStream<TcpStream>> {
    acceptor
        .accept_compat(compio::io::compat::AsyncStream::with_capacity(
            TLS_COMPAT_BUF,
            stream,
        ))
        .await
}

/// Adapts any compio `AsyncRead + AsyncWrite` stream to [`SmtpStream`].
pub struct CompioStream<S> {
    inner: S,
    /// Reusable owned buffer for writes: completion ops need owned buffers,
    /// so replies are copied here (they are tiny) and the buffer is handed
    /// back by the op when it finishes.
    wbuf: BytesMut,
}

impl<S> CompioStream<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            wbuf: BytesMut::new(),
        }
    }

    pub fn into_inner(self) -> S {
        self.inner
    }
}

impl<S: AsyncRead + AsyncWrite> SmtpStream for CompioStream<S> {
    async fn read_buf_timeout(
        &mut self,
        buf: &mut BytesMut,
        timeout: Duration,
    ) -> std::io::Result<Option<usize>> {
        if buf.capacity() - buf.len() < MIN_SPARE {
            buf.reserve(READ_CHUNK);
        }
        // The op fills its buffer from the view's start, so hand it an empty
        // view over the spare capacity; unsplit re-merges without copying.
        let tail = buf.split_off(buf.len());
        match compio::time::timeout(timeout, self.inner.read(tail)).await {
            Ok(BufResult(res, tail)) => {
                buf.unsplit(tail);
                res.map(Some)
            }
            // The dropped op keeps the tail alive until the kernel cancels
            // it; the bytes already in `buf` stay valid and the connection
            // is about to close anyway.
            Err(_) => Ok(None),
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.wbuf.clear();
        self.wbuf.extend_from_slice(data);
        let wbuf = std::mem::take(&mut self.wbuf);
        let BufResult(res, wbuf) = self.inner.write_all(wbuf).await;
        self.wbuf = wbuf;
        res?;
        self.inner.flush().await
    }
}

/// A compio TCP connection that may be TLS from the start (implicit TLS),
/// plain, or plain with a STARTTLS upgrade available.
pub enum CompioTcpStream {
    Plain(CompioStream<TcpStream>, Option<TlsAcceptor>),
    Tls(Box<CompioStream<TlsStream<TcpStream>>>),
    /// Transient state while the TLS handshake runs; only observable if the
    /// handshake fails, after which the connection is unusable.
    Upgrading,
}

impl CompioTcpStream {
    /// Plain connection; pass an acceptor to offer STARTTLS.
    pub fn plain(stream: TcpStream, acceptor: Option<TlsAcceptor>) -> Self {
        Self::Plain(CompioStream::new(stream), acceptor)
    }

    /// Already-established TLS connection (implicit TLS listeners).
    pub fn tls(stream: TlsStream<TcpStream>) -> Self {
        Self::Tls(Box::new(CompioStream::new(stream)))
    }
}

impl SmtpStream for CompioTcpStream {
    async fn read_buf_timeout(
        &mut self,
        buf: &mut BytesMut,
        timeout: Duration,
    ) -> std::io::Result<Option<usize>> {
        match self {
            CompioTcpStream::Plain(s, _) => s.read_buf_timeout(buf, timeout).await,
            CompioTcpStream::Tls(s) => s.read_buf_timeout(buf, timeout).await,
            CompioTcpStream::Upgrading => Err(upgrading_io_error()),
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            CompioTcpStream::Plain(s, _) => s.write_all(data).await,
            CompioTcpStream::Tls(s) => s.write_all(data).await,
            CompioTcpStream::Upgrading => Err(upgrading_io_error()),
        }
    }

    fn supports_starttls(&self) -> bool {
        matches!(self, CompioTcpStream::Plain(_, Some(_)))
    }

    async fn upgrade_to_tls(&mut self, timeout: Duration) -> Result<bool> {
        match std::mem::replace(self, CompioTcpStream::Upgrading) {
            CompioTcpStream::Plain(stream, Some(acceptor)) => {
                let tcp = stream.into_inner();
                match compio::time::timeout(timeout, accept_tls(&acceptor, tcp)).await {
                    Ok(Ok(tls_stream)) => {
                        *self = CompioTcpStream::tls(tls_stream);
                        Ok(true)
                    }
                    Ok(Err(e)) => Err(e)
                        .into_diagnostic()
                        .wrap_err("TLS handshake failed during STARTTLS upgrade"),
                    // The handshake never completed; the stream is unusable.
                    Err(_) => Ok(false),
                }
            }
            other => {
                *self = other;
                bail!("STARTTLS not supported on this stream")
            }
        }
    }
}

fn upgrading_io_error() -> std::io::Error {
    std::io::Error::new(
        std::io::ErrorKind::NotConnected,
        "connection unusable after failed TLS upgrade",
    )
}
