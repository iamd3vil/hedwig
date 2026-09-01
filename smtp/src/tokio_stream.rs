//! [`SmtpStream`] implementations for tokio I/O (feature `tokio`).

use std::time::Duration;

use bytes::BytesMut;
use miette::{bail, IntoDiagnostic, Result, WrapErr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{server::TlsStream, TlsAcceptor};

use crate::stream::SmtpStream;

/// Adapts any tokio `AsyncRead + AsyncWrite` stream to [`SmtpStream`].
pub struct TokioStream<S>(pub S);

impl<S: AsyncRead + AsyncWrite + Unpin> SmtpStream for TokioStream<S> {
    async fn read_buf_timeout(
        &mut self,
        buf: &mut BytesMut,
        timeout: Duration,
    ) -> std::io::Result<Option<usize>> {
        match tokio::time::timeout(timeout, self.0.read_buf(buf)).await {
            Ok(res) => res.map(Some),
            Err(_) => Ok(None),
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.0.write_all(data).await?;
        // No-op for TcpStream; delivers buffered ciphertext for TLS.
        self.0.flush().await
    }
}

/// A connection that starts out as plain TCP and may be upgraded to TLS
/// mid-session via STARTTLS. Carrying the acceptor with the stream lets each
/// listener decide independently whether to offer STARTTLS.
pub enum MaybeTlsStream<S = TcpStream> {
    Plain(S, Option<TlsAcceptor>),
    Tls(Box<TlsStream<S>>),
    /// Transient state while the TLS handshake runs; only observable if the
    /// handshake fails, after which the connection is unusable.
    Upgrading,
}

impl<S: AsyncRead + AsyncWrite + Unpin> MaybeTlsStream<S> {
    async fn read_inner(&mut self, buf: &mut BytesMut) -> std::io::Result<usize> {
        match self {
            MaybeTlsStream::Plain(s, _) => s.read_buf(buf).await,
            MaybeTlsStream::Tls(s) => s.read_buf(buf).await,
            MaybeTlsStream::Upgrading => Err(upgrading_io_error()),
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SmtpStream for MaybeTlsStream<S> {
    async fn read_buf_timeout(
        &mut self,
        buf: &mut BytesMut,
        timeout: Duration,
    ) -> std::io::Result<Option<usize>> {
        match tokio::time::timeout(timeout, self.read_inner(buf)).await {
            Ok(res) => res.map(Some),
            Err(_) => Ok(None),
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()> {
        match self {
            MaybeTlsStream::Plain(s, _) => {
                s.write_all(data).await?;
                s.flush().await
            }
            MaybeTlsStream::Tls(s) => {
                s.write_all(data).await?;
                s.flush().await
            }
            MaybeTlsStream::Upgrading => Err(upgrading_io_error()),
        }
    }

    fn supports_starttls(&self) -> bool {
        matches!(self, MaybeTlsStream::Plain(_, Some(_)))
    }

    async fn upgrade_to_tls(&mut self, timeout: Duration) -> Result<bool> {
        match std::mem::replace(self, MaybeTlsStream::Upgrading) {
            MaybeTlsStream::Plain(tcp, Some(acceptor)) => {
                match tokio::time::timeout(timeout, acceptor.accept(tcp)).await {
                    Ok(Ok(tls_stream)) => {
                        *self = MaybeTlsStream::Tls(Box::new(tls_stream));
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
