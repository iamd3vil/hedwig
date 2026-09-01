//! The runtime-agnostic stream abstraction the session driver runs on.
//!
//! The driver only ever performs whole operations: read more bytes, deliver
//! a reply, upgrade to TLS. Abstracting at that level (instead of poll-based
//! AsyncRead/AsyncWrite) lets completion-based runtimes implement the trait
//! with owned-buffer ops and no adapter copies. Timeouts are part of the
//! operations so every runtime can use its native timer.
//!
//! Implementations live in runtime modules gated by cargo features:
//! [`crate::tokio_stream`] (feature `tokio`) and [`crate::compio_stream`]
//! (feature `compio`).

use std::time::Duration;

use bytes::BytesMut;
use miette::{bail, Result};

/// Note: no `Send` or `Unpin` bounds — completion-based runtimes bind
/// streams to one ring/thread, so sessions may be thread-local tasks.
#[allow(async_fn_in_trait)]
pub trait SmtpStream {
    /// Reads more bytes into `buf`, appending after any existing content,
    /// waiting at most `timeout`.
    ///
    /// Returns `Ok(None)` on timeout and `Ok(Some(0))` on EOF. After a
    /// timeout the stream is only good for a farewell write; the driver
    /// closes the connection.
    async fn read_buf_timeout(
        &mut self,
        buf: &mut BytesMut,
        timeout: Duration,
    ) -> std::io::Result<Option<usize>>;

    /// Delivers all of `data` to the peer, including whatever flushing the
    /// transport needs. Replies are batched by the driver, so this is called
    /// once per read iteration, not per command.
    async fn write_all(&mut self, data: &[u8]) -> std::io::Result<()>;

    /// Whether this stream can be upgraded to TLS via STARTTLS.
    fn supports_starttls(&self) -> bool {
        false
    }

    /// Upgrades the stream to TLS in place. Only valid when
    /// `supports_starttls()` returns true.
    ///
    /// Returns `Ok(false)` when the handshake timed out: the connection is
    /// unusable and the driver just drops it.
    async fn upgrade_to_tls(&mut self, timeout: Duration) -> Result<bool> {
        let _ = timeout;
        bail!("STARTTLS not supported on this stream")
    }
}
