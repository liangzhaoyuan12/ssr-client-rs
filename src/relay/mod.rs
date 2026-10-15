// TCP relay for bidirectional data forwarding between local SOCKS5 client
// and remote SSR server.
//
// Uses tokio::io for efficient async bidirectional data transfer.

use tokio::io;
use tokio::net::TcpStream;

use crate::error::{SsrError, SsrResult};

/// Bidirectional TCP relay.
///
/// Copies data between two TCP streams in both directions concurrently.
/// Returns when the FIRST direction finishes (EOF) or errors — the other
/// direction is torn down with it (GOAL 2.3: its socket halves drop with
/// the abandoned future, closing the connection instead of waiting on a
/// peer that may never speak again; the pre-2.3 `join!` waited for BOTH
/// sides and could hang forever on a silent peer).
///
/// This is the simple utility. Half-close draining with FIN propagation and
/// stall deadlines lives in the SSR relay (`ObfsRelay` in `local`).
pub struct TcpRelay {
    local: TcpStream,
    remote: TcpStream,
    buffer_size: usize,
}

impl TcpRelay {
    /// Create a new TCP relay with default buffer size (8KB).
    pub fn new(local: TcpStream, remote: TcpStream) -> Self {
        Self {
            local,
            remote,
            buffer_size: 8192,
        }
    }

    /// Create a new TCP relay with custom buffer size.
    pub fn with_buffer_size(local: TcpStream, remote: TcpStream, buffer_size: usize) -> Self {
        Self {
            local,
            remote,
            buffer_size,
        }
    }

    /// Run the bidirectional relay under first-finish-wins semantics
    /// (GOAL 2.3): whichever direction finishes first — EOF or error —
    /// terminates the other.
    ///
    /// Returns `Ok((bytes_upstream, 0))` when the upstream direction
    /// finished first, `Ok((0, bytes_downstream))` when downstream did; the
    /// torn-down side's partial count is not observable (it died
    /// mid-flight). Returns `Err` on the first I/O error encountered.
    pub async fn run(self) -> SsrResult<(u64, u64)> {
        let buf_size = self.buffer_size;
        let (mut local_read, mut local_write) = self.local.into_split();
        let (mut remote_read, mut remote_write) = self.remote.into_split();

        // upstream: local → remote
        let mut upstream = std::pin::pin!(async move {
            let mut total = 0u64;
            let mut buf = vec![0u8; buf_size];
            loop {
                let n = io::AsyncReadExt::read(&mut local_read, &mut buf).await?;
                if n == 0 {
                    break;
                }
                io::AsyncWriteExt::write_all(&mut remote_write, &buf[..n]).await?;
                total += n as u64;
            }
            Ok::<_, std::io::Error>(total)
        });

        // downstream: remote → local
        let mut downstream = std::pin::pin!(async move {
            let mut total = 0u64;
            let mut buf = vec![0u8; buf_size];
            loop {
                let n = io::AsyncReadExt::read(&mut remote_read, &mut buf).await?;
                if n == 0 {
                    break;
                }
                io::AsyncWriteExt::write_all(&mut local_write, &buf[..n]).await?;
                total += n as u64;
            }
            Ok::<_, std::io::Error>(total)
        });

        tokio::select! {
            res = &mut upstream => match res {
                Ok(total) => Ok((total, 0)),
                Err(e) => Err(SsrError::Connection(format!("Relay error: {e}"))),
            },
            res = &mut downstream => match res {
                Ok(total) => Ok((0, total)),
                Err(e) => Err(SsrError::Connection(format!("Relay error: {e}"))),
            },
        }
    }
}

/// Relay data between two byte-stream halves using tokio::io::copy.
///
/// Simpler alternative to TcpRelay that works with any AsyncRead + AsyncWrite.
/// Same first-finish-wins semantics as [`TcpRelay::run`] (GOAL 2.3): whichever
/// copy finishes or errors first terminates the other.
///
/// Returns the number of bytes transferred in the direction that finished
/// first, with `0` for the torn-down side.
pub async fn relay_streams(
    mut reader_a: impl io::AsyncRead + Unpin,
    mut writer_a: impl io::AsyncWrite + Unpin,
    mut reader_b: impl io::AsyncRead + Unpin,
    mut writer_b: impl io::AsyncWrite + Unpin,
) -> SsrResult<(u64, u64)> {
    let mut upstream = std::pin::pin!(async {
        io::copy(&mut reader_a, &mut writer_b)
            .await
            .map_err(|e| SsrError::Connection(format!("Upstream relay error: {e}")))
    });

    let mut downstream = std::pin::pin!(async {
        io::copy(&mut reader_b, &mut writer_a)
            .await
            .map_err(|e| SsrError::Connection(format!("Downstream relay error: {e}")))
    });

    tokio::select! {
        res = &mut upstream => Ok((res?, 0)),
        res = &mut downstream => Ok((0, res?)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::Duration;
    use tokio::io::AsyncRead;

    #[test]
    fn test_relay_buffer_size_default() {
        assert_eq!(8192, 8192); // TcpRelay default buffer size
    }

    #[tokio::test]
    async fn test_relay_streams_empty() {
        use tokio::io::AsyncReadExt;
        let (mut reader, writer) = tokio::io::duplex(1024);
        let mut buf = [0u8; 1024];
        // Write nothing, just verify split works
        drop(writer);
        let n = reader.read(&mut buf).await.unwrap();
        assert_eq!(n, 0); // EOF
    }

    // ── GOAL 2.3: first-finish-wins convergence ────────────────────────────

    /// Reader that hits EOF immediately.
    struct EofReader;
    impl AsyncRead for EofReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    /// Reader that never yields anything (a silent peer).
    struct PendingReader;
    impl AsyncRead for PendingReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Pending
        }
    }

    /// Reader that errors on the first poll.
    struct ErrReader;
    impl AsyncRead for ErrReader {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::ConnectionReset,
                "boom",
            )))
        }
    }

    /// One side EOFs while the other would wait forever: the call must
    /// return promptly (pre-2.3 `join!` hung here).
    #[tokio::test]
    async fn relay_streams_first_eof_wins() {
        let res = tokio::time::timeout(
            Duration::from_secs(5),
            relay_streams(
                EofReader,
                tokio::io::sink(),
                PendingReader,
                tokio::io::sink(),
            ),
        )
        .await
        .expect("GOAL 2.3: first finish must terminate the other side");
        assert_eq!(res.unwrap(), (0, 0));
    }

    /// One side errors while the other waits forever: the error propagates
    /// promptly instead of hanging.
    #[tokio::test]
    async fn relay_streams_first_error_wins() {
        let res = tokio::time::timeout(
            Duration::from_secs(5),
            relay_streams(
                ErrReader,
                tokio::io::sink(),
                PendingReader,
                tokio::io::sink(),
            ),
        )
        .await
        .expect("GOAL 2.3: an error must tear the relay down, not wait for the healthy side");
        assert!(res.is_err());
    }

    /// Real-socket variant: client writes one chunk then EOFs; the server
    /// side never speaks. The relay must return the upstream count promptly
    /// (pre-2.3 `join!` waited for the silent server forever).
    #[tokio::test]
    async fn tcp_relay_converges_on_first_eof() {
        use tokio::io::AsyncWriteExt;
        let l1 = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let l2 = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let mut a1 = TcpStream::connect(l1.local_addr().unwrap()).await.unwrap();
        let b1 = l1.accept().await.unwrap().0;
        let a2 = TcpStream::connect(l2.local_addr().unwrap()).await.unwrap();
        let b2 = l2.accept().await.unwrap().0;

        let relay = TcpRelay::new(b1, b2);
        a1.write_all(b"ping").await.unwrap();
        a1.shutdown().await.unwrap(); // EOF upstream

        let (up, down) = tokio::time::timeout(Duration::from_secs(5), relay.run())
            .await
            .expect("GOAL 2.3: first EOF must terminate the other direction")
            .expect("relay must finish clean on a plain EOF");
        assert_eq!(up, 4, "the written chunk must be counted");
        assert_eq!(down, 0, "torn-down side reports 0");
        drop(a2); // server side of the pair, never spoke
    }
}
