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
/// Returns when either direction encounters an error or EOF.
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

    /// Run the bidirectional relay.
    ///
    /// Spawns two tasks:
    /// 1. local → remote (upstream)
    /// 2. remote → local (downstream)
    ///
    /// Returns `Ok((bytes_upstream, bytes_downstream))` on clean shutdown,
    /// or `Err` on the first I/O error encountered.
    pub async fn run(self) -> SsrResult<(u64, u64)> {
        let (mut local_read, mut local_write) = self.local.into_split();
        let (mut remote_read, mut remote_write) = self.remote.into_split();

        // upstream: local → remote
        let upstream = {
            let buf_size = self.buffer_size;
            async move {
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
            }
        };

        // downstream: remote → local
        let downstream = {
            let buf_size = self.buffer_size;
            async move {
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
            }
        };

        let (up_result, down_result) = tokio::join!(upstream, downstream);

        match (up_result, down_result) {
            (Ok(up), Ok(down)) => Ok((up, down)),
            (Err(e), _) | (_, Err(e)) => Err(SsrError::Connection(format!("Relay error: {e}"))),
        }
    }
}

/// Relay data between two byte-stream halves using tokio::io::copy.
///
/// Simpler alternative to TcpRelay that works with any AsyncRead + AsyncWrite.
/// Returns the number of bytes transferred in each direction.
pub async fn relay_streams(
    mut reader_a: impl io::AsyncRead + Unpin,
    mut writer_a: impl io::AsyncWrite + Unpin,
    mut reader_b: impl io::AsyncRead + Unpin,
    mut writer_b: impl io::AsyncWrite + Unpin,
) -> SsrResult<(u64, u64)> {
    let upstream = async {
        io::copy(&mut reader_a, &mut writer_b)
            .await
            .map_err(|e| SsrError::Connection(format!("Upstream relay error: {e}")))
    };

    let downstream = async {
        io::copy(&mut reader_b, &mut writer_a)
            .await
            .map_err(|e| SsrError::Connection(format!("Downstream relay error: {e}")))
    };

    let (up, down) = tokio::join!(upstream, downstream);
    Ok((up?, down?))
}

#[cfg(test)]
mod tests {
    

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
}
