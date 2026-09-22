use ssr_client_rs::obfs::tls_ticket::Tls12TicketAuthObfs;
use ssr_client_rs::obfs::Obfs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn main() {
    for attempt in 1..=3 {
        println!("=== Attempt {} ===", attempt);

        let mut obfs =
            Tls12TicketAuthObfs::new("192.0.2.1".into(), 2800, String::new(), false);
        obfs.set_key(vec![0x42u8; 16]);

        match TcpStream::connect("192.0.2.1:2800") {
            Ok(mut stream) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();

                let client_hello = obfs.client_encode(b"").unwrap();
                println!("ClientHello: {} bytes", client_hello.len());

                if let Err(e) = stream.write_all(&client_hello) {
                    println!("Send error: {}", e);
                    continue;
                }

                let mut buf = [0u8; 4096];
                match stream.read(&mut buf) {
                    Ok(n) => {
                        println!("Response: {} bytes", n);
                        if n > 0 {
                            println!("Hex: {:02x?}", &buf[..n.min(40)]);
                            match obfs.client_decode(&buf[..n]) {
                                Ok((decoded, _)) => println!("Decoded: {} bytes", decoded.len()),
                                Err(e) => println!("Decode error: {:?}", e),
                            }
                        }
                    }
                    Err(e) => println!("Read error: {}", e),
                }
            }
            Err(e) => println!("Connect error: {}", e),
        }

        std::thread::sleep(Duration::from_secs(1));
    }
}
