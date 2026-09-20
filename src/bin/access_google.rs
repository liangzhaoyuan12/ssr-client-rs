use ssr_client_rs::crypto::cipher_env::CipherEnv;
use ssr_client_rs::protocol::{Protocol, ServerInfo};
use ssr_client_rs::protocol::auth_aes128::AuthAES128;
use ssr_client_rs::obfs::tls_ticket::Tls12TicketAuthObfs;
use ssr_client_rs::obfs::Obfs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

fn hex(b: &[u8]) -> String { b.iter().map(|x| format!("{:02x}", x)).collect() }

fn main() {
    let server = "127.0.0.1";
    let port = 18388u16;
    let password = "test-password";
    let env = CipherEnv::new(password, "aes-256-cfb").unwrap();
    let mut protocol = AuthAES128::new_md5(ServerInfo {
        key: env.key().to_vec(), iv: vec![0u8; 16], ..Default::default()
    });
    protocol.init_user_key();
    let mut obfs = Tls12TicketAuthObfs::new(server.to_string(), port, String::new(), false);
    obfs.set_key(env.key().to_vec());

    let mut stream = TcpStream::connect(format!("{}:{}", server, port)).unwrap();
    stream.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    stream.set_write_timeout(Some(Duration::from_secs(5))).unwrap();

    let connect_req = b"CONNECT www.baidu.com:443 HTTP/1.1\r\nHost: www.baidu.com\r\n\r\n";
    let framed = protocol.client_pre_encrypt(connect_req).unwrap();
    eprintln!("FRAMED: {} ({} bytes)", hex(&framed), framed.len());
    
    let encrypted = env.encrypt(&framed).unwrap();
    eprintln!("ENCRYPTED: {} ({} bytes)", hex(&encrypted), encrypted.len());

    let client_hello = obfs.client_encode(&encrypted).unwrap();
    eprintln!("CH: {} ({} bytes)", hex(&client_hello), client_hello.len());
    stream.write_all(&client_hello).unwrap();

    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).unwrap();
    eprintln!("SRV: {} ({} bytes)", n, hex(&buf[..n]));

    let (_decoded, needs_feedback) = obfs.client_decode(&buf[..n]).unwrap();
    eprintln!("FB: {}", needs_feedback);
    
    if needs_feedback {
        let finished = obfs.client_encode(&[]).unwrap();
        eprintln!("FIN: {} bytes", finished.len());
        eprintln!("FIN hex: {}", hex(&finished));
        stream.write_all(&finished).unwrap();
        
        match stream.read(&mut buf) {
            Ok(n2) => {
                if n2 > 0 { eprintln!("R2: {} bytes: {}", n2, hex(&buf[..n2])); }
                else { eprintln!("R2: empty"); }
            }
            Err(e) => eprintln!("R2: error {}", e),
        }
    }
}
