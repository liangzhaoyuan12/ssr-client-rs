use ssr_client_rs::config::SsrClientConfig;
use ssr_client_rs::config_json::config_from_json;
use ssr_client_rs::local::SsrClient;
use tokio::signal;

/// Read the configuration file path from argv, if given.
fn config_path() -> Option<String> {
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "-c" | "--config" => return args.next(),
            "-h" | "--help" => {
                println!("Usage: ssr_client [-c <config.json>]");
                println!("  -c, --config <file>  SSR client config (ssr-n JSON format)");
                std::process::exit(0);
            }
            other if !other.starts_with('-') => return Some(other.to_string()),
            _ => {}
        }
    }
    None
}

#[tokio::main]
async fn main() {
    let config = match config_path() {
        Some(path) => match std::fs::read_to_string(&path) {
            Ok(text) => match config_from_json(&text) {
                Ok(cfg) => {
                    eprintln!("Loaded config from {path}");
                    cfg
                }
                Err(e) => {
                    eprintln!("Failed to parse {path}: {e}");
                    std::process::exit(1);
                }
            },
            Err(e) => {
                eprintln!("Failed to read {path}: {e}");
                std::process::exit(1);
            }
        },
        None => SsrClientConfig::default_test(),
    };

    let listen =
        ssr_client_rs::utils::sockaddr::host_port(&config.listen_address, config.listen_port);
    let server = ssr_client_rs::utils::sockaddr::host_port(&config.server, config.server_port);

    let client = SsrClient::new(config);
    let client_ref = client.clone();

    tokio::spawn(async move {
        if let Err(e) = client.start().await {
            eprintln!("Error: {e}");
        }
    });

    eprintln!("SSR client listening on {listen} (remote {server})");
    if let Err(e) = signal::ctrl_c().await {
        eprintln!("ctrl-c wait failed: {e}");
    }
    client_ref.stop();
}
