use anyhow::Result;
use bacnet_discovery::network::create_shared_socket;
use bacnet_discovery::bacnet::{send_whois, process_response};
use std::net::UdpSocket;
use std::time::{Duration, Instant};
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

#[tokio::main]
async fn main() -> Result<()> {
    // Setup logging to stdout
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::DEBUG)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting Headless BACnet Scan");

    let socket = create_shared_socket(47808).unwrap_or_else(|e| {
        warn!("Failed to bind to 47808 ({}). Trying random port.", e);
        UdpSocket::bind("0.0.0.0:0").expect("Failed to bind")
    });

    info!("Socket bound to {:?}", socket.local_addr()?);

    send_whois(&socket)?;
    info!("Who-Is broadcast sent.");

    let mut buf = [0u8; 1500];
    let start = Instant::now();
    let scan_duration = Duration::from_secs(5);
    let mut discovered_count = 0;

    info!("Listening for I-Am responses for {} seconds...", scan_duration.as_secs());

    while start.elapsed() < scan_duration {
        match socket.recv_from(&mut buf) {
            Ok((len, addr)) => {
                if let Some(device) = process_response(&buf[..len], addr) {
                    discovered_count += 1;
                    info!("FOUND DEVICE: ID={} Vendor={} Address={}", 
                        device.device_id, device.vendor_name, device.address);
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock || e.kind() == std::io::ErrorKind::TimedOut => {
                tokio::task::yield_now().await;
            }
            Err(e) => {
                warn!("Receive error: {}", e);
            }
        }
    }

    info!("Scan complete. Total devices found: {}", discovered_count);
    Ok(())
}
