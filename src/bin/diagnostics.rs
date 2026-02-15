//! BACnet Network Diagnostic Tool
//!
//! Checks for common BACnet network issues like port availability and broadcast capability.

use std::net::{UdpSocket, SocketAddr};

fn main() {
    println!("BACnet Network Diagnostic");
    println!("=========================");

    let port = 47808;
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();

    // 1. Check if port is available
    println!("[1] Checking if port {} is available...", port);
    match UdpSocket::bind(addr) {
        Ok(socket) => {
            println!("  ✅ Port {} is available for binding.", port);
            
            // 2. Check broadcast capability
            println!("[2] Checking broadcast capability...");
            match socket.set_broadcast(true) {
                Ok(_) => println!("  ✅ Broadcast capability enabled."),
                Err(e) => println!("  ❌ Failed to enable broadcast: {}", e),
            }

            // 3. Interface Check
            println!("[3] Local interfaces information:");
            if let Ok(addrs) = if_addrs::get_if_addrs() {
                for iface in addrs {
                    println!("  - Interface: {}", iface.name);
                    println!("    Address:   {}", iface.ip());
                }
            } else {
                println!("  ❌ Could not retrieve interface information.");
            }
        },
        Err(e) => {
            println!("  ❌ Could not bind to port {}: {}", port, e);
            println!("     This usually means another BACnet application or service is already running.");
        }
    }

    println!("
Recommendations:");
    println!("- If the discovery tool finds nothing, try running the responder: 'cargo run --bin responder'");
    println!("- Ensure your firewall allows UDP port 47808.");
    println!("- If port 47808 is occupied, close the conflicting application.");
}
