use std::io;
use std::net::{SocketAddr, UdpSocket};
use socket2::{Domain, Protocol, Socket, Type};
use std::time::Duration;
use tracing::debug;

/// Creates a UDP socket configured for sharing port 47808 on supported platforms.
/// This allows multiple BACnet applications to coexist on the same host.
pub fn create_shared_socket(port: u16) -> io::Result<UdpSocket> {
    debug!("Creating shared socket on port {}", port);
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    
    // Enable SO_REUSEADDR and SO_REUSEPORT (Linux/BSD)
    socket.set_reuse_address(true)?;
    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;
    
    socket.set_broadcast(true)?;
    
    let addr: SocketAddr = format!("0.0.0.0:{}", port).parse().unwrap();
    socket.bind(&addr.into())?;
    
    // Set a short read timeout to keep the async loop responsive
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    
    Ok(socket.into())
}
