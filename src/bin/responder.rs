use bacnet_rs::{
    network::Npdu,
    object::Device,
    service::{IAmRequest, UnconfirmedServiceChoice, WhoIsRequest},
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::{SocketAddr, UdpSocket},
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    time::Duration,
};

fn create_shared_socket(port: u16) -> std::io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    #[cfg(target_os = "linux")]
    socket.set_reuse_port(true)?;
    socket.bind(&format!("0.0.0.0:{}", port).parse::<SocketAddr>().unwrap().into())?;
    socket.set_broadcast(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(100)))?;
    Ok(socket.into())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet Responder Device (Shared Mode)");
    println!("=====================================");

    let args: Vec<String> = std::env::args().collect();
    let device_id: u32 = if args.len() > 1 { args[1].parse().unwrap_or(12345) } else { 12345 };

    let mut device = Device::new(device_id, format!("Test Device {}", device_id));
    device.set_vendor_by_id(260)?;

    let socket = create_shared_socket(47808)?;
    println!("Listening on port 47808 (Shared)... Device ID: {}", device_id);

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || { r.store(false, Ordering::SeqCst); })?;

    let mut recv_buffer = [0u8; 1500];
    while running.load(Ordering::SeqCst) {
        if let Ok((len, source)) = socket.recv_from(&mut recv_buffer) {
            if let Some(whois) = process_whois(&recv_buffer[..len]) {
                if whois.matches(device_id) {
                    println!("Received Who-Is from {} -> Responding with I-Am", source);
                    if let Ok(response) = create_iam_response(&device) {
                        let _ = socket.send_to(&response, source);
                    }
                }
            }
        }
    }
    Ok(())
}

fn process_whois(data: &[u8]) -> Option<WhoIsRequest> {
    if data.len() < 4 || data[0] != 0x81 { return None; }
    let npdu_start = match data[1] { 0x0A | 0x0B => 4, 0x04 => 10, _ => return None };
    if data.len() <= npdu_start { return None; }
    let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;
    let apdu_start = npdu_start + npdu_len;
    if data.len() <= apdu_start { return None; }
    let apdu = &data[apdu_start..];
    if apdu.len() < 2 || apdu[0] != 0x10 || apdu[1] != UnconfirmedServiceChoice::WhoIs as u8 { return None; }
    if apdu.len() > 2 { WhoIsRequest::decode(&apdu[2..]).ok() } else { Some(WhoIsRequest::new()) }
}

fn create_iam_response(device: &Device) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let iam = IAmRequest::new(device.identifier, 1476, 0, device.vendor_identifier as u32);
    let mut iam_buffer = Vec::new();
    iam.encode(&mut iam_buffer)?;
    let npdu = Npdu::new();
    let mut apdu = vec![0x10, UnconfirmedServiceChoice::IAm as u8];
    apdu.extend_from_slice(&iam_buffer);
    let mut bvlc = vec![0x81, 0x0A, 0x00, 0x00];
    bvlc.extend_from_slice(&npdu.encode());
    bvlc.extend_from_slice(&apdu);
    let total_len = bvlc.len() as u16;
    bvlc[2] = (total_len >> 8) as u8;
    bvlc[3] = (total_len & 0xFF) as u8;
    Ok(bvlc)
}
