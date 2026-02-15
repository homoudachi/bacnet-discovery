use bacnet_discovery::network::create_shared_socket;
use bacnet_discovery::bacnet::{send_whois_to, process_response};
use bacnet_rs::{
    network::Npdu,
    object::Device,
    service::{IAmRequest, UnconfirmedServiceChoice},
};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use std::thread;

#[test]
fn test_local_discovery() {
    // 1. Setup a "Responder" on a specific port
    let responder_port = 47809;
    let responder_handle = thread::spawn(move || {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", responder_port)).expect("Responder failed to bind");
        let device_id = 99999;
        let mut device = Device::new(device_id, "Test Device".to_string());
        device.set_vendor_by_id(260).unwrap();

        let mut buf = [0u8; 1500];
        let start = Instant::now();
        
        while start.elapsed() < Duration::from_secs(2) {
            socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
            if let Ok((len, source)) = socket.recv_from(&mut buf) {
                if is_whois(&buf[..len]) {
                    let response = create_iam_response(&device);
                    socket.send_to(&response, source).ok();
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(200));

    // 2. Setup a "Scanner"
    let scanner_socket = UdpSocket::bind("127.0.0.1:0").expect("Scanner failed to bind");
    let dest: SocketAddr = format!("127.0.0.1:{}", responder_port).parse().unwrap();
    
    send_whois_to(&scanner_socket, dest).expect("Failed to send Who-Is");

    let mut buf = [0u8; 1500];
    let start = Instant::now();
    let mut found = false;

    scanner_socket.set_read_timeout(Some(Duration::from_secs(1))).ok();
    while start.elapsed() < Duration::from_secs(3) {
        if let Ok((len, addr)) = scanner_socket.recv_from(&mut buf) {
            if let Some(device) = process_response(&buf[..len], addr) {
                if device.device_id == 99999 {
                    found = true;
                    break;
                }
            }
        }
    }

    responder_handle.join().ok();
    assert!(found, "Should have discovered the local test device");
}

fn is_whois(data: &[u8]) -> bool {
    if data.len() < 4 || data[0] != 0x81 { return false; }
    let npdu_start = match data[1] { 0x0A | 0x0B => 4, 0x04 => 10, _ => return false };
    if data.len() <= npdu_start { return false; }
    let (_npdu, npdu_len) = match Npdu::decode(&data[npdu_start..]) {
        Ok(res) => res,
        Err(_) => return false,
    };
    let apdu_start = npdu_start + npdu_len;
    if data.len() <= apdu_start { return false; }
    let apdu = &data[apdu_start..];
    apdu.len() >= 2 && apdu[0] == 0x10 && apdu[1] == UnconfirmedServiceChoice::WhoIs as u8
}

fn create_iam_response(device: &Device) -> Vec<u8> {
    let iam = IAmRequest::new(device.identifier, 1476, 0, device.vendor_identifier as u32);
    let mut iam_buffer = Vec::new();
    iam.encode(&mut iam_buffer).unwrap();
    let npdu = Npdu::new();
    let mut apdu = vec![0x10, UnconfirmedServiceChoice::IAm as u8];
    apdu.extend_from_slice(&iam_buffer);
    let mut bvlc = vec![0x81, 0x0A, 0x00, 0x00];
    bvlc.extend_from_slice(&npdu.encode());
    bvlc.extend_from_slice(&apdu);
    let total_len = bvlc.len() as u16;
    bvlc[2] = (total_len >> 8) as u8;
    bvlc[3] = (total_len & 0xFF) as u8;
    bvlc
}
