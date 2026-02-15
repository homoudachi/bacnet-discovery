use bacnet_discovery::bacnet::{send_whois_to, process_response, read_device_objects};
use bacnet_rs::{
    app::Apdu,
    network::Npdu,
    object::{ObjectIdentifier, ObjectType},
    service::{IAmRequest, ConfirmedServiceChoice},
};
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;
use std::thread;
use tokio::sync::mpsc;

#[tokio::test]
async fn test_point_discovery() {
    let responder_port = 47811;
    let _responder_handle = thread::spawn(move || {
        let socket = UdpSocket::bind(format!("127.0.0.1:{}", responder_port)).expect("Responder failed to bind");
        let device_id = 12345;
        let mut buf = [0u8; 1500];
        
        loop {
            socket.set_read_timeout(Some(Duration::from_millis(100))).ok();
            if let Ok((len, source)) = socket.recv_from(&mut buf) {
                let data = &buf[..len];
                if let Some(whois) = process_whois(data) {
                    if whois.matches(device_id) {
                        let iam = create_iam_response(device_id);
                        socket.send_to(&iam, source).ok();
                    }
                } else if let Some((invoke_id, service, _)) = process_confirmed_request(data) {
                    if service == 14 { // RPM
                        let res = create_rpm_response(invoke_id, device_id);
                        socket.send_to(&res, source).ok();
                    }
                }
            }
        }
    });

    thread::sleep(Duration::from_millis(200));

    let scanner_socket = UdpSocket::bind("127.0.0.1:0").expect("Scanner failed to bind");
    let dest: SocketAddr = format!("127.0.0.1:{}", responder_port).parse().unwrap();
    
    let (tx_register, mut rx_register) = mpsc::channel::<(u8, tokio::sync::oneshot::Sender<Vec<u8>>)>(10);
    let (tx_found, mut rx_found) = mpsc::channel(10);
    
    let s_clone = scanner_socket.try_clone().unwrap();
    tokio::spawn(async move {
        let mut pending: std::collections::HashMap<u8, tokio::sync::oneshot::Sender<Vec<u8>>> = std::collections::HashMap::new();
        let mut buf = [0u8; 1500];
        loop {
            tokio::select! {
                reg = rx_register.recv() => {
                    if let Some((id, tx)) = reg { pending.insert(id, tx); }
                }
                _ = tokio::task::yield_now() => {
                    s_clone.set_nonblocking(true).ok();
                    if let Ok((len, addr)) = s_clone.recv_from(&mut buf) {
                        let data = &buf[..len];
                        if let Some(device) = process_response(data, addr) {
                            let _ = tx_found.send(device).await;
                        } else if let Some((id, sdata)) = bacnet_discovery::bacnet::parse_confirmed_response(data) {
                            if let Some(tx) = pending.remove(&id) { let _ = tx.send(sdata); }
                        }
                    }
                }
            }
        }
    });

    send_whois_to(&scanner_socket, dest).unwrap();
    let device = tokio::time::timeout(Duration::from_secs(2), rx_found.recv()).await.unwrap().unwrap();
    assert_eq!(device.device_id, 12345);

    let points = read_device_objects(&scanner_socket, device.address, device.device_id, 1, &tx_register).await.unwrap();
    assert!(!points.is_empty());
}

fn process_whois(data: &[u8]) -> Option<bacnet_rs::service::WhoIsRequest> {
    if data.len() < 4 || data[0] != 0x81 { return None; }
    let npdu_start = match data[1] { 0x0A | 0x0B => 4, 0x04 => 10, _ => return None };
    let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;
    let apdu = &data[npdu_start + npdu_len..];
    if apdu.len() >= 2 && apdu[0] == 0x10 && apdu[1] == 8 {
        if apdu.len() > 2 { bacnet_rs::service::WhoIsRequest::decode(&apdu[2..]).ok() } else { Some(bacnet_rs::service::WhoIsRequest::new()) }
    } else { None }
}

fn process_confirmed_request(data: &[u8]) -> Option<(u8, u8, Vec<u8>)> {
    if data.len() < 4 || data[0] != 0x81 { return None; }
    let npdu_start = match data[1] { 0x0A | 0x0B => 4, 0x04 => 10, _ => return None };
    let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;
    let apdu = Apdu::decode(&data[npdu_start + npdu_len..]).ok()?;
    if let Apdu::ConfirmedRequest { invoke_id, service_choice, service_data, .. } = apdu {
        Some((invoke_id, service_choice, service_data))
    } else { None }
}

fn create_iam_response(id: u32) -> Vec<u8> {
    let iam = IAmRequest::new(ObjectIdentifier::new(ObjectType::Device, id), 1476, 0, 260);
    let mut buf = Vec::new();
    iam.encode(&mut buf).unwrap();
    let mut apdu = vec![0x10, 0];
    apdu.extend_from_slice(&buf);
    let mut msg = Npdu::new().encode();
    msg.extend_from_slice(&apdu);
    let mut bvlc = vec![0x81, 0x0A, 0, (msg.len()+4) as u8];
    bvlc.extend_from_slice(&msg);
    bvlc
}

fn create_rpm_response(invoke_id: u8, device_id: u32) -> Vec<u8> {
    let mut service_data = Vec::new();
    let dev_id_encoded = ((ObjectType::Device as u32) << 22) | (device_id & 0x3FFFFF);
    service_data.push(0x0C);
    service_data.extend_from_slice(&dev_id_encoded.to_be_bytes());
    service_data.push(0x1E);
    service_data.push(0x29);
    service_data.push(76);
    service_data.push(0x4E);
    let obj_encoded = ((ObjectType::AnalogInput as u32) << 22) | (1 & 0x3FFFFF);
    service_data.push(0xC4);
    service_data.extend_from_slice(&obj_encoded.to_be_bytes());
    service_data.push(0x4F);
    service_data.push(0x1F);

    let apdu = Apdu::ComplexAck {
        segmented: false,
        more_follows: false,
        invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: ConfirmedServiceChoice::ReadPropertyMultiple as u8,
        service_data,
    };
    let mut msg = Npdu::new().encode();
    msg.extend_from_slice(&apdu.encode());
    let mut bvlc = vec![0x81, 0x0A, 0, (msg.len()+4) as u8];
    bvlc.extend_from_slice(&msg);
    bvlc
}
