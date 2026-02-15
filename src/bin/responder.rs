use bacnet_rs::{
    app::Apdu,
    network::Npdu,
    object::{Device, ObjectIdentifier, ObjectType},
    service::{IAmRequest, UnconfirmedServiceChoice, WhoIsRequest, ConfirmedServiceChoice},
};
use bacnet_discovery::network::create_shared_socket;
use std::{
    sync::atomic::{AtomicBool, Ordering},
    sync::Arc,
    net::SocketAddr,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet Responder Device (Shared Mode with Points)");
    println!("=================================================");

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
            let data = &recv_buffer[..len];
            
            if let Some(whois) = process_whois(data) {
                if whois.matches(device_id) {
                    println!("Received Who-Is from {} -> Broadcasting I-Am", source);
                    if let Ok(response) = create_iam_response(&device) {
                        // Send to broadcast address so all shared sockets see it
                        let broadcast: SocketAddr = "255.255.255.255:47808".parse().unwrap();
                        let _ = socket.send_to(&response, broadcast);
                    }
                }
            } else if let Some((invoke_id, service_choice, service_data)) = process_confirmed_request(data) {
                match service_choice {
                    12 => { // ReadProperty
                        if let Some(obj_id) = extract_object_id_from_rp(&service_data) {
                            println!("Received ReadProperty for {:?} from {}", obj_id, source);
                            if let Some(response) = handle_read_property(invoke_id, obj_id) {
                                let _ = socket.send_to(&response, source);
                            }
                        }
                    }
                    14 => { // ReadPropertyMultiple
                        println!("Received ReadPropertyMultiple from {}", source);
                        if let Some(response) = handle_read_property_multiple(invoke_id, device_id) {
                            let _ = socket.send_to(&response, source);
                        }
                    }
                    _ => println!("Received unsupported confirmed service {} from {}", service_choice, source),
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

fn process_confirmed_request(data: &[u8]) -> Option<(u8, u8, Vec<u8>)> {
    if data.len() < 4 || data[0] != 0x81 { return None; }
    let npdu_start = match data[1] { 0x0A | 0x0B => 4, 0x04 => 10, _ => return None };
    if data.len() <= npdu_start { return None; }
    let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;
    let apdu_start = npdu_start + npdu_len;
    if data.len() <= apdu_start { return None; }
    let apdu = Apdu::decode(&data[apdu_start..]).ok()?;

    if let Apdu::ConfirmedRequest { invoke_id, service_choice, service_data, .. } = apdu {
        Some((invoke_id, service_choice, service_data))
    } else {
        None
    }
}

fn extract_object_id_from_rp(data: &[u8]) -> Option<ObjectIdentifier> {
    if data.len() >= 5 && data[0] == 0x0C {
        let bytes = [data[1], data[2], data[3], data[4]];
        let encoded = u32::from_be_bytes(bytes);
        let obj_type = ((encoded >> 22) & 0x3FF) as u16;
        let instance = encoded & 0x3FFFFF;
        ObjectType::try_from(obj_type).ok().map(|ot| ObjectIdentifier::new(ot, instance))
    } else {
        None
    }
}

fn handle_read_property(invoke_id: u8, obj_id: ObjectIdentifier) -> Option<Vec<u8>> {
    let val_bytes = match obj_id.object_type {
        ObjectType::AnalogInput => vec![0x44, 0x41, 0xB4, 0x00, 0x00],
        ObjectType::BinaryInput => vec![0x11, 0x01],
        ObjectType::AnalogValue => vec![0x44, 0x42, 0x48, 0x00, 0x00],
        _ => vec![0x21, 0x00],
    };

    let mut response_data = Vec::new();
    let encoded_id = ((obj_id.object_type as u32) << 22) | (obj_id.instance & 0x3FFFFF);
    response_data.push(0x0C);
    response_data.extend_from_slice(&encoded_id.to_be_bytes());
    response_data.push(0x19);
    response_data.push(85);
    response_data.push(0x3E);
    response_data.extend_from_slice(&val_bytes);
    response_data.push(0x3F);

    create_complex_ack(invoke_id, ConfirmedServiceChoice::ReadProperty, response_data).ok()
}

fn handle_read_property_multiple(invoke_id: u8, device_id: u32) -> Option<Vec<u8>> {
    let objects = vec![
        (ObjectType::Device, device_id),
        (ObjectType::AnalogInput, 1),
        (ObjectType::BinaryInput, 1),
        (ObjectType::AnalogValue, 1),
    ];

    let mut service_data = Vec::new();
    let dev_id_encoded = ((ObjectType::Device as u32) << 22) | (device_id & 0x3FFFFF);
    service_data.push(0x0C);
    service_data.extend_from_slice(&dev_id_encoded.to_be_bytes());
    service_data.push(0x1E);
    service_data.push(0x29);
    service_data.push(76);
    service_data.push(0x4E);
    for (ot, inst) in objects {
        let encoded = ((ot as u32) << 22) | (inst & 0x3FFFFF);
        service_data.push(0xC4);
        service_data.extend_from_slice(&encoded.to_be_bytes());
    }
    service_data.push(0x4F);
    service_data.push(0x1F);

    create_complex_ack(invoke_id, ConfirmedServiceChoice::ReadPropertyMultiple, service_data).ok()
}

fn create_complex_ack(invoke_id: u8, service: ConfirmedServiceChoice, service_data: Vec<u8>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let apdu = Apdu::ComplexAck {
        segmented: false,
        more_follows: false,
        invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: service as u8,
        service_data,
    };
    let mut npdu = Npdu::new();
    let mut message = npdu.encode();
    message.extend_from_slice(&apdu.encode());
    let mut bvlc = vec![0x81, 0x0A, 0x00, 0x00];
    bvlc.extend_from_slice(&message);
    let total_len = bvlc.len() as u16;
    bvlc[2] = (total_len >> 8) as u8;
    bvlc[3] = (total_len & 0xFF) as u8;
    Ok(bvlc)
}

fn create_iam_response(device: &Device) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let iam = IAmRequest::new(device.identifier, 1476, 0, device.vendor_identifier as u32);
    let mut iam_buffer = Vec::new();
    iam.encode(&mut iam_buffer)?;
    let npdu = Npdu::new();
    let mut apdu = vec![0x10, UnconfirmedServiceChoice::IAm as u8];
    apdu.extend_from_slice(&iam_buffer);
    
    // Change to Original-Broadcast-NPDU (0x0B)
    let mut bvlc = vec![0x81, 0x0B, 0x00, 0x00];
    bvlc.extend_from_slice(&npdu.encode());
    bvlc.extend_from_slice(&apdu);
    let total_len = bvlc.len() as u16;
    bvlc[2] = (total_len >> 8) as u8;
    bvlc[3] = (total_len & 0xFF) as u8;
    Ok(bvlc)
}
