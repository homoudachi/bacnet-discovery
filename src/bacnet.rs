use bacnet_rs::{
    app::{Apdu, MaxApduSize, MaxSegments},
    network::Npdu,
    object::{ObjectIdentifier, ObjectType},
    service::{
        ConfirmedServiceChoice, IAmRequest, PropertyReference, ReadAccessSpecification,
        ReadPropertyMultipleRequest, UnconfirmedServiceChoice, WhoIsRequest,
    },
    vendor::get_vendor_name,
};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant};
use anyhow::{Result, anyhow};
use tracing::{debug, warn};
use crate::app::BacnetObject;

#[derive(Debug, Clone)]
pub struct DiscoveredDevice {
    pub device_id: u32,
    pub address: SocketAddr,
    pub vendor_id: u32,
    pub vendor_name: String,
    pub max_apdu: u32,
    pub segmentation: u32,
    pub last_seen: Instant,
}

pub fn send_whois(socket: &UdpSocket) -> Result<()> {
    debug!("Encoding Who-Is request");
    let whois = WhoIsRequest::new();
    let mut service_data = Vec::new();
    whois.encode(&mut service_data)?;

    let mut apdu = vec![0x10, UnconfirmedServiceChoice::WhoIs as u8];
    apdu.extend_from_slice(&service_data);

    let npdu = Npdu::global_broadcast();
    let npdu_buffer = npdu.encode();

    let mut message = npdu_buffer;
    message.extend_from_slice(&apdu);

    let mut bvlc = vec![0x81, 0x0B, 0x00, 0x00];
    bvlc.extend_from_slice(&message);
    let total_len = bvlc.len() as u16;
    bvlc[2] = (total_len >> 8) as u8;
    bvlc[3] = (total_len & 0xFF) as u8;

    let broadcast_addr: SocketAddr = "255.255.255.255:47808".parse()?;
    socket.send_to(&bvlc, broadcast_addr)?;
    
    Ok(())
}

pub fn process_response(data: &[u8], source: SocketAddr) -> Option<DiscoveredDevice> {
    if data.len() < 4 || data[0] != 0x81 {
        return None;
    }

    let bvlc_func = data[1];
    let npdu_start = match bvlc_func {
        0x0A | 0x0B => 4,
        0x04 => 10,
        _ => return None,
    };

    if data.len() <= npdu_start {
        return None;
    }

    let (_npdu, npdu_len) = match Npdu::decode(&data[npdu_start..]) {
        Ok(res) => res,
        Err(_) => return None,
    };

    let apdu_start = npdu_start + npdu_len;
    if data.len() <= apdu_start {
        return None;
    }

    let apdu = &data[apdu_start..];
    if apdu.len() < 2 || apdu[0] != 0x10 || apdu[1] != UnconfirmedServiceChoice::IAm as u8 {
        return None;
    }

    match IAmRequest::decode(&apdu[2..]) {
        Ok(iam) => {
            let vendor_id = iam.vendor_identifier;
            let vendor_name = get_vendor_name(vendor_id as u16)
                .unwrap_or("Unknown Vendor")
                .to_string();

            Some(DiscoveredDevice {
                device_id: iam.device_identifier.instance,
                address: source,
                vendor_id,
                vendor_name,
                max_apdu: iam.max_apdu_length_accepted,
                segmentation: iam.segmentation_supported,
                last_seen: Instant::now(),
            })
        }
        Err(_) => None,
    }
}

pub fn read_device_objects(socket: &UdpSocket, addr: SocketAddr, device_id: u32) -> Result<Vec<BacnetObject>> {
    debug!("Reading object list for device {}", device_id);
    
    let device_obj = ObjectIdentifier::new(ObjectType::Device, device_id);
    let prop_ref = PropertyReference::new(76); // Object_List
    let read_spec = ReadAccessSpecification::new(device_obj, vec![prop_ref]);
    let rpm_request = ReadPropertyMultipleRequest::new(vec![read_spec]);

    let mut service_data = Vec::new();
    encode_rpm_request_into(&rpm_request, &mut service_data)?;

    let response = send_confirmed_request(
        socket, 
        addr, 
        1, 
        ConfirmedServiceChoice::ReadPropertyMultiple, 
        &service_data
    )?;

    let mut objects = Vec::new();
    let mut pos = 0;
    while pos + 5 <= response.len() {
        if response[pos] == 0xC4 {
            pos += 1;
            let bytes = [response[pos], response[pos+1], response[pos+2], response[pos+3]];
            let encoded = u32::from_be_bytes(bytes);
            let obj_type = ((encoded >> 22) & 0x3FF) as u16;
            let instance = encoded & 0x3FFFFF;
            
            if let Ok(ot) = ObjectType::try_from(obj_type) {
                if ot != ObjectType::Device {
                    objects.push(BacnetObject {
                        id: ObjectIdentifier::new(ot, instance),
                        name: format!("{:?}:{}", ot, instance),
                        present_value: "N/A".to_string(),
                        units: "".to_string(),
                        last_updated: Instant::now(),
                    });
                }
            }
            pos += 4;
        } else {
            pos += 1;
        }
    }

    Ok(objects)
}

pub fn read_present_value(socket: &UdpSocket, addr: SocketAddr, obj: ObjectIdentifier) -> Result<String> {
    // Read Property 85 (Present_Value)
    let mut service_data = vec![0x09, 0x55]; // Context tag 1 (propertyIdentifier), length 1, value 85
    
    // Wrapped in ReadProperty (Service 12)
    let mut apdu_service_data = vec![0x0C]; // Context tag 0 (objectIdentifier), length 4
    let encoded_id = ((obj.object_type as u32) << 22) | (obj.instance & 0x3FFFFF);
    apdu_service_data.extend_from_slice(&encoded_id.to_be_bytes());
    apdu_service_data.extend_from_slice(&service_data);

    let response = send_confirmed_request(
        socket, 
        addr, 
        2, 
        ConfirmedServiceChoice::ReadProperty, 
        &apdu_service_data
    )?;

    // Parse the value from response (simplified)
    if response.len() >= 3 && response[0] == 0x2E { // Opening tag 3 (propertyValue)
        let val_data = &response[1..response.len()-1];
        if !val_data.is_empty() {
            match val_data[0] {
                0x44 => { // Real
                    if val_data.len() >= 5 {
                        let bytes = [val_data[1], val_data[2], val_data[3], val_data[4]];
                        return Ok(format!("{:.2}", f32::from_be_bytes(bytes)));
                    }
                }
                0x11 => { // Boolean
                    if val_data.len() >= 2 {
                        return Ok(if val_data[1] != 0 { "Active".to_string() } else { "Inactive".to_string() });
                    }
                }
                0x21 => { // Unsigned
                    if val_data.len() >= 2 {
                        return Ok(val_data[1].to_string());
                    }
                }
                _ => return Ok(format!("Tag 0x{:02X}", val_data[0])),
            }
        }
    }

    Ok("N/A".to_string())
}

fn send_confirmed_request(
    socket: &UdpSocket,
    addr: SocketAddr,
    invoke_id: u8,
    service_choice: ConfirmedServiceChoice,
    service_data: &[u8],
) -> Result<Vec<u8>> {
    let apdu = Apdu::ConfirmedRequest {
        segmented: false,
        more_follows: false,
        segmented_response_accepted: true,
        max_segments: MaxSegments::Unspecified,
        max_response_size: MaxApduSize::Up1476,
        invoke_id,
        sequence_number: None,
        proposed_window_size: None,
        service_choice: service_choice as u8,
        service_data: service_data.to_vec(),
    };

    let apdu_data = apdu.encode();
    let mut npdu = Npdu::new();
    npdu.control.expecting_reply = true;
    let mut message = npdu.encode();
    message.extend_from_slice(&apdu_data);

    let mut bvlc = vec![0x81, 0x0A, 0x00, 0x00];
    bvlc.extend_from_slice(&message);
    let total_len = bvlc.len() as u16;
    bvlc[2] = (total_len >> 8) as u8;
    bvlc[3] = (total_len & 0xFF) as u8;

    socket.send_to(&bvlc, addr)?;

    let mut recv_buffer = [0u8; 1500];
    let start = Instant::now();
    while start.elapsed() < Duration::from_secs(3) {
        if let Ok((len, src)) = socket.recv_from(&mut recv_buffer) {
            if src == addr {
                if let Some(data) = parse_confirmed_response(&recv_buffer[..len], invoke_id) {
                    return Ok(data);
                }
            }
        }
    }
    
    Err(anyhow!("Timeout waiting for response from {}", addr))
}

fn parse_confirmed_response(data: &[u8], expected_invoke_id: u8) -> Option<Vec<u8>> {
    if data.len() < 4 || data[0] != 0x81 { return None; }
    let npdu_start = match data[1] { 0x0A => 4, 0x04 => 10, _ => return None };
    let (_npdu, npdu_len) = Npdu::decode(&data[npdu_start..]).ok()?;
    let apdu = Apdu::decode(&data[npdu_start + npdu_len..]).ok()?;

    match apdu {
        Apdu::ComplexAck { invoke_id, service_data, .. } if invoke_id == expected_invoke_id => Some(service_data),
        Apdu::Error { invoke_id, error_class, error_code, .. } if invoke_id == expected_invoke_id => {
            warn!("BACnet Error: class={}, code={}", error_class, error_code);
            None
        }
        _ => None,
    }
}

fn encode_rpm_request_into(request: &ReadPropertyMultipleRequest, buffer: &mut Vec<u8>) -> Result<()> {
    for spec in &request.read_access_specifications {
        let obj_id = ((spec.object_identifier.object_type as u32) << 22) | (spec.object_identifier.instance & 0x3FFFFF);
        buffer.push(0x0C); // Context tag 0, length 4
        buffer.extend_from_slice(&obj_id.to_be_bytes());
        buffer.push(0x1E); // Context tag 1, opening tag
        for prop_ref in &spec.property_references {
            buffer.push(0x09); // Context tag 0, length 1
            buffer.push(prop_ref.property_identifier as u8);
        }
        buffer.push(0x1F); // Context tag 1, closing tag
    }
    Ok(())
}
