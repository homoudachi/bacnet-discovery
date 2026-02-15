use bacnet_discovery::bacnet::{process_response, DiscoveredDevice};
use bacnet_rs::service::{IAmRequest, UnconfirmedServiceChoice};
use bacnet_rs::network::Npdu;
use bacnet_rs::object::{ObjectIdentifier, ObjectType};
use std::net::SocketAddr;

#[test]
fn test_process_iam_response() {
    // Manually construct a valid BACnet I-Am packet
    let device_id = 1234;
    let vendor_id = 260;
    
    let iam = IAmRequest::new(
        ObjectIdentifier::new(ObjectType::Device, device_id),
        1476,
        0,
        vendor_id,
    );
    
    let mut iam_buf = Vec::new();
    iam.encode(&mut iam_buf).unwrap();
    
    let npdu = Npdu::new();
    let npdu_buf = npdu.encode();
    
    let mut apdu = vec![0x10, UnconfirmedServiceChoice::IAm as u8];
    apdu.extend_from_slice(&iam_buf);
    
    let mut packet = vec![0x81, 0x0A, 0x00, 0x00]; // BVLC Unicast
    packet.extend_from_slice(&npdu_buf);
    packet.extend_from_slice(&apdu);
    
    let len = packet.len() as u16;
    packet[2] = (len >> 8) as u8;
    packet[3] = (len & 0xFF) as u8;
    
    let source: SocketAddr = "192.168.1.100:47808".parse().unwrap();
    let result = process_response(&packet, source);
    
    assert!(result.is_some());
    let device = result.unwrap();
    assert_eq!(device.device_id, device_id);
    assert_eq!(device.vendor_id, vendor_id);
    assert_eq!(device.address, source);
}

#[test]
fn test_process_invalid_packet() {
    let source: SocketAddr = "127.0.0.1:47808".parse().unwrap();
    assert!(process_response(&[0, 1, 2], source).is_none());
    assert!(process_response(&[0x81, 0x0A, 0, 10, 0, 0], source).is_none());
}
