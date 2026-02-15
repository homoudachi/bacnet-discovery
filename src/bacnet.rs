use bacnet_rs::{
    network::Npdu,
    service::{IAmRequest, UnconfirmedServiceChoice, WhoIsRequest},
    vendor::get_vendor_name,
};
use std::net::{SocketAddr, UdpSocket};
use std::time::Instant;
use anyhow::Result;
use tracing::{debug, warn};

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

/// Sends a global Who-Is broadcast to discover BACnet devices.
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

    // Wrap in BVLC Original-Broadcast-NPDU (0x0B)
    let mut bvlc = vec![0x81, 0x0B, 0x00, 0x00];
    bvlc.extend_from_slice(&message);
    let total_len = bvlc.len() as u16;
    bvlc[2] = (total_len >> 8) as u8;
    bvlc[3] = (total_len & 0xFF) as u8;

    let broadcast_addr: SocketAddr = "255.255.255.255:47808".parse()?;
    debug!("Broadcasting Who-Is to {}", broadcast_addr);
    socket.send_to(&bvlc, broadcast_addr)?;
    
    Ok(())
}

/// Parses a raw BACnet/IP packet looking for I-Am responses.
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
        Err(e) => {
            debug!("Failed to decode NPDU from {}: {:?}", source, e);
            return None;
        }
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
        Err(e) => {
            warn!("Failed to decode I-Am request from {}: {:?}", source, e);
            None
        }
    }
}
