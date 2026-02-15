use bacnet_rs::{
    network::Npdu,
    service::UnconfirmedServiceChoice,
};
use bacnet_discovery::network::create_shared_socket;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("BACnet Network Sniffer (Shared Mode)");
    println!("====================================");

    let socket = match create_shared_socket(47808) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Error: Could not bind to 47808: {}", e);
            return Err(e.into());
        }
    };

    println!("Listening for BACnet traffic on port 47808 (Shared)...");
    println!("Press Ctrl+C to stop.\n");

    let mut buffer = [0u8; 1500];
    loop {
        match socket.recv_from(&mut buffer) {
            Ok((len, source)) => {
                println!("--- Packet from {} ({} bytes) ---", source, len);
                let data = &buffer[..len];
                
                if len >= 4 && data[0] == 0x81 {
                    let bvlc_func = data[1];
                    let bvlc_type = match bvlc_func {
                        0x00 => "Result",
                        0x04 => "Forwarded-NPDU",
                        0x0A => "Original-Unicast-NPDU",
                        0x0B => "Original-Broadcast-NPDU",
                        _ => "Unknown",
                    };
                    println!("BVLL: {} (0x{:02X})", bvlc_type, bvlc_func);

                    let npdu_start = match bvlc_func {
                        0x0A | 0x0B => 4,
                        0x04 => 10,
                        _ => 0,
                    };

                    if npdu_start > 0 && len > npdu_start {
                        if let Ok((_npdu, npdu_len)) = Npdu::decode(&data[npdu_start..]) {
                            let apdu_start = npdu_start + npdu_len;
                            if len > apdu_start {
                                let apdu = &data[apdu_start..];
                                let pdu_type = (apdu[0] & 0xF0) >> 4;
                                if pdu_type == 1 && apdu.len() >= 2 {
                                    let service = apdu[1];
                                    if service == UnconfirmedServiceChoice::IAm as u8 {
                                        println!("SERVICE: I-Am");
                                    } else if service == UnconfirmedServiceChoice::WhoIs as u8 {
                                        println!("SERVICE: Who-Is");
                                    }
                                }
                            }
                        }
                    }
                }
                println!();
            }
            Err(e) => eprintln!("Error receiving: {}", e),
        }
    }
}
