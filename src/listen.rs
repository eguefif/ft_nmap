use pnet::{
    packet::tcp::{TcpFlags, TcpPacket},
    transport::{tcp_packet_iter, TransportReceiver},
};

pub fn listen_responses(mut rx: TransportReceiver, port_source: u16) {
    let mut tcp_iter = tcp_packet_iter(&mut rx);
    loop {
        match tcp_iter.next() {
            Ok((packet, addr)) => {
                if should_dismiss_packet(&packet, port_source) {
                    continue;
                }
                let flags = get_flags(&packet);
                println!(
                    "Receive from {} TCP {} -> {} {}",
                    addr,
                    packet.get_source(),
                    packet.get_destination(),
                    flags
                );
            }
            Err(e) => eprintln!("Error while processing packet: {e}"),
        }
    }
}

fn should_dismiss_packet(packet: &TcpPacket, port_source: u16) -> bool {
    if packet.get_destination() != port_source {
        return true;
    }
    false
}

fn get_flags(packet: &TcpPacket) -> String {
    let mut flags = vec!["["];
    if packet.get_flags() & TcpFlags::SYN == 1 {
        flags.push("SYN");
    }

    if packet.get_flags() & TcpFlags::ACK == 1 {
        flags.push("ACK");
    }
    flags.push("]");
    flags.join(", ")
}
