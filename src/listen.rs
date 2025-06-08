use pnet::{
    packet::tcp::{TcpFlags, TcpPacket},
    transport::{tcp_packet_iter, TransportReceiver},
};

pub enum PortStatus {
    OPEN,
    CLOSED,
    FILTERED,
}

impl std::fmt::Display for PortStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PortStatus::OPEN => write!(f, "open"),
            PortStatus::CLOSED => write!(f, "closed"),
            PortStatus::FILTERED => write!(f, "filtered"),
        }
    }
}

pub fn listen_responses(mut rx: TransportReceiver, port_source: u16) -> PortStatus {
    let mut tcp_iter = tcp_packet_iter(&mut rx);
    loop {
        match tcp_iter.next() {
            Ok((packet, addr)) => {
                if should_dismiss_packet(&packet, port_source) {
                    continue;
                }
                let flags = get_flags(&packet);
                println!(
                    "Receive from {} TCP {} -> {} [{}]",
                    addr,
                    packet.get_source(),
                    packet.get_destination(),
                    flags
                );
                return get_port_status(&packet);
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
    let mut flags = Vec::new();
    if packet.get_flags() & TcpFlags::SYN == TcpFlags::SYN {
        flags.push("SYN");
    }

    if packet.get_flags() & TcpFlags::RST == TcpFlags::RST {
        flags.push("RST");
    }

    if packet.get_flags() & TcpFlags::ACK == TcpFlags::ACK {
        flags.push("ACK");
    }
    flags.join(", ")
}

fn get_port_status(packet: &TcpPacket) -> PortStatus {
    if packet.get_flags() & TcpFlags::SYN == TcpFlags::SYN
        && packet.get_flags() & TcpFlags::ACK == TcpFlags::ACK
    {
        return PortStatus::OPEN;
    }

    if packet.get_flags() & TcpFlags::RST == TcpFlags::RST {
        return PortStatus::CLOSED;
    }
    return PortStatus::FILTERED;
}
