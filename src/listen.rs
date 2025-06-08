use std::time::{Duration, Instant};

use pnet::{
    packet::tcp::{TcpFlags, TcpPacket},
    transport::{tcp_packet_iter, TransportReceiver},
};

pub enum PortStatus {
    OPEN,
    CLOSED,
    FILTERED,
}

const TIMEOUT_MS: u64 = 500;

impl std::fmt::Display for PortStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PortStatus::OPEN => write!(f, "open"),
            PortStatus::CLOSED => write!(f, "closed"),
            PortStatus::FILTERED => write!(f, "filtered"),
        }
    }
}

pub fn listen_responses(rx: &mut TransportReceiver, port_source: u16) -> PortStatus {
    let mut tcp_iter = tcp_packet_iter(rx);
    let timeout = Duration::from_millis(TIMEOUT_MS);
    loop {
        match tcp_iter.next_with_timeout(timeout) {
            Ok(Some((packet, _))) => {
                if should_dismiss_packet(&packet, port_source) {
                    continue;
                }
                return get_port_status(&packet);
            }
            Ok(None) => {
                return PortStatus::FILTERED;
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
