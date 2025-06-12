use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;

use crate::packet_crafter::TcpFlag;
use crate::tcp_transport::TCPTransport;
use crate::PortState;
use crate::Scan;

pub fn run_syn_scan(scan: &mut Scan) {
    let mut transport = TCPTransport::new(scan.dest_addr, scan.iname.clone(), &interpret_response);
    for &port in &scan.ports {
        transport.dest_port = port;
        let port_status = scan_port(&mut transport, false);
        scan.report.ports.push((port, port_status));
    }
}

fn scan_port(transport: &mut TCPTransport, filtered: bool) -> PortState {
    transport.send(&[TcpFlag::SYN]);

    let port_status = transport.listen_responses();
    match port_status {
        PortState::OPEN => transport.send(&[TcpFlag::RST]),
        PortState::FILTERED | PortState::OpenFiltered => {
            if !filtered {
                return scan_port(transport, true);
            }
        }
        PortState::CLOSED => {}
    }
    port_status
}

fn interpret_response(packet: Option<&TcpPacket>) -> PortState {
    match packet {
        Some(packet) => {
            if packet.get_flags() & TcpFlags::SYN == TcpFlags::SYN
                && packet.get_flags() & TcpFlags::ACK == TcpFlags::ACK
            {
                return PortState::OPEN;
            }

            if packet.get_flags() & TcpFlags::RST == TcpFlags::RST {
                return PortState::CLOSED;
            }
            return PortState::FILTERED;
        }
        None => PortState::FILTERED,
    }
}
