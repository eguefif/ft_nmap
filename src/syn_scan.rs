use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;

use crate::tcp_transport::TcpPortScanner;
use crate::PortState;
use crate::Scan;

pub fn run_syn_scan(scan: &mut Scan) {
    let mut scanner = TcpPortScanner::new(
        scan.dest_addr,
        scan.iname.clone(),
        &interpret_response,
        &scan.scan,
    );
    for &port in &scan.ports {
        let port_status = scanner.scan_port(port);
        scan.report.ports.push((port, port_status));
    }
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
