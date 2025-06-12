use pnet::packet::tcp::TcpFlags;
use pnet::packet::tcp::TcpPacket;

use crate::tcp_transport::TcpPortScanner;
use crate::PortState;
use crate::Scan;

pub fn run_fin_scan(scan: &mut Scan) {
    let mut transport = TcpPortScanner::new(
        scan.dest_addr,
        scan.iname.clone(),
        &interpret_response,
        &scan.scan,
    );
    for &port in &scan.ports {
        let port_status = transport.scan_port(port);
        scan.report.ports.push((port, port_status));
    }
}

fn interpret_response(packet: Option<&TcpPacket>) -> PortState {
    match packet {
        Some(packet) => {
            if packet.get_flags() & TcpFlags::RST == TcpFlags::RST {
                return PortState::CLOSED;
            }
            return PortState::UNDETERMINED;
        }
        None => PortState::OpenFiltered,
    }
}
