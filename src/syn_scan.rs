use crate::packet_crafter::TcpType;
use crate::tcp_transport::{PortStatus, TCPTransport};
use crate::Scan;

pub fn run_syn_scan(scan: &mut Scan) {
    let mut transport = TCPTransport::new(scan.dest_addr, scan.iname.clone());
    for &port in &scan.ports {
        transport.dest_port = port;
        let port_status = scan_port(&mut transport, false);
        scan.report.ports.push((port, port_status));
    }
}

fn scan_port(transport: &mut TCPTransport, filtered: bool) -> PortStatus {
    transport.send(&[TcpType::SYN]);

    let port_status = transport.listen_responses();
    match port_status {
        PortStatus::OPEN => transport.send(&[TcpType::RST]),
        PortStatus::FILTERED => {
            if !filtered {
                return scan_port(transport, true);
            }
        }
        PortStatus::CLOSED => {}
    }
    port_status
}
