use crate::packet_crafter::TcpType;
use crate::tcp_transport::TCPTransport;
use crate::PortState;
use crate::Scan;

pub fn run_syn_scan(scan: &mut Scan) {
    let mut transport = TCPTransport::new(scan.dest_addr, scan.iname.clone());
    for &port in &scan.ports {
        transport.dest_port = port;
        let port_status = scan_port(&mut transport, false);
        scan.report.ports.push((port, port_status));
    }
}

fn scan_port(transport: &mut TCPTransport, filtered: bool) -> PortState {
    transport.send(&[TcpType::SYN]);

    let port_status = transport.listen_responses();
    match port_status {
        PortState::OPEN => transport.send(&[TcpType::RST]),
        PortState::FILTERED => {
            if !filtered {
                return scan_port(transport, true);
            }
        }
        PortState::CLOSED => {}
    }
    port_status
}
