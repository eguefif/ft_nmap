use crate::tcp_port_scanner::Response;
use crate::tcp_port_scanner::TcpPortScanner;
use crate::PortState;
use crate::Scan;

pub fn run_ack_scan(scan: &mut Scan) {
    let mut scanner = TcpPortScanner::new(scan.dest_addr, scan.iname.clone(), &scan.scan);
    for &port in &scan.ports {
        let response = scanner.scan_port(port);
        let port_status = interpret_response(response);
        scan.report.ports.push((port, port_status));
    }
}

fn interpret_response(packet: Response) -> PortState {
    match packet {
        Response::TCP(flags) => {
            if flags.rst {
                return PortState::UNFILTERED;
            }
            return PortState::FILTERED;
        }
        Response::TIMEOUT => PortState::FILTERED,
    }
}
