use crate::tcp_port_scanner::Response;
use crate::tcp_port_scanner::TcpPortScanner;
use crate::PortState;
use crate::Scan;

pub fn run_syn_scan(scan: &mut Scan) {
    let mut scanner = TcpPortScanner::new(scan.dest_addr, scan.iname.clone(), &scan.scan);
    for &port in &scan.ports {
        let response = scanner.scan_port(port);
        let port_status = interpret_response(response);
        scan.report.ports.push((port, port_status));
    }
}

// Wonder if I could refactor this.
// the run_syn_scan is the same for everybody. The only difference is in the scan type
// in the scan.
// Maybe the interpret_response could be in the scan_type enum

fn interpret_response(packet: Response) -> PortState {
    match packet {
        Response::TCP(flags) => {
            if flags.syn && flags.ack {
                return PortState::OPEN;
            } else if flags.rst {
                return PortState::CLOSED;
            }
            return PortState::FILTERED;
        }
        Response::TIMEOUT => PortState::FILTERED,
    }
}
