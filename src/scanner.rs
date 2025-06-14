use crate::scan_report::ScanReport;
use crate::scan_type::ScanType;
use crate::tcp_port_scanner::TcpPortScanner;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

pub struct Scan {
    pub iname: String,
    pub scan: ScanType,
    pub dest_addr: Ipv4Addr,
    pub dest_addr_v6: Ipv6Addr,
    pub dest_host: String,
    pub ports: Vec<u16>,
    pub report: ScanReport,
    pub latency: Duration,
    pub down: bool,
}

impl Scan {
    pub fn default() -> Self {
        Self {
            iname: "wlo1".to_string(),
            scan: ScanType::SYN,
            dest_addr: Ipv4Addr::new(127, 0, 0, 1),
            dest_addr_v6: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
            ports: Vec::new(),
            report: ScanReport::new(),
            latency: Duration::default(),
            down: true,
            dest_host: String::default(),
        }
    }
    pub fn run(&mut self) {
        let mut scanner = TcpPortScanner::new(self.dest_addr, self.iname.clone(), &self.scan);
        for &port in &self.ports {
            let response = scanner.scan_port(port);
            let port_status = self.scan.interpret_response(response);
            self.report.ports.push((port, port_status));
        }
    }
}

pub enum PortState {
    OPEN,
    CLOSED,
    FILTERED,
    UNFILTERED,
    OpenFiltered,
    UNDETERMINED,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PortState::OPEN => write!(f, "open"),
            PortState::CLOSED => write!(f, "closed"),
            PortState::FILTERED => write!(f, "filtered"),
            PortState::UNFILTERED => write!(f, "unfiltered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
            PortState::UNDETERMINED => write!(f, "undetermined"),
        }
    }
}
