use crate::scan_report::ScanReport;
use crate::tcp_flag::TcpFlag;
use crate::tcp_port_scanner::Response;
use crate::tcp_port_scanner::TcpPortScanner;
use crate::udp_port_scanner::UdpPortScanner;
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

pub trait Scanner {
    fn scan_port(&mut self, scan_port: u16) -> Response;
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
        let mut scanner = self.get_scanner();
        for &port in &self.ports {
            let response = scanner.scan_port(port);
            let port_status = self.scan.interpret_response(response);
            self.report.ports.push((port, port_status));
        }
    }

    fn get_scanner(&self) -> Box<dyn Scanner> {
        match self.scan {
            ScanType::UDP => Box::new(UdpPortScanner::new(
                self.dest_addr,
                self.iname.clone(),
                &self.scan,
            )),
            _ => Box::new(TcpPortScanner::new(
                self.dest_addr,
                self.iname.clone(),
                &self.scan,
            )),
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

pub enum ScanType {
    SYN,
    FIN,
    XMAS,
    NULL,
    ACK,
    UDP,
}

impl ScanType {
    pub fn from_char(value: Option<char>) -> ScanType {
        if let Some(scan_value) = value {
            match scan_value {
                'S' => ScanType::SYN,
                'N' => ScanType::NULL,
                'X' => ScanType::XMAS,
                'F' => ScanType::FIN,
                'A' => ScanType::ACK,
                'U' => ScanType::UDP,
                _ => panic!("Error: invalid -s scan type"),
            }
        } else {
            panic!("Error: no value for -s");
        }
    }

    pub fn interpret_response(&self, response: Response) -> PortState {
        match self {
            ScanType::SYN => interpret_syn_scan_response(response),
            ScanType::NULL | ScanType::XMAS | ScanType::FIN => {
                interpret_xmas_null_fin_scan_response(response)
            }
            ScanType::ACK => interpret_ack_scan_response(response),
            ScanType::UDP => interpret_udp_scan_response(response),
        }
    }

    pub fn get_flags(&self) -> Vec<TcpFlag> {
        match self {
            ScanType::SYN => vec![TcpFlag::SYN],
            ScanType::ACK => vec![TcpFlag::ACK],
            ScanType::NULL => vec![],
            ScanType::FIN => vec![TcpFlag::FIN],
            ScanType::XMAS => vec![TcpFlag::RST, TcpFlag::URG, TcpFlag::PSH],
            ScanType::UDP => panic!("Error: trying to get TCP flag for UDP scan"),
        }
    }
}

fn interpret_syn_scan_response(packet: Response) -> PortState {
    match packet {
        Response::TCP(flags) => {
            if flags.syn && flags.ack {
                return PortState::OPEN;
            } else if flags.rst {
                return PortState::CLOSED;
            }
            return PortState::UNDETERMINED;
        }
        Response::ICMP((icmp_type, code)) => {
            if icmp_type == 3 && [1, 2, 3, 9, 10, 13].contains(&code) {
                return PortState::FILTERED;
            }
            return PortState::UNDETERMINED;
        }
        Response::UDP(_) => return PortState::UNDETERMINED,
        Response::TIMEOUT => PortState::FILTERED,
    }
}

fn interpret_xmas_null_fin_scan_response(packet: Response) -> PortState {
    match packet {
        Response::TCP(flags) => {
            if flags.rst {
                return PortState::CLOSED;
            }
            return PortState::UNDETERMINED;
        }
        Response::ICMP((icmp_type, code)) => {
            if icmp_type == 3 && [1, 2, 3, 9, 10, 13].contains(&code) {
                return PortState::FILTERED;
            }
            return PortState::UNDETERMINED;
        }
        Response::UDP(_) => return PortState::UNDETERMINED,
        Response::TIMEOUT => PortState::OpenFiltered,
    }
}

fn interpret_ack_scan_response(packet: Response) -> PortState {
    match packet {
        Response::TCP(flags) => {
            if flags.rst {
                return PortState::UNFILTERED;
            }
            return PortState::UNDETERMINED;
        }
        Response::ICMP((icmp_type, code)) => {
            if icmp_type == 3 && [1, 2, 3, 9, 10, 13].contains(&code) {
                return PortState::FILTERED;
            }
            return PortState::UNDETERMINED;
        }
        Response::UDP(_) => return PortState::UNDETERMINED,
        Response::TIMEOUT => PortState::FILTERED,
    }
}

fn interpret_udp_scan_response(packet: Response) -> PortState {
    match packet {
        Response::UDP(_) => {
            return PortState::UNDETERMINED;
        }
        Response::ICMP(_) | Response::TCP(_) => return PortState::UNDETERMINED,
        Response::TIMEOUT => PortState::FILTERED,
    }
}
