use std::net::{Ipv4Addr, Ipv6Addr};

use scan_report::ScanReport;
use std::time::Duration;

pub mod dns_lookup;
pub mod interface;
pub mod null_scan;
pub mod packet_crafter;
pub mod pre_scan;
pub mod scan_report;
pub mod syn_scan;
pub mod tcp_transport;

pub enum ScanType {
    SYN,
    NULL,
}

impl ScanType {
    pub fn from_char(value: Option<char>) -> ScanType {
        if let Some(scan_value) = value {
            match scan_value {
                'S' => ScanType::SYN,
                'N' => ScanType::NULL,
                _ => panic!("Error: invalid -s scan type"),
            }
        } else {
            panic!("Error: no value for -s");
        }
    }
}

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
}

pub enum PortState {
    OPEN,
    CLOSED,
    FILTERED,
    OpenFiltered,
}

impl std::fmt::Display for PortState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            PortState::OPEN => write!(f, "open"),
            PortState::CLOSED => write!(f, "closed"),
            PortState::FILTERED => write!(f, "filtered"),
            PortState::OpenFiltered => write!(f, "open|filtered"),
        }
    }
}
