use std::net::Ipv4Addr;

use scan_report::ScanReport;

pub mod interface;
pub mod listen;
pub mod packet_crafter;
pub mod scan_report;
pub mod syn_scan;

pub enum ScanType {
    REG,
    SYN,
}

impl ScanType {
    pub fn from_char(value: Option<char>) -> ScanType {
        if let Some(scan_value) = value {
            match scan_value {
                'S' => ScanType::SYN,
                'R' => ScanType::REG,
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
    pub ports: Vec<u16>,
    pub report: ScanReport,
}

impl Scan {
    pub fn default() -> Self {
        Self {
            iname: "wlo1".to_string(),
            scan: ScanType::REG,
            dest_addr: Ipv4Addr::new(127, 0, 0, 1),
            ports: Vec::new(),
            report: ScanReport::new(),
        }
    }
}
