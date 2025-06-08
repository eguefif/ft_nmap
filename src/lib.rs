use std::net::Ipv4Addr;

pub mod interface;
pub mod listen;
pub mod packet_crafter;
pub mod syn_scan;

pub enum Scan {
    REG,
    SYN,
}

impl Scan {
    pub fn from_char(value: Option<char>) -> Scan {
        if let Some(scan_value) = value {
            match scan_value {
                'S' => Scan::SYN,
                'R' => Scan::REG,
                _ => panic!("Error: invalid -s scan type"),
            }
        } else {
            panic!("Error: no value for -s");
        }
    }
}

pub struct Params {
    pub iname: String,
    pub scan: Scan,
    pub dest_addr: Ipv4Addr,
    pub ports: Vec<u16>,
}

impl Params {
    pub fn default() -> Self {
        Self {
            iname: "wlo1".to_string(),
            scan: Scan::REG,
            dest_addr: Ipv4Addr::new(127, 0, 0, 1),
            ports: Vec::new(),
        }
    }
}
