pub mod interface;
pub mod packet_crafter;
pub mod syn_scan;

pub enum Scan {
    REG,
    SYN,
}

impl Scan {
    pub fn from_char(value: Option<String>) -> Scan {
        if let Some(value) = value {
            let scan = value.chars().nth(0).expect("Error: -s needs a value");
            match scan {
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
    pub interface: Option<String>,
    pub scan: Scan,
    pub dest_addr: Option<String>,
}

impl Params {
    pub fn default() -> Self {
        Self {
            interface: None,
            scan: Scan::REG,
            dest_addr: None,
        }
    }
}
