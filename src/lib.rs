pub enum Scan {
    REG,
    SYN,
}

impl Scan {
    pub fn from_char(value: Option<String>) -> Scan {
        if let Some(value) = value {
            let scan = value.chars().nth(1).expect("Error: -s needs a value");
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
}

impl Params {
    pub fn default() -> Self {
        Self {
            interface: None,
            scan: Scan::REG,
        }
    }
}

pub mod interface;
pub mod packet_crafter;
pub mod syn_scan;
