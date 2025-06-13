use crate::{
    scanner::PortState,
    tcp_port_scanner::{Response, TcpFlag},
};

pub enum ScanType {
    SYN,
    FIN,
    XMAS,
    NULL,
    ACK,
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
        }
    }

    pub fn get_flags(&self) -> Vec<TcpFlag> {
        match self {
            ScanType::SYN => vec![TcpFlag::SYN],
            ScanType::ACK => vec![TcpFlag::ACK],
            ScanType::NULL => vec![],
            ScanType::FIN => vec![TcpFlag::FIN],
            ScanType::XMAS => vec![TcpFlag::RST, TcpFlag::URG, TcpFlag::PSH],
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
        Response::TIMEOUT => PortState::FILTERED,
    }
}
