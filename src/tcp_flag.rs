use pnet::packet::tcp::TcpPacket;

pub struct TcpFlags {
    pub syn: bool,
    pub fin: bool,
    pub ack: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl TcpFlags {
    pub fn new(tcp_packet: &TcpPacket) -> Self {
        let flags = tcp_packet.get_flags();
        Self {
            syn: flags & TcpFlag::SYN.get_flag() == TcpFlag::SYN.get_flag(),
            fin: flags & TcpFlag::FIN.get_flag() == TcpFlag::FIN.get_flag(),
            ack: flags & TcpFlag::ACK.get_flag() == TcpFlag::ACK.get_flag(),
            rst: flags & TcpFlag::RST.get_flag() == TcpFlag::RST.get_flag(),
            psh: flags & TcpFlag::PSH.get_flag() == TcpFlag::PSH.get_flag(),
            urg: flags & TcpFlag::URG.get_flag() == TcpFlag::URG.get_flag(),
            ece: flags & TcpFlag::ECE.get_flag() == TcpFlag::ECE.get_flag(),
            cwr: flags & TcpFlag::CWR.get_flag() == TcpFlag::CWR.get_flag(),
        }
    }
}

#[derive(Debug)]
pub enum TcpFlag {
    SYN,
    RST,
    ACK,
    PSH,
    FIN,
    URG,
    ECE,
    CWR,
}

impl TcpFlag {
    pub fn get_flag(&self) -> u8 {
        match self {
            TcpFlag::FIN => 0b0000_0001,
            TcpFlag::SYN => 0b0000_0010,
            TcpFlag::RST => 0b0000_0100,
            TcpFlag::PSH => 0b0000_1000,
            TcpFlag::ACK => 0b0001_0000,
            TcpFlag::URG => 0b0010_0000,
            TcpFlag::ECE => 0b0100_0000,
            TcpFlag::CWR => 0b1000_0000,
        }
    }
}
