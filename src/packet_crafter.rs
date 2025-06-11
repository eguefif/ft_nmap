use pnet::packet::tcp::{MutableTcpPacket, TcpOption, TcpOptionNumber};
use rand::prelude::*;

pub enum TcpType {
    SYN,
    RST,
    ACK,
    PSH,
    FIN,
}

impl TcpType {
    pub fn get_flag(&self) -> u8 {
        match self {
            TcpType::FIN => 0b000001,
            TcpType::SYN => 0b000010,
            TcpType::RST => 0b000100,
            TcpType::PSH => 0b001000,
            TcpType::ACK => 0b010000,
        }
    }
}

pub fn build_packet(buffer: &mut [u8], port: u16, source_port: u16, tcp_types: &[TcpType]) {
    let mut rng = rand::rng();
    let mut packet =
        MutableTcpPacket::new(buffer).expect("Impossible to create mutable TCP packet");
    packet.set_source(source_port);
    packet.set_destination(port);
    packet.set_data_offset(6);
    let flags = get_flags(tcp_types);
    packet.set_flags(flags);
    packet.set_sequence(rng.random::<u32>());
    packet.set_acknowledgement(0);
    packet.set_window(1024);

    let max_segment_opt = TcpOption {
        number: TcpOptionNumber(2),
        length: vec![04],
        data: vec![0x05, 0xb4],
    };
    packet.set_options(&[max_segment_opt]);
}

fn get_flags(tcp_types: &[TcpType]) -> u8 {
    let mut retval = 0;
    for tcp_type in tcp_types {
        retval |= tcp_type.get_flag()
    }
    retval
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_calculate_syn_rst_flag() {
        let flags = get_flags(&[TcpType::SYN, TcpType::RST]);
        assert_eq!(flags, 0b0000_0110);
    }

    #[test]
    fn it_should_calculate_all_flags() {
        let flags = get_flags(&[
            TcpType::SYN,
            TcpType::RST,
            TcpType::ACK,
            TcpType::FIN,
            TcpType::PSH,
        ]);
        assert_eq!(flags, 0b0001_1111);
    }

    #[test]
    fn it_should_calculate_ack_fin_flags() {
        let flags = get_flags(&[TcpType::ACK, TcpType::FIN]);
        assert_eq!(flags, 0b0001_0001);
    }
}
