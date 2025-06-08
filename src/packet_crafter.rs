use pnet::packet::tcp::{MutableTcpPacket, TcpOption, TcpOptionNumber};
use rand::prelude::*;

pub enum TcpType {
    SYN,
    RST,
}

impl TcpType {
    pub fn get_flags(&self) -> u8 {
        match self {
            TcpType::SYN => 0b000010,
            TcpType::RST => 0b000100,
        }
    }
}

pub fn build_packet(buffer: &mut [u8], port: u16, source_port: u16, tcp_type: TcpType) {
    let mut rng = rand::rng();
    let mut packet =
        MutableTcpPacket::new(buffer).expect("Impossible to create mutable TCP packet");
    packet.set_source(source_port);
    packet.set_destination(port);
    packet.set_data_offset(6);
    packet.set_flags(tcp_type.get_flags());
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
