use pnet::packet::{
    tcp::{MutableTcpPacket, TcpOption, TcpOptionNumber},
    udp::MutableUdpPacket,
};
use rand::prelude::*;

use crate::tcp_flag::TcpFlag;

pub fn build_tcp_packet(buffer: &mut [u8], port: u16, source_port: u16, tcp_types: &[TcpFlag]) {
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

fn get_flags(tcp_types: &[TcpFlag]) -> u8 {
    let mut retval = 0;
    for tcp_type in tcp_types {
        retval |= tcp_type.get_flag()
    }
    retval
}

pub fn build_udp_packet(buffer: &mut [u8], dest_port: u16, source_port: u16) {
    let mut udp_packet =
        MutableUdpPacket::new(buffer).expect("Error: impossible to create udp packet");
    udp_packet.set_source(source_port);
    udp_packet.set_destination(dest_port);
    udp_packet.set_length(8);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_should_calculate_syn_rst_flag() {
        let flags = get_flags(&[TcpFlag::SYN, TcpFlag::RST]);
        assert_eq!(flags, 0b0000_0110);
    }

    #[test]
    fn it_should_calculate_all_flags() {
        let flags = get_flags(&[
            TcpFlag::SYN,
            TcpFlag::RST,
            TcpFlag::ACK,
            TcpFlag::FIN,
            TcpFlag::PSH,
        ]);
        assert_eq!(flags, 0b0001_1111);
    }

    #[test]
    fn it_should_calculate_ack_fin_flags() {
        let flags = get_flags(&[TcpFlag::ACK, TcpFlag::FIN]);
        assert_eq!(flags, 0b0001_0001);
    }
}
