use pnet::packet::tcp::MutableTcpPacket;
use rand::prelude::*;
use std::net::Ipv4Addr;

pub const PORT_SOURCE: u16 = 0x2813;
pub const DEST_PORT: u16 = 80;
pub const SEQN: u32 = 0x74331e18;

pub fn get_syn_packet(buffer: &mut [u8], source_addr: Ipv4Addr, dest_addr: Ipv4Addr) {
    set_tcp_packet(&mut buffer[..], source_addr, dest_addr);
}

fn set_tcp_packet(buffer: &mut [u8], source_addr: Ipv4Addr, dest_addr: Ipv4Addr) {
    let mut rng = rand::rng();
    let mut packet =
        MutableTcpPacket::new(buffer).expect("Impossible to create mutable TCP packet");
    packet.set_source(PORT_SOURCE);
    packet.set_destination(DEST_PORT);
    packet.set_data_offset(6);
    packet.set_flags(0b000010);
    packet.set_sequence(rng.random::<u32>());
    packet.set_acknowledgement(0);
    packet.set_window(1024);

    let max_segment_opt = pnet::packet::tcp::TcpOption {
        number: pnet::packet::tcp::TcpOptionNumber(2),
        length: vec![04],
        data: vec![0x05, 0xb4],
    };
    packet.set_options(&[max_segment_opt]);

    let pnet_checksum =
        pnet::packet::tcp::ipv4_checksum(&packet.to_immutable(), &source_addr, &dest_addr);

    packet.set_checksum(pnet_checksum);
}
