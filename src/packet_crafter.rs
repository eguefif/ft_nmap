use pnet::packet::tcp::MutableTcpPacket;
use std::net::Ipv4Addr;

pub const PORT_SOURCE: u16 = 0x2813;
pub const DEST_PORT: u16 = 80;
pub const SEQN: u32 = 0x74331e18;

pub fn get_syn_packet(buffer: &mut [u8]) {
    set_tcp_packet(&mut buffer[..]);
}

fn set_tcp_packet(buffer: &mut [u8]) {
    let mut packet =
        MutableTcpPacket::new(buffer).expect("Impossible to create mutable TCP packet");
    packet.set_source(PORT_SOURCE);
    packet.set_destination(DEST_PORT);
    packet.set_data_offset(6);
    packet.set_flags(0b000010);
    packet.set_sequence(SEQN);
    packet.set_acknowledgement(0);
    packet.set_window(1024);

    let max_segment_opt = pnet::packet::tcp::TcpOption {
        number: pnet::packet::tcp::TcpOptionNumber(2),
        length: vec![04],
        data: vec![0x05, 0xb4],
    };
    packet.set_options(&[max_segment_opt]);

    let pnet_checksum = pnet::packet::tcp::ipv4_checksum(
        &packet.to_immutable(),
        &Ipv4Addr::new(192, 168, 2, 23),
        &Ipv4Addr::new(192, 168, 2, 1),
    );
    packet.set_checksum(pnet_checksum);
}
