use pnet::packet::tcp::{MutableTcpPacket, TcpOption, TcpOptionNumber};
use rand::prelude::*;

// TODO: find a way to randomize Port picking within conflictin
// with another service

pub const PORT_SOURCE: u16 = 0x2813;

pub fn build_packet(buffer: &mut [u8], port: u16) {
    let mut rng = rand::rng();
    let mut packet =
        MutableTcpPacket::new(buffer).expect("Impossible to create mutable TCP packet");
    packet.set_source(PORT_SOURCE);
    packet.set_destination(port);
    packet.set_data_offset(6);
    packet.set_flags(0b000010);
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
