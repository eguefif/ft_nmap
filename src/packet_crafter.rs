use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket, TcpOption, TcpOptionNumber};
use rand::prelude::*;
use std::net::Ipv4Addr;

// TODO: find a way to randomize Port picking within conflictin
// with another service

pub const PORT_SOURCE: u16 = 0x2813;

pub struct SynPacket {
    ip_dest: Ipv4Addr,
    ip_source: Ipv4Addr,
    port: u16,
    packet_size: usize,
}

impl SynPacket {
    pub fn new(ip_dest: Ipv4Addr, ip_source: Ipv4Addr, port: u16) -> Self {
        Self {
            ip_dest,
            ip_source,
            port,
            packet_size: 0,
        }
    }

    pub fn build_packet(&mut self, buffer: &mut [u8]) {
        self.set_tcp_packet(&mut buffer[..]);
    }

    pub fn size(&mut self) -> usize {
        return self.packet_size;
    }

    fn set_tcp_packet(&mut self, buffer: &mut [u8]) {
        let mut rng = rand::rng();
        let mut packet =
            MutableTcpPacket::new(buffer).expect("Impossible to create mutable TCP packet");
        packet.set_source(PORT_SOURCE);
        packet.set_destination(self.port);
        packet.set_data_offset(6);
        packet.set_flags(0b000010);
        packet.set_sequence(rng.random::<u32>());
        packet.set_acknowledgement(0);
        packet.set_window(1024);
        self.packet_size = 24;

        let max_segment_opt = TcpOption {
            number: TcpOptionNumber(2),
            length: vec![04],
            data: vec![0x05, 0xb4],
        };
        packet.set_options(&[max_segment_opt]);

        println!("Source ip: {:?}", self.ip_source);
        println!("Dest   ip: {:?}", self.ip_dest);
        println!("Packet: {:?}", packet);
        let checksum = ipv4_checksum(&packet.to_immutable(), &self.ip_source, &self.ip_dest);

        packet.set_checksum(checksum);
    }
}
