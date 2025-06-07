use etherparse::TcpHeader;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::process;

pub const PORT_SOURCE: u16 = 0x2813;
pub const DEST_PORT: u16 = 80;
pub const SEQN: u32 = 0x74331e18;

pub fn get_syn_packet(buffer: &mut [u8]) {
    set_ip_packet(buffer);
    set_tcp_packet(&mut buffer[20..]);
    set_ip_checksum(buffer);
    println!("buffer {:x?}", &buffer[0..44]);
}

fn set_ip_packet(buffer: &mut [u8]) {
    let mut packet =
        MutableIpv4Packet::new(buffer).expect("Impossible to create mutable IP packet");
    packet.set_version(4);
    packet.set_ttl(0x35);
    packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    packet.set_identification(process::id() as u16);
    packet.set_header_length(5);
    packet.set_total_length(21);
    packet.set_source(Ipv4Addr::new(192, 168, 2, 23));
    packet.set_destination(Ipv4Addr::new(192, 168, 2, 1));
    packet.set_total_length(20 + 24);
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

    // FIX: According to wireshark, our checksum is wrong
    // This is not due to checksum offloading since I calculate
    // the checksum here. It is not offloaded by the OS to the NIC
    packet.set_checksum(0);
    let tcp_opt = [0x2, 0x4, 0x05, 0xb4].into();
    let mut p = TcpHeader {
        source_port: PORT_SOURCE,
        destination_port: DEST_PORT,
        sequence_number: SEQN,
        acknowledgment_number: 0,
        syn: true,
        ack: false,
        checksum: 0,
        cwr: false,
        ece: false,
        fin: false,
        ns: false,
        psh: false,
        rst: false,
        urg: false,
        window_size: 1024,
        urgent_pointer: 0,
        options: tcp_opt,
    };
    let etherparse_checksum = p
        .calc_checksum_ipv4_raw([192, 168, 2, 23], [192, 168, 2, 1], &[])
        .unwrap();
    p.checksum = etherparse_checksum;
    let pnet_checksum = pnet::packet::tcp::ipv4_checksum(
        &packet.to_immutable(),
        &Ipv4Addr::new(192, 168, 2, 23),
        &Ipv4Addr::new(192, 168, 2, 1),
    );
    packet.set_checksum(etherparse_checksum);
    println!("tcp: {:x?}", &packet.to_immutable());
    println!("tcp bytes       : {:x?}", &packet.packet()[..24]);
    println!("etherparse bytes: {:x?}", p.to_bytes());
}

fn set_ip_checksum(buffer: &mut [u8]) {
    let mut ip_packet = MutableIpv4Packet::new(buffer).unwrap();
    ip_packet.set_checksum(0);
    let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
    ip_packet.set_checksum(checksum);
}
