use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::packet::tcp::MutableTcpPacket;
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::process;

const PORT_SOURCE: u16 = 62355;

pub fn get_syn_packet(buffer: &mut [u8]) {
    {
        let mut ip_packet =
            MutableIpv4Packet::new(buffer).expect("Impossible to create mutable IP packet");
        set_ip_packet(&mut ip_packet);
    }
    let mut tcp_packet =
        MutableTcpPacket::new(&mut buffer[20..]).expect("Impossible to create mutable tcp packet");
    set_tcp_packet(&mut tcp_packet);

    let mut ip_packet = MutableIpv4Packet::new(buffer).unwrap();
    let checksum = pnet::util::checksum(ip_packet.packet(), 0);
    ip_packet.set_checksum(0);
    ip_packet.set_checksum(checksum);
    ip_packet.set_total_length(20 + 24);
    println!("buffer {:x?}", &buffer[0..44]);
}

fn set_ip_packet(packet: &mut MutableIpv4Packet) {
    packet.set_version(4);
    packet.set_ttl(100);
    packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    packet.set_identification(process::id() as u16);
    packet.set_header_length(5);
    packet.set_total_length(21);
    //packet.set_destination(Ipv4Addr::new(127, 0, 0, 1));
    //packet.set_source(Ipv4Addr::new(127, 0, 0, 1));
    packet.set_source(Ipv4Addr::new(192, 168, 2, 23));
    packet.set_destination(Ipv4Addr::new(192, 168, 2, 1));
}

fn set_tcp_packet(packet: &mut MutableTcpPacket) {
    packet.set_source(PORT_SOURCE);
    packet.set_destination(8080);
    packet.set_data_offset(6);
    packet.set_flags(0b000010);
    packet.set_sequence(1951641362);
    packet.set_acknowledgement(0);
    packet.set_window(1024);

    let max_segment_opt = pnet::packet::tcp::TcpOption {
        number: pnet::packet::tcp::TcpOptionNumber(2),
        length: vec![04],
        data: vec![0x05, 0xb4],
    };
    packet.set_options(&[max_segment_opt]);

    packet.set_checksum(0);
    // TODO: seems that my checksum is wrong. I compared
    // with the one from a nmap packet captured with the exact
    // same header.
    let checksum = pnet::util::ipv4_checksum(
        &packet.packet(),
        0,
        &[],
        &Ipv4Addr::new(192, 168, 2, 23),
        &Ipv4Addr::new(192, 168, 2, 1),
        IpNextHeaderProtocols::Tcp,
    );
    packet.set_checksum(checksum);
    println!("Checksum: {:x}", checksum);
    println!("SHould beChecksum: {:x}", 0xd833);
}
