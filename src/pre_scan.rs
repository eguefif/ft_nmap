use pnet::packet::icmp::echo_request::MutableEchoRequestPacket;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::MutablePacket;
use pnet::transport::icmp_packet_iter;
use pnet::{
    datalink::{ChannelType, Config},
    packet::{
        icmp::{IcmpCode, IcmpType},
        ip::IpNextHeaderProtocols,
    },
    transport::{transport_channel, TransportReceiver},
};
use std::time::Duration;
use std::{net::IpAddr, time::Instant};

use crate::Scan;

pub fn run_prescan(scan: &mut Scan) -> bool {
    let mut config = Config::default();
    config.channel_type = ChannelType::Layer3(0x1);

    let layer_type = pnet::transport::TransportChannelType::Layer3(IpNextHeaderProtocols::Icmp);
    let (mut tx, mut rx) = match transport_channel(4096, layer_type) {
        Ok((tx, rx)) => (tx, rx),
        Err(e) => panic!("Error: {e}: while creating icmp channel"),
    };

    let mut ip_buffer = [0u8; 38];
    let mut icmp_buffer = [0u8; 8];
    get_icmp_packet(&mut ip_buffer, &mut icmp_buffer, scan);

    let packet = Ipv4Packet::new(&mut ip_buffer).unwrap();
    let checksum = pnet::packet::ipv4::checksum(&packet);
    let mut packet = MutableIpv4Packet::new(&mut ip_buffer).unwrap();
    packet.set_checksum(checksum);

    let start = Instant::now();
    if let Err(e) = tx.send_to(packet, IpAddr::V4(scan.dest_addr)) {
        eprintln!("Error: cannot send icmp packet: {e}");
    }

    if get_response(scan, &mut rx) {
        scan.report.latency = start.elapsed();
        scan.report.down = false;
        return true;
    }
    scan.report.down = true;
    false
}

fn get_icmp_packet(ip_buffer: &mut [u8], icmp_buffer: &mut [u8], scan: &mut Scan) {
    let mut ip_packet =
        MutableIpv4Packet::new(ip_buffer).expect("Error: impossible to creae ip packet for icmp");
    ip_packet.set_version(4);
    ip_packet.set_header_length(5);
    ip_packet.set_total_length(38);
    ip_packet.set_ttl(55);
    ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Icmp);
    ip_packet.set_destination(scan.dest_addr);

    let mut icmp_packet = MutableEchoRequestPacket::new(icmp_buffer)
        .expect("Error: impossible to create Icmp payload");
    icmp_packet.set_icmp_type(IcmpType(8));
    icmp_packet.set_icmp_code(IcmpCode(0));
    icmp_packet.set_sequence_number(1);
    let checksum = pnet::util::checksum(icmp_packet.packet_mut(), 1);
    icmp_packet.set_checksum(checksum);
    ip_packet.set_payload(icmp_packet.packet_mut());
}

fn get_response(scan: &mut Scan, rx: &mut TransportReceiver) -> bool {
    let mut icmp_iter = icmp_packet_iter(rx);
    let timeout = Duration::from_millis(1000);
    loop {
        match icmp_iter.next_with_timeout(timeout) {
            Ok(Some((packet, addr))) => {
                if addr != scan.dest_addr {
                    continue;
                }
                if packet.get_icmp_code() != IcmpCode(0) {
                    return false;
                }
                return true;
            }
            Ok(None) => return false,
            Err(e) => panic!("Error: while listening for icmp echo: {e}"),
        }
    }
}
