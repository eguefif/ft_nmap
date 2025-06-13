use crate::interface::get_interface;
use crate::packet_crafter::build_udp_packet;
use crate::scanner::Scanner;
use crate::tcp_port_scanner::Response;

use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::time::Duration;

use pnet::datalink::{ChannelType, Config};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::udp::{ipv4_checksum, MutableUdpPacket, UdpPacket};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{
    icmp_packet_iter, transport_channel, udp_packet_iter, TransportReceiver, TransportSender,
};

const PACKET_SIZE: usize = 24;
const PORT_LOW: u16 = 10000;
const PORT_HIGH: u16 = 64000;

const TIMEOUT_MS: u64 = 250;

pub struct UdpPortScanner {
    tx: TransportSender,
    rx: TransportReceiver,
    source_addr: Ipv4Addr,
    source_port: u16,
    dest_addr: Ipv4Addr,
}

impl Scanner for UdpPortScanner {
    fn scan_port(&mut self, scan_port: u16) -> Response {
        let mut retry = true;

        loop {
            self.send(scan_port);
            let response = self.listen_responses();
            match response {
                Response::TIMEOUT => {
                    if retry {
                        retry = false;
                        continue;
                    }
                    return response;
                }
                _ => return response,
            }
        }
    }
}

impl UdpPortScanner {
    pub fn new(dest_addr: Ipv4Addr, iname: String) -> Self {
        let (rx, tx) = get_transports();
        let source_addr = get_source_addr(iname);
        let source_port = get_source_port(source_addr);
        Self {
            tx,
            rx,
            source_addr,
            dest_addr,
            source_port,
        }
    }

    fn send(&mut self, dest_port: u16) {
        let mut buffer = [0u8; 1500];
        build_udp_packet(&mut buffer, dest_port, self.source_port);
        let mut packet = MutableUdpPacket::new(&mut buffer[..PACKET_SIZE]).unwrap();
        packet.set_checksum(ipv4_checksum(
            &packet.to_immutable(),
            &self.source_addr,
            &self.dest_addr,
        ));
        if let Err(e) = self.tx.send_to(packet, IpAddr::V4(self.dest_addr)) {
            eprintln!("Error: {e}");
        }
    }

    fn listen_responses(&mut self) -> Response {
        let mut udp_iter = udp_packet_iter(&mut self.rx);
        let timeout = Duration::from_millis(TIMEOUT_MS);
        loop {
            match udp_iter.next_with_timeout(timeout) {
                Ok(Some((packet, _))) => {
                    if should_dismiss_udp_packet(&packet, self.source_port) {
                        continue;
                    }
                    return Response::UDP(5);
                }
                Ok(None) => break,
                Err(e) => panic!("Error: error while listening tcp response: {e}"),
            }
        }

        let mut icmp_iter = icmp_packet_iter(&mut self.rx);
        loop {
            match icmp_iter.next_with_timeout(timeout) {
                Ok(Some((packet, addr))) => {
                    if let IpAddr::V4(addr_from_packet) = addr {
                        if should_dismiss_icmp_packet(self.dest_addr, addr_from_packet) {
                            continue;
                        }
                        return Response::ICMP((
                            packet.get_icmp_type().0,
                            packet.get_icmp_code().0,
                        ));
                    }
                }
                Ok(None) => return Response::TIMEOUT,
                Err(e) => panic!("Error: error while listening icmp response: {e}"),
            }
        }
    }
}

fn should_dismiss_udp_packet(packet: &UdpPacket, port_source: u16) -> bool {
    if packet.get_destination() != port_source {
        return true;
    }
    false
}

fn should_dismiss_icmp_packet(addr_target: Ipv4Addr, addr_from_packet: Ipv4Addr) -> bool {
    if addr_from_packet != addr_target {
        return true;
    }
    false
}

fn get_source_addr(iname: String) -> Ipv4Addr {
    let interface = get_interface(&iname);
    for network_ip in interface.ips {
        if let IpNetwork::V4(net_addr) = network_ip {
            return net_addr.ip();
        }
    }
    panic!("Error: interface has no IP address");
}

fn get_source_port(source_addr: Ipv4Addr) -> u16 {
    let mut i = 0;
    loop {
        let port = rand::random_range(PORT_LOW..PORT_HIGH);
        if let Ok(_) = TcpListener::bind((source_addr.to_string(), port)) {
            return port;
        }
        i += 1;
        if i == 100 {
            panic!("Error: Impossible to find an available port after 100 tries");
        }
    }
}

fn get_transports() -> (TransportReceiver, TransportSender) {
    let mut config = Config::default();
    config.channel_type = ChannelType::Layer3(0x800);

    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Udp));
    match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (rx, tx),
        Err(e) => panic!("Error: {e}"),
    }
}
