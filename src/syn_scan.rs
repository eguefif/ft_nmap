use crate::interface::get_interface;
use crate::listen::listen_responses;
use crate::packet_crafter::build_packet;
use crate::Params;
use pnet::ipnetwork::IpNetwork;
use pnet::packet::ip::IpNextHeaderProtocols;
use std::net::{IpAddr, Ipv4Addr, TcpListener};

use pnet::datalink::{ChannelType, Config};
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, TransportReceiver, TransportSender};

const PACKET_SIZE: usize = 24;
const PORT_LOW: u16 = 10000;
const PORT_HIGH: u16 = 64000;

pub fn run_syn_scan(params: Params) {
    let source_addr = get_source_addr(&params);
    let source_port = get_source_port(source_addr);
    let (rx, tx) = get_transports();

    send(tx, source_addr, params.dest_addr, params.port, source_port);

    let port_status = listen_responses(rx, source_port);
    println!("{}/tcp {}", params.port, port_status);
}

fn get_source_addr(params: &Params) -> Ipv4Addr {
    let interface = get_interface(&params.iname);
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

    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (rx, tx),
        Err(e) => panic!("Error: {e}"),
    }
}

fn send(
    mut tx: TransportSender,
    source_addr: Ipv4Addr,
    dest_addr: Ipv4Addr,
    port: u16,
    source_port: u16,
) {
    let mut buffer = [0u8; 1500];
    build_packet(&mut buffer, port, source_port);
    let mut packet = MutableTcpPacket::new(&mut buffer[..PACKET_SIZE]).unwrap();
    packet.set_checksum(ipv4_checksum(
        &packet.to_immutable(),
        &source_addr,
        &dest_addr,
    ));
    match tx.send_to(packet, IpAddr::V4(dest_addr)) {
        Err(e) => eprintln!("Error: {e}"),
        Ok(n) => eprintln!("Packet sent: {} bytes", n),
    }
}
