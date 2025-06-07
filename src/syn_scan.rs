use crate::interface::get_interface;
use crate::packet_crafter::{get_syn_packet, PORT_SOURCE};
use crate::Params;
use pnet::packet::ip::IpNextHeaderProtocols;
use std::net::{IpAddr, Ipv4Addr};
use std::thread;

use pnet::datalink::{ChannelType, Config, DataLinkReceiver, DataLinkSender};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, TransportSender};

pub fn run_syn_scan(params: Params) {
    let iface = get_interface(params.interface);
    println!("Starting working on interface: {}", iface.name);
    let mut config = Config::default();
    config.channel_type = ChannelType::Layer3(0x800);

    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let (rx, tx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (rx, tx),
        Err(e) => panic!("Error: {e}"),
    };

    send(tx);
    let listener = thread::spawn(move || listen(rx));

    match listener.join() {
        Ok(_) => println!("Scan is over"),
        Err(e) => panic!("Error: {e:?}"),
    }
}

fn send(mut tx: TransportSender) {
    let mut buffer = [0u8; 1500];
    get_syn_packet(&mut buffer);
    let packet = MutableTcpPacket::new(&mut buffer).unwrap();
    match tx.send_to(packet, IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))) {
        Err(e) => eprintln!("Error: {e}"),
        Ok(n) => eprintln!("Packet sent: {} bytes", n),
    }
}

fn listen(mut rx: Box<dyn DataLinkReceiver + 'static>) {
    loop {
        match rx.next() {
            Ok(packet) => {
                if should_dismiss_packet(packet) {
                    continue;
                }
                let ip_packet = Ipv4Packet::new(packet).unwrap();
                let tcp_packet = TcpPacket::new(packet).unwrap();
                println!("New packet:");
                println!(
                    "IP Source: {}:{}",
                    ip_packet.get_source(),
                    tcp_packet.get_source()
                );
                println!(
                    "IP Drst: {}:{}",
                    ip_packet.get_destination(),
                    tcp_packet.get_destination()
                );
                println!();
                println!("bytes: {:x?}", packet);
            }
            Err(e) => eprintln!("Error while processing packet: {e}"),
        }
    }
}

fn should_dismiss_packet(packet: &[u8]) -> bool {
    let ip_packet = Ipv4Packet::new(packet).unwrap();
    let tcp_packet = TcpPacket::new(packet).unwrap();
    if ip_packet.get_next_level_protocol() != IpNextHeaderProtocols::Tcp
        || tcp_packet.get_destination() != PORT_SOURCE
    {
        return true;
    }
    false
}
