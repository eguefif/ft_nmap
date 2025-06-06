use crate::interface::get_interface;
use crate::packet_crafter::get_syn_packet;
use crate::Params;
use std::thread;

use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{ChannelType, Config, DataLinkReceiver, DataLinkSender};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::TcpPacket;

pub fn run_syn_scan(params: Params) {
    let iface = get_interface(params.interface);
    println!("Starting working on interface: {}", iface.name);
    let mut config = Config::default();
    config.channel_type = ChannelType::Layer3(0x800);

    let (rx, tx) = match pnet::datalink::channel(&iface, config) {
        Ok(Ethernet(tx, rx)) => (rx, tx),
        Ok(_) => panic!("Channel format not handled"),
        Err(e) => panic!("Error: {e}"),
    };

    thread::spawn(move || listen(rx));
    send(tx);
}

fn send(mut tx: Box<dyn DataLinkSender>) {
    let mut buffer = [0u8; 1500];
    get_syn_packet(&mut buffer);
    if let Some(res) = tx.send_to(&buffer[0..44], None) {
        if let Err(e) = res {
            eprintln!("Error: {e}");
        } else {
            eprintln!("Packet sent");
        }
    } else {
        eprintln!("Packet sent");
    }
}

fn listen(mut rx: Box<dyn DataLinkReceiver + 'static>) {
    loop {
        match rx.next() {
            Ok(packet) => {
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
            }
            Err(e) => eprintln!("Error while processing packet: {e}"),
        }
    }
}
