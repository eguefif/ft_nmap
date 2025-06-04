use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{
    interfaces, ChannelType, Config, DataLinkReceiver, DataLinkSender, NetworkInterface,
};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};
use pnet::packet::Packet;
use std::net::Ipv4Addr;
use std::process;
use std::thread;

const PORT_SOURCE: u16 = 32123;

fn main() {
    if let Some(iface) = get_main_interface() {
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
}

fn send(mut tx: Box<dyn DataLinkSender>) {
    let mut buffer = [0u8; 1500];
    {
        let mut ip_packet =
            MutableIpv4Packet::new(&mut buffer).expect("Impossible to create mutable IP packet");
        set_ip_packet(&mut ip_packet);
    }
    let mut tcp_packet =
        MutableTcpPacket::new(&mut buffer[20..]).expect("Impossible to create mutable tcp packet");
    set_tcp_packet(&mut tcp_packet);

    let mut ip_packet = MutableIpv4Packet::new(&mut buffer).unwrap();
    let checksum = pnet::util::checksum(ip_packet.packet(), 0);
    ip_packet.set_checksum(0);
    ip_packet.set_checksum(checksum);
    ip_packet.set_total_length(20 + 24);
    println!("buffer {:x?}", &buffer[0..44]);
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

fn set_ip_packet(packet: &mut MutableIpv4Packet) {
    packet.set_version(4);
    packet.set_ttl(100);
    packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
    packet.set_identification(process::id() as u16);
    packet.set_header_length(5);
    packet.set_total_length(21);
    packet.set_destination(Ipv4Addr::new(192, 168, 2, 1));
    packet.set_source(Ipv4Addr::new(192, 168, 2, 23));
}

fn set_tcp_packet(packet: &mut MutableTcpPacket) {
    packet.set_source(PORT_SOURCE);
    packet.set_destination(80);
}

fn get_main_interface() -> Option<NetworkInterface> {
    let all_interfaces = interfaces();
    let iface = all_interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());
    iface.cloned()
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
