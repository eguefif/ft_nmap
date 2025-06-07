use crate::interface::get_interface;
use crate::packet_crafter::{SynPacket, PORT_SOURCE};
use crate::Params;
use pnet::ipnetwork::IpNetwork;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::Packet;
use std::net::{IpAddr, Ipv4Addr};
use std::thread;

use pnet::datalink::{ChannelType, Config};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{tcp_packet_iter, transport_channel, TransportReceiver, TransportSender};

pub fn run_syn_scan(params: Params) {
    let source_addr = get_source_addr(&params);
    let mut config = Config::default();
    config.channel_type = ChannelType::Layer3(0x800);

    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let (rx, tx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (rx, tx),
        Err(e) => panic!("Error: {e}"),
    };

    send(tx, source_addr, params.dest_addr, params.port);
    let listener = thread::spawn(move || listen(rx));

    match listener.join() {
        Ok(_) => println!("Scan is over"),
        Err(e) => panic!("Error: {e:?}"),
    }
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

fn send(mut tx: TransportSender, source_addr: Ipv4Addr, dest_addr: Ipv4Addr, port: u16) {
    let mut buffer = [0u8; 1500];
    let mut syn_packet = SynPacket::new(source_addr, dest_addr, port);
    syn_packet.get_packet(&mut buffer);
    let packet = MutableTcpPacket::new(&mut buffer[..syn_packet.size()]).unwrap();
    println!("bytes: {:x?}", packet.packet());
    match tx.send_to(packet, IpAddr::V4(dest_addr)) {
        Err(e) => eprintln!("Error: {e}"),
        Ok(n) => eprintln!("Packet sent: {} bytes", n),
    }
}

fn listen(mut rx: TransportReceiver) {
    let mut tcp_iter = tcp_packet_iter(&mut rx);
    loop {
        match tcp_iter.next() {
            Ok((packet, addr)) => {
                if should_dismiss_packet(&packet) {
                    continue;
                }
                let flags = get_flags(&packet);
                println!(
                    "Receive from {} TCP {} -> {} {}",
                    addr,
                    packet.get_source(),
                    packet.get_destination(),
                    flags
                );
            }
            Err(e) => eprintln!("Error while processing packet: {e}"),
        }
    }
}

fn should_dismiss_packet(packet: &TcpPacket) -> bool {
    if packet.get_destination() != PORT_SOURCE {
        return true;
    }
    false
}

fn get_flags(packet: &TcpPacket) -> String {
    let mut flags = vec!["["];
    if packet.get_flags() & TcpFlags::SYN == 1 {
        flags.push("SYN");
    }

    if packet.get_flags() & TcpFlags::ACK == 1 {
        flags.push("ACK");
    }
    flags.push("]");
    flags.join(", ")
}
