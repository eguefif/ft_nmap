use crate::packet_crafter::{get_syn_packet, PORT_SOURCE};
use crate::Params;
use pnet::packet::ip::IpNextHeaderProtocols;
use std::net::{IpAddr, Ipv4Addr};
use std::thread;

use pnet::datalink::{ChannelType, Config};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags, TcpPacket};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{tcp_packet_iter, transport_channel, TransportReceiver, TransportSender};

pub fn run_syn_scan(params: Params) {
    let mut config = Config::default();
    config.channel_type = ChannelType::Layer3(0x800);

    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    let (rx, tx) = match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (rx, tx),
        Err(e) => panic!("Error: {e}"),
    };

    send(tx, params.dest_addr);
    let listener = thread::spawn(move || listen(rx));

    match listener.join() {
        Ok(_) => println!("Scan is over"),
        Err(e) => panic!("Error: {e:?}"),
    }
}

fn send(mut tx: TransportSender, dest_addr: Ipv4Addr) {
    let mut buffer = [0u8; 1500];
    get_syn_packet(&mut buffer);
    let packet = MutableTcpPacket::new(&mut buffer).unwrap();
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
