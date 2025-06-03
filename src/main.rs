use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{interfaces, ChannelType, Config, NetworkInterface};
use pnet::packet::ipv4::Ipv4Packet;

fn main() {
    if let Some(iface) = get_main_interface() {
        println!("Starting working on interface: {}", iface.name);
        let mut config = Config::default();
        config.channel_type = ChannelType::Layer3(0x800);

        let mut rx = match pnet::datalink::channel(&iface, config) {
            Ok(Ethernet(_, rx)) => rx,
            Ok(_) => panic!("Channel format not handled"),
            Err(e) => panic!("Error: {e}"),
        };
        loop {
            match rx.next() {
                Ok(packet) => {
                    let packet = Ipv4Packet::new(packet).unwrap();
                    let source = packet.get_source();
                    println!("Source: {}", source);
                }
                Err(e) => eprintln!("Error while processing packet: {e}"),
            }
        }
    }
}

fn get_main_interface() -> Option<NetworkInterface> {
    let all_interfaces = interfaces();
    let iface = all_interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());
    iface.cloned()
}
