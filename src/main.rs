use pnet::datalink::Channel::Ethernet;
use pnet::datalink::{
    interfaces, ChannelType, Config, DataLinkReceiver, DataLinkSender, NetworkInterface,
};
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{MutableTcpPacket, TcpPacket};

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

        send(tx);
        listen(rx);
    }
}

fn send(mut tx: Box<dyn DataLinkSender + 'static>) {
    let mut buffer = [0; 4096];
    let mut packet =
        MutableTcpPacket::new(&mut buffer).expect("Impossible to create mutable tcp packet");
    packet.set_source(PORT_SOURCE);
    packet.set_source(80);
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
