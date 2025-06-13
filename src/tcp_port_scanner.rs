use crate::interface::get_interface;
use crate::packet_crafter::build_packet;
use crate::scan_type::ScanType;
use crate::tcp_flag::{TcpFlag, TcpFlags};

use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::time::Duration;

use pnet::datalink::{ChannelType, Config};
use pnet::ipnetwork::IpNetwork;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::tcp::{ipv4_checksum, MutableTcpPacket};
use pnet::transport::TransportChannelType::Layer4;
use pnet::transport::TransportProtocol::Ipv4;
use pnet::transport::{transport_channel, TransportReceiver, TransportSender};
use pnet::{packet::tcp::TcpPacket, transport::tcp_packet_iter};

const PACKET_SIZE: usize = 24;
const PORT_LOW: u16 = 10000;
const PORT_HIGH: u16 = 64000;

const TIMEOUT_MS: u64 = 1000;
pub enum Response {
    TCP(TcpFlags),
    TIMEOUT,
}

pub struct TcpPortScanner {
    tx: TransportSender,
    rx: TransportReceiver,
    source_addr: Ipv4Addr,
    source_port: u16,
    dest_addr: Ipv4Addr,
    flags: Vec<TcpFlag>,
}

impl TcpPortScanner {
    /// iname: String it is the network interface
    pub fn new(dest_addr: Ipv4Addr, iname: String, scan_type: &ScanType) -> Self {
        let (rx, tx) = get_transports();
        let source_addr = get_source_addr(iname);
        let source_port = get_source_port(source_addr);
        let flags = scan_type.get_flags();
        Self {
            tx,
            rx,
            source_addr,
            dest_addr,
            source_port,
            flags,
        }
    }

    pub fn scan_port(&mut self, scan_port: u16) -> Response {
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

    fn send(&mut self, dest_port: u16) {
        let mut buffer = [0u8; 1500];
        build_packet(&mut buffer, dest_port, self.source_port, &self.flags);
        let mut packet = MutableTcpPacket::new(&mut buffer[..PACKET_SIZE]).unwrap();
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
        let mut tcp_iter = tcp_packet_iter(&mut self.rx);
        let timeout = Duration::from_millis(TIMEOUT_MS);
        loop {
            match tcp_iter.next_with_timeout(timeout) {
                Ok(Some((packet, _))) => {
                    if should_dismiss_packet(&packet, self.source_port) {
                        continue;
                    }
                    let flags = TcpFlags::new(&packet);
                    return Response::TCP(flags);
                }
                Ok(None) => {
                    return Response::TIMEOUT;
                }
                Err(e) => panic!("Error: error while listening response: {e}"),
            }
        }
    }
}

fn should_dismiss_packet(packet: &TcpPacket, port_source: u16) -> bool {
    if packet.get_destination() != port_source {
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

    let protocol = Layer4(Ipv4(IpNextHeaderProtocols::Tcp));
    match transport_channel(4096, protocol) {
        Ok((tx, rx)) => (rx, tx),
        Err(e) => panic!("Error: {e}"),
    }
}
