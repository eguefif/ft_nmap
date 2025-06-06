use pnet::datalink::{interfaces, NetworkInterface};

pub fn get_main_interface() -> Option<NetworkInterface> {
    let all_interfaces = interfaces();
    let iface = all_interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());
    //.find(|e| e.is_up() && e.is_loopback() && !e.ips.is_empty());
    iface.cloned()
}
