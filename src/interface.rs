use pnet::datalink::{interfaces, NetworkInterface};

pub fn get_interface(iname: Option<String>) -> NetworkInterface {
    if let Some(iname) = iname {
        get_interface_from_name(iname).expect("Error: cannot get interface from name")
    } else {
        get_main_interface().expect("Error: cannot get main interface")
    }
}

fn get_main_interface() -> Option<NetworkInterface> {
    let all_interfaces = interfaces();
    let iface = all_interfaces
        .iter()
        .find(|e| e.is_up() && !e.is_loopback() && !e.ips.is_empty());
    iface.cloned()
}

fn get_interface_from_name(name: String) -> Option<NetworkInterface> {
    let all_interfaces = interfaces();
    let iface = all_interfaces.iter().find(|e| e.name == name);
    iface.cloned()
}
