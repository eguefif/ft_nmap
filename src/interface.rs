use pnet::datalink::{interfaces, NetworkInterface};

pub fn get_interface(iname: &str) -> NetworkInterface {
    get_interface_from_name(iname).expect("Error: cannot get interface from name")
}

fn get_interface_from_name(name: &str) -> Option<NetworkInterface> {
    let all_interfaces = interfaces();
    let iface = all_interfaces.iter().find(|e| e.name == name);
    iface.cloned()
}
