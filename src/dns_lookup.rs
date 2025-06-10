use std::net::IpAddr;

use dns_lookup::{lookup_addr, lookup_host};

use crate::Scan;

pub fn dns_lookup_host(scan: &mut Scan) {
    if let Ok(ips) = lookup_host(&scan.dest_host) {
        for ip in ips {
            match ip {
                IpAddr::V4(ip) => scan.dest_addr = ip,
                IpAddr::V6(ip) => scan.dest_addr_v6 = ip,
            }
        }
    }
}
pub fn dns_lookup_ip(scan: &mut Scan) {
    if let Ok(host) = lookup_addr(&scan.dest_addr.into()) {
        scan.dest_host = host;
    }
}
