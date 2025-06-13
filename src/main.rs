use chrono::Local;
use ft_nmap::dns_lookup::{dns_lookup_host, dns_lookup_ip};
use ft_nmap::pre_scan::run_prescan;
use ft_nmap::scan_type::ScanType;
use ft_nmap::scanner::Scan;
use std::env;
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::time::Instant;

fn main() {
    println!("Starting ft_nmap at {}", get_time_now());
    let mut scan = handle_params();
    if run_prescan(&mut scan) {
        run_scan(&mut scan);
    }
    scan.report.display_report()
}

fn run_scan(scan: &mut Scan) {
    let start = Instant::now();
    scan.run();
    scan.report.duration = start.elapsed();
}

fn handle_params() -> Scan {
    let mut scan = Scan::default();
    let mut arg_iter = env::args();
    loop {
        if let Some(arg) = arg_iter.next() {
            if arg.chars().nth(0).unwrap() != '-' {
                continue;
            }
            let flag = get_flag(&arg);
            match flag {
                't' => {
                    let addr = arg_iter
                        .next()
                        .expect("Error: -t needs a target IP address");
                    if let Ok(ip_addr) = Ipv4Addr::from_str(&addr) {
                        scan.dest_addr = ip_addr;
                        dns_lookup_ip(&mut scan);
                    } else {
                        scan.dest_host = addr;
                        dns_lookup_host(&mut scan);
                    }
                    scan.report.addr = scan.dest_addr.clone();
                    scan.report.addr_v6 = scan.dest_addr_v6.clone();
                    scan.report.hostname = scan.dest_host.clone();
                }
                'i' => {
                    scan.iname = arg_iter.next().expect("Error: -i an interface");
                }

                'p' => {
                    let ports_value = arg_iter.next().expect("Error: -p needs ports arguments");
                    scan.ports = get_ports(ports_value);
                }
                's' => scan.scan = ScanType::from_char(arg.chars().nth(2)),
                _ => panic!("Error: unhandled flag"),
            }
        } else {
            break;
        }
    }
    scan
}

fn get_flag(arg: &str) -> char {
    if arg.len() < 2 {
        panic!("Error: missing flag for -");
    }
    arg.chars().nth(1).unwrap()
}

fn get_ports(ports_param: String) -> Vec<u16> {
    let mut ports = Vec::new();
    let splits = ports_param.split(',');
    for split in splits {
        if split.contains('-') {
            let mut range_splits = split.split('-');
            let start = range_splits
                .next()
                .expect("Error: in -p, port range need a start")
                .parse::<u16>()
                .expect("Error: in -p, port range start is not a valid number");
            let end = range_splits
                .next()
                .expect("Error: in -p, port range need an end")
                .parse::<u16>()
                .expect("Error: in -p, port range end is not a valid number");
            for i in start..end {
                ports.push(i);
            }
        } else {
            let port = split
                .parse::<u16>()
                .expect("Error: in -p, port is not a valid number");
            ports.push(port);
        }
    }
    ports
}

fn get_time_now() -> String {
    let now = Local::now();
    now.format("%Y-%m-%d %H:%M %Z").to_string()
}
