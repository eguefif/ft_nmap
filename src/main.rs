use ft_nmap::syn_scan::run_syn_scan;
use ft_nmap::{Params, Scan};
use std::env;
use std::net::Ipv4Addr;
use std::str::FromStr;

fn main() {
    println!("Starting ft_nmap");
    let params = get_params();
    run(params);
}

fn run(params: Params) {
    print!("scanning: ");
    for port in &params.ports {
        print!(" {},", port);
    }
    println!();
    match params.scan {
        Scan::SYN => run_syn_scan(params),
        Scan::REG => todo!(),
    }
}

fn get_params() -> Params {
    let mut params = Params::default();
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
                    params.dest_addr = Ipv4Addr::from_str(&addr).expect(
                        "Error: impossible to create ipv4Addr object from given target IP address",
                    );
                }
                'i' => {
                    params.iname = arg_iter.next().expect("Error: -i an interface");
                }

                'p' => {
                    let ports_value = arg_iter.next().expect("Error: -p needs ports arguments");
                    params.ports = get_ports(ports_value);
                }
                's' => params.scan = Scan::from_char(arg.chars().nth(2)),
                _ => panic!("Error: unhandled flag"),
            }
        } else {
            break;
        }
    }
    params
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
                .expect("Error: in -p, port range start is not a valid number");
            for i in start..end {
                ports.push(i);
            }
        } else {
            let port = split
                .parse::<u16>()
                .expect("Error: in -p, port i not a valid number");
            ports.push(port);
        }
    }
    ports
}
