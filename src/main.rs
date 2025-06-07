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
