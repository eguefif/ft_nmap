use ft_nmap::syn_scan::run_syn_scan;
use ft_nmap::{Params, Scan};
use std::env;

fn main() {
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
    for arg in env::args() {
        if arg.chars().nth(0).unwrap() != '-' {
            continue;
        }
        let (flag, value) = get_param(arg);
        println!("flag {}, value {:?}", flag, value);
        match flag.as_str() {
            "i" => params.interface = value,
            "s" => params.scan = Scan::from_char(value),
            _ => panic!("Error: unhandled flag"),
        }
    }

    params
}

fn get_param(arg: String) -> (String, Option<String>) {
    let flag = arg
        .chars()
        .nth(1)
        .expect("Error: need an option after -")
        .to_string();
    let mut splits = arg.split_whitespace();
    // TODO: get value differently, -sS differnt than -i wlo1
    splits.next();
    if let Some(value) = splits.next() {
        return (flag, Some(value.to_string()));
    }
    (flag, None)
}
