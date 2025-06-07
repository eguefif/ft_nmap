#/bin/bash
cargo build
sudo ./target/debug/ft_nmap -sS -t 10.10.10.1
