#/bin/bash
cargo build
sudo ./target/debug/ft_nmap -sS -t 192.168.2.1 -p 80-85,123,144
