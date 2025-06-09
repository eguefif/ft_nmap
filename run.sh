#/bin/bash
cargo build
sudo setcap  CAP_NET_RAW+eip ./target/debug/ft_nmap 
./target/debug/ft_nmap -sS -t 192.168.2.1 -p 80-82,123,144
