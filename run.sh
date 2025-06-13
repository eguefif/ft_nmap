#/bin/bash
cargo build
sudo setcap  CAP_NET_RAW+eip ./target/debug/ft_nmap 
./target/debug/ft_nmap -sS -t 192.168.2.1 -p 80
#./target/debug/ft_nmap -sX -t mynetwork.home -p 80-82,443,123
#./target/debug/ft_nmap -sN -t www.google.com -p 80
#./target/debug/ft_nmap -sF -t www.google.com -p 80
#./target/debug/ft_nmap -sA -t www.google.com -p 80
