# ft_nmap

A basic nmap clone in Rust, written to learn TCP/IP and raw packet crafting. Uses [libpnet](https://github.com/libpnet/libpnet).

## Author

Emmanuel Guefif

## Getting Started

```bash
cargo build
sudo setcap CAP_NET_RAW+eip ./target/debug/ft_nmap
./target/debug/ft_nmap -sS -t 192.168.1.1 -p 22,80,443
```

Or use `run.sh` which does the above. Must be run from the project root (reads `./services.csv`).

## Parameters

| Flag | Description |
|------|-------------|
| `-t <target>` | Target IP or hostname |
| `-p <ports>` | Ports: `80`, `80,443`, `1-1024`, or combined `22,80-90,443` |
| `-sS` / `-sF` / `-sX` / `-sN` / `-sA` | Scan type (default: SYN) |
| `-i <interface>` | Network interface (default: `wlo1`) |

## Scan Types

| Flag | Type | How it works |
|------|------|--------------|
| `-sS` | SYN | SYN-ACK = open, RST = closed, timeout = filtered |
| `-sF` | FIN | RST = closed, timeout = open\|filtered |
| `-sX` | XMAS | FIN+URG+PSH set. Same logic as FIN. |
| `-sN` | NULL | No flags set. Same logic as FIN. |
| `-sA` | ACK | RST = unfiltered, timeout = filtered (maps firewall rules) |
