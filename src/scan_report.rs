use std::{
    collections::HashMap,
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use crate::PortState;

pub struct ScanReport {
    pub ports: Vec<(u16, PortState)>,
    pub udp_services: HashMap<u16, String>,
    pub tcp_services: HashMap<u16, String>,
    pub sctp_services: HashMap<u16, String>,
    pub duration: Duration,
    pub latency: Duration,
    pub down: bool,
    pub addr: Ipv4Addr,
    pub addr_v6: Ipv6Addr,
    pub hostname: String,
}

impl ScanReport {
    pub fn new() -> Self {
        let mut reader = csv::ReaderBuilder::new()
            .delimiter(b',')
            .from_path("./services.csv")
            .expect("Error: Impossible to open services.csv file");
        let mut tcp_services = HashMap::new();
        let mut udp_services = HashMap::new();
        let mut sctp_services = HashMap::new();
        for row in reader.records() {
            let record = row.expect("Error: row error in services.csv file");
            if let Ok(port) = record[0].parse::<u16>() {
                let service = &record[1];
                let protocol = &record[2];
                if protocol == "tcp" {
                    tcp_services.insert(port, service.to_string());
                } else if protocol == "udp" {
                    udp_services.insert(port, service.to_string());
                } else if protocol == "sctp" {
                    sctp_services.insert(port, service.to_string());
                }
            }
        }
        Self {
            ports: vec![],
            tcp_services,
            udp_services,
            sctp_services,
            duration: Duration::default(),
            latency: Duration::default(),
            down: true,
            hostname: String::default(),
            addr: Ipv4Addr::new(127, 0, 0, 1),
            addr_v6: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
        }
    }

    pub fn display_report(&self) {
        if self.down {
            println!("Host seems down");
        }
        println!("Scan report for {} ({})", self.hostname, self.addr);
        println!(
            "Host is up({:2}s latency)",
            self.latency.as_millis() as f64 / 1000 as f64
        );
        let filtered = self.ports.iter().fold(0, |mut acc, (_, state)| {
            if let PortState::FILTERED = state {
                acc += 1;
            }
            acc
        });
        let closed = self.ports.iter().fold(0, |mut acc, (_, state)| {
            if let PortState::CLOSED = state {
                acc += 1;
            }
            acc
        });

        let unfiltered = self.ports.iter().fold(0, |mut acc, (_, state)| {
            if let PortState::UNFILTERED = state {
                acc += 1;
            }
            acc
        });

        let open_filtered = self.ports.iter().fold(0, |mut acc, (_, state)| {
            if let PortState::OpenFiltered = state {
                acc += 1;
            }
            acc
        });
        if filtered > 50 {
            println!("Not shown: {} filtered tcp ports (no-reponse)", filtered);
        }
        if closed > 50 {
            println!("Not shown: {} closed tcp ports (return RST)", closed);
        }

        if open_filtered > 50 {
            println!(
                "Not shown: {} open|filtered tcp ports (return RST)",
                open_filtered
            );
        }

        if unfiltered > 50 {
            println!(
                "Not shown: {} unfiltered tcp ports (return RST)",
                unfiltered
            );
        }
        println!("{:<10}{:<15}{:<10}", "PORT", "STATE", "SERVICE");
        for (port, state) in self.ports.iter() {
            let service = self.get_service(port);
            let port = format!("{}/tcp", port);
            match state {
                PortState::OPEN => println!("{:<10}{:<15}{:<10}", port, "open", service),
                PortState::FILTERED => {
                    if filtered < 50 {
                        println!("{:<10}{:<15}{:<10}", port, "filtered", service);
                    }
                }
                PortState::CLOSED => {
                    if closed < 50 {
                        println!("{:<10}{:<15}{:<10}", port, "closed", service);
                    }
                }
                PortState::OpenFiltered => {
                    if unfiltered < 50 {
                        println!("{:<10}{:<15}{:<10}", port, "open|filtered", service);
                    }
                }
                PortState::UNFILTERED => {
                    if open_filtered < 50 {
                        println!("{:<10}{:<15}{:<10}", port, "unfiltered", service);
                    }
                }
                PortState::UNDETERMINED => {}
            }
        }
        println!(
            "\nft_nmap done: 1 IP address (1 host up) scanned in {:.2}s",
            (self.duration.as_millis() as f64 / 1000 as f64)
        );
    }

    fn get_service(&self, port: &u16) -> &str {
        match self.tcp_services.get(port) {
            Some(service) => return service,
            None => {}
        }
        ""
    }
}
