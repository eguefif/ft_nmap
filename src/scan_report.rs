use std::collections::HashMap;

use crate::listen::PortStatus;

pub struct ScanReport {
    pub ports: Vec<(u16, PortStatus)>,
    pub udp_services: HashMap<u16, String>,
    pub tcp_services: HashMap<u16, String>,
    pub sctp_services: HashMap<u16, String>,
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
        }
    }

    pub fn display(&self) {
        let filtered = self.ports.iter().fold(0, |mut acc, (_, state)| {
            if let PortStatus::FILTERED = state {
                acc += 1;
            }
            acc
        });
        let closed = self.ports.iter().fold(0, |mut acc, (_, state)| {
            if let PortStatus::CLOSED = state {
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
        println!("{:<10}{:<10}{:<10}", "PORT", "STATE", "SERVICE");
        for (port, state) in self.ports.iter() {
            let service = self.get_service(port);
            let port = format!("{}/tcp", port);
            match state {
                PortStatus::OPEN => println!("{:<10}{:<10}{:<10}", port, "open", service),
                PortStatus::FILTERED => {
                    if filtered < 50 {
                        println!("{:<10}{:<10}{:<10}", port, "filtered", service);
                    }
                }
                PortStatus::CLOSED => {
                    if closed < 50 {
                        println!("{:<10}{:<10}{:<10}", port, "closed", service);
                    }
                }
            }
        }
    }

    fn get_service(&self, port: &u16) -> &str {
        match self.tcp_services.get(port) {
            Some(service) => return service,
            None => {}
        }
        ""
    }
}
