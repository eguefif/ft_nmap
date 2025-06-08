use crate::listen::PortStatus;

pub struct ScanReport {
    pub ports: Vec<(u16, PortStatus)>,
}

impl ScanReport {
    pub fn new() -> Self {
        Self { ports: vec![] }
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
            let port = format!("{}/tcp", port);
            match state {
                PortStatus::OPEN => println!("{:<10}open", port),
                PortStatus::FILTERED => {
                    if filtered < 50 {
                        println!("{:<10}filtered", port);
                    }
                }
                PortStatus::CLOSED => {
                    if closed < 50 {
                        println!("{:<10}closed", port);
                    }
                }
            }
        }
    }
}
