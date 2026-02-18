use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub struct RateLimiter {
    connections: HashMap<SocketAddr, VecDeque<Instant>>,
    max_per_minute: usize,
}

impl RateLimiter {
    pub fn new(max_per_minute: usize) -> Self {
        Self {
            connections: HashMap::new(),
            max_per_minute,
        }
    }
    
    pub fn check_and_add(&mut self, addr: SocketAddr) -> bool {
        let now = Instant::now();
        let entries = self.connections.entry(addr).or_insert_with(VecDeque::new);
        
        // Nettoyer les entrées plus vieilles qu'une minute
        while let Some(&time) = entries.front() {
            if now.duration_since(time) > Duration::from_secs(60) {
                entries.pop_front();
            } else {
                break;
            }
        }
        
        if entries.len() >= self.max_per_minute {
            false
        } else {
            entries.push_back(now);
            true
        }
    }
}

