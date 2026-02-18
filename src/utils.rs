use chrono::Local;
use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;

/// Filtre pour ne garder que les caractères ASCII imprimables et les espaces blancs
pub fn filter_printable_chars(input: &str) -> String {
    input.chars()
        .filter(|c| {
            c.is_ascii_graphic() || 
            c.is_ascii_whitespace() || 
            *c == '\n' || 
            *c == '\r' || 
            *c == '\t'
        })
        .collect()
}

/// Remplace les caractères non imprimables par �
pub fn filter_safe_display(input: &str) -> String {
    input.chars()
        .map(|c| {
            if c.is_ascii_graphic() || c.is_ascii_whitespace() || c == '\n' || c == '\r' {
                c
            } else {
                '�'
            }
        })
        .collect()
}

/// Convertit les caractères non imprimables en séquences d'échappement
pub fn safe_log_string(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '\0' => result.push_str("\\0"),
            '\x01'..='\x08' | '\x0b' | '\x0c' | '\x0e'..='\x1f' | '\x7f' => {
                result.push_str(&format!("\\x{:02x}", c as u32));
            }
            _ if c.is_ascii_graphic() || c.is_ascii_whitespace() || c == '\n' || c == '\r' => {
                result.push(c);
            }
            _ => {
                result.push_str(&format!("\\u{{{:x}}}", c as u32));
            }
        }
    }
    result
}

pub struct Logger {
    writer: Option<Arc<Mutex<BufWriter<File>>>>,
    raw_display: bool,
}

impl Logger {
    pub fn new(log_file: Option<PathBuf>, raw_display: bool) -> anyhow::Result<Self> {
        let writer = if let Some(path) = log_file {
            if let Some(parent) = path.parent() {
                if !parent.exists() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)?;
            
            Some(Arc::new(Mutex::new(BufWriter::new(file))))
        } else {
            None
        };
        
        Ok(Self { writer, raw_display })
    }
    
    pub async fn log(&self, client_addr: &SocketAddr, message: &str) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        
        let display_message = if self.raw_display {
            message.to_string()
        } else {
            filter_printable_chars(message)
        };
        
        let log_line = format!("{} {} {}\n", timestamp, client_addr, display_message);
        
        if self.raw_display {
            print!("{}", log_line);
        } else {
            print!("{}", filter_printable_chars(&log_line));
        }
        
        if let Some(writer) = &self.writer {
            let mut writer = writer.lock().await;
            let file_line = format!("{} {} {}\n", timestamp, client_addr, message);
            let _ = writer.write_all(file_line.as_bytes());
            let _ = writer.flush();
        }
    }
    
    pub async fn log_verbose(&self, client_addr: &SocketAddr, title: &str, details: &str) {
        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
        let separator = "─".repeat(60);
        
        let display_details = if self.raw_display {
            details.to_string()
        } else {
            safe_log_string(details)
        };
        
        let verbose_log = format!(
            "{}\n{} VERBOSE: {} {}\n{}\n{}\n{}\n\n",
            separator,
            timestamp,
            client_addr,
            title,
            separator,
            display_details,
            separator
        );
        
        if self.raw_display {
            print!("{}", verbose_log);
        } else {
            print!("{}", filter_printable_chars(&verbose_log));
        }
        
        if let Some(writer) = &self.writer {
            let mut writer = writer.lock().await;
            let file_log = format!(
                "{}\n{} VERBOSE: {} {}\n{}\n{}\n{}\n\n",
                separator,
                timestamp,
                client_addr,
                title,
                separator,
                safe_log_string(details),
                separator
            );
            let _ = writer.write_all(file_log.as_bytes());
            let _ = writer.flush();
        }
    }
}

