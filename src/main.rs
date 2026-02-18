mod utils;
mod ratelimiter;
mod session;
mod honeypot;
mod daemon;

use structopt::StructOpt;
use anyhow::Result;
use std::sync::Arc;
use std::path::PathBuf;

#[derive(Debug, StructOpt, Clone)]
#[structopt(
    name = "smtp-honeypot",
    about = "A SMTP honeypot for detecting and analyzing SMTP attacks",
    author = "2026, Philippe TEMESI <https://www.tems.be>",
    version = "0.1.0"
)]
pub struct Opt {
    /// Run as daemon
    #[structopt(short = "d", long = "daemon")]
    pub daemon: bool,
    
    /// Listening ports (can be specified multiple times, default: 25)
    #[structopt(short = "p", long = "port", default_value = "25", number_of_values = 1)]
    pub ports: Vec<u16>,
    
    /// Listening address (default: 0.0.0.0)
    #[structopt(short = "a", long = "address", default_value = "0.0.0.0")]
    pub address: String,
    
    /// Domain(s) to accept mail for (can be specified multiple times, required)
    #[structopt(long = "domain", required = true, number_of_values = 1)]
    pub domains: Vec<String>,
    
    /// Valid mailbox(es) (e.g., user@domain.com) (can be specified multiple times)
    #[structopt(long = "valid-mailbox", number_of_values = 1)]
    pub valid_mailboxes: Vec<String>,
    
    /// Enable open relay mode (accept all recipients)
    #[structopt(long = "open-relay")]
    pub open_relay: bool,
    
    /// HELO/EHLO response string (default: smtp-honeypot.local)
    #[structopt(long = "helo", default_value = "smtp.local")]
    pub helo: String,
    
    /// Log file path
    #[structopt(long = "logs", parse(from_os_str))]
    pub log_file: Option<PathBuf>,
    
    /// Directory to save email contents
    #[structopt(long = "data", parse(from_os_str))]
    pub data_dir: Option<PathBuf>,
    
    /// Maximum connections per minute from same IP (default: 10)
    #[structopt(long = "max-connections", default_value = "10")]
    pub max_connections_per_minute: usize,
    
    /// Verbose mode - display SMTP details
    #[structopt(short = "v", long = "verbose")]
    pub verbose: bool,
    
    /// Enable raw display (not filtered) - DANGEROUS
    #[structopt(short = "r", long = "raw")]
    pub raw_display: bool,
    
    /// TLS certificate file (for ports 465/587)
    #[structopt(long = "tls-cert", parse(from_os_str))]
    pub tls_cert: Option<PathBuf>,
    
    /// TLS private key file
    #[structopt(long = "tls-key", parse(from_os_str))]
    pub tls_key: Option<PathBuf>,
    
    /// Banner delay in milliseconds (default: 0)
    #[structopt(long = "banner-delay", default_value = "0")]
    pub banner_delay: u64,
    
    /// Enable STARTTLS on port 25/587
    #[structopt(long = "starttls")]
    pub starttls: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let opt = Opt::from_args();
    
    if opt.domains.is_empty() {
        eprintln!("[ERROR] At least one domain must be specified with --domain");
        std::process::exit(1);
    }
    
    println!("==========================================");
    println!("SMTP Honeypot v{}", env!("CARGO_PKG_VERSION"));
    println!("{}", env!("CARGO_PKG_AUTHORS"));
    println!("{}", env!("CARGO_PKG_REPOSITORY"));
    println!("==========================================");
    
    if opt.daemon {
        daemon::daemonize()?;
    }
    
    let honeypot = Arc::new(honeypot::SmtpHoneypot::new(opt).await?);
    
    println!("[INFO] SMTP honeypot started");
    println!("[INFO] Ports: {:?}", honeypot.opt.ports);
    println!("[INFO] Domains: {:?}", honeypot.opt.domains);
    println!("[INFO] Open relay mode: {}", honeypot.opt.open_relay);
    if !honeypot.valid_mailboxes.is_empty() {
        println!("[INFO] Valid mailboxes: {:?}", honeypot.valid_mailboxes);
    }
    if honeypot.tls_acceptor.is_some() {
        println!("[INFO] TLS enabled");
    }
    if honeypot.opt.starttls {
        println!("[INFO] STARTTLS enabled on port 25/587");
    }
    println!("[INFO] Max connections per minute per IP: {}", honeypot.opt.max_connections_per_minute);
    println!("[INFO] Waiting for connections...");
    println!("[INFO] Press Ctrl+C to stop");
    
    honeypot.run().await?;
    
    Ok(())
}

