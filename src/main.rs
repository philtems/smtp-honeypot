mod utils;
mod ratelimiter;
mod session;
mod honeypot;

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
    println!("==========================================");
    
    eprintln!("[INFO] Starting as user: {}", 
              std::env::var("USER").unwrap_or_else(|_| "unknown".to_string()));
    eprintln!("[INFO] PID: {}", std::process::id());
    eprintln!("[INFO] Working directory: {:?}", std::env::current_dir().unwrap());
    
    // Vérifier/Créer les répertoires nécessaires AVANT daemonisation
    if let Some(log_path) = &opt.log_file {
        if let Some(parent) = log_path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
                eprintln!("[INFO] Created log directory: {:?}", parent);
            }
        }
    }
    
    if let Some(data_dir) = &opt.data_dir {
        if !data_dir.exists() {
            std::fs::create_dir_all(data_dir)?;
            eprintln!("[INFO] Created data directory: {:?}", data_dir);
        }
    }
    
    // === DAEMONISATION DANS UN THREAD SÉPARÉ ===
    if opt.daemon {
        eprintln!("[INFO] Starting daemon mode...");
        
        use tokio::sync::oneshot;
        let (tx, rx) = oneshot::channel();
        
        // Cloner opt pour le mouvement dans le thread
        let opt_clone = opt.clone();
        
        std::thread::spawn(move || {
            use daemonize::Daemonize;
            use std::fs;
            
            // Daemonisation
            let daemonize = Daemonize::new()
                .pid_file("/tmp/smtp-honeypot.pid")
                .chown_pid_file(true)
                .working_directory(".");  // Garde le répertoire courant
            
            match daemonize.start() {
                Ok(_) => {
                    // Dans le processus enfant
                    let pid = std::process::id();
                    
                    // Écrire un fichier de test
                    let _ = fs::write("/tmp/smtp-honeypot-daemon-test.txt", 
                                      format!("Child process started at PID {}\n", pid));
                    
                    // Tester la création d'un socket simple
                    use std::net::TcpListener;
                    match TcpListener::bind("127.0.0.1:0") {
                        Ok(_) => {
                            let _ = fs::write("/tmp/smtp-honeypot-socket-test.txt", 
                                             "Socket test successful\n");
                        }
                        Err(e) => {
                            let _ = fs::write("/tmp/smtp-honeypot-socket-test.txt", 
                                             format!("Socket test failed: {}\n", e));
                        }
                    }
                    
                    // Signaler au parent que la daemonisation a réussi
                    let _ = tx.send(pid);
                    
                    // CRÉER UN NOUVEAU RUNTIME TOKIO DANS L'ENFANT
                    let runtime = tokio::runtime::Runtime::new().unwrap();
                    runtime.block_on(async {
                        eprintln!("[INFO] Child process: creating honeypot...");
                        
                        match honeypot::SmtpHoneypot::new(opt_clone).await {
                            Ok(h) => {
                                let honeypot = Arc::new(h);
                                eprintln!("[INFO] Child process: honeypot created successfully");
                                eprintln!("[INFO] Child process: starting main loop...");
                                
                                if let Err(e) = honeypot.run().await {
                                    eprintln!("[ERROR] Child process: server error: {}", e);
                                }
                            }
                            Err(e) => {
                                eprintln!("[ERROR] Child process: failed to create honeypot: {}", e);
                            }
                        }
                    });
                }
                Err(e) => {
                    eprintln!("[ERROR] Daemon startup failed: {}", e);
                    std::process::exit(1);
                }
            }
        });
        
        // Attendre que le processus enfant signale qu'il est prêt
        match rx.await {
            Ok(pid) => {
                eprintln!("[INFO] Daemon child process running (PID: {})", pid);
                eprintln!("[INFO] Parent process exiting");
                std::process::exit(0);
            }
            Err(_) => {
                eprintln!("[ERROR] Daemon child failed to start");
                std::process::exit(1);
            }
        }
    }
    
    // === MODE NORMAL (PAS DE DAEMON) ===
    eprintln!("[INFO] Creating honeypot instance...");
    
    let honeypot = match honeypot::SmtpHoneypot::new(opt).await {
        Ok(h) => Arc::new(h),
        Err(e) => {
            eprintln!("[ERROR] Failed to create honeypot: {}", e);
            std::process::exit(1);
        }
    };
    
    println!("[INFO] SMTP honeypot started in foreground");
    println!("[INFO] PID: {}", std::process::id());
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

