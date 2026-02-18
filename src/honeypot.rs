use crate::{Opt, ratelimiter, session};
use crate::utils::Logger;

use std::io::{BufReader as StdBufReader};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Result, Context};
use chrono::Local;
use rustls::{ServerConfig, Certificate, PrivateKey};
use rustls_pemfile::{certs, pkcs8_private_keys};
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::Mutex;
use tokio::time;
use tokio_rustls::TlsAcceptor;

pub struct SmtpHoneypot {
    pub opt: Opt,
    logger: Logger,
    rate_limiter: Arc<Mutex<ratelimiter::RateLimiter>>,
    pub valid_mailboxes: Vec<String>,
    pub tls_acceptor: Option<Arc<TlsAcceptor>>,
}

impl SmtpHoneypot {
    pub async fn new(opt: Opt) -> Result<Self> {
        let logger = Logger::new(opt.log_file.clone(), opt.raw_display)?;
        
        // Créer le dossier data si spécifié
        if let Some(data_dir) = &opt.data_dir {
            if !data_dir.exists() {
                std::fs::create_dir_all(data_dir)
                    .with_context(|| format!("Failed to create data directory: {:?}", data_dir))?;
                eprintln!("[INFO] Data directory created: {:?}", data_dir);
            }
        }
        
        // Configurer TLS avec RustLS
        let tls_acceptor = if let (Some(cert_path), Some(key_path)) = (&opt.tls_cert, &opt.tls_key) {
            // Lire le certificat
            let cert_file = &mut std::fs::File::open(cert_path)
                .with_context(|| format!("Failed to open certificate: {:?}", cert_path))?;
            let mut cert_reader = StdBufReader::new(cert_file);
            let cert_chain = certs(&mut cert_reader)
                .map_err(|_| anyhow::anyhow!("Failed to parse certificate"))?
                .into_iter()
                .map(Certificate)
                .collect();
            
            // Lire la clé privée
            let key_file = &mut std::fs::File::open(key_path)
                .with_context(|| format!("Failed to open private key: {:?}", key_path))?;
            let mut key_reader = StdBufReader::new(key_file);
            let mut keys = pkcs8_private_keys(&mut key_reader)
                .map_err(|_| anyhow::anyhow!("Failed to parse private key"))?;
            
            if keys.is_empty() {
                return Err(anyhow::anyhow!("No private key found"));
            }
            
            let private_key = PrivateKey(keys.remove(0));
            
            // Configurer le serveur TLS
            let config = ServerConfig::builder()
                .with_safe_defaults()
                .with_no_client_auth()
                .with_single_cert(cert_chain, private_key)
                .map_err(|e| anyhow::anyhow!("Failed to build TLS config: {}", e))?;
            
            let acceptor = TlsAcceptor::from(Arc::new(config));
            
            eprintln!("[INFO] TLS enabled with certificate: {:?}", cert_path);
            Some(Arc::new(acceptor))
        } else {
            if opt.ports.contains(&465) || opt.ports.contains(&587) {
                eprintln!("[WARNING] TLS ports specified but no certificates provided");
            }
            None
        };
        
        Ok(Self {
            opt: opt.clone(),
            logger,
            rate_limiter: Arc::new(Mutex::new(ratelimiter::RateLimiter::new(opt.max_connections_per_minute))),
            valid_mailboxes: opt.valid_mailboxes.clone(),
            tls_acceptor,
        })
    }
    
    async fn save_email_data(&self, client_addr: &SocketAddr, session: &session::SmtpSession) -> Result<()> {
        if let Some(data_dir) = &self.opt.data_dir {
            let timestamp = Local::now().format("%Y%m%d_%H%M%S");
            let filename = format!("{}_{}.eml", timestamp, client_addr.ip().to_string().replace('.', "_"));
            let filepath = data_dir.join(filename);
            
            let mut content = String::new();
            content.push_str(&format!("X-Honeypot-Client: {}\r\n", client_addr));
            content.push_str(&format!("X-Honeypot-Date: {}\r\n", Local::now().format("%Y-%m-%d %H:%M:%S")));
            if let Some(helo) = &session.helo {
                content.push_str(&format!("X-Honeypot-HELO: {}\r\n", helo));
            }
            if let Some(mail_from) = &session.mail_from {
                content.push_str(&format!("X-Honeypot-MailFrom: {}\r\n", mail_from));
            }
            for rcpt in &session.rcpt_to {
                content.push_str(&format!("X-Honeypot-RcptTo: {}\r\n", rcpt));
            }
            content.push_str("\r\n");
            content.push_str(&session.data.join("\r\n"));
            
            tokio::fs::write(&filepath, content).await?;
            self.logger.log(client_addr, &format!("Email saved to: {:?}", filepath)).await;
        }
        Ok(())
    }
    
    fn is_valid_recipient(&self, recipient: &str) -> bool {
        if self.opt.open_relay {
            return true;
        }
        
        // Vérifier si le destinataire est dans la liste des boîtes valides
        if self.valid_mailboxes.iter().any(|mb| mb == recipient) {
            return true;
        }
        
        // Vérifier si le domaine est accepté
        if let Some((_, domain)) = recipient.split_once('@') {
            if self.opt.domains.iter().any(|d| d == domain) {
                return true;
            }
        }
        
        false
    }
    
    async fn process_command(&self, cmd_line: &str, session: &mut session::SmtpSession) -> Option<String> {
        let parts: Vec<&str> = cmd_line.split_whitespace().collect();
        if parts.is_empty() {
            return Some("500 Syntax error\r\n".to_string());
        }
        
        let cmd = parts[0].to_uppercase();
        
        match cmd.as_str() {
            "HELO" | "EHLO" => {
                let helo_name = parts.get(1).unwrap_or(&"unknown");
                session.helo = Some(helo_name.to_string());
                self.logger.log_verbose(&session.client_addr, "HELO/EHLO", helo_name).await;
                
                let mut response = format!("250-{} Hello {}\r\n", self.opt.helo, helo_name);
                if session.starttls_enabled && !session.tls_active && self.tls_acceptor.is_some() {
                    response.push_str("250-STARTTLS\r\n");
                }
                response.push_str("250 HELP\r\n");
                Some(response)
            }
            
            "STARTTLS" => {
                if session.starttls_enabled && self.tls_acceptor.is_some() && !session.tls_active {
                    Some("220 Ready to start TLS\r\n".to_string())
                } else {
                    Some("454 TLS not available\r\n".to_string())
                }
            }
            
            "MAIL" => {
                if parts.len() < 2 || !parts[1].to_uppercase().starts_with("FROM:") {
                    return Some("501 Syntax error in parameters\r\n".to_string());
                }
                
                let from = parts[1][5..].trim_matches('<').trim_matches('>').to_string();
                session.mail_from = Some(from.clone());
                self.logger.log_verbose(&session.client_addr, "MAIL FROM", &from).await;
                Some("250 OK\r\n".to_string())
            }
            
            "RCPT" => {
                if parts.len() < 2 || !parts[1].to_uppercase().starts_with("TO:") {
                    return Some("501 Syntax error in parameters\r\n".to_string());
                }
                
                let to = parts[1][3..].trim_matches('<').trim_matches('>').to_string();
                
                if self.is_valid_recipient(&to) {
                    session.rcpt_to.push(to.clone());
                    self.logger.log_verbose(&session.client_addr, "RCPT TO (accepted)", &to).await;
                    Some("250 OK\r\n".to_string())
                } else {
                    self.logger.log_verbose(&session.client_addr, "RCPT TO (rejected)", &to).await;
                    Some("550 No such user\r\n".to_string())
                }
            }
            
            "DATA" => {
                if session.mail_from.is_none() || session.rcpt_to.is_empty() {
                    return Some("503 Bad sequence of commands\r\n".to_string());
                }
                Some("354 Start mail input; end with <CRLF>.<CRLF>\r\n".to_string())
            }
            
            "AUTH" => {
                if parts.len() > 1 {
                    self.logger.log_verbose(&session.client_addr, "AUTH attempt", cmd_line).await;
                }
                
                if parts.len() >= 2 && parts[1].to_uppercase() == "LOGIN" {
                    Some("334 VXNlcm5hbWU6\r\n".to_string())
                } else if parts.len() == 1 {
                    Some("504 Unrecognized authentication type\r\n".to_string())
                } else {
                    Some("235 Authentication successful\r\n".to_string())
                }
            }
            
            "QUIT" => {
                Some("221 Bye\r\n".to_string())
            }
            
            "RSET" => {
                session.reset();
                Some("250 OK\r\n".to_string())
            }
            
            "NOOP" => {
                Some("250 OK\r\n".to_string())
            }
            
            "VRFY" | "EXPN" => {
                Some("252 Cannot verify user\r\n".to_string())
            }
            
            _ => {
                Some("500 Command not recognized\r\n".to_string())
            }
        }
    }
    
    async fn handle_tls_stream(&self, stream: tokio_rustls::server::TlsStream<TcpStream>, client_addr: SocketAddr) -> Result<()> {
        self.logger.log(&client_addr, "TLS session established").await;
        
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);
        
        let banner = format!("220 {} SMTP Honeypot (TLS)\r\n", self.opt.helo);
        writer.write_all(banner.as_bytes()).await?;
        
        let mut line = String::new();
        let mut session = session::SmtpSession::new(client_addr, false);
        session.tls_active = true;
        
        loop {
            line.clear();
            
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let cmd_line = line.trim_end();
                    self.logger.log(&client_addr, &format!(">> (TLS) {}", cmd_line)).await;
                    
                    if session.expecting_data {
                        if cmd_line == "." {
                            session.expecting_data = false;
                            self.logger.log_verbose(&client_addr, "EMAIL DATA", &session.data.join("\r\n")).await;
                            
                            if let Err(e) = self.save_email_data(&client_addr, &session).await {
                                self.logger.log(&client_addr, &format!("Failed to save email: {}", e)).await;
                            }
                            
                            session.reset();
                            writer.write_all(b"250 OK: Message accepted\r\n").await?;
                        } else {
                            session.data.push(cmd_line.to_string());
                        }
                        continue;
                    }
                    
                    let response = self.process_command(cmd_line, &mut session).await;
                    
                    if let Some(resp) = response {
                        self.logger.log(&client_addr, &format!("<< (TLS) {}", resp.trim())).await;
                        writer.write_all(resp.as_bytes()).await?;
                        
                        if resp.starts_with("221") {
                            break;
                        }
                        
                        if resp.starts_with("354") {
                            session.expecting_data = true;
                        }
                    }
                }
                Err(e) => {
                    self.logger.log(&client_addr, &format!("TLS read error: {}", e)).await;
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    async fn handle_plain_stream(&self, stream: TcpStream, client_addr: SocketAddr) -> Result<()> {
        let banner_delay = self.opt.banner_delay;
        if banner_delay > 0 {
            time::sleep(Duration::from_millis(banner_delay)).await;
        }
        
        let (reader, mut writer) = tokio::io::split(stream);
        let mut reader = BufReader::new(reader);
        
        let banner = format!("220 {} SMTP Honeypot\r\n", self.opt.helo);
        writer.write_all(banner.as_bytes()).await?;
        
        let mut line = String::new();
        let mut session = session::SmtpSession::new(client_addr, false);
        
        loop {
            line.clear();
            
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let cmd_line = line.trim_end();
                    self.logger.log(&client_addr, &format!(">> {}", cmd_line)).await;
                    
                    if session.expecting_data {
                        if cmd_line == "." {
                            session.expecting_data = false;
                            self.logger.log_verbose(&client_addr, "EMAIL DATA", &session.data.join("\r\n")).await;
                            
                            if let Err(e) = self.save_email_data(&client_addr, &session).await {
                                self.logger.log(&client_addr, &format!("Failed to save email: {}", e)).await;
                            }
                            
                            session.reset();
                            writer.write_all(b"250 OK: Message accepted\r\n").await?;
                        } else {
                            session.data.push(cmd_line.to_string());
                        }
                        continue;
                    }
                    
                    let response = self.process_command(cmd_line, &mut session).await;
                    
                    if let Some(resp) = response {
                        self.logger.log(&client_addr, &format!("<< {}", resp.trim())).await;
                        writer.write_all(resp.as_bytes()).await?;
                        
                        if resp.starts_with("221") {
                            break;
                        }
                        
                        if resp.starts_with("354") {
                            session.expecting_data = true;
                        }
                    }
                }
                Err(e) => {
                    self.logger.log(&client_addr, &format!("Read error: {}", e)).await;
                    break;
                }
            }
        }
        
        self.logger.log(&client_addr, "Connection closed").await;
        Ok(())
    }
    
    async fn handle_starttls_stream(&self, stream: TcpStream, client_addr: SocketAddr) -> Result<()> {
        self.logger.log(&client_addr, "Starting STARTTLS handshake").await;
        
        if let Some(acceptor) = &self.tls_acceptor {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    self.handle_tls_stream(tls_stream, client_addr).await
                }
                Err(e) => {
                    self.logger.log(&client_addr, &format!("TLS handshake failed: {}", e)).await;
                    Ok(())
                }
            }
        } else {
            Ok(())
        }
    }
    
    pub async fn handle_client(&self, stream: TcpStream, client_addr: SocketAddr, port: u16) -> Result<()> {
        // Vérifier le rate limiting
        {
            let mut limiter = self.rate_limiter.lock().await;
            if !limiter.check_and_add(client_addr) {
                self.logger.log(&client_addr, &format!("Rate limit exceeded ({} per minute)", self.opt.max_connections_per_minute)).await;
                let _ = stream.writable().await;
                let _ = stream.try_write(b"421 Too many connections from your IP\r\n");
                return Ok(());
            }
        }
        
        self.logger.log(&client_addr, &format!("New connection on port {}", port)).await;
        
        // Port 465 : TLS implicite
        if port == 465 {
            if let Some(acceptor) = &self.tls_acceptor {
                self.logger.log(&client_addr, "Starting TLS handshake (implicit)").await;
                match acceptor.accept(stream).await {
                    Ok(tls_stream) => {
                        self.handle_tls_stream(tls_stream, client_addr).await
                    }
                    Err(e) => {
                        self.logger.log(&client_addr, &format!("TLS handshake failed: {}", e)).await;
                        Ok(())
                    }
                }
            } else {
                self.handle_plain_stream(stream, client_addr).await
            }
        }
        // Port 25 ou 587 : STARTTLS possible
        else if (port == 25 || port == 587) && self.opt.starttls && self.tls_acceptor.is_some() {
            // On commence en clair
            self.handle_plain_stream(stream, client_addr).await
        }
        // Autres ports : clair seulement
        else {
            self.handle_plain_stream(stream, client_addr).await
        }
    }
    
    async fn run_server(&self, port: u16) -> Result<()> {
        let addr = format!("{}:{}", self.opt.address, port);
        let listener = TcpListener::bind(&addr).await
            .with_context(|| format!("Failed to bind to {}", addr))?;
        
        self.logger.log(&SocketAddr::from(([0,0,0,0], 0)), &format!("Listening on port {}", port)).await;
        
        loop {
            match listener.accept().await {
                Ok((stream, client_addr)) => {
                    let this = Arc::new(self.clone());
                    let port = port;
                    
                    tokio::spawn(async move {
                        if let Err(e) = this.handle_client(stream, client_addr, port).await {
                            let _ = this.logger.log(&client_addr, &format!("Error: {}", e)).await;
                        }
                    });
                }
                Err(e) => {
                    self.logger.log(&SocketAddr::from(([0,0,0,0], 0)), &format!("Accept error on port {}: {}", port, e)).await;
                }
            }
        }
    }
    
    pub async fn run(self: Arc<Self>) -> Result<()> {
        let mut handles = vec![];
        
        for port in self.opt.ports.clone() {
            let this = self.clone();
            let handle = tokio::spawn(async move {
                if let Err(e) = this.run_server(port).await {
                    eprintln!("[ERROR] Server on port {} failed: {}", port, e);
                }
            });
            handles.push(handle);
        }
        
        for handle in handles {
            handle.await?;
        }
        
        Ok(())
    }
}

impl Clone for SmtpHoneypot {
    fn clone(&self) -> Self {
        Self {
            opt: self.opt.clone(),
            logger: Logger::new(self.opt.log_file.clone(), self.opt.raw_display).unwrap(),
            rate_limiter: self.rate_limiter.clone(),
            valid_mailboxes: self.valid_mailboxes.clone(),
            tls_acceptor: self.tls_acceptor.clone(),
        }
    }
}

