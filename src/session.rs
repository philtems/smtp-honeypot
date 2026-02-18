use std::net::SocketAddr;

pub struct SmtpSession {
    pub client_addr: SocketAddr,
    pub helo: Option<String>,
    pub mail_from: Option<String>,
    pub rcpt_to: Vec<String>,
    pub data: Vec<String>,
    pub authenticated: bool,
    pub tls_active: bool,
    pub starttls_enabled: bool,
    pub expecting_data: bool,
}

impl SmtpSession {
    pub fn new(client_addr: SocketAddr, starttls_enabled: bool) -> Self {
        Self {
            client_addr,
            helo: None,
            mail_from: None,
            rcpt_to: Vec::new(),
            data: Vec::new(),
            authenticated: false,
            tls_active: false,
            starttls_enabled,
            expecting_data: false,
        }
    }
    
    pub fn reset(&mut self) {
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data.clear();
        self.expecting_data = false;
    }
    
    pub fn reset_all(&mut self) {
        self.helo = None;
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data.clear();
        self.authenticated = false;
        self.expecting_data = false;
    }
}

