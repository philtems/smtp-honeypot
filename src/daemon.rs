#[cfg(unix)]
pub fn daemonize() -> anyhow::Result<()> {
    use daemonize::Daemonize;
    
    eprintln!("[INFO] Starting daemon mode...");
    
    let daemonize = Daemonize::new()
        .pid_file("/tmp/smtp-honeypot.pid")
        .chown_pid_file(true)
        .working_directory("/tmp")
        .user("nobody")
        .group("nogroup")
        .umask(0o027);
    
    match daemonize.start() {
        Ok(_) => {
            eprintln!("[INFO] SMTP honeypot daemon started successfully");
            Ok(())
        }
        Err(e) => {
            eprintln!("[ERROR] Daemon startup: {}", e);
            Err(anyhow::anyhow!("Failed to start daemon mode"))
        }
    }
}

#[cfg(windows)]
pub fn daemonize() -> anyhow::Result<()> {
    eprintln!("[INFO] Daemon mode not fully supported on Windows");
    eprintln!("[INFO] Continuing in background...");
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn daemonize() -> anyhow::Result<()> {
    eprintln!("[INFO] Daemon mode not supported on this platform");
    Ok(())
}

