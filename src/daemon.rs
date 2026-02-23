#[cfg(unix)]
pub fn daemonize(opt: &crate::Opt) -> anyhow::Result<()> {
    use daemonize::Daemonize;
    use std::fs::{self, File, OpenOptions};
    use std::io::Write;
    use std::path::{Path, PathBuf};  // ← Ajout de PathBuf
    use std::os::unix::io::AsRawFd;
    use chrono::Local;
    use anyhow::Context;
    
    // Créer un fichier de log pour le débogage
    let debug_log_path = "/tmp/smtp-honeypot-daemon.log";
    let mut debug_log = File::create(debug_log_path)?;
    writeln!(debug_log, "[{}] Starting daemon mode...", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(debug_log, "[{}] Current PID: {}", Local::now().format("%Y-%m-%d %H:%M:%S"), std::process::id())?;
    writeln!(debug_log, "[{}] Current working dir: {:?}", Local::now().format("%Y-%m-%d %H:%M:%S"), 
              std::env::current_dir().unwrap())?;
    debug_log.sync_all()?;
    
    // IMPORTANT: Garder le répertoire de travail courant
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("/"));
    writeln!(debug_log, "[{}] Keeping working directory: {:?}", 
             Local::now().format("%Y-%m-%d %H:%M:%S"), current_dir)?;
    
    // Vérifier/Créer les répertoires nécessaires (avec chemins absolus)
    if let Some(log_path) = &opt.log_file {
        if let Some(parent) = log_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Cannot create log directory: {:?}", parent))?;
            }
        }
    }
    
    if let Some(data_dir) = &opt.data_dir {
        if !data_dir.exists() {
            fs::create_dir_all(data_dir)
                .with_context(|| format!("Cannot create data directory: {:?}", data_dir))?;
        }
    }
    
    // S'assurer que le répertoire pour le PID file existe
    let pid_path = Path::new("/tmp/smtp-honeypot.pid");
    if let Some(parent) = pid_path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Cannot create PID directory: {:?}", parent))?;
        }
    }
    
    writeln!(debug_log, "[{}] Calling daemonize.start() with working dir: {:?}", 
             Local::now().format("%Y-%m-%d %H:%M:%S"), current_dir)?;
    debug_log.sync_all()?;
    
    // Daemonisation avec le répertoire de travail actuel
    let daemonize = Daemonize::new()
        .pid_file(pid_path)
        .chown_pid_file(true)
        .working_directory(&current_dir);  // ← Garde le répertoire courant !
    
    match daemonize.start() {
        Ok(_) => {
            let mut child_log = File::create("/tmp/smtp-honeypot-child.log")?;
            writeln!(child_log, "[{}] Daemon started successfully", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
            writeln!(child_log, "[{}] New PID: {}", Local::now().format("%Y-%m-%d %H:%M:%S"), std::process::id())?;
            writeln!(child_log, "[{}] New working dir: {:?}", Local::now().format("%Y-%m-%d %H:%M:%S"), 
                      std::env::current_dir().unwrap())?;
            child_log.sync_all()?;
            
            // Rediriger stdout/stderr si nécessaire
            if let Some(log_path) = &opt.log_file {
                if let Ok(log_file) = OpenOptions::new().create(true).append(true).open(log_path) {
                    let fd = log_file.as_raw_fd();
                    unsafe {
                        libc::dup2(fd, libc::STDOUT_FILENO);
                        libc::dup2(fd, libc::STDERR_FILENO);
                    }
                }
            }
            
            Ok(())
        }
        Err(e) => {
            writeln!(debug_log, "[{}] Daemon startup error: {}", Local::now().format("%Y-%m-%d %H:%M:%S"), e)?;
            Err(anyhow::anyhow!("Failed to start daemon mode: {}", e))
        }
    }
}

#[cfg(windows)]
pub fn daemonize(_opt: &crate::Opt) -> anyhow::Result<()> {
    eprintln!("[INFO] Daemon mode not fully supported on Windows");
    eprintln!("[INFO] Continuing in background...");
    Ok(())
}

#[cfg(not(any(unix, windows)))]
pub fn daemonize(_opt: &crate::Opt) -> anyhow::Result<()> {
    eprintln!("[INFO] Daemon mode not supported on this platform");
    Ok(())
}

