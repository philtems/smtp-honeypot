#[cfg(unix)]
pub fn daemonize(opt: &crate::Opt) -> anyhow::Result<()> {
    use daemonize::Daemonize;
    use std::fs::{self, File};
    use std::io::Write;
    use std::path::Path;
    use std::os::unix::io::AsRawFd;
    use chrono::Local;
    use anyhow::Context;  // AJOUT IMPORTANT
    
    // Créer un fichier de log pour le débogage de la daemonisation
    let debug_log_path = "/tmp/smtp-honeypot-daemon.log";
    let mut debug_log = File::create(debug_log_path)?;
    writeln!(debug_log, "[{}] Starting daemon mode...", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(debug_log, "[{}] Current PID: {}", Local::now().format("%Y-%m-%d %H:%M:%S"), std::process::id())?;
    writeln!(debug_log, "[{}] Current user: {}", Local::now().format("%Y-%m-%d %H:%M:%S"),
              users::get_current_username().unwrap().to_string_lossy())?;
    debug_log.sync_all()?;
    
    // Vérifier/Créer le répertoire pour le fichier de log
    if let Some(log_path) = &opt.log_file {
        writeln!(debug_log, "[{}] Log file: {:?}", Local::now().format("%Y-%m-%d %H:%M:%S"), log_path)?;
        if let Some(parent) = log_path.parent() {
            if !parent.exists() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("Cannot create log directory: {:?}", parent))?;
                writeln!(debug_log, "[{}] Created log directory: {:?}", Local::now().format("%Y-%m-%d %H:%M:%S"), parent)?;
            }
        }
    }
    
    // Vérifier/Créer le répertoire pour les données
    if let Some(data_dir) = &opt.data_dir {
        if !data_dir.exists() {
            fs::create_dir_all(data_dir)
                .with_context(|| format!("Cannot create data directory: {:?}", data_dir))?;
            writeln!(debug_log, "[{}] Created data directory: {:?}", Local::now().format("%Y-%m-%d %H:%M:%S"), data_dir)?;
        }
    }
    
    // S'assurer que le répertoire pour le PID file existe
    if let Some(parent) = Path::new("/tmp/smtp-honeypot.pid").parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Cannot create PID directory: {:?}", parent))?;
        }
    }
    
    writeln!(debug_log, "[{}] Calling daemonize.start()...", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    debug_log.sync_all()?;
    
    // Daemonisation SANS changer d'utilisateur (on enlève .user("nobody") et .group("nogroup"))
    let daemonize = Daemonize::new()
        .pid_file("/tmp/smtp-honeypot.pid")
        .chown_pid_file(true)
        .working_directory("/tmp");
    
    match daemonize.start() {
        Ok(_) => {
            // Après daemonisation, on est dans le processus enfant
            // Réouvrir un fichier de log pour le processus enfant
            let mut child_log = File::create("/tmp/smtp-honeypot-child.log")?;
            writeln!(child_log, "[{}] Daemon started successfully in child", Local::now().format("%Y-%m-%d %H:%M:%S"))?;
            writeln!(child_log, "[{}] New PID: {}", Local::now().format("%Y-%m-%d %H:%M:%S"), std::process::id())?;
            child_log.sync_all()?;
            
            // Rediriger stdout/stderr vers le fichier de log si spécifié
            if let Some(log_path) = &opt.log_file {
                if let Ok(log_file) = fs::OpenOptions::new().create(true).append(true).open(log_path) {
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
            debug_log.sync_all()?;
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

