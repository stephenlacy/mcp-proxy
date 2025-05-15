use dirs::home_dir;
use log::{debug, error};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::time::SystemTime;
use thiserror::Error;
use uuid::Uuid;

pub const MCP_REMOTE_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("Config not found")]
    NotFound,
    #[error("Lock error: {0}")]
    Lock(String),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthConfig {
    pub server_url: String,
    pub access_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_at: Option<u64>,
    pub auth_state: Option<String>,
    pub session_id: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LockFile {
    pub session_id: String,
    pub server_url: String,
    pub callback_port: u16,
    pub created_at: u64,
    pub pid: u32,
}

pub struct ConfigManager {
    config_dir: PathBuf,
}

impl Default for ConfigManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConfigManager {
    pub fn new() -> Self {
        Self {
            config_dir: get_config_dir(),
        }
    }

    pub fn get_auth_config_path(&self, server_url_hash: &str) -> PathBuf {
        self.config_dir
            .join(format!("auth-{}.json", server_url_hash))
    }

    pub fn get_lock_file_path(&self, server_url_hash: &str) -> PathBuf {
        self.config_dir
            .join(format!("auth-{}.lock", server_url_hash))
    }

    pub fn get_registration_path(&self, server_url_hash: &str) -> PathBuf {
        self.config_dir
            .join(format!("client-registration-{}.json", server_url_hash))
    }

    pub fn ensure_config_dir(&self) -> Result<()> {
        debug!("Ensuring config directory exists: {:?}", self.config_dir);
        if !self.config_dir.exists() {
            debug!("Creating config directory");
            fs::create_dir_all(&self.config_dir)?;
        }
        Ok(())
    }

    pub fn load_auth_config(&self, server_url_hash: &str) -> Result<AuthConfig> {
        let config_path = self.get_auth_config_path(server_url_hash);
        debug!("Loading auth config from {:?}", config_path);

        if !config_path.exists() {
            debug!("Config file not found");
            return Err(ConfigError::NotFound);
        }

        let mut file = File::open(config_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let config: AuthConfig = serde_json::from_str(&contents)?;
        Ok(config)
    }

    pub fn save_auth_config(&self, server_url_hash: &str, config: &AuthConfig) -> Result<()> {
        self.ensure_config_dir()?;

        let config_path = self.get_auth_config_path(server_url_hash);
        debug!("Saving auth config to {:?}", config_path);

        let json = serde_json::to_string_pretty(config)?;
        let mut file = File::create(config_path)?;
        file.write_all(json.as_bytes())?;

        Ok(())
    }

    pub fn create_lock_file(
        &self,
        server_url_hash: &str,
        server_url: &str,
        callback_port: u16,
    ) -> Result<LockFile> {
        self.ensure_config_dir()?;

        let lock_path = self.get_lock_file_path(server_url_hash);
        debug!("Creating lock file at {:?}", lock_path);

        // Check if lock file exists and is valid
        if let Ok(existing_lock) = self.read_lock_file(server_url_hash) {
            // Check if process is still running
            if is_process_running(existing_lock.pid) && !is_lock_expired(&existing_lock) {
                debug!("Lock file exists and process is running");
                return Ok(existing_lock);
            }
            debug!("Lock file exists but process is not running or lock is expired, removing");
            let _ = fs::remove_file(&lock_path);
        }

        let lock_file = LockFile {
            session_id: Uuid::new_v4().to_string(),
            server_url: server_url.to_owned(),
            callback_port,
            created_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            pid: std::process::id(),
        };

        let json = serde_json::to_string_pretty(&lock_file)?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(lock_path)?;
        file.write_all(json.as_bytes())?;

        Ok(lock_file)
    }

    pub fn read_lock_file(&self, server_url_hash: &str) -> Result<LockFile> {
        let lock_path = self.get_lock_file_path(server_url_hash);
        debug!("Reading lock file from {:?}", lock_path);

        if !lock_path.exists() {
            return Err(ConfigError::NotFound);
        }

        let mut file = File::open(lock_path)?;
        let mut contents = String::new();
        file.read_to_string(&mut contents)?;

        let lock_file: LockFile = serde_json::from_str(&contents)?;
        Ok(lock_file)
    }

    pub fn remove_lock_file(&self, server_url_hash: &str) -> Result<()> {
        let lock_path = self.get_lock_file_path(server_url_hash);
        debug!("Removing lock file at {:?}", lock_path);

        if lock_path.exists() {
            fs::remove_file(lock_path)?;
        }

        Ok(())
    }
}

pub fn get_config_dir() -> PathBuf {
    // Use environment variable or default to ~/.mcp-auth
    let base_config_dir = match std::env::var("MCP_REMOTE_CONFIG_DIR") {
        Ok(dir) => PathBuf::from(dir),
        Err(_) => home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".mcp-auth"),
    };
    // Add version subdirectory for compatibility
    base_config_dir.join(format!("mcp-proxy-rust-{}", MCP_REMOTE_VERSION))
}

fn is_process_running(pid: u32) -> bool {
    #[cfg(unix)]
    {
        use std::process::Command;
        let output = Command::new("ps").arg("-p").arg(pid.to_string()).output();

        match output {
            Ok(output) => output.status.success(),
            Err(_) => false,
        }
    }

    #[cfg(windows)]
    {
        use std::process::Command;
        let output = Command::new("tasklist")
            .arg("/FI")
            .arg(format!("PID eq {}", pid))
            .output();

        match output {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout);
                stdout.contains(&format!("{}", pid))
            }
            Err(_) => false,
        }
    }
}

fn is_lock_expired(lock: &LockFile) -> bool {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Lock expires after 10 minutes
    now > lock.created_at + 600
}
