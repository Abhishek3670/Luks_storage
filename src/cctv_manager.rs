use std::process::{Child, Command, Stdio};
use std::path::PathBuf;
use std::time::Duration;
use tokio::time;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use log::{info, warn, error, debug};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum CctvError {
    #[error("Failed to start CCTV API server: {0}")]
    StartupError(String),
    
    #[error("CCTV API server is not running")]
    NotRunning,
    
    #[error("HTTP request failed: {0}")]
    RequestError(#[from] reqwest::Error),
    
    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("JSON parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
    
    #[error("Process management error: {0}")]
    ProcessError(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CameraInfo {
    pub id: String,
    pub name: String,
    pub url: String,
    pub status: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemStatus {
    pub running: bool,
    pub cameras_count: u32,
    pub active_streams: u32,
    pub uptime_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Recording {
    pub filename: String,
    pub camera_id: String,
    pub timestamp: String,
    pub size_bytes: u64,
    pub duration_seconds: Option<u32>,
}

pub struct CctvManager {
    process: Option<Child>,
    api_url: String,
    client: Client,
    python_script_path: PathBuf,
    api_port: u16,
}

impl CctvManager {
    pub fn new(python_project_path: &str, api_port: u16) -> Self {
        let python_script_path = PathBuf::from(python_project_path).join("test_api_server.py");
        let api_url = format!("http://127.0.0.1:{}", api_port);
        
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("Failed to create HTTP client");
            
        Self {
            process: None,
            api_url,
            client,
            python_script_path,
            api_port,
        }
    }
    
    pub async fn start_api_server(&mut self) -> Result<(), CctvError> {
        if self.is_process_running() {
            info!("CCTV API server is already running");
            return Ok(());
        }
        
        info!("Starting CCTV API server at {}", self.api_url);
        
        // Check if Python script exists
        if !self.python_script_path.exists() {
            return Err(CctvError::StartupError(
                format!("Python script not found: {:?}", self.python_script_path)
            ));
        }
        
        // Start the Python API server
        let mut command = Command::new("../Home_CCTV_AI/venv/bin/python");
        command
            .arg(&self.python_script_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .current_dir(self.python_script_path.parent().unwrap());
        
        let child = command.spawn()
            .map_err(|e| CctvError::StartupError(format!("Failed to spawn process: {}", e)))?;
            
        self.process = Some(child);
        
        // Wait for the server to start up (with retries)
        let mut retries = 0;
        const MAX_RETRIES: u32 = 60;
        const RETRY_DELAY: Duration = Duration::from_millis(1000);
        
        while retries < MAX_RETRIES {
            time::sleep(RETRY_DELAY).await;
            
            if self.health_check().await.unwrap_or(false) {
                info!("CCTV API server started successfully");
                return Ok(());
            }
            
            retries += 1;
            debug!("Waiting for CCTV API server to start... (attempt {}/{})", retries, MAX_RETRIES);
        }
        
        // If we get here, the server failed to start
        self.stop_api_server().await?;
        Err(CctvError::StartupError("Server failed to start within timeout".to_string()))
    }
    
    pub async fn stop_api_server(&mut self) -> Result<(), CctvError> {
        if let Some(mut child) = self.process.take() {
            info!("Stopping CCTV API server");
            
            // Try graceful shutdown first
            if let Err(e) = child.kill() {
                warn!("Failed to kill CCTV process gracefully: {}", e);
            }
            
            // Wait for process to exit
            match child.wait() {
                Ok(status) => {
                    if status.success() {
                        info!("CCTV API server stopped successfully");
                    } else {
                        warn!("CCTV API server exited with status: {}", status);
                    }
                }
                Err(e) => {
                    error!("Failed to wait for CCTV process: {}", e);
                }
            }
        } else {
            debug!("CCTV API server was not running");
        }
        
        Ok(())
    }
    
    pub async fn health_check(&self) -> Result<bool, CctvError> {
        let url = format!("{}/health", self.api_url);
        
        match self.client.get(&url).send().await {
            Ok(response) => {
                let is_healthy = response.status().is_success();
                debug!("Health check: {}", if is_healthy { "OK" } else { "FAILED" });
                Ok(is_healthy)
            }
            Err(_) => {
                debug!("Health check failed - server not reachable");
                Ok(false)
            }
        }
    }
    
    pub async fn get_system_status(&self) -> Result<SystemStatus, CctvError> {
        self.ensure_running().await?;
        
        let url = format!("{}/status", self.api_url);
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let status: SystemStatus = response.json().await?;
            Ok(status)
        } else {
            Err(CctvError::RequestError(reqwest::Error::from(
                response.error_for_status().unwrap_err()
            )))
        }
    }
    
    pub async fn list_cameras(&self) -> Result<Vec<CameraInfo>, CctvError> {
        self.ensure_running().await?;
        
        let url = format!("{}/cameras", self.api_url);
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let cameras: Vec<CameraInfo> = response.json().await?;
            Ok(cameras)
        } else {
            Err(CctvError::RequestError(reqwest::Error::from(
                response.error_for_status().unwrap_err()
            )))
        }
    }
    
    pub async fn get_camera_stream_url(&self, camera_id: &str) -> Result<String, CctvError> {
        self.ensure_running().await?;
        Ok(format!("{}/stream/{}", self.api_url, camera_id))
    }
    
    pub async fn list_recordings(&self) -> Result<Vec<Recording>, CctvError> {
        self.ensure_running().await?;
        
        let url = format!("{}/recordings", self.api_url);
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let recordings: Vec<Recording> = response.json().await?;
            Ok(recordings)
        } else {
            Err(CctvError::RequestError(reqwest::Error::from(
                response.error_for_status().unwrap_err()
            )))
        }
    }
    
    pub async fn get_recording_url(&self, filename: &str) -> Result<String, CctvError> {
        self.ensure_running().await?;
        Ok(format!("{}/recordings/{}", self.api_url, filename))
    }
    
    fn is_process_running(&self) -> bool {
        if let Some(ref child) = self.process {
            // Check if process is still alive (this is a simple check)
            // In a real implementation, you might want to check the PID more thoroughly
            true
        } else {
            false
        }
    }
    
    async fn ensure_running(&self) -> Result<(), CctvError> {
        if !self.health_check().await? {
            return Err(CctvError::NotRunning);
        }
        Ok(())
    }
}

impl Drop for CctvManager {
    fn drop(&mut self) {
        if let Some(mut child) = self.process.take() {
            warn!("CCTV manager dropped, attempting to kill child process");
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_cctv_manager_creation() {
        let manager = CctvManager::new("../Home_CCTV_AI", 8082);
        assert_eq!(manager.api_port, 8082);
        assert!(manager.api_url.contains("8082"));
    }
    
    #[tokio::test]
    async fn test_health_check_when_server_down() {
        let manager = CctvManager::new("../Home_CCTV_AI", 9999); // Use unlikely port
        let result = manager.health_check().await;
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should be false when server is down
    }
}
