//! Session management for NEAR AI authentication.
//!
//! Handles session token persistence, expiration detection, and renewal via
//! OAuth flow. Tokens are persisted encrypted-at-rest in
//! `~/.uniclaw/session.json` and refreshed automatically when expired.

use std::path::PathBuf;
use std::sync::Arc;

use base64::{Engine, engine::general_purpose::STANDARD as BASE64_STANDARD};
use chrono::{DateTime, Utc};
use reqwest::Client;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use crate::error::LlmError;
use crate::secrets::SecretsCrypto;

/// Session data persisted to disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionData {
    /// Encrypted token bytes (nonce || ciphertext || tag), base64 encoded.
    #[serde(default)]
    pub encrypted_token: Option<String>,
    /// Per-token salt for HKDF, base64 encoded.
    #[serde(default)]
    pub key_salt: Option<String>,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub auth_provider: Option<String>,
    /// Legacy plaintext token field kept only for backward-compatible reads.
    #[serde(default)]
    pub session_token: Option<String>,
}

/// Configuration for session management.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// Base URL for auth endpoints (e.g., https://private.near.ai).
    pub auth_base_url: String,
    /// Path to session file (e.g., ~/.uniclaw/session.json).
    pub session_path: PathBuf,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            auth_base_url: "https://private.near.ai".to_string(),
            session_path: default_session_path(),
        }
    }
}

/// Get the default session file path (~/.uniclaw/session.json).
pub fn default_session_path() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".uniclaw")
        .join("session.json")
}

/// Manages NEAR AI session tokens with persistence and automatic renewal.
pub struct SessionManager {
    config: SessionConfig,
    client: Client,
    /// Current token in memory.
    token: RwLock<Option<SecretString>>,
    /// Prevents thundering herd during concurrent 401s.
    renewal_lock: Mutex<()>,
    /// Optional database store reference (currently unused for token persistence).
    store: RwLock<Option<Arc<dyn crate::db::Database>>>,
    /// User ID associated with the store attachment (default: "default").
    user_id: RwLock<String>,
}

impl SessionManager {
    /// Create a new session manager.
    ///
    /// Use `new_async` for disk loading.
    pub fn new(config: SessionConfig) -> Self {
        Self {
            config,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
            token: RwLock::new(None),
            renewal_lock: Mutex::new(()),
            store: RwLock::new(None),
            user_id: RwLock::new("default".to_string()),
        }
    }

    /// Create a session manager and load token asynchronously.
    pub async fn new_async(config: SessionConfig) -> Self {
        let manager = Self {
            config,
            client: Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|_| Client::new()),
            token: RwLock::new(None),
            renewal_lock: Mutex::new(()),
            store: RwLock::new(None),
            user_id: RwLock::new("default".to_string()),
        };

        if let Err(e) = manager.load_session().await {
            tracing::debug!("No existing session found: {}", e);
        }

        manager
    }

    /// Attach a database store for future session metadata use.
    ///
    /// Session bearer tokens are intentionally **not** written to generic
    /// settings storage to avoid plaintext token persistence in DB settings.
    pub async fn attach_store(&self, store: Arc<dyn crate::db::Database>, user_id: &str) {
        *self.store.write().await = Some(store);
        *self.user_id.write().await = user_id.to_string();
    }

    /// Get the current session token, returning an error if not authenticated.
    pub async fn get_token(&self) -> Result<SecretString, LlmError> {
        let guard = self.token.read().await;
        guard.clone().ok_or_else(|| LlmError::AuthFailed {
            provider: "nearai".to_string(),
        })
    }

    /// Check if we have a valid token (doesn't verify with server).
    pub async fn has_token(&self) -> bool {
        self.token.read().await.is_some()
    }

    /// Ensure we have a valid session, triggering login flow if needed.
    ///
    /// If no token exists, triggers the OAuth login flow. If a token exists,
    /// validates it by making a test API call. If validation fails, triggers
    /// the login flow.
    pub async fn ensure_authenticated(&self) -> Result<(), LlmError> {
        if !self.has_token().await {
            // No token, need to authenticate
            return self.initiate_login().await;
        }

        // Token exists, validate it by calling /v1/users/me
        println!("Validating session...");
        match self.validate_token().await {
            Ok(()) => {
                println!("Session valid.");
                Ok(())
            }
            Err(e) => {
                println!("Session expired or invalid: {}", e);
                self.initiate_login().await
            }
        }
    }

    /// Validate the current token by calling the /v1/users/me endpoint.
    async fn validate_token(&self) -> Result<(), LlmError> {
        use secrecy::ExposeSecret;

        let token = self.get_token().await?;
        let url = format!("{}/v1/users/me", self.config.auth_base_url);

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", token.expose_secret()))
            .send()
            .await
            .map_err(|e| LlmError::SessionRenewalFailed {
                provider: "nearai".to_string(),
                reason: format!("Validation request failed: {}", e),
            })?;

        if response.status().is_success() {
            return Ok(());
        }

        if response.status().as_u16() == 401 {
            return Err(LlmError::SessionExpired {
                provider: "nearai".to_string(),
            });
        }

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        Err(LlmError::SessionRenewalFailed {
            provider: "nearai".to_string(),
            reason: format!("Validation failed: HTTP {}: {}", status, body),
        })
    }

    /// Handle an authentication failure (401 response).
    ///
    /// Triggers the OAuth login flow to get a new session token.
    pub async fn handle_auth_failure(&self) -> Result<(), LlmError> {
        // Acquire renewal lock to prevent thundering herd
        let _guard = self.renewal_lock.lock().await;

        tracing::info!("Session expired or invalid, re-authenticating...");
        self.initiate_login().await
    }

    /// Start the OAuth login flow.
    ///
    /// 1. Bind the fixed callback port
    /// 2. Print the auth URL and attempt to open browser
    /// 3. Wait for OAuth callback with session token
    /// 4. Save and return the token
    async fn initiate_login(&self) -> Result<(), LlmError> {
        use crate::cli::oauth_defaults::{self, OAUTH_CALLBACK_PORT};

        let listener = oauth_defaults::bind_callback_listener()
            .await
            .map_err(|e| LlmError::SessionRenewalFailed {
                provider: "nearai".to_string(),
                reason: e.to_string(),
            })?;

        let callback_url = format!("http://127.0.0.1:{}", OAUTH_CALLBACK_PORT);

        // Show auth provider menu
        println!();
        println!("╔════════════════════════════════════════════════════════════════╗");
        println!("║                    NEAR AI Authentication                      ║");
        println!("╠════════════════════════════════════════════════════════════════╣");
        println!("║  Choose an authentication method:                              ║");
        println!("║                                                                ║");
        println!("║    [1] GitHub                                                  ║");
        println!("║    [2] Google                                                  ║");
        println!("║    [3] NEAR Wallet (coming soon)                               ║");
        println!("║                                                                ║");
        println!("╚════════════════════════════════════════════════════════════════╝");
        println!();
        print!("Enter choice [1-3]: ");

        // Flush stdout to ensure prompt is displayed
        use std::io::Write;
        std::io::stdout().flush().ok();

        // Read user choice
        let mut choice = String::new();
        std::io::stdin()
            .read_line(&mut choice)
            .map_err(|e| LlmError::SessionRenewalFailed {
                provider: "nearai".to_string(),
                reason: format!("Failed to read input: {}", e),
            })?;

        let (auth_provider, auth_url) = match choice.trim() {
            "1" | "" => {
                let url = format!(
                    "{}/v1/auth/github?frontend_callback={}",
                    self.config.auth_base_url,
                    urlencoding::encode(&callback_url)
                );
                ("github", url)
            }
            "2" => {
                let url = format!(
                    "{}/v1/auth/google?frontend_callback={}",
                    self.config.auth_base_url,
                    urlencoding::encode(&callback_url)
                );
                ("google", url)
            }
            "3" => {
                println!();
                println!("NEAR Wallet authentication is not yet implemented.");
                println!("Please use GitHub or Google for now.");
                return Err(LlmError::SessionRenewalFailed {
                    provider: "nearai".to_string(),
                    reason: "NEAR Wallet auth not yet implemented".to_string(),
                });
            }
            _ => {
                return Err(LlmError::SessionRenewalFailed {
                    provider: "nearai".to_string(),
                    reason: format!("Invalid choice: {}", choice.trim()),
                });
            }
        };

        println!();
        println!("Opening {} authentication...", auth_provider);
        println!();
        println!("  {}", auth_url);
        println!();

        // Try to open browser automatically
        if let Err(e) = open::that(&auth_url) {
            tracing::debug!("Could not open browser automatically: {}", e);
            println!("(Could not open browser automatically, please copy the URL above)");
        } else {
            println!("(Opening browser...)");
        }
        println!();
        println!("Waiting for authentication...");

        // The NEAR AI API redirects to: {frontend_callback}/auth/callback?token=X&...
        let session_token =
            oauth_defaults::wait_for_callback(listener, "/auth/callback", "token", "NEAR AI")
                .await
                .map_err(|e| LlmError::SessionRenewalFailed {
                    provider: "nearai".to_string(),
                    reason: e.to_string(),
                })?;

        let auth_provider = Some(auth_provider.to_string());

        // Save the token
        self.save_session(&session_token, auth_provider.as_deref())
            .await?;

        // Update in-memory token
        {
            let mut guard = self.token.write().await;
            *guard = Some(SecretString::from(session_token));
        }

        println!();
        println!("✓ Authentication successful!");
        println!();

        Ok(())
    }

    /// Save session data to disk and (if available) to the database.
    async fn save_session(&self, token: &str, auth_provider: Option<&str>) -> Result<(), LlmError> {
        let (encrypted, salt) = encrypt_session_token(token).await?;
        let session = SessionData {
            encrypted_token: Some(BASE64_STANDARD.encode(encrypted)),
            key_salt: Some(BASE64_STANDARD.encode(salt)),
            created_at: Utc::now(),
            auth_provider: auth_provider.map(String::from),
            session_token: None,
        };

        // Save to disk (always, as bootstrap fallback)
        if let Some(parent) = self.config.session_path.parent() {
            tokio::fs::create_dir_all(parent).await.map_err(|e| {
                LlmError::Io(std::io::Error::new(
                    e.kind(),
                    format!("Failed to create session directory: {}", e),
                ))
            })?;
        }

        let json =
            serde_json::to_string_pretty(&session).map_err(|e| LlmError::SessionRenewalFailed {
                provider: "nearai".to_string(),
                reason: format!("Failed to serialize session: {}", e),
            })?;

        tokio::fs::write(&self.config.session_path, json)
            .await
            .map_err(|e| {
                LlmError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to write session file {}: {}",
                        self.config.session_path.display(),
                        e
                    ),
                ))
            })?;

        // Restrictive permissions: session file contains a secret token
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o600);
            tokio::fs::set_permissions(&self.config.session_path, perms)
                .await
                .map_err(|e| {
                    LlmError::Io(std::io::Error::new(
                        e.kind(),
                        format!(
                            "Failed to set permissions on {}: {}",
                            self.config.session_path.display(),
                            e
                        ),
                    ))
                })?;
        }

        tracing::debug!(
            "Encrypted session saved to {}",
            self.config.session_path.display()
        );

        Ok(())
    }

    /// Load session data from disk.
    async fn load_session(&self) -> Result<(), LlmError> {
        let data = tokio::fs::read_to_string(&self.config.session_path)
            .await
            .map_err(|e| {
                LlmError::Io(std::io::Error::new(
                    e.kind(),
                    format!(
                        "Failed to read session file {}: {}",
                        self.config.session_path.display(),
                        e
                    ),
                ))
            })?;

        let session: SessionData =
            serde_json::from_str(&data).map_err(|e| LlmError::SessionRenewalFailed {
                provider: "nearai".to_string(),
                reason: format!("Failed to parse session file: {}", e),
            })?;

        let token = decrypt_session_token(&session).await?;

        {
            let mut guard = self.token.write().await;
            *guard = Some(SecretString::from(token));
        }

        // Auto-migrate legacy plaintext session file to encrypted format.
        if session.session_token.is_some() {
            if let Some(ref guard) = *self.token.read().await {
                if let Err(e) = self
                    .save_session(guard.expose_secret(), session.auth_provider.as_deref())
                    .await
                {
                    tracing::warn!("Failed to auto-migrate legacy session file: {}", e);
                }
            }
        }

        tracing::info!(
            "Loaded session from {} (created: {})",
            self.config.session_path.display(),
            session.created_at
        );

        Ok(())
    }

    /// Set token directly (useful for testing or migration from env var).
    pub async fn set_token(&self, token: SecretString) {
        let mut guard = self.token.write().await;
        *guard = Some(token);
    }
}

async fn load_session_master_key() -> Result<SecretString, LlmError> {
    if let Ok(env_key) = std::env::var("SECRETS_MASTER_KEY")
        && !env_key.is_empty()
    {
        return Ok(SecretString::from(env_key));
    }

    let keychain_key_bytes = crate::secrets::keychain::get_master_key()
        .await
        .map_err(|e| LlmError::SessionRenewalFailed {
            provider: "nearai".to_string(),
            reason: format!(
                "No encryption key for session persistence. Set SECRETS_MASTER_KEY or configure keychain: {}",
                e
            ),
        })?;

    let key_hex: String = keychain_key_bytes
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    Ok(SecretString::from(key_hex))
}

async fn encrypt_session_token(token: &str) -> Result<(Vec<u8>, Vec<u8>), LlmError> {
    let master_key = load_session_master_key().await?;
    let crypto = SecretsCrypto::new(master_key).map_err(|e| LlmError::SessionRenewalFailed {
        provider: "nearai".to_string(),
        reason: format!("Invalid session encryption key: {}", e),
    })?;
    crypto
        .encrypt(token.as_bytes())
        .map_err(|e| LlmError::SessionRenewalFailed {
            provider: "nearai".to_string(),
            reason: format!("Failed to encrypt session token: {}", e),
        })
}

async fn decrypt_session_token(session: &SessionData) -> Result<String, LlmError> {
    if let Some(ref legacy_token) = session.session_token {
        tracing::warn!("Loaded legacy plaintext session token; it will be re-saved encrypted.");
        return Ok(legacy_token.clone());
    }

    let encrypted_b64 =
        session
            .encrypted_token
            .as_deref()
            .ok_or_else(|| LlmError::SessionRenewalFailed {
                provider: "nearai".to_string(),
                reason: "Missing encrypted session token".to_string(),
            })?;
    let salt_b64 = session
        .key_salt
        .as_deref()
        .ok_or_else(|| LlmError::SessionRenewalFailed {
            provider: "nearai".to_string(),
            reason: "Missing session key salt".to_string(),
        })?;

    let encrypted =
        BASE64_STANDARD
            .decode(encrypted_b64)
            .map_err(|e| LlmError::SessionRenewalFailed {
                provider: "nearai".to_string(),
                reason: format!("Invalid encrypted session token encoding: {}", e),
            })?;
    let salt = BASE64_STANDARD
        .decode(salt_b64)
        .map_err(|e| LlmError::SessionRenewalFailed {
            provider: "nearai".to_string(),
            reason: format!("Invalid session key salt encoding: {}", e),
        })?;

    let master_key = load_session_master_key().await?;
    let crypto = SecretsCrypto::new(master_key).map_err(|e| LlmError::SessionRenewalFailed {
        provider: "nearai".to_string(),
        reason: format!("Invalid session encryption key: {}", e),
    })?;

    crypto
        .decrypt(&encrypted, &salt)
        .map_err(|e| LlmError::SessionRenewalFailed {
            provider: "nearai".to_string(),
            reason: format!("Failed to decrypt session token: {}", e),
        })
        .map(|s| s.expose().to_string())
}

/// Create a session manager from a config, migrating from env var if present.
pub async fn create_session_manager(config: SessionConfig) -> Arc<SessionManager> {
    let manager = SessionManager::new_async(config).await;

    // Check for legacy env var and migrate if present and no file token
    if !manager.has_token().await
        && let Ok(token) = std::env::var("NEARAI_SESSION_TOKEN")
        && !token.is_empty()
    {
        tracing::info!("Migrating session token from NEARAI_SESSION_TOKEN env var to file");
        manager.set_token(SecretString::from(token.clone())).await;
        if let Err(e) = manager.save_session(&token, None).await {
            tracing::warn!("Failed to save migrated session: {}", e);
        }
    }

    Arc::new(manager)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_session_save_load() {
        let dir = tempdir().unwrap();
        let session_path = dir.path().join("session.json");

        let config = SessionConfig {
            auth_base_url: "https://example.com".to_string(),
            session_path: session_path.clone(),
        };

        let manager = SessionManager::new_async(config.clone()).await;

        // SAFETY: test-only process-local mutation of env var for deterministic key setup.
        unsafe {
            std::env::set_var(
                "SECRETS_MASTER_KEY",
                "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            );
        }

        // No token initially
        assert!(!manager.has_token().await);

        // Save a token
        manager
            .save_session("test_token_123", Some("near"))
            .await
            .unwrap();
        manager
            .set_token(SecretString::from("test_token_123"))
            .await;

        // Verify it's set
        assert!(manager.has_token().await);
        let token = manager.get_token().await.unwrap();
        assert_eq!(token.expose_secret(), "test_token_123");

        // Create new manager and verify it loads the token
        let manager2 = SessionManager::new_async(config).await;
        assert!(manager2.has_token().await);
        let token2 = manager2.get_token().await.unwrap();
        assert_eq!(token2.expose_secret(), "test_token_123");

        // Verify file contents
        let data: SessionData =
            serde_json::from_str(&std::fs::read_to_string(&session_path).unwrap()).unwrap();
        assert!(data.session_token.is_none());
        assert!(data.encrypted_token.is_some());
        assert!(!data.encrypted_token.unwrap().contains("test_token_123"));
        assert_eq!(data.auth_provider, Some("near".to_string()));

        // SAFETY: test cleanup for process-local env var created above.
        unsafe {
            std::env::remove_var("SECRETS_MASTER_KEY");
        }
    }

    #[tokio::test]
    async fn test_get_token_without_auth_fails() {
        let dir = tempdir().unwrap();
        let config = SessionConfig {
            auth_base_url: "https://example.com".to_string(),
            session_path: dir.path().join("nonexistent.json"),
        };

        let manager = SessionManager::new_async(config).await;
        let result = manager.get_token().await;
        assert!(result.is_err());
        assert!(matches!(result, Err(LlmError::AuthFailed { .. })));
    }

    #[test]
    fn test_default_session_path() {
        let path = default_session_path();
        assert!(path.ends_with("session.json"));
        assert!(path.to_string_lossy().contains(".uniclaw"));
    }
}
