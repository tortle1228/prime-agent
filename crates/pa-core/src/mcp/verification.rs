//! OAuth connection verification, detached from manager locks.

use std::sync::{Arc, Mutex};

use anyhow::{anyhow, bail, Context as _, Result};

use super::catalog_views::oauth_grant_usable;
use super::connection_store::{
    new_pending_record, McpConnectionRecord, McpConnectionStatus, McpConnectionStore,
};
use super::probe::{McpEndpointProbe, PROBE_ERROR_UNAUTHORIZED};
use super::McpManager;
use crate::auth::AuthStorage;

/// A detached OAuth handshake and durable connection-state update. No manager lock is held while
/// refreshing credentials or contacting the endpoint.
pub struct McpVerificationContext {
    record: McpConnectionRecord,
    auth_storage: Arc<tokio::sync::Mutex<AuthStorage>>,
    store: Arc<Mutex<McpConnectionStore>>,
    probe: McpEndpointProbe,
}

impl McpManager {
    /// Prepare verification of a known OAuth connection with its pinned endpoint.
    ///
    /// # Errors
    /// Returns an error for unknown or non-OAuth integrations.
    ///
    /// # Panics
    /// Panics if the connection store mutex is poisoned.
    pub fn verification_context(&self, server: &str) -> Result<McpVerificationContext> {
        let config = self
            .oauth_config(server)
            .ok_or_else(|| anyhow!("Unknown MCP integration: {server}"))?;
        let integration = &self.integrations()[server];
        let mut store = self
            .connection_store
            .lock()
            .expect("MCP connection store lock poisoned");
        store.load();
        let mut record = store.get(server).cloned().unwrap_or_else(|| {
            new_pending_record(
                server,
                integration.catalog_service_id.as_deref().unwrap_or(server),
                &config.label,
                &config.url,
            )
        });
        if record.endpoint != config.url {
            record.endpoint = config.url;
            record.verified_at = None;
            record.tool_count = None;
        }
        Ok(McpVerificationContext {
            record,
            auth_storage: self.auth_storage_handle(),
            store: Arc::clone(&self.connection_store),
            probe: self.probe(),
        })
    }
}

impl McpVerificationContext {
    /// Refresh the stored grant if necessary, verify the endpoint, and save its health state.
    ///
    /// # Errors
    /// Returns a safe error if credentials are unusable or changed, the handshake fails, or the
    /// connection state cannot be saved.
    ///
    /// # Panics
    /// Panics if the connection store mutex is poisoned.
    #[tracing::instrument(skip_all)]
    pub async fn run(mut self) -> Result<usize> {
        let provider = format!("mcp:{}", self.record.connection_id);
        let storage = Arc::clone(&self.auth_storage);
        let endpoint = self.record.endpoint.clone();
        let key = provider.clone();
        let (token, credential) = tokio::task::spawn_blocking(move || -> Result<_> {
            let mut auth = storage.blocking_lock();
            auth.reload();
            if auth.load_error().is_some() {
                bail!("auth storage failed to load");
            }
            let credential = auth
                .get_all()
                .get(&key)
                .cloned()
                .and_then(|value| serde_json::from_value(value).ok());
            oauth_grant_usable(credential.as_ref(), &endpoint).map_err(|_| {
                anyhow!("Stored OAuth credentials are not usable for this endpoint")
            })?;
            let token = auth
                .get_api_key(&key)
                .ok_or_else(|| anyhow!("Could not refresh OAuth credentials"))?;
            let credential = auth
                .get_all()
                .get(&key)
                .cloned()
                .ok_or_else(|| anyhow!("OAuth credentials changed during refresh"))?;
            let current = serde_json::from_value::<crate::auth::AuthCredential>(credential.clone())
                .map_err(|_| anyhow!("OAuth credentials changed during refresh"))?;
            oauth_grant_usable(Some(&current), &endpoint)
                .map_err(|_| anyhow!("OAuth credentials changed during refresh"))?;
            if !matches!(&current, crate::auth::AuthCredential::Oauth { access, .. } if access == &token) {
                bail!("Resolved token does not match the stored OAuth grant");
            }
            Ok((token, credential))
        })
        .await
        .context("OAuth credential resolution failed")??;
        let outcome = self.probe.probe(&self.record.endpoint, &token).await;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|time| time.as_millis() as u64)
            .unwrap_or_default();
        self.record.updated_at = now;
        self.record.attempt_id = None;
        if outcome.is_ok() {
            self.record.verified_at = Some(now);
        }
        self.record.tool_count = outcome.as_ref().ok().copied();
        self.record.last_error = outcome
            .as_ref()
            .err()
            .map(|category| (*category).to_string());
        self.record.status = match outcome {
            Ok(_) => McpConnectionStatus::Connected,
            Err(PROBE_ERROR_UNAUTHORIZED) => McpConnectionStatus::Error,
            Err(_) => McpConnectionStatus::Pending,
        };
        tokio::task::spawn_blocking(move || -> Result<()> {
            let mut auth = self.auth_storage.blocking_lock();
            auth.reload();
            if auth.load_error().is_some() {
                bail!("auth storage failed to load");
            }
            let still_current = auth.get_all().get(&provider) == Some(&credential);
            let committed = self
                .store
                .lock()
                .expect("MCP connection store lock poisoned")
                .apply_verify_result(&self.record, still_current)
                .context("could not save connection verification")?;
            if !committed {
                bail!("OAuth credentials changed during verification");
            }
            Ok(())
        })
        .await
        .context("connection verification persistence failed")??;
        outcome.map_err(|category| anyhow!("Connection verification failed: {category}"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::probe::{McpEndpointProbe, McpEndpointProbeImpl, ProbeOutcome};
    use super::super::*;
    use crate::auth::{AuthCredential, AuthStorage};
    use std::sync::Arc;

    struct Probe {
        outcome: ProbeOutcome,
        logout_dir: Option<std::path::PathBuf>,
    }
    impl McpEndpointProbeImpl for Probe {
        fn probe_dyn(
            &self,
            _url: &str,
            token: &str,
        ) -> futures::future::BoxFuture<'static, ProbeOutcome> {
            assert_eq!(token, "access");
            if let Some(dir) = &self.logout_dir {
                // A second auth-store instance models logout by another process during the probe.
                AuthStorage::create(dir).remove("mcp:linear");
            }
            let outcome = self.outcome;
            Box::pin(async move { outcome })
        }
    }

    fn manager(dir: &std::path::Path, probe: Probe) -> McpManager {
        let mut auth = AuthStorage::create(dir);
        auth.set(
            "mcp:linear",
            AuthCredential::Oauth {
                access: "access".into(),
                refresh: None,
                expires: i64::MAX,
                endpoint: Some("https://mcp.linear.app/mcp".into()),
                token_endpoint: None,
                client_id: None,
                resource: None,
                issuer: None,
                audience_mode: None,
                enterprise_url: None,
                account_id: None,
            },
        );
        McpManager::new(McpManagerOptions {
            auth_storage: auth,
            get_user_servers: Box::new(|| None),
            begin_login: None,
            agent_dir: Some(dir.to_path_buf()),
            get_catalog_sources: None,
            remote_source: None,
            probe_override: Some(McpEndpointProbe::new(Arc::new(probe))),
        })
    }

    #[tokio::test]
    async fn stored_oauth_verification_persists_connected_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut observer = manager(
            dir.path(),
            Probe {
                outcome: Ok(3),
                logout_dir: None,
            },
        );
        let manager = manager(
            dir.path(),
            Probe {
                outcome: Ok(3),
                logout_dir: None,
            },
        );
        let original = super::new_pending_record(
            "linear",
            "linear",
            "Linear account",
            "https://mcp.linear.app/mcp",
        );
        manager
            .connection_store
            .lock()
            .unwrap()
            .upsert(&original)
            .unwrap();
        assert_eq!(
            manager
                .verification_context("linear")
                .unwrap()
                .run()
                .await
                .unwrap(),
            3
        );
        let record = manager
            .connection_store
            .lock()
            .unwrap()
            .get("linear")
            .cloned()
            .unwrap();
        let mut expected = original;
        expected.updated_at = record.updated_at;
        expected.status = super::McpConnectionStatus::Connected;
        expected.verified_at = Some(record.updated_at);
        expected.tool_count = Some(3);
        assert_eq!(record, expected);
        let views = tokio::task::spawn_blocking(move || {
            observer.refresh();
            observer.service_catalog_views()
        })
        .await
        .unwrap();
        let row = views.iter().find(|row| row.service_id == "linear").unwrap();
        assert_eq!(row.connection_status.as_str(), "connected");
    }

    #[tokio::test]
    async fn failed_oauth_probe_persists_safe_failure_category() {
        for (category, expected_status) in [
            (
                super::PROBE_ERROR_UNAUTHORIZED,
                super::McpConnectionStatus::Error,
            ),
            (
                super::super::probe::PROBE_ERROR_TIMEOUT,
                super::McpConnectionStatus::Pending,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let manager = manager(
                dir.path(),
                Probe {
                    outcome: Err(category),
                    logout_dir: None,
                },
            );
            let error = manager
                .verification_context("linear")
                .unwrap()
                .run()
                .await
                .unwrap_err();
            assert_eq!(
                error.to_string(),
                format!("Connection verification failed: {category}")
            );
            let record = manager
                .connection_store
                .lock()
                .unwrap()
                .get("linear")
                .cloned()
                .unwrap();
            assert_eq!(
                (
                    record.status,
                    record.tool_count,
                    record.verified_at,
                    record.last_error
                ),
                (expected_status, None, None, Some(category.to_string()))
            );
        }
    }

    #[tokio::test]
    async fn failed_reverification_keeps_the_approved_endpoint_for_retry() {
        struct PinnedProbe(ProbeOutcome);

        impl McpEndpointProbeImpl for PinnedProbe {
            fn probe_dyn(
                &self,
                url: &str,
                token: &str,
            ) -> futures::future::BoxFuture<'static, ProbeOutcome> {
                assert_eq!(url, "https://old.example/mcp");
                assert_eq!(token, "access");
                let outcome = self.0;
                Box::pin(async move { outcome })
            }
        }

        for (category, status) in [
            (
                super::super::probe::PROBE_ERROR_TIMEOUT,
                super::McpConnectionStatus::Pending,
            ),
            (
                super::PROBE_ERROR_UNAUTHORIZED,
                super::McpConnectionStatus::Error,
            ),
        ] {
            let dir = tempfile::tempdir().unwrap();
            let mut manager = manager(
                dir.path(),
                Probe {
                    outcome: Ok(3),
                    logout_dir: None,
                },
            );
            let storage = manager.auth_storage_handle();
            let mut auth = storage.lock().await;
            let mut grant = auth.get_all().get("mcp:linear").cloned().unwrap();
            grant["endpoint"] = serde_json::json!("https://old.example/mcp");
            auth.set("mcp:linear", serde_json::from_value(grant).unwrap());
            drop(auth);
            let mut original = super::new_pending_record(
                "linear",
                "linear",
                "Linear account",
                "https://old.example/mcp",
            );
            original.status = super::McpConnectionStatus::Connected;
            original.verified_at = Some(original.created_at);
            original.tool_count = Some(3);
            manager
                .connection_store
                .lock()
                .unwrap()
                .upsert(&original)
                .unwrap();
            manager.refresh();
            assert_eq!(
                manager.oauth_config("linear").unwrap().url,
                original.endpoint
            );
            manager.probe_override =
                Some(McpEndpointProbe::new(Arc::new(PinnedProbe(Err(category)))));
            assert!(manager
                .verification_context("linear")
                .unwrap()
                .run()
                .await
                .is_err());
            manager.refresh();
            assert_eq!(
                manager.oauth_config("linear").unwrap().url,
                original.endpoint
            );
            let record = manager
                .connection_store
                .lock()
                .unwrap()
                .get("linear")
                .cloned()
                .unwrap();
            let mut expected = original.clone();
            expected.updated_at = record.updated_at;
            expected.status = status;
            expected.tool_count = None;
            expected.last_error = Some(category.to_string());
            assert_eq!(record, expected);
            manager.probe_override = Some(McpEndpointProbe::new(Arc::new(PinnedProbe(Ok(3)))));
            assert_eq!(
                manager
                    .verification_context("linear")
                    .unwrap()
                    .run()
                    .await
                    .unwrap(),
                3
            );
            assert_eq!(
                manager
                    .connection_store
                    .lock()
                    .unwrap()
                    .get("linear")
                    .unwrap()
                    .status,
                super::McpConnectionStatus::Connected
            );
        }
    }

    #[tokio::test]
    async fn runtime_override_cannot_be_sent_as_the_stored_oauth_grant() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(
            dir.path(),
            Probe {
                outcome: Ok(3),
                logout_dir: None,
            },
        );
        manager
            .auth_storage_handle()
            .lock()
            .await
            .set_runtime_api_key("mcp:linear", "override".to_string());
        let error = manager
            .verification_context("linear")
            .unwrap()
            .run()
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Resolved token does not match the stored OAuth grant"
        );
        assert!(manager
            .connection_store
            .lock()
            .unwrap()
            .get("linear")
            .is_none());
    }

    #[tokio::test]
    async fn retargeted_user_connection_requires_the_new_endpoints_grant() {
        let dir = tempfile::tempdir().unwrap();
        let mut manager = manager(
            dir.path(),
            Probe {
                outcome: Ok(3),
                logout_dir: None,
            },
        );
        manager.get_user_servers = Box::new(|| {
            Some(
                serde_json::from_value(serde_json::json!({
                    "fixture": {
                        "type": "http", "url": "https://new.example/mcp", "oauth": true,
                    },
                }))
                .unwrap(),
            )
        });
        let mut original = super::new_pending_record(
            "fixture",
            "fixture",
            "My account",
            "https://old.example/mcp",
        );
        original.status = super::McpConnectionStatus::Connected;
        original.verified_at = Some(original.created_at);
        original.tool_count = Some(3);
        manager
            .connection_store
            .lock()
            .unwrap()
            .upsert(&original)
            .unwrap();
        manager.resolve_integrations_over_catalog();
        let storage = manager.auth_storage_handle();
        let mut grant = storage
            .lock()
            .await
            .get_all()
            .get("mcp:linear")
            .cloned()
            .unwrap();
        grant["endpoint"] = serde_json::json!("https://old.example/mcp");
        storage.lock().await.set(
            "mcp:fixture",
            serde_json::from_value(grant.clone()).unwrap(),
        );
        let error = manager
            .verification_context("fixture")
            .unwrap()
            .run()
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "Stored OAuth credentials are not usable for this endpoint"
        );
        assert_eq!(
            manager.connection_store.lock().unwrap().get("fixture"),
            Some(&original)
        );
        grant["endpoint"] = serde_json::json!("https://new.example/mcp");
        storage
            .lock()
            .await
            .set("mcp:fixture", serde_json::from_value(grant).unwrap());
        manager.probe_override = Some(McpEndpointProbe::new(Arc::new(Probe {
            outcome: Err(super::super::probe::PROBE_ERROR_TIMEOUT),
            logout_dir: None,
        })));
        assert!(manager
            .verification_context("fixture")
            .unwrap()
            .run()
            .await
            .is_err());
        let unverified = manager
            .connection_store
            .lock()
            .unwrap()
            .get("fixture")
            .cloned()
            .unwrap();
        let mut expected = original.clone();
        expected.endpoint = "https://new.example/mcp".to_string();
        expected.updated_at = unverified.updated_at;
        expected.status = super::McpConnectionStatus::Pending;
        expected.verified_at = None;
        expected.tool_count = None;
        expected.last_error = Some(super::super::probe::PROBE_ERROR_TIMEOUT.to_string());
        assert_eq!(unverified, expected);
        manager.probe_override = Some(McpEndpointProbe::new(Arc::new(Probe {
            outcome: Ok(3),
            logout_dir: None,
        })));
        assert_eq!(
            manager
                .verification_context("fixture")
                .unwrap()
                .run()
                .await
                .unwrap(),
            3
        );
        let record = manager
            .connection_store
            .lock()
            .unwrap()
            .get("fixture")
            .cloned()
            .unwrap();
        let mut expected = original;
        expected.endpoint = "https://new.example/mcp".to_string();
        expected.updated_at = record.updated_at;
        expected.status = super::McpConnectionStatus::Connected;
        expected.verified_at = Some(record.updated_at);
        expected.tool_count = Some(3);
        assert_eq!(record, expected);
    }

    #[tokio::test]
    async fn oauth_probe_cannot_commit_after_external_logout() {
        let dir = tempfile::tempdir().unwrap();
        let manager = manager(
            dir.path(),
            Probe {
                outcome: Ok(3),
                logout_dir: Some(dir.path().to_path_buf()),
            },
        );
        let error = manager
            .verification_context("linear")
            .unwrap()
            .run()
            .await
            .unwrap_err();
        assert_eq!(
            error.to_string(),
            "OAuth credentials changed during verification"
        );
        assert!(manager
            .connection_store
            .lock()
            .unwrap()
            .get("linear")
            .is_none());
    }
}
