//! Automatic session titles: the first prompt of an unnamed interactive
//! session, and `generate_session_title`, start a background title call;
//! the title lands through the supervisor's rename route, so name
//! uniqueness and the roster stay daemon-owned.

use std::time::Duration;

use serde_json::{json, Map};

use super::session_core::SessionCore;
use super::Worker;
use crate::protocol::{response_failure, response_success, DaemonCommand, DaemonResponse};
use crate::saved_session_commands::name_unavailable_error;
use crate::session_store::SessionFile;

const RENAME_TIMEOUT: Duration = Duration::from_secs(30);
const NAME_ATTEMPTS: u32 = 3;

impl Worker {
    /// `generate_session_title`: regenerate the title from the first user
    /// message, overwriting the current name. Answers before the model call.
    pub(crate) fn handle_generate_session_title(&self) -> DaemonResponse {
        const NAME: &str = "generate_session_title";
        if let Err(response) = self.require_created(NAME) {
            return response;
        }
        let core = self.core.lock().unwrap();
        let settings =
            pa_core::settings::SettingsManager::create(&core.cwd, &self.config.agent_dir);
        if settings.get_session_title_model().is_none() {
            return response_failure(
                None,
                NAME,
                "Set sessionTitleModel in settings.json to generate session titles",
                None,
            );
        }
        let Some(first_message) = core.store.as_ref().and_then(SessionFile::first_message) else {
            return response_failure(None, NAME, "No user message to name the session from", None);
        };
        self.spawn_session_title(&core, first_message);
        response_success(None, NAME, None)
    }

    /// Generate a title in the background and rename the session with it,
    /// unless the session or its name changed meanwhile. Failures are logged only.
    pub(crate) fn spawn_session_title(&self, core: &SessionCore, first_message: String) {
        let Some(store) = core.store.as_ref() else {
            return;
        };
        let title_for = json!({
            "sessionId": store.session_id(),
            "name": store.session_name(),
        });
        let context = pa_core::session_engine::auxiliary_model::AuxiliaryModelContext {
            cwd: core.cwd.clone().into(),
            agent_dir: self.config.agent_dir.clone(),
        };
        let active_session_id = core.active_session_id.clone();
        let depth = core.rlm_depth;
        let link = std::sync::Arc::clone(&self.roster_link);
        tokio::spawn(async move {
            let renamed = async {
                let Some(title) = pa_core::session_engine::session_title::generate_session_title(
                    &context,
                    &first_message,
                )
                .await?
                else {
                    return Ok(());
                };
                // Session names are unique: a title another session holds gets a number.
                let mut attempt = 1;
                loop {
                    let name = match attempt {
                        1 => title.clone(),
                        n => format!("{title} {n}"),
                    };
                    let command = DaemonCommand::Rename {
                        id: None,
                        active_session_id: active_session_id.clone(),
                        name: name.clone(),
                        renamed_by: None,
                        rest: Map::from_iter([(
                            "generatedTitleFor".to_string(),
                            title_for.clone(),
                        )]),
                    };
                    match link
                        .request_success(serde_json::to_value(&command)?, RENAME_TIMEOUT)
                        .await
                    {
                        Err(error)
                            if attempt < NAME_ATTEMPTS
                                && error.to_string() == name_unavailable_error(&name, depth) =>
                        {
                            attempt += 1;
                        }
                        result => return result.map(drop),
                    }
                }
            };
            if let Err(error) = renamed.await {
                eprintln!("pa-daemon: session title not set: {error:#}");
            }
        });
    }
}
