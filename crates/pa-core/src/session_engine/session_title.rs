//! Automatic session titles: one short call to the `sessionTitleModel`
//! model over a session's first user message.

use anyhow::{anyhow, bail};

use super::auxiliary_model::{resolve_model_selector, AuxiliaryModelContext};

const SYSTEM_PROMPT: &str = "You write titles for chat sessions. Reply with the title only: a short noun phrase of about 30 characters, in the same language as the user's message, with no quotes and no trailing period.";

/// The first message's share of the request; a title needs only its opening.
const MAX_INPUT_CHARS: usize = 4_000;
const MAX_TITLE_CHARS: usize = 60;
const MAX_OUTPUT_TOKENS: u64 = 256;

/// Generate a title for the session whose first user message is
/// `first_message`. `Ok(None)` when `sessionTitleModel` is unset (the
/// feature is off); an unusable selector, a failed call, or an empty reply is an error.
///
/// # Errors
///
/// Returns an error when the selector resolves to no usable model, the
/// provider call fails, or the reply holds no title text.
pub async fn generate_session_title(
    context: &AuxiliaryModelContext,
    first_message: &str,
) -> anyhow::Result<Option<String>> {
    let resolved = {
        let context = context.clone();
        tokio::task::spawn_blocking(move || {
            let settings =
                crate::settings::SettingsManager::create(&context.cwd, &context.agent_dir);
            let selector = settings.get_session_title_model()?.to_lowercase();
            Some(
                resolve_model_selector(&context, &settings, &selector)
                    .ok_or_else(|| anyhow!("sessionTitleModel \"{selector}\" is unusable")),
            )
        })
        .await?
    };
    let Some(resolved) = resolved.transpose()? else {
        return Ok(None);
    };
    let request = pa_types::ai::Context {
        system_prompt: Some(SYSTEM_PROMPT.to_string()),
        messages: vec![pa_types::ai::Message::User(pa_types::ai::UserMessage {
            content: pa_types::ai::UserContent::Text(
                first_message.chars().take(MAX_INPUT_CHARS).collect(),
            ),
            timestamp: 0,
            rest: serde_json::Map::default(),
        })],
        tools: None,
    };
    let mut options = pa_ai::types::SimpleStreamOptions::from_base(pa_ai::types::StreamOptions {
        max_tokens: Some(MAX_OUTPUT_TOKENS),
        api_key: resolved.api_key,
        transport: Some(pa_ai::types::Transport::Sse),
        headers: resolved
            .headers
            .map(|headers| headers.into_iter().collect()),
        ..Default::default()
    });
    options.reasoning = pa_types::ai::minimum_reasoning(&resolved.model);
    let response = pa_ai::complete_simple(&resolved.model, &request, Some(options)).await?;
    match response.stop_reason {
        pa_types::ai::StopReason::Error | pa_types::ai::StopReason::Aborted => bail!(
            "{}",
            response
                .error_message
                .unwrap_or_else(|| "title request failed".to_string())
        ),
        pa_types::ai::StopReason::Stop
        | pa_types::ai::StopReason::Length
        | pa_types::ai::StopReason::ToolUse => {}
    }
    let text = response
        .content
        .iter()
        .filter_map(|block| match block {
            pa_types::ai::AssistantContentBlock::Text(text) => Some(text.text.as_str()),
            pa_types::ai::AssistantContentBlock::Thinking(_)
            | pa_types::ai::AssistantContentBlock::ToolCall(_) => None,
        })
        .collect::<String>();
    let line = text
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("");
    let quotes: &[char] = &['"', '\'', '`', '“', '”', '‘', '’', '«', '»', '「', '」'];
    let periods = ['.', '。'];
    let title: String = line
        .trim_end_matches(periods)
        .trim_matches(quotes)
        .trim_end_matches(periods)
        .trim()
        .chars()
        .take(MAX_TITLE_CHARS)
        .collect();
    let title = title.trim_end();
    if title.is_empty() {
        bail!("the title model returned no title");
    }
    Ok(Some(title.to_string()))
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    /// The configured title model receives the first message, and the
    /// quoted, period-terminated reply is stored as a bare title.
    #[tokio::test]
    async fn the_title_model_names_the_session_from_the_first_message() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            while !String::from_utf8_lossy(&request).contains("login page") {
                let read = socket.read(&mut chunk).await.unwrap();
                assert!(read > 0, "the request ended without the first message");
                request.extend_from_slice(&chunk[..read]);
            }
            let body = concat!(
                "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"title-model\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\\\"Login page crash fix\\\".\"}}]}\n\n",
                "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"title-model\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
                "data: [DONE]\n\n",
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        });
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(
            dir.path().join("settings.json"),
            serde_json::json!({ "sessionTitleModel": "testtitle/title-model" }).to_string(),
        )
        .unwrap();
        std::fs::write(
            dir.path().join("models.json"),
            serde_json::json!({
                "providers": {
                    "testtitle": {
                        "baseUrl": format!("http://{addr}"),
                        "apiKey": "title-key",
                        "api": "openai-completions",
                        "models": [ { "id": "title-model", "name": "Title Model" } ]
                    }
                }
            })
            .to_string(),
        )
        .unwrap();
        let context = AuxiliaryModelContext {
            cwd: dir.path().to_path_buf(),
            agent_dir: dir.path().to_path_buf(),
        };
        let title =
            generate_session_title(&context, "The login page crashes when I submit the form")
                .await
                .unwrap();
        server.await.unwrap();
        assert_eq!(title.as_deref(), Some("Login page crash fix"));
    }
}
