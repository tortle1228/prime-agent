//! MCP connection verification: a real streamable-HTTP handshake (initialize ->
//! tools/list) against the connection's endpoint. Health check only — the Python
//! generic runtime performs all real execution; error reporting uses fixed, safe
//! categories.

use std::time::Duration;

/// Fixed failure categories; safe to persist and show.
pub const PROBE_ERROR_TIMEOUT: &str = "verification-timeout";
pub const PROBE_ERROR_UNAUTHORIZED: &str = "http-unauthorized";
pub const PROBE_ERROR_NETWORK: &str = "network-unreachable";
pub const PROBE_ERROR_SERVER_REJECTED: &str = "server-rejected-handshake";
pub const PROBE_ERROR_HTTP: &str = "http-error";
pub const PROBE_ERROR_INVALID_RESPONSE: &str = "invalid-response";

/// One probe outcome: `Ok(tool_count)` on a completed handshake, or a fixed
/// failure category.
pub type ProbeOutcome = Result<usize, &'static str>;

/// The per-request timeout (TS default).
const DEFAULT_TIMEOUT_MS: u64 = 15_000;

/// The host's MCP handshake verifier. Implementations verify the exact supplied endpoint with
/// the supplied bearer token and return the total tool count or a fixed, credential-safe error.
/// The default implementation uses streamable HTTP.
pub trait McpEndpointProbeImpl: Send + Sync {
    fn probe_dyn(
        &self,
        url: &str,
        token: &str,
    ) -> futures::future::BoxFuture<'static, ProbeOutcome>;
}

/// The dyn-compatible object form the manager holds.
#[derive(Clone)]
pub struct McpEndpointProbe(std::sync::Arc<dyn McpEndpointProbeImpl>);

impl std::fmt::Debug for McpEndpointProbe {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("McpEndpointProbe").finish()
    }
}

impl McpEndpointProbe {
    pub fn new(probe: std::sync::Arc<dyn McpEndpointProbeImpl>) -> Self {
        Self(probe)
    }

    /// Verify one endpoint with the bearer `token` (empty = no Authorization header).
    /// A completed initialize + tools/list returns the total tool count.
    ///
    /// # Errors
    /// Returns a fixed, credential-safe category if the handshake or tool listing fails.
    pub async fn probe(&self, url: &str, token: &str) -> ProbeOutcome {
        self.0.probe_dyn(url, token).await
    }
}

/// The real handshake probe.
pub struct ReqwestMcpProbe {
    client: reqwest::Client,
    timeout: Duration,
}

impl Default for ReqwestMcpProbe {
    fn default() -> Self {
        Self {
            client: pa_ai::utils::tls::http_client_builder()
                // No redirects: a redirecting endpoint must not receive the token.
                .redirect(reqwest::redirect::Policy::none())
                .build()
                .unwrap_or_default(),
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
        }
    }
}

impl McpEndpointProbeImpl for ReqwestMcpProbe {
    fn probe_dyn(
        &self,
        url: &str,
        token: &str,
    ) -> futures::future::BoxFuture<'static, ProbeOutcome> {
        let client = self.client.clone();
        let timeout = self.timeout;
        let url = url.to_string();
        let token = token.to_string();
        Box::pin(async move { probe_endpoint(&client, &url, &token, timeout).await })
    }
}

/// One JSON-RPC request body for the handshake.
fn rpc(method: &str, id: i64, params: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params.clone() })
}

fn auth_headers(token: &str) -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    if !token.is_empty() {
        // The bearer is a literal value from the credential store.
        if let Ok(value) = reqwest::header::HeaderValue::from_str(&format!("Bearer {token}")) {
            headers.insert(reqwest::header::AUTHORIZATION, value);
        }
    }
    headers
}

async fn post_json_rpc(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    session: Option<(&str, Option<&str>)>,
    body: serde_json::Value,
    timeout: Duration,
) -> Result<(u16, Option<String>, Option<serde_json::Value>), &'static str> {
    let mut request = client
        .post(url)
        .timeout(timeout)
        .headers(auth_headers(token))
        .header(
            reqwest::header::ACCEPT,
            "application/json, text/event-stream",
        )
        .json(&body);
    if let Some((protocol, session_id)) = session {
        request = request.header("mcp-protocol-version", protocol);
        if let Some(session_id) = session_id {
            request = request.header("mcp-session-id", session_id);
        }
    }
    let mut response = request.send().await.map_err(|error| http_error(&error))?;
    let status = response.status().as_u16();
    let session_id = response
        .headers()
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    // Notifications have no JSON-RPC response. Errors are classified by status,
    // without waiting for or parsing an arbitrary error body.
    let Some(id) = body.get("id") else {
        return Ok((status, session_id, None));
    };
    if !(200..300).contains(&status) {
        return Ok((status, session_id, None));
    }
    let is_sse = response
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.contains("text/event-stream"));
    let payload = if is_sse {
        // A stream can stay open after the reply. Consume complete SSE events
        // until our response arrives, ignoring server notifications and requests.
        let mut pending = Vec::new();
        let mut data = Vec::new();
        let mut reply = None;
        'stream: while let Some(chunk) =
            response.chunk().await.map_err(|error| http_error(&error))?
        {
            pending.extend_from_slice(&chunk);
            while let Some(end) = pending.iter().position(|byte| *byte == b'\n') {
                let line = pending.drain(..=end).collect::<Vec<_>>();
                let line = std::str::from_utf8(&line)
                    .map_err(|_| PROBE_ERROR_INVALID_RESPONSE)?
                    .trim_end_matches(['\r', '\n']);
                if line.is_empty() {
                    if !data.is_empty() {
                        let value: serde_json::Value = serde_json::from_str(&data.join("\n"))
                            .map_err(|_| PROBE_ERROR_INVALID_RESPONSE)?;
                        data.clear();
                        if value.get("id") == Some(id)
                            && (value.get("result").is_some() || value.get("error").is_some())
                        {
                            reply = Some(value);
                            break 'stream;
                        }
                    }
                } else if let Some(value) = line.strip_prefix("data:") {
                    data.push(value.strip_prefix(' ').unwrap_or(value).to_string());
                }
            }
        }
        reply
    } else {
        let bytes = response.bytes().await.map_err(|error| http_error(&error))?;
        serde_json::from_slice::<serde_json::Value>(&bytes)
            .ok()
            .filter(|value| {
                value.get("id") == Some(id)
                    && (value.get("result").is_some() || value.get("error").is_some())
            })
    };
    Ok((status, session_id, payload))
}

fn http_error(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        PROBE_ERROR_TIMEOUT
    } else {
        PROBE_ERROR_NETWORK
    }
}

/// The full handshake: initialize, the initialized notification, tools/list. Each step's session id
/// feeds the next request; a rejected initialize maps to the fixed categories.
async fn probe_endpoint(
    client: &reqwest::Client,
    url: &str,
    token: &str,
    timeout: Duration,
) -> ProbeOutcome {
    let initialize = rpc(
        "initialize",
        1,
        &serde_json::json!({
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": { "name": "prime-agent", "version": "mcp-verify" }
        }),
    );
    let (status, session_id, value) =
        post_json_rpc(client, url, token, None, initialize, timeout).await?;
    if status == 401 || status == 403 {
        return Err(PROBE_ERROR_UNAUTHORIZED);
    }
    if !(200..300).contains(&status) {
        return Err(PROBE_ERROR_HTTP);
    }
    let Some(response) = value else {
        return Err(PROBE_ERROR_INVALID_RESPONSE);
    };
    if response.get("error").is_some() {
        return Err(PROBE_ERROR_SERVER_REJECTED);
    }
    let protocol = response
        .pointer("/result/protocolVersion")
        .and_then(serde_json::Value::as_str)
        .filter(|version| {
            matches!(
                *version,
                "2024-11-05" | "2025-03-26" | "2025-06-18" | "2025-11-25"
            )
        })
        .ok_or(PROBE_ERROR_INVALID_RESPONSE)?;
    let session = Some((protocol, session_id.as_deref()));
    let initialized = serde_json::json!({
        "jsonrpc": "2.0", "method": "notifications/initialized", "params": {}
    });
    let (status, _, _) = post_json_rpc(client, url, token, session, initialized, timeout).await?;
    if status == 401 || status == 403 {
        return Err(PROBE_ERROR_UNAUTHORIZED);
    }
    if !(200..300).contains(&status) {
        return Err(PROBE_ERROR_HTTP);
    }
    let mut params = serde_json::json!({});
    let mut tool_count = 0;
    let mut cursors = std::collections::HashSet::new();
    let mut id = 2;
    loop {
        let list = rpc("tools/list", id, &params);
        let (status, _, value) = post_json_rpc(client, url, token, session, list, timeout).await?;
        if status == 401 || status == 403 {
            return Err(PROBE_ERROR_UNAUTHORIZED);
        }
        if !(200..300).contains(&status) {
            return Err(PROBE_ERROR_HTTP);
        }
        let response = value.ok_or(PROBE_ERROR_INVALID_RESPONSE)?;
        if response.get("error").is_some() {
            return Err(PROBE_ERROR_SERVER_REJECTED);
        }
        let tools = response
            .pointer("/result/tools")
            .and_then(serde_json::Value::as_array)
            .ok_or(PROBE_ERROR_INVALID_RESPONSE)?;
        tool_count += tools.len();
        match response.pointer("/result/nextCursor") {
            None | Some(serde_json::Value::Null) => return Ok(tool_count),
            Some(serde_json::Value::String(cursor)) if cursors.insert(cursor.clone()) => {
                params = serde_json::json!({"cursor": cursor});
                id += 1;
            }
            Some(_) => return Err(PROBE_ERROR_INVALID_RESPONSE),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn server(
        responses: Vec<(&'static str, &'static str, &'static str)>,
    ) -> (
        String,
        tokio::task::JoinHandle<Vec<(String, serde_json::Value)>>,
    ) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let task = tokio::spawn(async move {
            let mut requests = Vec::new();
            for (status, content_type, body) in responses {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                let mut buffer = [0; 1024];
                let (head, body_start, length) = loop {
                    let read = socket.read(&mut buffer).await.unwrap();
                    assert_ne!(read, 0);
                    bytes.extend_from_slice(&buffer[..read]);
                    if let Some(end) = bytes.windows(4).position(|part| part == b"\r\n\r\n") {
                        let head = String::from_utf8(bytes[..end].to_vec())
                            .unwrap()
                            .to_lowercase();
                        let length = head
                            .lines()
                            .find_map(|line| line.strip_prefix("content-length: "))
                            .unwrap()
                            .parse::<usize>()
                            .unwrap();
                        break (head, end + 4, length);
                    }
                };
                while bytes.len() < body_start + length {
                    let read = socket.read(&mut buffer).await.unwrap();
                    assert_ne!(read, 0);
                    bytes.extend_from_slice(&buffer[..read]);
                }
                requests.push((
                    head,
                    serde_json::from_slice(&bytes[body_start..body_start + length]).unwrap(),
                ));
                let framing = if content_type == "text/event-stream" {
                    String::new()
                } else {
                    format!("content-length: {}\r\n", body.len())
                };
                let response = format!(
                    "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\nmcp-session-id: test-session\r\n{framing}connection: close\r\n\r\n{body}"
                );
                socket.write_all(response.as_bytes()).await.unwrap();
                if content_type == "text/event-stream" {
                    // EOF is the client's signal that it has consumed its reply;
                    // the server deliberately does not end the event stream.
                    assert_eq!(socket.read(&mut buffer).await.unwrap(), 0);
                }
            }
            requests
        });
        (url, task)
    }

    #[tokio::test]
    async fn negotiates_http_headers_and_counts_all_tool_pages() {
        let (url, task) = server(vec![
            ("200 OK", "application/json", r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-03-26","capabilities":{}}}"#),
            ("202 Accepted", "application/json", ""),
            ("200 OK", "text/event-stream", "data: {\"jsonrpc\":\"2.0\",\"method\":\"notifications/tools/list_changed\"}\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":2,\"result\":{\"tools\":[{\"name\":\"one\"}],\"nextCursor\":\"page-two\"}}\n\n"),
            ("200 OK", "application/json", r#"{"jsonrpc":"2.0","id":3,"result":{"tools":[{"name":"two"},{"name":"three"}],"nextCursor":null}}"#),
        ]).await;
        let outcome = probe_endpoint(
            &reqwest::Client::new(),
            &url,
            "secret",
            Duration::from_secs(2),
        )
        .await;
        assert_eq!(outcome, Ok(3));
        let requests = task.await.unwrap();
        for (index, (head, _)) in requests.iter().enumerate() {
            assert!(head.contains("accept: application/json, text/event-stream"));
            assert!(head.contains("authorization: bearer secret"));
            if index > 0 {
                assert!(head.contains("mcp-protocol-version: 2025-03-26"));
                assert!(head.contains("mcp-session-id: test-session"));
            }
        }
        assert_eq!(requests[2].1["params"], serde_json::json!({}));
        assert_eq!(
            requests[3].1["params"],
            serde_json::json!({"cursor": "page-two"})
        );
    }

    #[tokio::test]
    async fn accepts_the_sdk_supported_2025_11_25_protocol() {
        let (url, task) = server(vec![
            ("200 OK", "application/json", r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-11-25","capabilities":{}}}"#),
            ("202 Accepted", "application/json", ""),
            ("200 OK", "application/json", r#"{"jsonrpc":"2.0","id":2,"result":{"tools":[{"name":"one"}]}}"#),
        ]).await;
        assert_eq!(
            probe_endpoint(&reqwest::Client::new(), &url, "", Duration::from_secs(2)).await,
            Ok(1)
        );
        let requests = task.await.unwrap();
        for (head, _) in requests.iter().skip(1) {
            assert!(head.contains("mcp-protocol-version: 2025-11-25"));
        }
    }

    #[tokio::test]
    async fn a_missing_tool_array_is_not_a_successful_verification() {
        let (url, task) = server(vec![
            ("200 OK", "application/json", r#"{"jsonrpc":"2.0","id":1,"result":{"protocolVersion":"2025-06-18","capabilities":{}}}"#),
            ("202 Accepted", "application/json", ""),
            ("200 OK", "application/json", r#"{"jsonrpc":"2.0","id":2,"result":{}}"#),
        ]).await;
        assert_eq!(
            probe_endpoint(&reqwest::Client::new(), &url, "", Duration::from_secs(2)).await,
            Err(PROBE_ERROR_INVALID_RESPONSE)
        );
        task.await.unwrap();
    }
}
