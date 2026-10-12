//! REVIEW PoC (not in upstream): an EHBP proxy (the untrusted intermediary
//! the proxy mode is designed around) can silently truncate a *streamed*
//! completion. EHBP frames are length-prefixed in the clear, so the proxy can
//! forward any prefix of the authenticated frames and end the HTTP body
//! cleanly; the SDK's streaming paths treat transport EOF as the end of the
//! completion and surface no error. The proxy never needs any key.
//!
//! Scenario: the enclave streams content deltas, then a tool_call delta, then
//! `finish_reason: "stop"` and `[DONE]`. The proxy forwards only the first
//! three frames. The client sees "The answer is " and never learns that the
//! model requested a tool call, nor that the stream was cut.

#[cfg(test)]
mod tests {
    use crate::client::Client;
    use crate::test_support::ehbp::{encrypt_response_chunks, TestEnclave};
    use futures_util::StreamExt;
    use serde_json::json;
    use std::fs;
    use std::io::Write as _;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const TEST_ENCLAVE_URL: &str = "https://enclave.test.invalid";
    const RESPONSE_NONCE: [u8; 32] = [7u8; 32];
    const EVIDENCE: &str =
        "/root/tinfoil-review/work/rust-sdk-verifier/results/ehbp_truncation_evidence.txt";

    fn log(line: &str) {
        println!("{line}");
        let _ = fs::create_dir_all("/root/tinfoil-review/work/rust-sdk-verifier/results");
        if let Ok(mut f) = fs::OpenOptions::new().create(true).append(true).open(EVIDENCE) {
            let _ = writeln!(f, "{line}");
        }
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn header_value(head: &str, name: &str) -> Option<String> {
        head.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_string())
        })
    }

    /// Minimal HTTP/1.1 request reader (header block + de-chunked body).
    async fn read_request(socket: &mut TcpStream) -> (String, Vec<u8>) {
        let mut buf = Vec::new();
        let head_end = loop {
            if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                break pos + 4;
            }
            let mut tmp = [0u8; 4096];
            let n = socket.read(&mut tmp).await.unwrap();
            assert!(n > 0);
            buf.extend_from_slice(&tmp[..n]);
        };
        let head = String::from_utf8_lossy(&buf[..head_end]).to_string();
        let mut rest = buf[head_end..].to_vec();
        let mut body = Vec::new();
        if header_value(&head, "transfer-encoding").is_some_and(|te| te.eq_ignore_ascii_case("chunked")) {
            let mut offset = 0usize;
            loop {
                let line_end = loop {
                    if let Some(pos) = find_subslice(&rest[offset..], b"\r\n") {
                        break offset + pos;
                    }
                    let mut tmp = [0u8; 4096];
                    let n = socket.read(&mut tmp).await.unwrap();
                    assert!(n > 0);
                    rest.extend_from_slice(&tmp[..n]);
                };
                let size = usize::from_str_radix(
                    std::str::from_utf8(&rest[offset..line_end]).unwrap().trim(),
                    16,
                )
                .unwrap();
                offset = line_end + 2;
                if size == 0 {
                    break;
                }
                while rest.len() < offset + size + 2 {
                    let mut tmp = [0u8; 4096];
                    let n = socket.read(&mut tmp).await.unwrap();
                    assert!(n > 0);
                    rest.extend_from_slice(&tmp[..n]);
                }
                body.extend_from_slice(&rest[offset..offset + size]);
                offset += size + 2;
            }
        } else if let Some(len) = header_value(&head, "content-length") {
            let len: usize = len.parse().unwrap();
            while rest.len() < len {
                let mut tmp = [0u8; 4096];
                let n = socket.read(&mut tmp).await.unwrap();
                assert!(n > 0);
                rest.extend_from_slice(&tmp[..n]);
            }
            rest.truncate(len);
            body = rest;
        }
        (head, body)
    }

    /// Split a framed EHBP body (LEN || CIPHERTEXT ...) into its frames. This
    /// is all a proxy needs: the framing is in the clear.
    fn split_frames(framed: &[u8]) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        let mut offset = 0;
        while offset + 4 <= framed.len() {
            let len = u32::from_be_bytes(framed[offset..offset + 4].try_into().unwrap()) as usize;
            frames.push(framed[offset..offset + 4 + len].to_vec());
            offset += 4 + len;
        }
        frames
    }

    /// The genuine enclave stream: content, then a tool call, then stop.
    fn genuine_events() -> Vec<String> {
        vec![
            r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"role":"assistant","content":"The "},"finish_reason":null}]}"#.into(),
            r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"answer "},"finish_reason":null}]}"#.into(),
            r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"is "},"finish_reason":null}]}"#.into(),
            r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"content":"NO. Do not proceed."},"finish_reason":null}]}"#.into(),
            r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{"tool_calls":[{"index":0,"id":"call_1","type":"function","function":{"name":"abort_transfer","arguments":"{}"}}]},"finish_reason":null}]}"#.into(),
            r#"{"id":"c1","object":"chat.completion.chunk","created":1,"model":"m","choices":[{"index":0,"delta":{},"finish_reason":"tool_calls"}]}"#.into(),
        ]
    }

    /// Spawn a server that plays the enclave (encrypts the genuine stream,
    /// one SSE event per frame, exactly as the middleware flushes) and the
    /// proxy (forwards only `keep_frames` frames, then ends the body cleanly).
    async fn spawn_truncating_proxy(keep_frames: usize) -> (String, String, tokio::task::JoinHandle<usize>) {
        let enclave = TestEnclave::generate();
        let public_key_hex = enclave.public_key_hex();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (head, _body) = read_request(&mut socket).await;
            let enc_hex = header_value(&head, "ehbp-encapsulated-key").unwrap();
            // --- enclave side: genuine, fully authenticated response ---
            let (secret, enc) = enclave.export_secret(&enc_hex);
            let mut sse: Vec<String> = genuine_events().into_iter().map(|e| format!("data: {e}\n\n")).collect();
            sse.push("data: [DONE]\n\n".to_string());
            let chunks: Vec<&[u8]> = sse.iter().map(|e| e.as_bytes()).collect();
            let encrypted = encrypt_response_chunks(&secret, &enc, &RESPONSE_NONCE, &chunks);
            // --- proxy side: no keys, just forwards a prefix of the frames ---
            let frames = split_frames(&encrypted);
            let total = frames.len();
            let forwarded: Vec<u8> = frames[..keep_frames.min(total)].concat();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nEhbp-Response-Nonce: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                hex::encode(RESPONSE_NONCE),
                forwarded.len()
            );
            socket.write_all(head.as_bytes()).await.unwrap();
            socket.write_all(&forwarded).await.unwrap();
            let _ = socket.shutdown().await;
            total
        });
        (format!("http://{addr}"), public_key_hex, server)
    }

    #[tokio::test]
    async fn poc_typed_stream_truncated_by_proxy_ends_without_error() {
        use async_openai::types::chat::{
            ChatCompletionRequestUserMessageArgs, CreateChatCompletionRequestArgs,
        };
        let keep = 3;
        let (proxy_url, public_key_hex, server) = spawn_truncating_proxy(keep).await;
        let client = Client::test_client_with_ehbp(proxy_url, TEST_ENCLAVE_URL, &public_key_hex);
        let request = CreateChatCompletionRequestArgs::default()
            .model("m")
            .stream(true)
            .messages(vec![ChatCompletionRequestUserMessageArgs::default()
                .content("Should I wire the funds?")
                .build()
                .unwrap()
                .into()])
            .build()
            .unwrap();

        let mut stream = client.chat().create_stream(request).await.unwrap();
        let mut content = String::new();
        let mut chunks = 0;
        let mut errors = 0;
        let mut finish_reason = None;
        let mut tool_calls = 0;
        while let Some(item) = stream.next().await {
            match item {
                Ok(chunk) => {
                    chunks += 1;
                    for choice in &chunk.choices {
                        if let Some(c) = choice.delta.content.as_deref() {
                            content.push_str(c);
                        }
                        if choice.finish_reason.is_some() {
                            finish_reason = choice.finish_reason.clone();
                        }
                        tool_calls += choice.delta.tool_calls.as_ref().map_or(0, |t| t.len());
                    }
                }
                Err(e) => {
                    errors += 1;
                    log(&format!("typed stream error: {e}"));
                }
            }
        }
        let total_frames = server.await.unwrap();
        log(&format!(
            "[typed chat().create_stream via EHBP proxy] genuine frames={total_frames} forwarded={keep} -> client got chunks={chunks} errors={errors} content={content:?} finish_reason={finish_reason:?} tool_call_deltas={tool_calls}"
        ));
        assert_eq!(errors, 0, "truncation must be invisible for the PoC to hold");
        assert_eq!(chunks, keep);
        assert_eq!(content, "The answer is ");
        assert!(finish_reason.is_none());
        assert_eq!(tool_calls, 0);
    }

    #[tokio::test]
    async fn poc_relaxed_stream_truncated_by_proxy_ends_without_error() {
        let keep = 3;
        let (proxy_url, public_key_hex, server) = spawn_truncating_proxy(keep).await;
        let client = Client::test_client_with_ehbp(proxy_url, TEST_ENCLAVE_URL, &public_key_hex);
        let body = client
            .chat_relaxed()
            .request()
            .model("m")
            .push_message(json!({"role": "user", "content": "Should I wire the funds?"}))
            .build();
        let mut stream = client.chat_relaxed().create_stream(body).await.unwrap();
        let mut content = String::new();
        let mut chunks = 0;
        let mut errors = 0;
        let mut finish_reason = None;
        let mut tool_calls = 0;
        while let Some(item) = stream.next().await {
            match item {
                Ok(chunk) => {
                    chunks += 1;
                    if let Some(c) = chunk.delta_content() {
                        content.push_str(c);
                    }
                    if let Some(f) = chunk.finish_reason() {
                        finish_reason = Some(f.to_string());
                    }
                    tool_calls += chunk.tool_call_deltas().len();
                }
                Err(e) => {
                    errors += 1;
                    log(&format!("relaxed stream error: {e}"));
                }
            }
        }
        let total_frames = server.await.unwrap();
        log(&format!(
            "[chat_relaxed().create_stream via EHBP proxy] genuine frames={total_frames} forwarded={keep} -> client got chunks={chunks} errors={errors} content={content:?} finish_reason={finish_reason:?} tool_call_deltas={tool_calls}"
        ));
        assert_eq!(errors, 0);
        assert_eq!(chunks, keep);
        assert_eq!(content, "The answer is ");
        assert!(finish_reason.is_none());
        assert_eq!(tool_calls, 0);
    }

    /// Zero forwarded frames: a 200 with a valid nonce and an empty body is
    /// accepted as an empty stream (no events, no error).
    #[tokio::test]
    async fn poc_relaxed_stream_emptied_by_proxy_ends_without_error() {
        let (proxy_url, public_key_hex, server) = spawn_truncating_proxy(0).await;
        let client = Client::test_client_with_ehbp(proxy_url, TEST_ENCLAVE_URL, &public_key_hex);
        let body = client
            .chat_relaxed()
            .request()
            .model("m")
            .push_message(json!({"role": "user", "content": "hi"}))
            .build();
        let mut stream = client.chat_relaxed().create_stream(body).await.unwrap();
        let mut chunks = 0;
        let mut errors = 0;
        while let Some(item) = stream.next().await {
            match item {
                Ok(_) => chunks += 1,
                Err(e) => {
                    errors += 1;
                    log(&format!("relaxed stream error: {e}"));
                }
            }
        }
        let total_frames = server.await.unwrap();
        log(&format!(
            "[chat_relaxed().create_stream, proxy forwards 0 of {total_frames} frames] chunks={chunks} errors={errors}"
        ));
        assert_eq!(errors, 0);
        assert_eq!(chunks, 0);
    }

    /// Control: a non-streaming JSON completion truncated at a frame boundary
    /// is caught, because the JSON document no longer parses.
    #[tokio::test]
    async fn control_non_streaming_truncation_is_detected() {
        let enclave = TestEnclave::generate();
        let public_key_hex = enclave.public_key_hex();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let (head, _body) = read_request(&mut socket).await;
            let enc_hex = header_value(&head, "ehbp-encapsulated-key").unwrap();
            let (secret, enc) = enclave.export_secret(&enc_hex);
            let reply = br#"{"id":"chatcmpl-1","object":"chat.completion","created":1,"model":"m","choices":[{"index":0,"message":{"role":"assistant","content":"NO. Do not proceed."},"finish_reason":"stop","logprobs":null}]}"#;
            let (a, b) = reply.split_at(60);
            let encrypted = encrypt_response_chunks(&secret, &enc, &RESPONSE_NONCE, &[a, b]);
            let frames = split_frames(&encrypted);
            let forwarded = frames[0].clone();
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nEhbp-Response-Nonce: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                hex::encode(RESPONSE_NONCE),
                forwarded.len()
            );
            socket.write_all(head.as_bytes()).await.unwrap();
            socket.write_all(&forwarded).await.unwrap();
            let _ = socket.shutdown().await;
        });
        let client = Client::test_client_with_ehbp(format!("http://{addr}"), TEST_ENCLAVE_URL, &public_key_hex);
        let body = client
            .chat_relaxed()
            .request()
            .model("m")
            .push_message(json!({"role": "user", "content": "hi"}))
            .build();
        let result = client.chat_relaxed().create(body).await;
        server.await.unwrap();
        log(&format!(
            "[control: non-streaming JSON truncated at frame boundary] result={}",
            match &result {
                Ok(r) => format!("ACCEPTED {:?}", r.raw()),
                Err(e) => format!("error: {e}"),
            }
        ));
        assert!(result.is_err());
    }
}
