use std::{
    io::{Read, Write},
    net::TcpListener,
    process::Command,
    thread,
};

fn response(status: &str, body: &str, args: &[&str]) -> std::process::Output {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let reply = format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(std::time::Duration::from_secs(5)))
            .unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            assert!(
                request.len() < 4096,
                "request headers exceeded fixture limit"
            );
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        stream.write_all(reply.as_bytes()).unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_sfctl"))
        .args(["--url", &url, "--json"])
        .args(args)
        .output()
        .unwrap();
    server.join().unwrap();
    output
}

#[test]
fn unavailable_stop_is_a_failure_not_a_success_message() {
    let output = response(
        "503 Service Unavailable",
        r#"{"error":"watchdog unavailable"}"#,
        &["stop", "task"],
    );
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("watchdog unavailable"));
}

#[test]
fn legacy_error_payload_is_a_cli_failure_even_with_http_200() {
    let output = response("200 OK", r#"{"error":"not found"}"#, &["status", "missing"]);
    assert!(!output.status.success());
}

#[test]
fn successful_status_keeps_machine_readable_stdout() {
    let output = response(
        "200 OK",
        r#"{"task":{"id":"task","status":"pending"}}"#,
        &["status", "task"],
    );
    assert!(output.status.success());
    let value: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["task"]["status"], "pending");
}
