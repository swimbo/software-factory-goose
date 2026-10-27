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

#[test]
fn normal_work_package_identifier_remains_accepted() {
    let output = response(
        "200 OK",
        r#"{"task":{"id":"p:scaffold"}}"#,
        &["status", "p:scaffold"],
    );
    assert!(output.status.success());
}

#[test]
fn oversized_responses_never_print_partial_data() {
    for (status, chunked) in [
        ("200 OK", false),
        ("503 Service Unavailable", false),
        ("200 OK", true),
        ("503 Service Unavailable", true),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 4096);
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let bytes = vec![b'x'; 1_048_577];
            let headers = if chunked {
                format!(
                    "HTTP/1.1 {status}\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:X}\r\n",
                    bytes.len()
                )
            } else {
                format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    bytes.len()
                )
            };
            let _ = stream.write_all(headers.as_bytes());
            let _ = stream.write_all(&bytes);
            if chunked {
                let _ = stream.write_all(b"\r\n0\r\n\r\n");
            }
        });
        let output = Command::new(env!("CARGO_BIN_EXE_sfctl"))
            .args(["--url", &url, "--json", "status"])
            .output()
            .unwrap();
        server.join().unwrap();
        assert!(!output.status.success(), "{status}, chunked={chunked}");
        assert!(
            output.stdout.is_empty(),
            "partial response printed for {status}, chunked={chunked}"
        );
        assert!(String::from_utf8_lossy(&output.stderr).contains("response body exceeds limit"));
    }
}

#[test]
fn bounded_chunked_json_is_accepted() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 4096);
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        stream.write_all(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n6\r\n{\"ok\":\r\n5\r\ntrue}\r\n0\r\n\r\n").unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_sfctl"))
        .args(["--url", &url, "--json", "status"])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(output.status.success());
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&output.stdout).unwrap()["ok"],
        true
    );
}

#[test]
fn successful_http_with_invalid_json_is_not_success() {
    let output = response("200 OK", "not-json", &["status"]);
    assert!(!output.status.success());
}

#[test]
fn path_metacharacters_in_task_id_are_rejected_before_network() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let server = thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                    );
                    return true;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    thread::sleep(std::time::Duration::from_millis(10))
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return false,
                Err(e) => panic!("listener accept: {e}"),
            }
        }
    });
    let output = Command::new(env!("CARGO_BIN_EXE_sfctl"))
        .args(["--url", &url, "status", "task/../../intents"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("invalid identifier"));
    assert!(!server.join().unwrap());
}

#[test]
fn redirected_status_does_not_contact_another_origin() {
    let destination = TcpListener::bind("127.0.0.1:0").unwrap();
    destination.set_nonblocking(true).unwrap();
    let source = TcpListener::bind("127.0.0.1:0").unwrap();
    let source_url = format!("http://{}", source.local_addr().unwrap());
    let destination_url = format!("http://{}/unexpected", destination.local_addr().unwrap());
    let destination_server = thread::spawn(move || {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        loop {
            match destination.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}",
                        )
                        .unwrap();
                    return true;
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        && std::time::Instant::now() < deadline =>
                {
                    thread::sleep(std::time::Duration::from_millis(10))
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return false,
                Err(e) => panic!("destination accept: {e}"),
            }
        }
    });
    let server = thread::spawn(move || {
        let (mut stream, _) = source.accept().unwrap();
        let mut request = Vec::new();
        let mut byte = [0];
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 4096);
            stream.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        stream.write_all(format!("HTTP/1.1 307 Temporary Redirect\r\nLocation: {destination_url}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").as_bytes()).unwrap();
    });
    let output = Command::new(env!("CARGO_BIN_EXE_sfctl"))
        .args(["--url", &source_url, "status"])
        .output()
        .unwrap();
    server.join().unwrap();
    assert!(!output.status.success());
    assert!(!destination_server.join().unwrap());
}
