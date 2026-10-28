#![cfg(feature = "fixture")]
//! Harmless black-box fixture: no standing process, service or real credential is targeted.
use std::{
    fs,
    io::Write,
    os::unix::{fs::PermissionsExt, process::CommandExt},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use watchdog::StopResult;
const FIXTURE_KEY: [u8; 32] = [0x5a; 32];
struct Fixture {
    root: PathBuf,
    server: Option<Child>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if let Some(mut server) = self.server.take() {
            // Retained, unreaped Child owns this PID. Never signal a saved arbitrary PID.
            unsafe { libc::kill(server.id() as i32, libc::SIGTERM) };
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if server.try_wait().ok().flatten().is_some() {
                    break;
                }
                if Instant::now() >= deadline {
                    let _ = server.kill();
                    let _ = server.wait();
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        for name in [
            "brake.sock",
            "registry.json",
            "children.json",
            "children-worker.json",
            "children-goose.json",
            "children-tool.json",
            "recovery-required",
        ] {
            let _ = fs::remove_file(self.root.join(name));
        }
        let _ = fs::remove_dir(&self.root);
    }
}
impl Fixture {
    async fn start() -> Self {
        Self::start_mode("--fixture-server").await
    }
    async fn start_mode(mode: &str) -> Self {
        let root = PathBuf::from(format!(
            "/tmp/sfwd-{}",
            &ulid::Ulid::new().to_string()[10..]
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let server = Command::new(env!("CARGO_BIN_EXE_sf-watchdog-fixture"))
            .arg(mode)
            .arg(&root)
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn()
            .unwrap();
        let mut fixture = Self {
            root,
            server: Some(server),
        };
        let mut input = fixture.server.as_mut().unwrap().stdin.take().unwrap();
        input.write_all(&FIXTURE_KEY).unwrap();
        drop(input);
        let deadline = Instant::now() + Duration::from_secs(6);
        while !fixture.root.join("registry.json").exists() {
            assert!(
                Instant::now() < deadline,
                "watchdog fixture did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        fixture
    }
    fn read(&self, name: &str) -> serde_json::Value {
        serde_json::from_slice(&fs::read(self.root.join(name)).unwrap()).unwrap()
    }
    fn client(&self) -> reqwest::Client {
        reqwest::Client::builder()
            .unix_socket(self.root.join("brake.sock"))
            .no_proxy()
            .timeout(Duration::from_secs(5))
            .build()
            .unwrap()
    }
}
#[tokio::test]
async fn separate_watchdog_stops_entire_owned_group_without_main_or_database() {
    let fixture = Fixture::start().await;
    let registry = fixture.read("registry.json");
    let children = fixture.read("children.json");
    let target = registry["target"].as_str().unwrap();
    assert_ne!(
        registry["watchdog"].as_u64().unwrap(),
        u64::from(std::process::id())
    );
    let leader = children["leader"].as_i64().unwrap() as i32;
    let descendant = children["descendant"].as_i64().unwrap() as i32;
    assert_eq!(unsafe { libc::getpgid(leader) }, leader);
    assert_eq!(unsafe { libc::getpgid(descendant) }, leader);
    // Two owned harmless stand-ins demonstrate no dependency on their continued lifetime.
    // No actual control-plane or database is started or stopped by this fixture.
    for _ in 0..2 {
        let mut dependency = Command::new("/bin/sleep")
            .arg("60")
            .env_clear()
            .spawn()
            .unwrap();
        dependency.kill().unwrap();
        dependency.wait().unwrap();
    }
    let client = fixture.client();
    let key = "5a".repeat(32);
    let denied = client
        .post("http://localhost/stop")
        .header("x-brake-key", "ordinary-operator-token")
        .json(&serde_json::json!({"target":target}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    assert_eq!(unsafe { libc::kill(leader, 0) }, 0);
    assert_eq!(unsafe { libc::kill(descendant, 0) }, 0);
    let forged = client
        .post("http://localhost/stop")
        .header("x-brake-key", &key)
        .json(&serde_json::json!({"target":target,"pid":std::process::id()}))
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 422);
    let unknown = client
        .post("http://localhost/stop")
        .header("x-brake-key", &key)
        .json(&serde_json::json!({"target":ulid::Ulid::new().to_string()}))
        .send()
        .await
        .unwrap();
    assert_eq!(unknown.status(), 409);
    let no_registration = client
        .post("http://localhost/register")
        .header("x-brake-key", &key)
        .json(&serde_json::json!({"pid":leader}))
        .send()
        .await
        .unwrap();
    assert_eq!(no_registration.status(), 404);
    let oversized = client
        .post("http://localhost/stop")
        .header("x-brake-key", &key)
        .json(&serde_json::json!({"target":"a".repeat(2000)}))
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), 413);
    let duplicate = client
        .post("http://localhost/stop")
        .header("x-brake-key", &key)
        .header("x-brake-key", &key)
        .json(&serde_json::json!({"target":target}))
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), 403);
    // Accepted credentials do not permit an indefinitely stalled request body.
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut slow = tokio::net::UnixStream::connect(fixture.root.join("brake.sock"))
        .await
        .unwrap();
    slow.write_all(format!("POST /stop HTTP/1.1\r\nHost: localhost\r\nX-Brake-Key: {key}\r\nContent-Type: application/json\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{{").as_bytes()).await.unwrap();
    let mut reply = Vec::new();
    tokio::time::timeout(Duration::from_secs(6), slow.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert!(String::from_utf8_lossy(&reply).starts_with("HTTP/1.1 408"));
    let stopped = client
        .post("http://localhost/stop")
        .header("x-brake-key", &key)
        .json(&serde_json::json!({"target":target}))
        .send()
        .await
        .unwrap();
    assert_eq!(stopped.status(), 200);
    let result: StopResult = stopped.json().await.unwrap();
    assert!(result.signal_sent && result.leader_reaped && result.group_absent);
    assert_eq!(result.leader_signal, Some(libc::SIGKILL));
    assert_eq!(unsafe { libc::kill(-leader, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    assert_eq!(unsafe { libc::kill(descendant, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    let repeated = client
        .post("http://localhost/stop")
        .header("x-brake-key", &key)
        .json(&serde_json::json!({"target":target}))
        .send()
        .await
        .unwrap();
    assert_eq!(repeated.status(), 200);
    assert_eq!(repeated.json::<StopResult>().await.unwrap(), result);
}

#[tokio::test]
async fn directly_owned_family_stops_three_groups_with_unresponsive_worker() {
    let fixture = Fixture::start_mode("--fixture-family-server").await;
    let registry = fixture.read("registry.json");
    let target = registry["target"].as_str().unwrap();
    let mut groups = std::collections::BTreeSet::new();
    let mut members = Vec::new();
    for role in ["worker", "goose", "tool"] {
        let processes = fixture.read(&format!("children-{role}.json"));
        let leader = processes["leader"].as_i64().unwrap() as i32;
        let descendant = processes["descendant"].as_i64().unwrap() as i32;
        assert_eq!(unsafe { libc::getpgid(leader) }, leader);
        assert_eq!(unsafe { libc::getpgid(descendant) }, leader);
        groups.insert(leader);
        members.push((leader, descendant));
    }
    assert_eq!(
        groups.len(),
        3,
        "fixture must exercise distinct process groups"
    );
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let status = Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", &members[0].0.to_string()])
            .output()
            .unwrap();
        if String::from_utf8_lossy(&status.stdout).contains('T') {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "fixture worker did not stop itself"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let client = fixture.client();
    let key = "5a".repeat(32);
    let stopped = client
        .post("http://localhost/stop")
        .header("x-brake-key", &key)
        .json(&serde_json::json!({"target":target}))
        .send()
        .await
        .unwrap();
    assert_eq!(stopped.status(), 200);
    let result: StopResult = stopped.json().await.unwrap();
    assert_eq!(result.groups.len(), 3);
    assert!(
        result.leader_reaped
            && result.group_absent
            && result.groups.iter().all(|g| g.leader_reaped
                && g.group_absent
                && g.leader_signal == Some(libc::SIGKILL))
    );
    for (leader, descendant) in members {
        for pid in [leader, descendant] {
            assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
            assert_eq!(
                std::io::Error::last_os_error().raw_os_error(),
                Some(libc::ESRCH)
            );
        }
        assert_eq!(unsafe { libc::kill(-leader, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
    let repeated = client
        .post("http://localhost/stop")
        .header("x-brake-key", &key)
        .json(&serde_json::json!({"target":target}))
        .send()
        .await
        .unwrap();
    assert_eq!(repeated.status(), 200);
    assert_eq!(repeated.json::<StopResult>().await.unwrap(), result);
}
