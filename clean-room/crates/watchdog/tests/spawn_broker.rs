#![cfg(feature = "fixture")]
use std::{
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use watchdog::broker::{ApprovedLaunch, LaunchRole, SpawnBroker, SpawnReply};
use watchdog::{BrakePeer, BrakeSecret, Registry, StopResult};

struct SocketCleanup {
    root: PathBuf,
    servers: Vec<tokio::task::JoinHandle<()>>,
}
impl Drop for SocketCleanup {
    fn drop(&mut self) {
        for server in &self.servers {
            server.abort();
        }
        for name in [
            "broker.sock",
            "brake.sock",
            "worker.pid",
            "goose.pid",
            "tool.pid",
        ] {
            let _ = std::fs::remove_file(self.root.join(name));
        }
        let _ = std::fs::remove_dir(&self.root);
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}
fn spec(family: &str, role: LaunchRole, args: &[&str]) -> ApprovedLaunch {
    ApprovedLaunch::new(
        family.into(),
        role,
        PathBuf::from("/bin/sh"),
        args.iter().map(|s| (*s).into()).collect(),
        PathBuf::from("/tmp"),
        unsafe { libc::geteuid() },
        unsafe { libc::getegid() },
        now(),
        now() + 20_000,
    )
    .unwrap()
}
#[tokio::test]
async fn authenticated_broker_replays_and_stops_all_roots_with_hung_worker() {
    let registry = Arc::new(Registry::new().unwrap());
    let target = registry.create_family().unwrap();
    let broker = Arc::new(SpawnBroker::fixture(
        registry.clone(),
        BrakeSecret::new([0x69; 32]).unwrap(),
    ));
    let root = PathBuf::from(format!(
        "/tmp/sfbr-{}",
        &ulid::Ulid::new().to_string()[10..]
    ));
    std::fs::create_dir(&root).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut cleanup = SocketCleanup {
        root: root.clone(),
        servers: Vec::new(),
    };
    let worker_command = format!(
        "echo $$ > '{}'; kill -STOP $$; sleep 60",
        root.join("worker.pid").display()
    );
    let worker = broker
        .admit(spec(&target, LaunchRole::Worker, &["-c", &worker_command]))
        .unwrap();
    let goose_command = format!(
        "sleep 60 & echo $$ $! > '{}'; wait",
        root.join("goose.pid").display()
    );
    let tool_command = format!(
        "sleep 60 & echo $$ $! > '{}'; wait",
        root.join("tool.pid").display()
    );
    let goose = broker
        .admit(spec(&target, LaunchRole::Goose, &["-c", &goose_command]))
        .unwrap();
    let tool = broker
        .admit(spec(&target, LaunchRole::Tool, &["-c", &tool_command]))
        .unwrap();
    let socket = root.join("broker.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let router = broker.fixture_router();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<BrakePeer>(),
        )
        .await
        .unwrap()
    });
    cleanup.servers.push(server);
    let brake_socket = root.join("brake.sock");
    let brake_listener = tokio::net::UnixListener::bind(&brake_socket).unwrap();
    let brake_router =
        watchdog::fixture_router(BrakeSecret::new([0x5a; 32]).unwrap(), registry.clone());
    cleanup.servers.push(tokio::spawn(async move {
        axum::serve(
            brake_listener,
            brake_router.into_make_service_with_connect_info::<BrakePeer>(),
        )
        .await
        .unwrap();
    }));
    let brake = reqwest::Client::builder()
        .unix_socket(brake_socket)
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let client = reqwest::Client::builder()
        .unix_socket(socket.clone())
        .no_proxy()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap();
    let call = |id: String| {
        client
            .post("http://localhost/launch")
            .header("x-spawn-key", "69".repeat(32))
            .json(&serde_json::json!({"launch_id":id}))
    };
    let denied = client
        .post("http://localhost/launch")
        .header("x-spawn-key", "5a".repeat(32))
        .json(&serde_json::json!({"launch_id":worker}))
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    let forged = client
        .post("http://localhost/launch")
        .header("x-spawn-key", "69".repeat(32))
        .json(&serde_json::json!({"launch_id":worker,"command":"whoami","uid":0}))
        .send()
        .await
        .unwrap();
    assert_eq!(forged.status(), 422);
    let duplicate = client
        .post("http://localhost/launch")
        .header("x-spawn-key", "69".repeat(32))
        .header("x-spawn-key", "69".repeat(32))
        .json(&serde_json::json!({"launch_id":worker}))
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), 403);
    let oversized = client
        .post("http://localhost/launch")
        .header("x-spawn-key", "69".repeat(32))
        .json(&serde_json::json!({"launch_id":"x".repeat(2048)}))
        .send()
        .await
        .unwrap();
    assert_eq!(oversized.status(), 413);
    let brake_denied = brake
        .post("http://localhost/stop")
        .header("x-brake-key", "69".repeat(32))
        .json(&serde_json::json!({"target":target}))
        .send()
        .await
        .unwrap();
    assert_eq!(brake_denied.status(), 403);
    // Drop a successful response without reading its receipt, then recover by the same ID.
    let lost = call(goose.clone()).send().await.unwrap();
    assert_eq!(lost.status(), 200);
    drop(lost);
    let mut replies = Vec::new();
    for id in [&worker, &goose, &tool] {
        let response = call(id.clone()).send().await.unwrap();
        assert_eq!(response.status(), 200);
        replies.push(response.json::<SpawnReply>().await.unwrap());
    }
    assert_eq!(
        replies[0],
        call(worker.clone())
            .send()
            .await
            .unwrap()
            .json::<SpawnReply>()
            .await
            .unwrap()
    );
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(3);
    let worker_pid = loop {
        if let Ok(text) = std::fs::read_to_string(root.join("worker.pid"))
            && let Ok(pid) = text.trim().parse::<u32>()
        {
            break pid;
        }
        assert!(std::time::Instant::now() < deadline, "worker did not start");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    };
    loop {
        let status = std::process::Command::new("/bin/ps")
            .args(["-o", "stat=", "-p", &worker_pid.to_string()])
            .output()
            .unwrap();
        if String::from_utf8_lossy(&status.stdout).contains('T') {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "worker was not suspended"
        );
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    let mut fixture_pids = vec![worker_pid as i32];
    for file in ["goose.pid", "tool.pid"] {
        let pids = loop {
            if let Ok(text) = std::fs::read_to_string(root.join(file)) {
                let pids: Vec<i32> = text
                    .split_whitespace()
                    .filter_map(|s| s.parse().ok())
                    .collect();
                if pids.len() == 2 {
                    break pids;
                }
            }
            assert!(
                std::time::Instant::now() < deadline,
                "group descendants not ready"
            );
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        };
        assert_eq!(unsafe { libc::getpgid(pids[0]) }, pids[0]);
        assert_eq!(unsafe { libc::getpgid(pids[1]) }, pids[0]);
        fixture_pids.extend(pids);
    }
    let response = brake
        .post("http://localhost/stop")
        .header("x-brake-key", "5a".repeat(32))
        .json(&serde_json::json!({"target":target}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    let stopped = response.json::<StopResult>().await.unwrap();
    assert_eq!(stopped.groups.len(), 3);
    assert!(stopped.leader_reaped && stopped.group_absent);
    assert!(
        stopped
            .groups
            .iter()
            .all(|g| g.leader_signal == Some(libc::SIGKILL))
    );
    for pid in fixture_pids {
        assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
        assert_eq!(
            std::io::Error::last_os_error().raw_os_error(),
            Some(libc::ESRCH)
        );
    }
    // A lost reply replay is historical receipt only; it never reopens admission.
    assert_eq!(
        replies[0],
        call(worker)
            .send()
            .await
            .unwrap()
            .json::<SpawnReply>()
            .await
            .unwrap()
    );
    let late = broker
        .admit(spec(&target, LaunchRole::Tool, &["-c", "sleep 60"]))
        .unwrap();
    assert_eq!(call(late).send().await.unwrap().status(), 409);
    assert_eq!(registry.stop(&target).unwrap(), stopped);
    let unknown = call(ulid::Ulid::new().to_string()).send().await.unwrap();
    assert_eq!(unknown.status(), 409);
    let no_stop = client
        .post("http://localhost/stop")
        .header("x-spawn-key", "69".repeat(32))
        .send()
        .await
        .unwrap();
    assert_eq!(no_stop.status(), 404);
    drop(cleanup);
}

#[tokio::test]
async fn kernel_identity_cannot_be_replaced_with_claimed_uid() {
    use watchdog::broker::BrokerPolicy;
    let uid = unsafe { libc::geteuid() };
    let registry = Arc::new(Registry::new().unwrap());
    let broker = Arc::new(
        SpawnBroker::new(
            registry.clone(),
            BrokerPolicy::new(
                uid,
                uid + 100_000,
                uid + 100_001,
                vec![uid + 100_002],
                BrakeSecret::new([0x69; 32]).unwrap(),
            )
            .unwrap(),
        )
        .unwrap(),
    );
    let root = PathBuf::from(format!(
        "/tmp/sfbr-{}",
        &ulid::Ulid::new().to_string()[10..]
    ));
    std::fs::create_dir(&root).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let socket = root.join("broker.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let router = broker.router().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<BrakePeer>(),
        )
        .await
        .unwrap();
    });
    let _cleanup = SocketCleanup {
        root,
        servers: vec![server],
    };
    let client = reqwest::Client::builder()
        .unix_socket(socket)
        .no_proxy()
        .build()
        .unwrap();
    let response = client
        .post("http://localhost/launch")
        .header("x-spawn-key", "69".repeat(32))
        .header("x-peer-uid", (uid + 100_000).to_string())
        .json(&serde_json::json!({"launch_id":ulid::Ulid::new().to_string(),"uid":uid+100_000}))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 403);
    assert!(registry.is_empty());
}
