//! Fixed synthetic Docker adapter, review only. It is not a production recipe.
//! No caller-controlled Docker options, mounts, commands, or executable paths.
use anyhow::{Result, bail, ensure};
use serde_json::Value;
use std::{
    io::Read,
    os::fd::AsRawFd,
    process::{Child, Command, Stdio},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};
const DOCKER: &str = "/usr/bin/docker";
const IMAGE: &str = "sha256:ae952e0a57138a4317b9b61caaa19a8217c2f356803f8d7e63aad08769950937";
const LABEL: &str = "org.software-factory.root-launch-canary";
const PROGRAM: &str = "/usr/bin/setsid /bin/sleep 60 & wait";

/// Runner must retain uncertain Docker outcomes: a killed CLI is not a cancelled RPC.
pub trait Runner {
    fn run(&self, args: &[String]) -> Result<String>;
}
pub struct BoundedCli;
static CHILD: OnceLock<Mutex<Option<Child>>> = OnceLock::new();
impl BoundedCli {
    pub(crate) fn run_program(
        &self,
        program: &str,
        args: &[String],
        timeout: Duration,
    ) -> Result<String> {
        let mut slot = CHILD
            .get_or_init(|| Mutex::new(None))
            .try_lock()
            .map_err(|_| anyhow::anyhow!("engine CLI busy"))?;
        if let Some(previous) = slot.as_mut() {
            ensure!(
                previous.try_wait()?.is_some(),
                "previous CLI still owned and unresolved"
            );
            *slot = None;
        }
        *slot = Some(
            Command::new(program)
                .args(args)
                .env_clear()
                .env("PATH", "/usr/bin:/bin")
                .env("HOME", "/nonexistent")
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?,
        );
        let result = (|| -> Result<String> {
            let child = slot
                .as_mut()
                .ok_or_else(|| anyhow::anyhow!("child missing"))?;
            let mut stdout = child
                .stdout
                .take()
                .ok_or_else(|| anyhow::anyhow!("no stdout"))?;
            // SAFETY: fcntl operates on the live child stdout descriptor.
            let flags = unsafe { libc::fcntl(stdout.as_raw_fd(), libc::F_GETFL) };
            ensure!(
                flags >= 0
                    && unsafe {
                        libc::fcntl(stdout.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK)
                    } >= 0,
                "stdout setup failed"
            );
            let end = Instant::now() + timeout;
            let mut bytes = Vec::new();
            let mut buf = [0u8; 4096];
            let mut eof = false;
            let mut status = None;
            loop {
                match stdout.read(&mut buf) {
                    Ok(0) => eof = true,
                    Ok(n) => {
                        bytes.extend_from_slice(&buf[..n]);
                        ensure!(bytes.len() <= 65536, "output overflow");
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => return Err(e.into()),
                }
                if status.is_none() {
                    status = child.try_wait()?;
                }
                if eof && status.is_some() {
                    ensure!(status.is_some_and(|s| s.success()), "engine failed");
                    return Ok(String::from_utf8(bytes)?);
                }
                ensure!(Instant::now() < end, "engine deadline");
                std::thread::sleep(Duration::from_millis(10));
            }
        })();
        if result.is_err() {
            if let Some(child) = slot.as_mut() {
                match child.try_wait() {
                    Ok(Some(_)) => *slot = None,
                    Ok(None) => {
                        let _ = child.kill();
                        if child.try_wait().ok().flatten().is_some() {
                            *slot = None;
                        }
                    }
                    Err(_) => {}
                }
            }
            bail!("engine outcome unknown");
        }
        *slot = None;
        result
    }
}

impl Runner for BoundedCli {
    fn run(&self, args: &[String]) -> Result<String> {
        let mut fixed = vec!["--host".to_string(), "unix:///run/docker.sock".to_string()];
        fixed.extend_from_slice(args);
        self.run_program(DOCKER, &fixed, Duration::from_secs(8))
    }
}

fn canonical(g: &str) -> Result<()> {
    ensure!(
        ulid::Ulid::from_string(g).is_ok_and(|u| u.to_string() == g),
        "invalid generation"
    );
    Ok(())
}
fn full_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn name(g: &str) -> String {
    format!("sfactory-launch-{}", g.to_lowercase())
}
fn slice(g: &str) -> String {
    format!("sfactory{}.slice", g.to_lowercase())
}
fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|v| (*v).to_string()).collect()
}
fn empty_list(v: &Value) -> bool {
    v.is_null() || v.as_array().is_some_and(|a| a.is_empty())
}
/// Generation must already be bound to the root catalogue and pre-created cgroup.
pub fn create_stopped(r: &impl Runner, g: &str) -> Result<String> {
    canonical(g)?;
    let n = name(g);
    let sl = slice(g);
    let label = format!("{LABEL}={g}");
    let out = r.run(&args(&[
        "create",
        "--name",
        &n,
        "--label",
        &label,
        "--cgroup-parent",
        &sl,
        "--network",
        "none",
        "--cgroupns",
        "private",
        "--ipc",
        "private",
        "--read-only",
        "--cap-drop",
        "ALL",
        "--security-opt",
        "no-new-privileges",
        "--pids-limit",
        "16",
        "--memory",
        "128m",
        "--cpus",
        "0.5",
        "--restart",
        "no",
        "--user",
        "2001:2001",
        "--pull",
        "never",
        "--entrypoint",
        "/bin/sh",
        IMAGE,
        "-c",
        PROGRAM,
    ]))?;
    let id = out.trim();
    ensure!(full_id(id), "create returned no exact id");
    Ok(id.to_owned())
}
/// Fail closed if any asserted isolation option, exact name, label or full ID differs.
pub fn verify_stopped(r: &impl Runner, g: &str, id: &str) -> Result<()> {
    canonical(g)?;
    ensure!(full_id(id), "bad id");
    let x: Value = serde_json::from_str(&r.run(&args(&["inspect", id]))?)?;
    let a = x.as_array().ok_or_else(|| anyhow::anyhow!("bad inspect"))?;
    ensure!(a.len() == 1, "ambiguous inspect");
    let o = &a[0];
    let h = &o["HostConfig"];
    let c = &o["Config"];
    ensure!(
        o["Id"] == id
            && o["Name"] == format!("/{}", name(g))
            && o["Image"] == IMAGE
            && o["State"]["Status"] == "created"
            && o["State"]["Pid"] == 0
            && c["Labels"][LABEL] == g
            && c["User"] == "2001:2001"
            && c["Entrypoint"] == serde_json::json!(["/bin/sh"])
            && c["Cmd"] == serde_json::json!(["-c", PROGRAM])
            && c["Env"]
                == serde_json::json!([
                    "PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG=C.UTF-8",
                    "GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D",
                    "PYTHON_VERSION=3.11.18",
                    "PYTHON_SHA256=9120e0a653868f6e3698d36cdd99e5a58903ec9469e448f21d98f7b16d8fa290"
                ])
            && h["CgroupParent"] == slice(g)
            && h["NetworkMode"] == "none"
            && h["CgroupnsMode"] == "private"
            && h["IpcMode"] == "private"
            && h["PidMode"] == ""
            && h["UTSMode"] == ""
            && h["ReadonlyRootfs"] == true
            && h["Privileged"] == false
            && h["CapDrop"] == serde_json::json!(["ALL"])
            && empty_list(&h["CapAdd"])
            && h["SecurityOpt"] == serde_json::json!(["no-new-privileges"])
            && empty_list(&h["Binds"])
            && empty_list(&h["Devices"])
            && h["PidsLimit"] == 16
            && h["Memory"] == 134217728
            && h["NanoCpus"] == 500000000
            && h["RestartPolicy"]["Name"] == "no"
            && o["Mounts"].as_array().is_some_and(|m| m.is_empty()),
        "synthetic container identity mismatch"
    );
    Ok(())
}
pub fn start(r: &impl Runner, id: &str) -> Result<()> {
    ensure!(full_id(id), "bad id");
    r.run(&args(&["start", id]))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    struct Mock {
        calls: RefCell<Vec<Vec<String>>>,
        reply: String,
    }
    impl Runner for Mock {
        fn run(&self, a: &[String]) -> Result<String> {
            self.calls.borrow_mut().push(a.to_vec());
            Ok(self.reply.clone())
        }
    }
    #[test]
    fn create_is_fixed_and_bad_generation_never_dispatches() {
        let _: fn(&BoundedCli, &[String]) -> Result<String> = BoundedCli::run;
        let m = Mock {
            calls: RefCell::new(vec![]),
            reply: "a".repeat(64),
        };
        assert!(create_stopped(&m, "../../bad").is_err());
        assert!(m.calls.borrow().is_empty());
        let g = ulid::Ulid::new().to_string();
        assert_eq!(create_stopped(&m, &g).unwrap(), "a".repeat(64));
        let calls = m.calls.borrow();
        let a = &calls[0];
        assert!(a.contains(&"none".to_string()));
        assert!(a.contains(&"2001:2001".to_string()));
        assert!(!a.iter().any(|s| s.contains("mount")));
    }
    #[test]
    fn inspect_rejects_untrusted_or_ambiguous_objects() {
        let m = Mock {
            calls: RefCell::new(vec![]),
            reply: "[]".to_owned(),
        };
        let g = ulid::Ulid::new().to_string();
        assert!(verify_stopped(&m, &g, &"a".repeat(64)).is_err());
        assert!(start(&m, "relative-name").is_err());
        assert_eq!(m.calls.borrow().len(), 1);
    }
    #[test]
    fn owned_cli_timeout_is_bounded_and_slot_recovers_only_after_reap() {
        let cli = BoundedCli;
        let start = Instant::now();
        assert!(
            cli.run_program("/bin/sleep", &["2".into()], Duration::from_millis(50))
                .is_err()
        );
        assert!(start.elapsed() < Duration::from_secs(1));
        let mut recovered = false;
        for _ in 0..100 {
            if cli
                .run_program("/bin/echo", &["owned".into()], Duration::from_secs(1))
                .is_ok_and(|s| s == "owned\n")
            {
                recovered = true;
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(recovered);
    }
    #[test]
    fn fixed_inspect_positive_and_mutations() {
        let g = ulid::Ulid::new().to_string();
        let id = "a".repeat(64);
        let mut object = serde_json::json!({"Id":id,"Name":format!("/{}",name(&g)),"Image":IMAGE,
            "State":{"Status":"created","Pid":0},
            "Config":{"Labels":{},"User":"2001:2001","Entrypoint":["/bin/sh"],"Cmd":["-c",PROGRAM],"Env":["PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin","LANG=C.UTF-8","GPG_KEY=A035C8C19219BA821ECEA86B64E628F8D684696D","PYTHON_VERSION=3.11.18","PYTHON_SHA256=9120e0a653868f6e3698d36cdd99e5a58903ec9469e448f21d98f7b16d8fa290"]},
            "HostConfig":{"CgroupParent":slice(&g),"NetworkMode":"none","CgroupnsMode":"private","IpcMode":"private","PidMode":"","UTSMode":"","ReadonlyRootfs":true,"Privileged":false,
                "CapDrop":["ALL"],"CapAdd":null,"SecurityOpt":["no-new-privileges"],"PidsLimit":16,"Memory":134217728,"NanoCpus":500000000,"RestartPolicy":{"Name":"no"}},"Mounts":[]});
        object["Config"]["Labels"][LABEL] = serde_json::json!(g);
        let inspect = |o: &Value| Mock {
            calls: RefCell::new(vec![]),
            reply: serde_json::json!([o]).to_string(),
        };
        assert!(verify_stopped(&inspect(&object), &g, &id).is_ok());
        object["HostConfig"]["CgroupParent"] = serde_json::json!("wrong.slice");
        assert!(verify_stopped(&inspect(&object), &g, &id).is_err());
        object["HostConfig"]["CgroupParent"] = serde_json::json!(slice(&g));
        object["Config"]["Cmd"] = serde_json::json!(["-c", "true"]);
        assert!(verify_stopped(&inspect(&object), &g, &id).is_err());
        object["Config"]["Cmd"] = serde_json::json!(["-c", PROGRAM]);
        object["HostConfig"]["NetworkMode"] = serde_json::json!("host");
        assert!(verify_stopped(&inspect(&object), &g, &id).is_err());
        object["HostConfig"]["NetworkMode"] = serde_json::json!("none");
        object["Mounts"] = serde_json::json!([{"Source":"/"}]);
        assert!(verify_stopped(&inspect(&object), &g, &id).is_err());
    }
}
