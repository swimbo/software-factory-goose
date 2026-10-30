#[cfg(target_os = "linux")]
use watchdog::root_cgroup;
#[allow(dead_code)]
#[path = "../src/root_grant.rs"]
mod root_grant;
#[cfg(target_os = "linux")]
#[allow(dead_code)]
#[path = "../src/root_grant_attestor.rs"]
mod root_grant_attestor;
#[allow(dead_code)]
#[path = "../src/root_launch_docker.rs"]
mod root_launch_docker;
