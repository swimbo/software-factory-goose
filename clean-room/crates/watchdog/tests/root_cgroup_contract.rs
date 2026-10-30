use std::sync::Mutex;
use watchdog::root_cgroup::{StopBackend, StopResult};

#[derive(Default)]
struct Fake {
    events: Mutex<Vec<&'static str>>,
    fail: Option<&'static str>,
}
impl StopBackend for Fake {
    fn close_admission(&self) -> anyhow::Result<()> {
        self.events.lock().unwrap().push("closed");
        if self.fail == Some("close") {
            anyhow::bail!("close")
        }
        Ok(())
    }
    fn freeze(&self) -> anyhow::Result<()> {
        self.events.lock().unwrap().push("freeze");
        if self.fail == Some("freeze") {
            anyhow::bail!("freeze")
        }
        Ok(())
    }
    fn kill_and_observe_empty(&self) -> anyhow::Result<()> {
        self.events.lock().unwrap().push("kill");
        if self.fail == Some("kill") {
            anyhow::bail!("kill")
        }
        Ok(())
    }
}
#[test]
fn stop_closes_before_freeze_and_never_claims_engine_reconciled() {
    let x = Fake::default();
    let r = watchdog::root_cgroup::stop_kernel(&x).unwrap();
    assert_eq!(
        r,
        StopResult {
            closed: true,
            frozen: true,
            empty: true,
            engine_reconciled: false
        }
    );
    assert_eq!(*x.events.lock().unwrap(), vec!["closed", "freeze", "kill"]);
}
#[test]
fn failure_never_skips_or_invents_completion() {
    for (fail, expected) in [
        ("close", vec!["closed"]),
        ("freeze", vec!["closed", "freeze"]),
        ("kill", vec!["closed", "freeze", "kill"]),
    ] {
        let x = Fake {
            fail: Some(fail),
            ..Default::default()
        };
        assert!(watchdog::root_cgroup::stop_kernel(&x).is_err());
        assert_eq!(*x.events.lock().unwrap(), expected);
    }
}
