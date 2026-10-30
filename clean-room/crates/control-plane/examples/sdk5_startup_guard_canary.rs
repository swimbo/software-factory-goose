//! Native PID1 canary for the exact SDK5 pre-runtime descriptor guard.
#[cfg(all(target_os = "linux", feature = "sdk5-guard-canary"))]
fn main() -> anyhow::Result<()> {
    control_plane::sdk5_startup_guard::verify_canary()?;
    println!("sdk5-startup-guard-passed");
    Ok(())
}
#[cfg(not(all(target_os = "linux", feature = "sdk5-guard-canary")))]
fn main() {
    eprintln!("SDK5 guard canary requires Linux and sdk5-guard-canary");
    std::process::exit(1);
}
