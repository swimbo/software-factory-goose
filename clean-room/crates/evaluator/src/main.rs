//! Thin binary entry for the verification plane; the wall's logic lives in the library so the
//! control-plane driver can call it from the build-result callback.

fn main() {
    println!("evaluator: the wall (deterministic verifier + holdout gate)");
    println!("isolation: run under a dedicated uid with a Seatbelt deny-read profile");
}
