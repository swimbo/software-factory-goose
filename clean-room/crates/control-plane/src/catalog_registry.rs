//! Bounded root-provisioned catalog registry. Manifest data is never request authority.
use serde::Deserialize;
use std::collections::BTreeSet;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub schema: u32,
    pub active_intent: String,
    pub entries: Vec<Entry>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Entry {
    pub config: String,
    pub evidence: String,
    pub config_sha256: String,
    pub evidence_sha256: String,
    pub catalog_sha256: String,
}
fn filename(s: &str) -> bool {
    s.len() <= 80
        && s.ends_with(".json")
        && !s.starts_with('.')
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
        && !s.contains("..")
}
fn digest(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl Registry {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.schema == 1
                && (4..=16).contains(&self.entries.len())
                && ulid::Ulid::from_string(&self.active_intent)
                    .is_ok_and(|u| u.to_string() == self.active_intent),
            "registry scope invalid"
        );
        let mut files = BTreeSet::new();
        for e in &self.entries {
            anyhow::ensure!(
                filename(&e.config)
                    && filename(&e.evidence)
                    && files.insert(&e.config)
                    && files.insert(&e.evidence)
                    && digest(&e.config_sha256)
                    && digest(&e.evidence_sha256)
                    && digest(&e.catalog_sha256),
                "registry entry invalid"
            );
        }
        for (cfg, evidence, config_sha, evidence_sha, fingerprint) in [
            (
                "runtime.json",
                "evidence.json",
                "53082a93e3405f49f70ca5ea5681565a88cc3e1ca6d23397c803f4f5bfe152f6",
                "b3b456afd136d8541a9ef66ccc49cd3fd3d76111bbb837c3f09ed881cd10c65a",
                "e6e11a0b060dc2760f4c44ba607c45a931c01b839039158cbbec1e5f7e9ebbaf",
            ),
            (
                "grant-runtime.json",
                "grant-evidence.json",
                "70c14a65b8229304e04eb7e693eb7dc2ef20c7c947349e2e09e0b08dae84547f",
                "b3b456afd136d8541a9ef66ccc49cd3fd3d76111bbb837c3f09ed881cd10c65a",
                "4218228a2a9c0fcc51ec838414ebd92542b18e06ddd40d7a1a2b628d4d8caf19",
            ),
            (
                "real-runtime.json",
                "real-evidence.json",
                "1fe972454f55de3f6dd9e3f7783e810470e628a7f9da304a740412062a9dc1bf",
                "b67520e3e8ab7f5e700f7e77db5493c1dcd2a6e0ab489c130bed44b6f3f247b2",
                "cc5c4ae8ec34730f037fddefcb7b6d92fd4eab2bc1ac06dabd92abd747c1f1b7",
            ),
        ] {
            anyhow::ensure!(
                self.entries.iter().any(|e| e.config == cfg
                    && e.evidence == evidence
                    && e.config_sha256 == config_sha
                    && e.evidence_sha256 == evidence_sha
                    && e.catalog_sha256 == fingerprint),
                "required historical catalog missing or changed"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn manifest() -> serde_json::Value {
        serde_json::json!({"schema":1,"active_intent":"01J00000000000000000000006","entries":[
            {"config":"runtime.json","evidence":"evidence.json","config_sha256":"53082a93e3405f49f70ca5ea5681565a88cc3e1ca6d23397c803f4f5bfe152f6","evidence_sha256":"b3b456afd136d8541a9ef66ccc49cd3fd3d76111bbb837c3f09ed881cd10c65a","catalog_sha256":"e6e11a0b060dc2760f4c44ba607c45a931c01b839039158cbbec1e5f7e9ebbaf"},
            {"config":"grant-runtime.json","evidence":"grant-evidence.json","config_sha256":"70c14a65b8229304e04eb7e693eb7dc2ef20c7c947349e2e09e0b08dae84547f","evidence_sha256":"b3b456afd136d8541a9ef66ccc49cd3fd3d76111bbb837c3f09ed881cd10c65a","catalog_sha256":"4218228a2a9c0fcc51ec838414ebd92542b18e06ddd40d7a1a2b628d4d8caf19"},
            {"config":"real-runtime.json","evidence":"real-evidence.json","config_sha256":"1fe972454f55de3f6dd9e3f7783e810470e628a7f9da304a740412062a9dc1bf","evidence_sha256":"b67520e3e8ab7f5e700f7e77db5493c1dcd2a6e0ab489c130bed44b6f3f247b2","catalog_sha256":"cc5c4ae8ec34730f037fddefcb7b6d92fd4eab2bc1ac06dabd92abd747c1f1b7"},
            {"config":"new-runtime.json","evidence":"new-evidence.json","config_sha256":"a".repeat(64),"evidence_sha256":"b".repeat(64),"catalog_sha256":"c".repeat(64)}]})
    }
    #[test]
    fn preserves_required_catalogs_and_denies_rebinding_or_unsafe_paths() {
        let value = manifest();
        assert!(
            serde_json::from_value::<Registry>(value.clone())
                .unwrap()
                .validate()
                .is_ok()
        );
        for mutation in 0..5 {
            let mut bad = value.clone();
            match mutation {
                0 => bad["entries"][0]["catalog_sha256"] = serde_json::json!("a".repeat(64)),
                1 => bad["entries"][3]["config"] = serde_json::json!("../runtime.json"),
                2 => bad["entries"][3]["evidence"] = serde_json::json!("runtime.json"),
                3 => bad["entries"][3]["config_sha256"] = serde_json::json!("short"),
                _ => {
                    bad["entries"].as_array_mut().unwrap().remove(1);
                }
            }
            assert!(
                serde_json::from_value::<Registry>(bad)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }
    #[test]
    fn rejects_unbounded_and_unknown_fields() {
        let mut value = manifest();
        value["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<Registry>(value).is_err());
        let mut value = manifest();
        let original = value["entries"][3].clone();
        for i in 0..13 {
            let mut e = original.clone();
            e["config"] = serde_json::json!(format!("cfg-{i}.json"));
            e["evidence"] = serde_json::json!(format!("ev-{i}.json"));
            value["entries"].as_array_mut().unwrap().push(e);
        }
        assert!(
            serde_json::from_value::<Registry>(value)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
