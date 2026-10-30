//! Pure root finalization contract. Provenance and authenticated ingress are separate gates.
use crate::{
    launch_reservation::{LaunchReservation, LaunchScope},
    workflow::{ClaimLeaseState, LeaseStage},
};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootLaunchCatalog {
    pub schema: u32,
    pub scope: LaunchScope,
    pub boot_id: String,
    pub cgroup_dev: u64,
    pub cgroup_ino: u64,
    pub recipe_sha256: String,
    pub max_expiry_ms: u64,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootLaunchRecipe {
    pub schema: u32,
    pub purpose: String,
    pub generation: String,
    pub task_id: String,
    pub worker_uid: u32,
    pub goose_binary_sha256: String,
    pub worker_image_id: String,
    pub worker_program_sha256: String,
    pub writer_image_id: String,
    pub writer_program_sha256: String,
    pub profile_sha256: String,
    pub prompt_sha256: String,
    pub relay_scope_template_sha256: String,
    pub provider_binding_sha256: String,
    pub fixed_parent: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    #[serde(deserialize_with = "unique_files")]
    pub files: BTreeMap<String, String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    pub evaluator_id: String,
    pub receipt_sha256: String,
    pub snapshot_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Commit {
    pub revision: String,
    #[serde(deserialize_with = "unique_files")]
    pub blobs: BTreeMap<String, String>,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Cleanup {
    pub boot_id: String,
    pub cgroup_dev: u64,
    pub cgroup_ino: u64,
    pub writer_id: String,
    pub goose_id: String,
    pub closure_sha256: String,
    pub observation_sha256: String,
    pub reconciliation_sha256: String,
    pub terminal_receipts_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownPhase {
    Admission,
    Launch,
    Execution,
    Cleanup,
    Evaluation,
    Commit,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnknownReason {
    MissingEvidence,
    OutcomeUnknown,
    IntegrityConflict,
    Deadline,
    AuthorityUnavailable,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Evidence {
    EvaluatedPass {
        snapshot: Snapshot,
        evaluation: Evaluation,
        commit: Commit,
        cleanup: Cleanup,
    },
    EvaluatedFail {
        snapshot: Snapshot,
        evaluation: Evaluation,
        commit: Option<Commit>,
        cleanup: Cleanup,
    },
    Unknown {
        phase: UnknownPhase,
        reason: UnknownReason,
        observation_sha256: String,
    },
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Spend {
    Unknown,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootFinalizationRequest {
    pub schema: u32,
    pub reservation: LaunchReservation,
    pub catalog: RootLaunchCatalog,
    pub recipe: RootLaunchRecipe,
    pub binding_sha256: String,
    pub evidence: Evidence,
    pub spend: Spend,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboxEvent {
    pub version: u64,
    pub payload_sha256: String,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExportState {
    Pending,
    Current,
    Quarantined,
}
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub record: RootFinalizationRequest,
    pub event: OutboxEvent,
    pub export: ExportState,
}
#[derive(Debug, Clone)]
pub struct Validated(RootFinalizationRequest);
fn unique_files<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> std::result::Result<BTreeMap<String, String>, D::Error> {
    struct Unique;
    impl<'de> serde::de::Visitor<'de> for Unique {
        type Value = BTreeMap<String, String>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a bounded map with unique file names")
        }
        fn visit_map<M: serde::de::MapAccess<'de>>(
            self,
            mut m: M,
        ) -> std::result::Result<Self::Value, M::Error> {
            let mut out = BTreeMap::new();
            while let Some((k, v)) = m.next_entry::<String, String>()? {
                if out.len() >= 128 || out.insert(k, v).is_some() {
                    return Err(serde::de::Error::custom("duplicate or oversized file map"));
                }
            }
            Ok(out)
        }
    }
    d.deserialize_map(Unique)
}
fn hash(b: &[u8]) -> String {
    format!("{:x}", Sha256::digest(b))
}
fn hex(s: &str, n: usize) -> bool {
    s.len() == n
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn id(s: &str) -> bool {
    ulid::Ulid::from_string(s).is_ok_and(|x| x.to_string() == s)
}
fn canonical_value(v: serde_json::Value) -> serde_json::Value {
    match v {
        serde_json::Value::Object(m) => serde_json::to_value(
            m.into_iter()
                .map(|(k, v)| (k, canonical_value(v)))
                .collect::<BTreeMap<_, _>>(),
        )
        .expect("JSON"),
        serde_json::Value::Array(a) => {
            serde_json::Value::Array(a.into_iter().map(canonical_value).collect())
        }
        x => x,
    }
}
pub fn canonical_bytes<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    let b = serde_json::to_vec(&canonical_value(serde_json::to_value(v)?))?;
    ensure!(b.len() <= 65536, "record too large");
    Ok(b)
}
/// Strict bounded wire parser. Struct and nested file-map visitors reject duplicate fields.
pub fn parse_request(raw: &[u8]) -> Result<RootFinalizationRequest> {
    ensure!(
        !raw.is_empty() && raw.len() <= 65536,
        "request size invalid"
    );
    Ok(serde_json::from_slice(raw)?)
}
pub fn record_digest(v: &RootFinalizationRequest) -> Result<String> {
    Ok(hash(&canonical_bytes(v)?))
}
pub fn binding_digest(
    reservation: &LaunchReservation,
    catalog: &RootLaunchCatalog,
) -> Result<String> {
    let g = canonical_bytes(reservation)?;
    let c = canonical_bytes(catalog)?;
    let mut h = Sha256::new();
    h.update(b"sfactory-root-grant-v1\0");
    h.update((g.len() as u64).to_be_bytes());
    h.update(g);
    h.update((c.len() as u64).to_be_bytes());
    h.update(c);
    Ok(format!("{:x}", h.finalize()))
}
fn snapshot(s: &Snapshot) -> Result<()> {
    ensure!(!s.files.is_empty() && s.files.len() <= 128, "snapshot size");
    for (name, digest) in &s.files {
        ensure!(
            !name.is_empty()
                && name.len() <= 256
                && !name.starts_with('/')
                && !name
                    .split('/')
                    .any(|p| p.is_empty() || p == "." || p == "..")
                && name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_. /".contains(&b))
                && hex(digest, 64),
            "snapshot entry"
        );
    }
    Ok(())
}
fn evaluated(
    s: &Snapshot,
    e: &Evaluation,
    c: Option<&Commit>,
    clean: &Cleanup,
    cat: &RootLaunchCatalog,
) -> Result<()> {
    snapshot(s)?;
    ensure!(
        !e.evaluator_id.is_empty()
            && e.evaluator_id.len() <= 128
            && e.evaluator_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
            && hex(&e.receipt_sha256, 64)
            && e.snapshot_sha256 == hash(&canonical_bytes(s)?),
        "evaluation mismatch"
    );
    if let Some(c) = c {
        ensure!(
            (hex(&c.revision, 40) || hex(&c.revision, 64)) && c.blobs == s.files,
            "commit mismatch"
        );
    }
    ensure!(
        clean.boot_id == cat.boot_id
            && clean.cgroup_dev == cat.cgroup_dev
            && clean.cgroup_ino == cat.cgroup_ino
            && hex(&clean.writer_id, 64)
            && hex(&clean.goose_id, 64)
            && clean.writer_id != clean.goose_id
            && [
                &clean.closure_sha256,
                &clean.observation_sha256,
                &clean.reconciliation_sha256,
                &clean.terminal_receipts_sha256
            ]
            .iter()
            .all(|x| hex(x, 64)),
        "cleanup mismatch"
    );
    Ok(())
}
pub fn validate(
    req: RootFinalizationRequest,
    stored: &LaunchReservation,
    claim: &ClaimLeaseState,
    scope: &LaunchScope,
) -> Result<Validated> {
    let c = &req.catalog;
    let r = &req.recipe;
    let g = &req.reservation;
    let lease = claim
        .active
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("claim missing"))?;
    ensure!(
        req.schema == 1
            && &req.reservation == stored
            && &g.scope == scope
            && c.scope == *scope
            && g.generation == scope.generation
            && claim.work_package_id == scope.task_id
            && claim.spec == scope.spec
            && claim.stage == LeaseStage::Leased
            && claim.attempts == g.attempt
            && lease.attempt == g.attempt
            && g.attempt > 0
            && lease.worker_id == scope.worker_id
            && hash(lease.token.as_bytes()) == g.token_sha256
            && id(&lease.token)
            && lease.issued_at_ms < g.expires_at_ms
            && lease.expires_at_ms == g.expires_at_ms
            && lease.hard_deadline_ms == g.hard_deadline_ms
            && g.expires_at_ms <= g.hard_deadline_ms
            && g.hard_deadline_ms <= c.max_expiry_ms,
        "reservation mismatch"
    );
    scope.validate()?;
    ensure!(
        c.schema == 1
            && id(&scope.generation)
            && !c.boot_id.is_empty()
            && c.boot_id.len() <= 64
            && c.cgroup_dev > 0
            && c.cgroup_ino > 0
            && hex(&c.recipe_sha256, 64)
            && hex(&scope.catalog_sha256, 64),
        "catalog invalid"
    );
    ensure!(
        r.schema == 1
            && r.purpose == "nuc-goose-write-files-v1"
            && r.generation == scope.generation
            && r.task_id == scope.task_id
            && r.worker_uid == 2001
            && r.fixed_parent == format!("sfactory{}.slice", r.generation.to_lowercase())
            && r.goose_binary_sha256
                == "802d1478e6a53ef7c68a56ccfed3aec59eab0afd68aa411ec0c1b516dc5334db"
            && r.worker_image_id
                == "sha256:509d7c54cfdbf6afd9e1c80ff924d367bdaf0979e6ef63b1f7d1134ce3a9710a"
            && r.worker_program_sha256
                == "c0f51ee7767c6448c1fa3908e137c280753de302af9e7196751bb67fbc601df1"
            && r.writer_image_id
                == "sha256:2efe778192492f6934540be9771bc1057b4724fe20bed6f71a362a4b91636b48"
            && r.writer_program_sha256
                == "4ade60e556a391795b8f2b13a5e6d52efb68a04d6d806f5e0bf76e3cdc0d3d8c"
            && [
                &r.profile_sha256,
                &r.prompt_sha256,
                &r.relay_scope_template_sha256,
                &r.provider_binding_sha256
            ]
            .iter()
            .all(|x| hex(x, 64))
            && hash(&canonical_bytes(r)?) == c.recipe_sha256,
        "recipe mismatch"
    );
    ensure!(
        binding_digest(g, c)? == req.binding_sha256,
        "binding mismatch"
    );
    match &req.evidence {
        Evidence::EvaluatedPass {
            snapshot: s,
            evaluation: e,
            commit,
            cleanup,
        } => evaluated(s, e, Some(commit), cleanup, c)?,
        Evidence::EvaluatedFail {
            snapshot: s,
            evaluation: e,
            commit,
            cleanup,
        } => evaluated(s, e, commit.as_ref(), cleanup, c)?,
        Evidence::Unknown {
            observation_sha256, ..
        } => ensure!(hex(observation_sha256, 64), "observation invalid"),
    };
    canonical_bytes(&req)?;
    Ok(Validated(req))
}
pub fn decide(existing: Option<&Envelope>, validated: Validated) -> Result<Envelope> {
    let record = validated.0;
    let digest = record_digest(&record)?;
    if let Some(old) = existing {
        ensure!(
            old.record == record && old.event.version == 1 && old.event.payload_sha256 == digest,
            "finalization conflict"
        );
        return Ok(old.clone());
    }
    Ok(Envelope {
        record,
        event: OutboxEvent {
            version: 1,
            payload_sha256: digest,
        },
        export: ExportState::Pending,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::workflow::{ActiveLease, LeaseSpec};
    fn fixture() -> (
        RootFinalizationRequest,
        LaunchReservation,
        ClaimLeaseState,
        LaunchScope,
    ) {
        let g = "01M65RMR3F04YB1B016EBBSXGG".to_string();
        let token = "01ARZ3NDEKTSV4RRFFQ69G5FAX".to_string();
        let spec = LeaseSpec {
            repository: "repo".into(),
            base_revision: "a".repeat(40),
        };
        let scope = LaunchScope {
            task_id: "task".into(),
            intent_id: "intent".into(),
            queue_id: "queue".into(),
            generation: g.clone(),
            spec: spec.clone(),
            worker_id: "worker".into(),
            catalog_sha256: "a".repeat(64),
        };
        let lease = ActiveLease {
            worker_id: "worker".into(),
            attempt: 1,
            token: token.clone(),
            issued_at_ms: 1,
            expires_at_ms: 10,
            hard_deadline_ms: 20,
        };
        let claim = ClaimLeaseState {
            version: 1,
            work_package_id: "task".into(),
            spec,
            stage: LeaseStage::Leased,
            attempts: 1,
            cooldown_until_ms: 0,
            active: Some(lease),
            last_completion: None,
        };
        let grant = LaunchReservation {
            scope: scope.clone(),
            generation: g.clone(),
            attempt: 1,
            token_sha256: hash(token.as_bytes()),
            expires_at_ms: 10,
            hard_deadline_ms: 20,
        };
        let recipe = RootLaunchRecipe {
            schema: 1,
            purpose: "nuc-goose-write-files-v1".into(),
            generation: g.clone(),
            task_id: "task".into(),
            worker_uid: 2001,
            goose_binary_sha256: "802d1478e6a53ef7c68a56ccfed3aec59eab0afd68aa411ec0c1b516dc5334db"
                .into(),
            worker_image_id:
                "sha256:509d7c54cfdbf6afd9e1c80ff924d367bdaf0979e6ef63b1f7d1134ce3a9710a".into(),
            worker_program_sha256:
                "c0f51ee7767c6448c1fa3908e137c280753de302af9e7196751bb67fbc601df1".into(),
            writer_image_id:
                "sha256:2efe778192492f6934540be9771bc1057b4724fe20bed6f71a362a4b91636b48".into(),
            writer_program_sha256:
                "4ade60e556a391795b8f2b13a5e6d52efb68a04d6d806f5e0bf76e3cdc0d3d8c".into(),
            profile_sha256: "a".repeat(64),
            prompt_sha256: "b".repeat(64),
            relay_scope_template_sha256: "c".repeat(64),
            provider_binding_sha256: "d".repeat(64),
            fixed_parent: format!("sfactory{}.slice", g.to_lowercase()),
        };
        let catalog = RootLaunchCatalog {
            schema: 1,
            scope: scope.clone(),
            boot_id: "boot".into(),
            cgroup_dev: 1,
            cgroup_ino: 2,
            recipe_sha256: hash(&canonical_bytes(&recipe).unwrap()),
            max_expiry_ms: 30,
        };
        let req = RootFinalizationRequest {
            schema: 1,
            reservation: grant.clone(),
            binding_sha256: binding_digest(&grant, &catalog).unwrap(),
            catalog,
            recipe,
            evidence: Evidence::Unknown {
                phase: UnknownPhase::Launch,
                reason: UnknownReason::OutcomeUnknown,
                observation_sha256: "e".repeat(64),
            },
            spend: Spend::Unknown,
        };
        (req, grant, claim, scope)
    }
    #[test]
    fn root_binding_matches_watchdog_pinned_vector() {
        let (mut r, _, _, _) = fixture();
        let g = "01M65N5TM28WPH7BKQ153SPNJR".to_string();
        r.reservation.scope.generation = g.clone();
        r.reservation.generation = g;
        r.reservation.scope.spec.base_revision = "b".repeat(40);
        r.reservation.token_sha256 = "c".repeat(64);
        r.reservation.expires_at_ms = 200;
        r.reservation.hard_deadline_ms = 300;
        r.catalog.scope = r.reservation.scope.clone();
        r.catalog.cgroup_dev = 29;
        r.catalog.cgroup_ino = 42;
        r.catalog.recipe_sha256 = "d".repeat(64);
        r.catalog.max_expiry_ms = 300;
        assert_eq!(
            binding_digest(&r.reservation, &r.catalog).unwrap(),
            "c414f3b8434a6a95ab5aaed7ce414acfbde118400bebb5e4f0f933f01abe3d43"
        );
    }
    #[test]
    fn expired_reservation_replays_without_reopening_claim() {
        let (req, grant, claim, scope) = fixture();
        let first = decide(None, validate(req.clone(), &grant, &claim, &scope).unwrap()).unwrap();
        let mut old = first.clone();
        old.export = ExportState::Current;
        assert_eq!(
            decide(Some(&old), validate(req, &grant, &claim, &scope).unwrap()).unwrap(),
            old
        );
        assert_eq!(first.export, ExportState::Pending);
    }
    #[test]
    fn changed_binding_claim_recipe_or_replay_denied() {
        let (req, grant, claim, scope) = fixture();
        let first = decide(None, validate(req.clone(), &grant, &claim, &scope).unwrap()).unwrap();
        let mut bad = req.clone();
        bad.binding_sha256 = "0".repeat(64);
        assert!(validate(bad, &grant, &claim, &scope).is_err());
        let mut bad = req.clone();
        bad.recipe.prompt_sha256 = "0".repeat(64);
        assert!(validate(bad, &grant, &claim, &scope).is_err());
        let mut bad_claim = claim.clone();
        bad_claim.attempts = 2;
        assert!(validate(req.clone(), &grant, &bad_claim, &scope).is_err());
        let mut changed = req;
        changed.evidence = Evidence::Unknown {
            phase: UnknownPhase::Cleanup,
            reason: UnknownReason::Deadline,
            observation_sha256: "e".repeat(64),
        };
        assert!(
            decide(
                Some(&first),
                validate(changed, &grant, &claim, &scope).unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn strict_json_rejects_unknown_duplicate_and_numeric_spend() {
        let (req, _, _, _) = fixture();
        let raw = String::from_utf8(canonical_bytes(&req).unwrap()).unwrap();
        let extra = raw.replacen('{', "{\"unexpected\":true,", 1);
        assert!(serde_json::from_str::<RootFinalizationRequest>(&extra).is_err());
        let duplicate = raw.replacen('{', "{\"schema\":1,", 1);
        assert!(serde_json::from_str::<RootFinalizationRequest>(&duplicate).is_err());
        let numeric = raw.replace("\"spend\":\"unknown\"", "\"spend\":0.0");
        assert!(serde_json::from_str::<RootFinalizationRequest>(&numeric).is_err());
    }
    #[test]
    fn duplicate_nested_files_and_nonfinite_json_are_denied() {
        let digest = "a".repeat(64);
        let duplicate = format!("{{\"files\":{{\"x\":\"{digest}\",\"x\":\"{digest}\"}}}}");
        assert!(serde_json::from_str::<Snapshot>(&duplicate).is_err());
        let duplicate = format!(
            "{{\"revision\":\"{}\",\"blobs\":{{\"x\":\"{digest}\",\"x\":\"{digest}\"}}}}",
            "b".repeat(40)
        );
        assert!(serde_json::from_str::<Commit>(&duplicate).is_err());
        let (req, _, _, _) = fixture();
        let raw = String::from_utf8(canonical_bytes(&req).unwrap()).unwrap();
        assert!(
            parse_request(
                raw.replace("\"spend\":\"unknown\"", "\"spend\":NaN")
                    .as_bytes()
            )
            .is_err()
        );
        assert!(parse_request(&vec![b' '; 65537]).is_err());
    }
    #[test]
    fn evaluated_commit_must_match_snapshot_and_fail_can_omit_it() {
        let (mut req, grant, claim, scope) = fixture();
        let mut files = BTreeMap::new();
        files.insert("hello.py".into(), "a".repeat(64));
        let snapshot = Snapshot {
            files: files.clone(),
        };
        let evaluation = Evaluation {
            evaluator_id: "independent".into(),
            receipt_sha256: "b".repeat(64),
            snapshot_sha256: hash(&canonical_bytes(&snapshot).unwrap()),
        };
        let cleanup = Cleanup {
            boot_id: "boot".into(),
            cgroup_dev: 1,
            cgroup_ino: 2,
            writer_id: "c".repeat(64),
            goose_id: "d".repeat(64),
            closure_sha256: "e".repeat(64),
            observation_sha256: "f".repeat(64),
            reconciliation_sha256: "1".repeat(64),
            terminal_receipts_sha256: "2".repeat(64),
        };
        req.evidence = Evidence::EvaluatedFail {
            snapshot: snapshot.clone(),
            evaluation: evaluation.clone(),
            commit: None,
            cleanup: cleanup.clone(),
        };
        assert!(validate(req.clone(), &grant, &claim, &scope).is_ok());
        let mut bad = files;
        bad.insert("hello.py".into(), "3".repeat(64));
        req.evidence = Evidence::EvaluatedPass {
            snapshot,
            evaluation,
            commit: Commit {
                revision: "4".repeat(40),
                blobs: bad,
            },
            cleanup,
        };
        assert!(validate(req, &grant, &claim, &scope).is_err());
    }
}
