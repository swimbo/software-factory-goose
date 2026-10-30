//! Catalog-bound private intake to qualification and durable queue handoff.
//! Registration requires protected bootstrap and private Restate ingress; configuration alone
//! does not authenticate callers or prevent direct queue scheduling.
use crate::{
    intake::{IntakeRequest, StoredIntake, submit_once, valid_principal},
    intake_workflow::IntakeJournalClient,
    qualifier::{self, IntentFeatures},
    worker_queue::{ScheduleRequest, WorkerQueueJournalClient},
    workflow::LeaseSpec,
};
use restate_sdk::{prelude::*, serde::Json};
use sha2::{Digest, Sha256};

#[derive(Clone)]
pub struct Catalog {
    principal: String,
    queue: String,
    intent_id: String,
    task_id: String,
    request: IntakeRequest,
    features: IntentFeatures,
    evidence_digest: String,
}
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QualifiedHandoff {
    pub intake: StoredIntake,
    pub catalog_digest: String,
    pub score: f64,
    pub reason: String,
    pub schedule: ScheduleRequest,
}
impl Catalog {
    /// Trusted bootstrap configuration; never deserialize it from an intake request.
    pub fn new(
        principal: String,
        queue: String,
        intent_id: String,
        task_id: String,
        request: IntakeRequest,
        features: IntentFeatures,
        evidence_digest: String,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(valid_principal(&principal), "invalid catalog principal");
        anyhow::ensure!(
            !queue.is_empty()
                && queue.len() <= 256
                && queue
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "invalid queue scope"
        );
        for id in [&intent_id, &task_id] {
            anyhow::ensure!(
                ulid::Ulid::from_string(id).is_ok_and(|v| v.to_string() == *id),
                "invalid catalog identity"
            );
        }
        anyhow::ensure!(
            intent_id != task_id
                && evidence_digest.len() == 64
                && evidence_digest
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
            "invalid catalog binding"
        );
        submit_once(None, &intent_id, &principal, request.clone(), 0)?;
        Ok(Self {
            principal,
            queue,
            intent_id,
            task_id,
            request,
            features,
            evidence_digest,
        })
    }
    pub fn fingerprint(&self) -> anyhow::Result<String> {
        let bytes = serde_json::to_vec(&(
            &self.principal,
            &self.queue,
            &self.intent_id,
            &self.task_id,
            &self.request,
            &self.features,
            &self.evidence_digest,
        ))?;
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }
    fn qualify(&self, intake: &StoredIntake) -> anyhow::Result<QualifiedHandoff> {
        anyhow::ensure!(
            intake.idempotency_key == self.intent_id
                && intake.intent_id == self.intent_id
                && intake.submitted_by == self.principal
                && intake.request == self.request,
            "intake does not match catalog"
        );
        submit_once(
            Some(intake),
            &self.intent_id,
            &self.principal,
            self.request.clone(),
            0,
        )?;
        let decision = qualifier::decide(&self.intent_id, &self.features);
        anyhow::ensure!(
            decision.lane == shared::Lane::Dark,
            "qualification requires human review"
        );
        Ok(QualifiedHandoff {
            intake: intake.clone(),
            catalog_digest: self.fingerprint()?,
            score: decision.score,
            reason: decision.reason,
            schedule: ScheduleRequest {
                work_package_id: self.task_id.clone(),
                spec: LeaseSpec {
                    repository: self.request.repository.clone(),
                    base_revision: self.request.base_revision.clone(),
                },
            },
        })
    }
}

pub struct RuntimeIntakeJournal {
    catalogs: Vec<Catalog>,
}
impl RuntimeIntakeJournal {
    pub fn new_for_protected_bootstrap(catalog: Catalog) -> Self {
        Self {
            catalogs: vec![catalog],
        }
    }
    pub fn new_with_preserved_catalog(
        preserved: Catalog,
        catalog: Catalog,
    ) -> anyhow::Result<Self> {
        Self::new_with_catalogs(vec![preserved, catalog])
    }
    /// Root-owned immutable scopes only; all object identities remain unique across history.
    pub fn new_with_catalogs(catalogs: Vec<Catalog>) -> anyhow::Result<Self> {
        anyhow::ensure!(
            !catalogs.is_empty() && catalogs.len() <= 16,
            "catalog count invalid"
        );
        let mut ids = std::collections::BTreeSet::new();
        let mut queues = std::collections::BTreeSet::new();
        let principal = &catalogs[0].principal;
        for c in &catalogs {
            anyhow::ensure!(
                c.principal == *principal
                    && ids.insert(&c.intent_id)
                    && ids.insert(&c.task_id)
                    && queues.insert(&c.queue),
                "catalog scopes collide or principal differs"
            );
        }
        Ok(Self { catalogs })
    }
    fn catalog_for(&self, key: &str) -> Option<&Catalog> {
        self.catalogs.iter().find(|c| c.intent_id == key)
    }
}
#[restate_sdk::object]
impl RuntimeIntakeJournal {
    #[handler]
    async fn submit_and_schedule(
        &self,
        ctx: ObjectContext<'_>,
        request: Json<IntakeRequest>,
    ) -> HandlerResult<Json<QualifiedHandoff>> {
        let _admission = crate::registry_journal_gate::enter_production().map_err(|_| {
            TerminalError::new_with_code(503, "registry transition blocks mutations")
        })?;
        let catalog = self
            .catalog_for(ctx.key())
            .ok_or_else(|| TerminalError::new_with_code(403, "intake outside catalog"))?;
        if request.0 != catalog.request {
            return Err(TerminalError::new_with_code(403, "intake outside catalog").into());
        }
        let stored = ctx
            .object_client::<IntakeJournalClient>(ctx.key())
            .submit(request)
            .call()
            .await?;
        let plan = catalog
            .qualify(&stored.0)
            .map_err(|_| TerminalError::new_with_code(403, "qualification unavailable"))?;
        if let Some(previous) = ctx.get::<Json<QualifiedHandoff>>("handoff").await? {
            if previous.0 != plan {
                return Err(TerminalError::new_with_code(409, "immutable handoff conflict").into());
            }
        } else {
            ctx.set("handoff", Json(plan.clone()));
        }
        // Restate journals this RPC; queue scheduling and claim initialization are immutable.
        ctx.object_client::<WorkerQueueJournalClient>(&catalog.queue)
            .schedule(Json(plan.schedule.clone()))
            .call()
            .await?;
        ctx.set("published", Json(true));
        Ok(Json(plan))
    }

    /// No usable task lookup is released until queue publication was acknowledged.
    #[handler]
    async fn inspect(
        &self,
        ctx: SharedObjectContext<'_>,
    ) -> HandlerResult<Json<Option<QualifiedHandoff>>> {
        let catalog = self
            .catalog_for(ctx.key())
            .ok_or_else(|| TerminalError::new_with_code(403, "intake outside catalog"))?;
        let published = ctx
            .get::<Json<bool>>("published")
            .await?
            .map(|v| v.0)
            .unwrap_or(false);
        if !published {
            return Ok(Json(None));
        }
        let prior = ctx
            .get::<Json<QualifiedHandoff>>("handoff")
            .await?
            .ok_or_else(|| TerminalError::new_with_code(500, "handoff state unavailable"))?
            .0;
        let checked = catalog
            .qualify(&prior.intake)
            .map_err(|_| TerminalError::new_with_code(500, "handoff catalog mismatch"))?;
        if prior != checked {
            return Err(TerminalError::new_with_code(500, "handoff state mismatch").into());
        }
        Ok(Json(Some(prior)))
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::intake::{INTAKE_SCHEMA_VERSION, IntakeRequest};
    use crate::qualifier::IntentFeatures;
    fn request() -> IntakeRequest {
        IntakeRequest {
            schema_version: INTAKE_SCHEMA_VERSION,
            repository: "org/repo".into(),
            target_ref: "refs/heads/main".into(),
            base_revision: "a".repeat(40),
            intent: "Build reviewed unit".into(),
            acceptance_criteria: vec!["Verify expected behavior".into()],
        }
    }
    fn catalog() -> Catalog {
        Catalog::new(
            "operator".into(),
            "queue".into(),
            "01J00000000000000000000000".into(),
            "01J00000000000000000000001".into(),
            request(),
            IntentFeatures {
                spec_clarity: 1.0,
                blast_radius: 0.0,
                novelty: 0.0,
                reversibility: 0.0,
                has_codified_knowledge: true,
                fatal: false,
            },
            "a".repeat(64),
        )
        .unwrap()
    }
    #[test]
    fn fixture_root_catalog_fingerprint_matches_installer() {
        let c = Catalog::new(
            "fixture-submitter".into(),
            "root-grant-canary-20261030".into(),
            "01M65GTQYKXECJWHCPKQD248SY".into(),
            "01M65GTQYKQQMN3NG1V0EFCVH5".into(),
            IntakeRequest {
                schema_version: 1,
                repository: "fixture".into(),
                target_ref: "refs/heads/main".into(),
                base_revision: "a".repeat(40),
                intent: "build fixture".into(),
                acceptance_criteria: vec!["passes fixture".into()],
            },
            IntentFeatures {
                spec_clarity: 1.0,
                blast_radius: 0.0,
                novelty: 0.0,
                reversibility: 0.0,
                has_codified_knowledge: true,
                fatal: false,
            },
            "b3b456afd136d8541a9ef66ccc49cd3fd3d76111bbb837c3f09ed881cd10c65a".into(),
        )
        .unwrap();
        assert_eq!(
            c.fingerprint().unwrap(),
            "4218228a2a9c0fcc51ec838414ebd92542b18e06ddd40d7a1a2b628d4d8caf19"
        );
    }
    #[test]
    fn bounded_catalogs_preserve_old_and_new_and_reject_collisions() {
        let old = catalog();
        let mut new = catalog();
        new.intent_id = "01J00000000000000000000002".into();
        new.task_id = "01J00000000000000000000003".into();
        new.queue = "new-queue".into();
        let journals = RuntimeIntakeJournal::new_with_preserved_catalog(old, new).unwrap();
        assert!(journals.catalog_for("01J00000000000000000000000").is_some());
        assert!(journals.catalog_for("01J00000000000000000000002").is_some());
        assert!(journals.catalog_for("01J00000000000000000000004").is_none());
        let old = catalog();
        let mut collision = catalog();
        collision.intent_id = "01J00000000000000000000002".into();
        assert!(RuntimeIntakeJournal::new_with_preserved_catalog(old, collision).is_err());
    }
    #[test]
    fn three_catalogs_keep_all_histories_and_reject_rebinding() {
        let a = catalog();
        let mut b = catalog();
        let mut c = catalog();
        b.intent_id = "01J00000000000000000000002".into();
        b.task_id = "01J00000000000000000000003".into();
        b.queue = "queue-b".into();
        c.intent_id = "01J00000000000000000000004".into();
        c.task_id = "01J00000000000000000000005".into();
        c.queue = "queue-c".into();
        let j =
            RuntimeIntakeJournal::new_with_catalogs(vec![a.clone(), b.clone(), c.clone()]).unwrap();
        for cat in [&a, &b, &c] {
            assert_eq!(j.catalog_for(&cat.intent_id).unwrap().task_id, cat.task_id);
        }
        c.task_id = b.task_id.clone();
        assert!(RuntimeIntakeJournal::new_with_catalogs(vec![a, b, c]).is_err());
    }
    #[test]
    fn registry_capacity_is_bounded_at_sixteen() {
        let mut all = Vec::new();
        for i in 0..17_u128 {
            let mut c = catalog();
            c.intent_id = ulid::Ulid::from(i * 2 + 100).to_string();
            c.task_id = ulid::Ulid::from(i * 2 + 101).to_string();
            c.queue = format!("queue-{i}");
            all.push(c);
        }
        assert!(RuntimeIntakeJournal::new_with_catalogs(all[..16].to_vec()).is_ok());
        assert!(RuntimeIntakeJournal::new_with_catalogs(all).is_err());
    }
    #[test]
    fn only_exact_catalog_intake_can_create_qualified_schedule() {
        let c = catalog();
        let original = request();
        let stored = crate::intake::submit_once(
            None,
            "01J00000000000000000000000",
            "operator",
            original.clone(),
            1,
        )
        .unwrap();
        let plan = c.qualify(&stored).unwrap();
        assert_eq!(plan.schedule.work_package_id, "01J00000000000000000000001");
        let mut changed = stored.clone();
        changed.request.intent.push('!');
        assert!(c.qualify(&changed).is_err());
        let mut changed = stored.clone();
        changed.submitted_by = "other".into();
        assert!(c.qualify(&changed).is_err());
    }
    #[test]
    fn catalog_digest_detects_changed_authority_and_known_facts() {
        let first = catalog();
        let mut changed = catalog();
        assert_eq!(first.fingerprint().unwrap(), changed.fingerprint().unwrap());
        changed.evidence_digest = "b".repeat(64);
        assert_ne!(first.fingerprint().unwrap(), changed.fingerprint().unwrap());
        changed = catalog();
        changed.features.novelty = 0.25;
        assert_ne!(first.fingerprint().unwrap(), changed.fingerprint().unwrap());
        changed = catalog();
        changed.queue = "other".into();
        assert_ne!(first.fingerprint().unwrap(), changed.fingerprint().unwrap());
    }
    #[test]
    fn fatal_and_missing_knowledge_never_schedule() {
        let mut c = catalog();
        let stored = crate::intake::submit_once(
            None,
            "01J00000000000000000000000",
            "operator",
            request(),
            1,
        )
        .unwrap();
        c.features.fatal = true;
        assert!(c.qualify(&stored).is_err());
        c.features.fatal = false;
        c.features.has_codified_knowledge = false;
        assert!(c.qualify(&stored).is_err());
    }
}
