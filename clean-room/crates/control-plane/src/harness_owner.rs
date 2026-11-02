//! Opt-in production SDK owner binding. Registration creates no spending authority;
//! all eight mutations retain registry admission and explicit root bootstrap.
use crate::{harness_spending::HarnessSpending, private_runtime::PrivateRuntimeConfig};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::PathBuf};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HarnessOwnerBinding {
    pub schema: u32,
    pub owner: String,
    pub policy_sha256: String,
    pub suite_sha256: String,
    pub route_sha256: String,
    pub tariff_sha256: String,
    pub broker_uid: u32,
    pub collector_uid: u32,
    pub socket_gid: u32,
}
fn hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
impl HarnessOwnerBinding {
    fn syntax(&self) -> anyhow::Result<()> {
        anyhow::ensure!(
            self.schema == 1
                && !self.owner.is_empty()
                && self.owner.len() <= 128
                && self
                    .owner
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b)),
            "invalid harness owner"
        );
        anyhow::ensure!(
            [
                &self.policy_sha256,
                &self.suite_sha256,
                &self.route_sha256,
                &self.tariff_sha256
            ]
            .iter()
            .all(|s| hex(s)),
            "missing harness review binding"
        );
        anyhow::ensure!(
            self.broker_uid > 0 && self.collector_uid > 0 && self.broker_uid != self.collector_uid,
            "distinct harness identities required"
        );
        anyhow::ensure!(self.socket_gid > 0, "harness socket group required");
        Ok(())
    }
    pub fn validate(&self, c: &PrivateRuntimeConfig) -> anyhow::Result<()> {
        self.syntax()?;
        anyhow::ensure!(
            self.socket_gid != c.operator_socket_gid && self.socket_gid != c.worker_socket_gid,
            "dedicated harness socket group required"
        );
        anyhow::ensure!(c.service_uid == 2000, "registry journal identity required");
        let ids = [
            0,
            c.service_uid,
            c.operator_uid,
            c.evaluator_uid,
            c.worker_uid,
            c.brake_uid,
            c.journal_uid,
            self.broker_uid,
            self.collector_uid,
        ];
        anyhow::ensure!(
            ids.into_iter().collect::<BTreeSet<_>>().len() == ids.len(),
            "harness roles overlap protected identities"
        );
        Ok(())
    }
    pub fn ingress_path(&self) -> PathBuf {
        PathBuf::from(format!(
            "/var/lib/sfactory-harness/spending/{}/spending.sock",
            self.owner
        ))
    }
    pub fn policy(
        &self,
        c: &PrivateRuntimeConfig,
    ) -> anyhow::Result<crate::harness_spending_ingress::Policy> {
        self.validate(c)?;
        crate::harness_spending_ingress::Policy::new(
            c.journal_uid,
            self.broker_uid,
            self.collector_uid,
            c.worker_uid,
            self.owner.clone(),
        )
    }
    fn check_scope(&self, scope: &crate::harness_spending::AttemptScope) -> anyhow::Result<()> {
        anyhow::ensure!(
            scope.route.route_sha256 == self.route_sha256
                && scope.route.usage_tariff_sha256.as_deref() == Some(self.tariff_sha256.as_str()),
            "harness route or tariff mismatch"
        );
        Ok(())
    }
    pub fn check_mutation(&self, method: &str, body: &serde_json::Value) -> anyhow::Result<()> {
        self.syntax()?;
        match method {
            "initialize" => {
                let b: crate::harness_spending::Bootstrap = serde_json::from_value(body.clone())?;
                anyhow::ensure!(
                    b.owner == self.owner && b.policy_sha256 == self.policy_sha256,
                    "harness bootstrap binding changed"
                );
                for scope in &b.scopes {
                    self.check_scope(scope)?;
                }
            }
            "admit_attempt" => self.check_scope(&serde_json::from_value(body.clone())?)?,
            "complete" => {
                let receipt: crate::harness_spending::CollectorReceipt =
                    serde_json::from_value(body.clone())?;
                anyhow::ensure!(
                    receipt.route_sha256 == self.route_sha256
                        && receipt.billed_microusd.is_none()
                        && receipt
                            .usage_rating
                            .as_ref()
                            .is_some_and(|r| r.tariff_sha256 == self.tariff_sha256),
                    "harness receipt basis changed"
                );
            }
            "reserve" | "begin" | "verify_inflight" | "claim_receipts" | "admit_day" | "revoke" => {}
            _ => anyhow::bail!("harness method denied"),
        }
        Ok(())
    }
}
/// Only root-authored optional catalog configuration can add the service. All
/// mutations retain their registry gate; discovery may run before admission so
/// prospective registration does not deadlock the existing transition protocol.
pub fn bind_owner(
    builder: restate_sdk::endpoint::Builder,
    binding: Option<&HarnessOwnerBinding>,
) -> anyhow::Result<restate_sdk::endpoint::Builder> {
    if let Some(binding) = binding {
        binding.syntax()?;
        anyhow::ensure!(
            cfg!(feature = "registry-sidecar"),
            "harness owner requires production registry build"
        );
        Ok(builder.bind(HarnessSpending))
    } else {
        Ok(builder)
    }
}

/// Select the registry's unique active scope, preserving historical catalog bytes.
/// The caller loads the fixed Root-owned registry; this does not authenticate input.
pub fn active_owner_catalog<'a>(
    active_intent: &str,
    catalogs: &'a [(PrivateRuntimeConfig, String)],
) -> anyhow::Result<(&'a PrivateRuntimeConfig, &'a str)> {
    let mut matching = catalogs
        .iter()
        .filter(|(c, _)| c.intent_id == active_intent);
    let (config, evidence) = matching
        .next()
        .ok_or_else(|| anyhow::anyhow!("active owner catalog unavailable"))?;
    anyhow::ensure!(matching.next().is_none(), "active owner catalog ambiguous");
    anyhow::ensure!(
        config.harness_owner.is_some(),
        "active harness owner not configured"
    );
    anyhow::ensure!(
        catalogs
            .iter()
            .all(|(prior, _)| config.registry_compatible(prior)),
        "inconsistent owner catalogs"
    );
    Ok((config, evidence))
}

/// Namespace-local durable backend, fixed to the root catalog's sole owner.
/// No request supplies a URL, object key, service, credentials or alternate ledger.
pub struct HarnessJournalBackend {
    binding: HarnessOwnerBinding,
    client: reqwest::Client,
    port: u16,
}
impl HarnessJournalBackend {
    pub fn new(port: u16, binding: HarnessOwnerBinding) -> anyhow::Result<Self> {
        binding.syntax()?;
        anyhow::ensure!(port >= 1024, "invalid journal port");
        Ok(Self {
            binding,
            port,
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .pool_max_idle_per_host(0)
                .timeout(std::time::Duration::from_secs(10))
                .build()?,
        })
    }
}
impl crate::harness_spending_ingress::Journal for HarnessJournalBackend {
    fn owner(&self) -> &str {
        &self.binding.owner
    }
    async fn call(
        &self,
        method: &'static str,
        body: serde_json::Value,
    ) -> Result<serde_json::Value, crate::harness_spending_ingress::Refused> {
        use crate::harness_spending_ingress::Refused;
        self.binding
            .check_mutation(method, &body)
            .map_err(|_| Refused::new(403, "harness binding rejected"))?;
        let mut response = self
            .client
            .post(format!(
                "http://127.0.0.1:{}/restate/call/HarnessSpending/{}/{}",
                self.port, self.binding.owner, method
            ))
            .json(&body)
            .send()
            .await
            .map_err(|_| Refused::new(503, "spending outcome unknown"))?;
        let status = response.status().as_u16();
        let mut bytes = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|_| Refused::new(503, "spending reply incomplete"))?
        {
            if bytes.len().saturating_add(chunk.len()) > 65536 {
                return Err(Refused::new(502, "spending reply exceeds limit"));
            }
            bytes.extend_from_slice(&chunk);
        }
        if !(200..300).contains(&status) {
            return Err(Refused::new(
                if matches!(status, 400 | 403 | 404 | 409 | 410 | 429) {
                    status
                } else {
                    502
                },
                "spending mutation rejected; outcome retained",
            ));
        }
        let value = if bytes.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_slice(&bytes)
                .map_err(|_| Refused::new(502, "invalid spending reply"))?
        };
        let valid = match method {
            "reserve" => matches!(
                value.as_str(),
                Some("Denied" | "Reserved" | "Unknown" | "Complete")
            ),
            "begin" | "verify_inflight" => value == serde_json::Value::Bool(true),
            "admit_attempt" => {
                serde_json::from_value::<crate::harness_spending::AttemptScope>(body)
                    .ok()
                    .and_then(|s| s.digest().ok())
                    .as_deref()
                    == value.as_str()
            }
            _ => value.is_null(),
        };
        if !valid {
            return Err(Refused::new(502, "spending reply binding invalid"));
        }
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::private_runtime::PrivateRuntimeConfig;
    fn catalog() -> PrivateRuntimeConfig {
        serde_json::from_value(serde_json::json!({"service_uid":2000,"operator_uid":1000,"evaluator_uid":2002,"worker_uid":2001,"brake_uid":2003,"journal_uid":2004,"operator_socket_gid":3000,"worker_socket_gid":3001,"boot_id":"12345678-1234-1234-1234-123456789abc","namespace_dev":4,"namespace_ino":5,"host_namespace_dev":4,"host_namespace_ino":7,"sdk_port":9085,"restate_ingress_port":8080,"postgres_port":5432,"principal":"operator","worker_id":"worker","queue_id":"queue","intent_id":"01J00000000000000000000000","task_id":"01J00000000000000000000001","request":{"schema_version":1,"repository":"r","target_ref":"refs/heads/main","base_revision":"a".repeat(40),"intent":"build","acceptance_criteria":["test"]},"facts":{"spec_clarity":1.0,"blast_radius":0.0,"novelty":0.0,"reversibility":0.0,"has_codified_knowledge":true,"fatal":false},"evidence_sha256":"a".repeat(64)})).unwrap()
    }
    fn binding() -> HarnessOwnerBinding {
        serde_json::from_value(serde_json::json!({"schema":1,"owner":"phase11a-paired-20261030","policy_sha256":"a".repeat(64),"suite_sha256":"b".repeat(64),"route_sha256":"c".repeat(64),"tariff_sha256":"d".repeat(64),"broker_uid":2005,"collector_uid":2006,"socket_gid":3002})).unwrap()
    }
    #[test]
    fn absent_binding_keeps_existing_catalogs_and_endpoint_unmodified() {
        let c = catalog();
        assert!(c.harness_owner.is_none());
        assert!(bind_owner(restate_sdk::endpoint::Endpoint::builder(), None).is_ok());
    }
    #[test]
    fn owner_binding_cannot_share_privileged_or_worker_identities() {
        for uid in [0, 1000, 2000, 2001, 2002, 2003, 2004, 2006] {
            let mut b = binding();
            b.broker_uid = uid;
            assert!(b.validate(&catalog()).is_err());
        }
        assert!(binding().validate(&catalog()).is_ok());
    }
    #[test]
    fn active_owner_can_preserve_unbound_history_but_cannot_remove_or_change_owner() {
        let mut a = catalog();
        let mut b = catalog();
        a.harness_owner = Some(binding());
        assert!(a.registry_compatible(&b));
        assert!(!b.registry_compatible(&a));
        b.harness_owner = Some(binding());
        assert!(a.registry_compatible(&b));
        b.harness_owner.as_mut().unwrap().tariff_sha256 = "e".repeat(64);
        assert!(!a.registry_compatible(&b));
    }
    #[test]
    fn frontend_selects_unique_active_owner_instead_of_historical_first() {
        let active_id = "01J00000000000000000000009";
        let make_active = || {
            let mut active = catalog();
            active.intent_id = active_id.into();
            active.harness_owner = Some(binding());
            active
        };
        let mut entries = vec![(catalog(), "old".into()), (make_active(), "current".into())];
        let (selected, evidence) = active_owner_catalog(active_id, &entries).unwrap();
        assert_eq!(selected.harness_owner, Some(binding()));
        assert_eq!(evidence, "current");
        assert!(active_owner_catalog("01J00000000000000000000008", &entries).is_err());
        assert!(active_owner_catalog(&entries[0].0.intent_id, &entries).is_err());
        entries.push((make_active(), "duplicate".into()));
        assert!(active_owner_catalog(active_id, &entries).is_err());
        entries.pop();
        entries[0].0.harness_owner = Some(binding());
        entries[0].0.harness_owner.as_mut().unwrap().tariff_sha256 = "e".repeat(64);
        assert!(active_owner_catalog(active_id, &entries).is_err());
    }
    #[test]
    fn owner_names_and_reviews_are_not_worker_selected_paths_or_zero_defaults() {
        let mut b = binding();
        b.owner = "../another".into();
        assert!(b.validate(&catalog()).is_err());
        b = binding();
        b.policy_sha256 = "".into();
        assert!(b.validate(&catalog()).is_err());
        assert_eq!(
            binding().ingress_path(),
            std::path::PathBuf::from(
                "/var/lib/sfactory-harness/spending/phase11a-paired-20261030/spending.sock"
            )
        );
    }
    #[tokio::test]
    async fn sdk_discovery_binds_only_the_nine_guarded_owner_handlers() {
        use http_body_util::BodyExt;
        let configured = if cfg!(feature = "registry-sidecar") {
            Some(binding())
        } else {
            None
        };
        let endpoint = bind_owner(
            restate_sdk::endpoint::Endpoint::builder().bind(
                crate::intake_workflow::IntakeJournal::new_for_private_ingress("operator".into())
                    .unwrap(),
            ),
            configured.as_ref(),
        )
        .unwrap()
        .build();
        let request = axum::http::Request::builder()
            .uri("/discover")
            .header("accept", "application/vnd.restate.endpointmanifest.v4+json")
            .body(axum::body::Body::empty())
            .unwrap();
        let response = endpoint.handle(request);
        assert_eq!(response.status(), 200);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let services = value["services"].as_array().unwrap();
        if configured.is_none() {
            assert_eq!(services.len(), 1);
            assert_eq!(services[0]["name"], "IntakeJournal");
            assert!(
                bind_owner(restate_sdk::endpoint::Endpoint::builder(), Some(&binding())).is_err()
            );
            return;
        }
        assert_eq!(services.len(), 2);
        assert!(
            services
                .iter()
                .any(|service| service["name"] == "IntakeJournal")
        );
        let owner = services
            .iter()
            .find(|service| service["name"] == "HarnessSpending")
            .unwrap();
        let found: BTreeSet<_> = owner["handlers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["name"].as_str().unwrap())
            .collect();
        assert_eq!(
            found,
            [
                "initialize",
                "admit_attempt",
                "admit_day",
                "reserve",
                "begin",
                "verify_inflight",
                "claim_receipts",
                "complete",
                "revoke"
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            bind_owner(restate_sdk::endpoint::Endpoint::builder(), Some(&binding())).is_ok(),
            cfg!(feature = "registry-sidecar")
        );
    }
    #[tokio::test]
    async fn namespace_backend_uses_only_fixed_owner_and_masks_unknown_replies() {
        use crate::harness_spending_ingress::Journal;
        use axum::{Json, Router, routing::post};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let app = Router::new().route(
            "/restate/call/HarnessSpending/phase11a-paired-20261030/reserve",
            post(|| async { Json("Reserved") }),
        );
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        let backend = HarnessJournalBackend::new(port, binding()).unwrap();
        assert_eq!(
            backend
                .call("reserve", serde_json::json!({}))
                .await
                .unwrap(),
            serde_json::json!("Reserved")
        );
        assert!(
            backend
                .call("initialize", serde_json::json!({"owner":"other"}))
                .await
                .is_err()
        );
        assert!(
            backend
                .call("arbitrary", serde_json::json!({}))
                .await
                .is_err()
        );
        assert!(backend.call("begin", serde_json::json!({})).await.is_err());
        server.abort();
    }
    #[test]
    fn root_mutations_cannot_change_policy_route_tariff_or_receipt_basis() {
        let b = binding();
        let scope = serde_json::json!({"task":"task","attempt":1,"generation":"gen","worker":"worker","lease_sha256":"a".repeat(64),"issued_at_ms":100,"expires_at_ms":1000,"route":{"route_sha256":b.route_sha256,"review_sha256":"a".repeat(64),"usage_tariff_sha256":b.tariff_sha256,"valid_from_ms":100,"valid_until_ms":1000,"max_request_bytes":65536,"max_output_tokens":16384,"components":[{"id":"answer","max_charge_microusd":1000}]}});
        assert!(b.check_mutation("admit_attempt", &scope).is_ok());
        let mut changed = scope.clone();
        changed["route"]["route_sha256"] = serde_json::json!("e".repeat(64));
        assert!(b.check_mutation("admit_attempt", &changed).is_err());
        changed = scope.clone();
        changed["route"]["usage_tariff_sha256"] = serde_json::Value::Null;
        assert!(b.check_mutation("admit_attempt", &changed).is_err());
        let bootstrap = serde_json::json!({"owner":b.owner,"policy_sha256":b.policy_sha256,"predecessor_fence_sha256":"a".repeat(64),"inventory_sha256":"a".repeat(64),"observed_at_ms":100,"approved_daily_cap_microusd":5000000,"daily_cap_microusd":5000000,"opening_tasks":{"task":0},"opening_days":{"0":0},"scopes":[scope]});
        assert!(b.check_mutation("initialize", &bootstrap).is_ok());
        changed = bootstrap.clone();
        changed["policy_sha256"] = serde_json::json!("e".repeat(64));
        assert!(b.check_mutation("initialize", &changed).is_err());
        let receipt = serde_json::json!({"call_id":"logical","request_sha256":"a".repeat(64),"scope_sha256":"a".repeat(64),"route_sha256":b.route_sha256,"manifest_sha256":"a".repeat(64),"components":{"answer":"a".repeat(64)},"generation_ids":[format!("usage_{}","a".repeat(64))],"usage_rating":{"tariff_sha256":b.tariff_sha256,"audit_sha256":"a".repeat(64),"usage_rated_microusd":10}});
        assert!(b.check_mutation("complete", &receipt).is_ok());
        changed = receipt.clone();
        changed["billed_microusd"] = serde_json::json!(10);
        assert!(b.check_mutation("complete", &changed).is_err());
        changed = receipt.clone();
        changed["usage_rating"]["tariff_sha256"] = serde_json::json!("e".repeat(64));
        assert!(b.check_mutation("complete", &changed).is_err());
    }
}
