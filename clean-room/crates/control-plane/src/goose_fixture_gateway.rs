//! Synthetic-only reservation ordering tests. No listener or production provider exists here.

use serde_json::Value;
use std::future::Future;

trait FixtureBackend {
    fn reserve(&self, amount: u64) -> impl Future<Output = Result<bool, ()>>;
    fn call_provider(&self, body: &Value) -> impl Future<Output = Result<Vec<u8>, ()>>;
}

struct SyntheticGateway {
    model: String,
    tool: Value,
    max_tokens: u64,
    max_request: usize,
    reservation: u64,
    max_response: usize,
}
impl SyntheticGateway {
    fn new(
        model: &str,
        tool: Value,
        max_tokens: u64,
        max_request: usize,
        reservation: u64,
        max_response: usize,
    ) -> Result<Self, &'static str> {
        if model.is_empty() || reservation == 0 || max_response == 0 || max_response > 1_048_576 {
            return Err("invalid synthetic configuration");
        }
        Ok(Self {
            model: model.into(),
            tool,
            max_tokens,
            max_request,
            reservation,
            max_response,
        })
    }

    /// A fixture mock, deliberately no external identity or network: only a positive reservation
    /// admits a provider call. There is no refund on later errors or ambiguous outcomes.
    async fn invoke(
        &self,
        backend: &impl FixtureBackend,
        request: &[u8],
    ) -> Result<Vec<u8>, &'static str> {
        let parsed = crate::goose_protocol::validate_goose_fixture_bytes(
            request,
            &self.model,
            &self.tool,
            self.max_tokens,
            self.max_request,
        )
        .map_err(|_| "invalid fixture request")?;
        if !backend
            .reserve(self.reservation)
            .await
            .map_err(|_| "reservation unavailable")?
        {
            return Err("reservation denied");
        }
        let response = backend
            .call_provider(&parsed)
            .await
            .map_err(|_| "provider unavailable")?;
        if response.len() > self.max_response {
            return Err("fixture response exceeds limit");
        }
        Ok(response)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{Value, json};
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fake {
        reserve_calls: AtomicUsize,
        provider_calls: AtomicUsize,
        reserve_ok: bool,
        body: Option<Vec<u8>>,
    }
    impl Fake {
        fn new(reserve_ok: bool, body: Option<Vec<u8>>) -> Self {
            Self {
                reserve_calls: AtomicUsize::new(0),
                provider_calls: AtomicUsize::new(0),
                reserve_ok,
                body,
            }
        }
    }
    impl FixtureBackend for Fake {
        async fn reserve(&self, amount: u64) -> Result<bool, ()> {
            assert_eq!(amount, 1200);
            self.reserve_calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.reserve_ok)
        }
        async fn call_provider(&self, _: &Value) -> Result<Vec<u8>, ()> {
            assert_eq!(
                self.reserve_calls.load(Ordering::SeqCst),
                1,
                "provider ran before reservation"
            );
            self.provider_calls.fetch_add(1, Ordering::SeqCst);
            self.body.clone().ok_or(())
        }
    }
    fn tool() -> Value {
        json!({"type":"function","function":{"name":"factory__shell","parameters":{}}})
    }
    fn request() -> Vec<u8> {
        serde_json::to_vec(&json!({"model":"fixture","messages":[{"role":"system","content":"s"},{"role":"user","content":"u"}],"tools":[tool()],"max_tokens":100,"stream":true,"stream_options":{"include_usage":true}})).unwrap()
    }
    fn gateway() -> SyntheticGateway {
        SyntheticGateway::new("fixture", tool(), 100, 8192, 1200, 64).unwrap()
    }
    #[tokio::test]
    async fn valid_request_reserves_once_before_provider() {
        let backend = Fake::new(true, Some(b"synthetic".to_vec()));
        assert_eq!(
            gateway().invoke(&backend, &request()).await.unwrap(),
            b"synthetic"
        );
        assert_eq!(backend.reserve_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.provider_calls.load(Ordering::SeqCst), 1);
    }
    #[tokio::test]
    async fn invalid_request_and_denied_reservation_never_call_provider() {
        let backend = Fake::new(true, Some(vec![]));
        let mut bad: Value = serde_json::from_slice(&request()).unwrap();
        bad["extra"] = json!(true);
        assert!(
            gateway()
                .invoke(&backend, &serde_json::to_vec(&bad).unwrap())
                .await
                .is_err()
        );
        let duplicate = String::from_utf8(request()).unwrap().replace(
            "\"model\":\"fixture\"",
            "\"model\":\"fixture\",\"model\":\"fixture\"",
        );
        assert!(
            gateway()
                .invoke(&backend, duplicate.as_bytes())
                .await
                .is_err()
        );
        assert_eq!(backend.reserve_calls.load(Ordering::SeqCst), 0);
        assert_eq!(backend.provider_calls.load(Ordering::SeqCst), 0);
        let backend = Fake::new(false, Some(vec![]));
        assert!(gateway().invoke(&backend, &request()).await.is_err());
        assert_eq!(backend.reserve_calls.load(Ordering::SeqCst), 1);
        assert_eq!(backend.provider_calls.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn unknown_reservation_outcome_never_calls_provider() {
        struct Unavailable(AtomicUsize);
        impl FixtureBackend for Unavailable {
            async fn reserve(&self, _: u64) -> Result<bool, ()> {
                Err(())
            }
            async fn call_provider(&self, _: &Value) -> Result<Vec<u8>, ()> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Ok(vec![])
            }
        }
        let backend = Unavailable(AtomicUsize::new(0));
        assert!(gateway().invoke(&backend, &request()).await.is_err());
        assert_eq!(backend.0.load(Ordering::SeqCst), 0);
    }
    #[tokio::test]
    async fn provider_failure_or_oversize_does_not_undo_reservation() {
        for body in [None, Some(vec![0; 65])] {
            let backend = Fake::new(true, body);
            assert!(gateway().invoke(&backend, &request()).await.is_err());
            assert_eq!(backend.reserve_calls.load(Ordering::SeqCst), 1);
            assert_eq!(backend.provider_calls.load(Ordering::SeqCst), 1);
        }
    }
}
