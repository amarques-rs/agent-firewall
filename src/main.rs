use axum::{
    extract::{Path, Request, State},
    http::{HeaderMap, StatusCode},
    middleware::{from_fn_with_state, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use prometheus::Encoder;
use serde::Deserialize;
use std::sync::Arc;
use ulid::Ulid;

mod cost;
mod policy;
mod session;
mod store;

use session::{Limits, Session, ToolRule};
use store::{CheckOutcome, Store};

struct Metrics { check_total: prometheus::IntCounterVec, check_latency: prometheus::Histogram, sessions_active: prometheus::IntGauge, kills_total: prometheus::IntCounter, registry: prometheus::Registry }

fn build_metrics() -> Metrics {
    use prometheus::{core::Collector, HistogramOpts, IntCounter, IntCounterVec, IntGauge, Opts, Registry};
    let (r, reg) = (Registry::new(), |r: &Registry, c: Box<dyn Collector>| r.register(c).unwrap());
    let check_total = IntCounterVec::new(Opts::new("check_total", "Total /v1/check decisions"), &["decision", "reason"]).unwrap();
    let check_latency = prometheus::Histogram::with_opts(HistogramOpts::new("check_latency_seconds", "/v1/check latency").buckets(vec![0.001, 0.002, 0.005, 0.01, 0.025, 0.05, 0.1])).unwrap();
    let sessions_active = IntGauge::new("sessions_active", "Active session rows in sled").unwrap();
    let kills_total = IntCounter::new("kills_total", "Successful /v1/session/:id/kill").unwrap();
    reg(&r, Box::new(check_total.clone())); reg(&r, Box::new(check_latency.clone())); reg(&r, Box::new(sessions_active.clone())); reg(&r, Box::new(kills_total.clone()));
    Metrics { check_total, check_latency, sessions_active, kills_total, registry: r }
}

struct AppState {
    store: Store,
    admin_token: Option<String>,
    proxy_secret: Option<String>,
    metrics: Metrics,
}

#[derive(Deserialize)]
struct OpenSessionReq {
    session_id: String,
    #[serde(default)]
    policy_id: Option<String>,
    limits: Limits,
    #[serde(default)]
    tool_allowlist: Vec<ToolRule>,
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase")]
enum CheckReq {
    Model {
        session_id: String,
        model: String,
        projected_input_tokens: u64,
        projected_output_tokens: u64,
    },
    Tool {
        session_id: String,
        tool_name: String,
        #[serde(default)]
        tool_target: Option<String>,
    },
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().json().init();
    let sled_path = std::env::var("SLED_PATH").unwrap_or_else(|_| "data/firewall.sled".into());
    let store = Store::open(&sled_path).expect("open sled db");
    let admin_token = std::env::var("ADMIN_TOKEN").ok().filter(|s| !s.is_empty());
    let proxy_secret = std::env::var("RAPIDAPI_PROXY_SECRET").ok().filter(|s| !s.is_empty());
    let state = Arc::new(AppState { store, admin_token, proxy_secret, metrics: build_metrics() });
    let app = build_router(state);
    let port: u16 = std::env::var("PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8080);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::info!(?addr, %sled_path, "listening");
    axum::serve(listener, app).await.unwrap();
}

fn build_router(state: Arc<AppState>) -> Router {
    let gated = Router::new()
        .route("/v1/session", post(open_session))
        .route("/v1/check", post(check))
        .route_layer(from_fn_with_state(state.clone(), proxy_secret_mw));
    gated.route("/v1/session/:id/kill", post(kill_session)).route("/metrics", get(metrics)).with_state(state)
}

async fn metrics(State(state): State<Arc<AppState>>) -> Response {
    state.metrics.sessions_active.set(state.store.count_sessions().unwrap_or(0) as i64);
    let mut buf = Vec::new();
    prometheus::TextEncoder::new().encode(&state.metrics.registry.gather(), &mut buf).unwrap();
    (StatusCode::OK, [("content-type", "text/plain; version=0.0.4")], buf).into_response()
}

async fn proxy_secret_mw(State(state): State<Arc<AppState>>, headers: HeaderMap, req: Request, next: Next) -> Response {
    if let Some(want) = &state.proxy_secret {
        let got = headers.get("x-rapidapi-proxy-secret").and_then(|h| h.to_str().ok());
        if got != Some(want.as_str()) {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"unauthorized"}))).into_response();
        }
    }
    next.run(req).await
}

async fn open_session(State(state): State<Arc<AppState>>, Json(req): Json<OpenSessionReq>) -> Response {
    match state.store.open_session(&req.session_id, req.limits, req.tool_allowlist, req.policy_id) {
        Ok((s, is_new)) => (if is_new { StatusCode::CREATED } else { StatusCode::OK }, Json(view(&req.session_id, &s))).into_response(),
        Err(e) => internal_error(e),
    }
}

async fn check(State(state): State<Arc<AppState>>, Json(req): Json<CheckReq>) -> Response {
    let audit_id = format!("evt_{}", Ulid::new());
    let sid = match &req {
        CheckReq::Model { session_id, .. } | CheckReq::Tool { session_id, .. } => session_id.clone(),
    };
    let outcome = {
        let _t = state.metrics.check_latency.start_timer();
        match req {
            CheckReq::Model { model, projected_input_tokens, projected_output_tokens, .. } => state.store.check_model(&sid, &audit_id, &model, projected_input_tokens, projected_output_tokens),
            CheckReq::Tool { tool_name, tool_target, .. } => state.store.check_tool(&sid, &audit_id, &tool_name, tool_target.as_deref()),
        }
    };
    let (decision, reason) = match &outcome {
        Ok(Some(CheckOutcome::Allow(_))) => ("allow", ""),
        Ok(Some(CheckOutcome::Deny { reason, .. })) => ("deny", *reason),
        Ok(None) => ("deny", "session_not_found"),
        Err(_) => ("deny", "internal_error"),
    };
    state.metrics.check_total.with_label_values(&[decision, reason]).inc();
    match outcome {
        Ok(Some(CheckOutcome::Allow(s))) => decided(&s, &sid, "allow", None, audit_id),
        Ok(Some(CheckOutcome::Deny { session, reason })) => decided(&session, &sid, "deny", Some(reason), audit_id),
        Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"decision":"deny","reason":"session_not_found","audit_id":audit_id}))).into_response(),
        Err(e) => internal_error(e),
    }
}

async fn kill_session(State(state): State<Arc<AppState>>, headers: HeaderMap, Path(session_id): Path<String>) -> Response {
    if let Some(want) = &state.admin_token {
        let got = headers.get("authorization").and_then(|h| h.to_str().ok()).and_then(|h| h.strip_prefix("Bearer "));
        if got != Some(want.as_str()) {
            return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error":"unauthorized"}))).into_response();
        }
    }
    match state.store.kill(&session_id) {
        Ok(true) => { state.metrics.kills_total.inc(); (StatusCode::OK, Json(serde_json::json!({"decision":"killed","session_id":session_id}))).into_response() }
        Ok(false) => (StatusCode::NOT_FOUND, Json(serde_json::json!({"error":"session_not_found"}))).into_response(),
        Err(e) => internal_error(e),
    }
}

fn decided(s: &Session, sid: &str, decision: &str, reason: Option<&str>, audit_id: String) -> Response {
    (StatusCode::OK, Json(serde_json::json!({"decision":decision,"reason":reason,"session":view(sid, s),"audit_id":audit_id}))).into_response()
}

fn internal_error(e: sled::Error) -> Response {
    tracing::error!(?e, "sled error");
    (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"decision":"deny","reason":"internal_error"}))).into_response()
}

fn view(sid: &str, s: &Session) -> serde_json::Value {
    let r = |x: f64| (x * 100.0).round() / 100.0;
    serde_json::json!({"session_id": sid, "tokens_used": s.tokens_used, "tokens_remaining": s.tokens_remaining, "usd_used": r(s.usd_used), "usd_remaining": r(s.usd_remaining), "calls_remaining": s.calls_remaining})
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request as HttpRequest;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn router_with_state(state: Arc<AppState>) -> Router {
        build_router(state)
    }

    fn router_with_store_and_admin(store: Store, admin_token: Option<String>) -> Router {
        router_with_state(Arc::new(AppState { store, admin_token, proxy_secret: None, metrics: build_metrics() }))
    }

    fn router_with_store(store: Store) -> Router {
        router_with_store_and_admin(store, None)
    }

    fn router_with_proxy(store: Store, proxy_secret: Option<String>) -> Router {
        router_with_state(Arc::new(AppState { store, admin_token: None, proxy_secret, metrics: build_metrics() }))
    }

    fn app() -> Router {
        router_with_store(Store::temporary().unwrap())
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn open_req(session_id: &str, max_usd: f64, max_calls: u64, ttl: u64) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "session_id": session_id,
                    "limits": {
                        "max_usd": max_usd,
                        "max_input_tokens": 100000,
                        "max_output_tokens": 50000,
                        "max_calls": max_calls,
                        "ttl_seconds": ttl
                    },
                    "tool_allowlist": [{"tool_name": "filesystem.read"}]
                }))
                .unwrap(),
            ))
            .unwrap()
    }

    fn check_model_req(session_id: &str, model: &str, input: u64, output: u64) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method("POST")
            .uri("/v1/check")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "kind": "model",
                    "session_id": session_id,
                    "model": model,
                    "projected_input_tokens": input,
                    "projected_output_tokens": output
                }))
                .unwrap(),
            ))
            .unwrap()
    }

    fn check_tool_req(session_id: &str, tool_name: &str) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method("POST")
            .uri("/v1/check")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "kind": "tool",
                    "session_id": session_id,
                    "tool_name": tool_name
                }))
                .unwrap(),
            ))
            .unwrap()
    }

    fn check_tool_target_req(session_id: &str, tool_name: &str, target: &str) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method("POST")
            .uri("/v1/check")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "kind": "tool",
                    "session_id": session_id,
                    "tool_name": tool_name,
                    "tool_target": target
                }))
                .unwrap(),
            ))
            .unwrap()
    }

    fn open_with_pattern_req(session_id: &str, tool_name: &str, target_pattern: &str) -> HttpRequest<Body> {
        HttpRequest::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "session_id": session_id,
                    "limits": {
                        "max_usd": 5.0,
                        "max_input_tokens": 100000,
                        "max_output_tokens": 50000,
                        "max_calls": 10,
                        "ttl_seconds": 3600
                    },
                    "tool_allowlist": [
                        {"tool_name": tool_name, "target_pattern": target_pattern}
                    ]
                }))
                .unwrap(),
            ))
            .unwrap()
    }

    #[tokio::test]
    async fn opens_session_then_allow_then_deny_on_budget() {
        let app = app();
        let resp = app.clone().oneshot(open_req("sess_smoke", 0.10, 5, 3600)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let v = body_json(
            app.clone()
                .oneshot(check_model_req("sess_smoke", "claude-haiku-4-5", 1000, 500))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(v["decision"], "allow");

        let v = body_json(
            app.clone()
                .oneshot(check_model_req("sess_smoke", "claude-opus-4-7", 9000, 4500))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["reason"], "session_budget_exhausted_usd");
    }

    #[tokio::test]
    async fn tool_allowlist_gating() {
        let app = app();
        app.clone().oneshot(open_req("sess_tool", 5.0, 10, 3600)).await.unwrap();

        let v = body_json(
            app.clone().oneshot(check_tool_req("sess_tool", "filesystem.read")).await.unwrap(),
        )
        .await;
        assert_eq!(v["decision"], "allow");

        let v = body_json(
            app.clone().oneshot(check_tool_req("sess_tool", "filesystem.write")).await.unwrap(),
        )
        .await;
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["reason"], "tool_not_in_allowlist");
    }

    #[tokio::test]
    async fn session_survives_restart() {
        let dir = std::env::temp_dir().join(format!("agent-firewall-test-{}", Ulid::new()));
        {
            let store = Store::open(&dir).unwrap();
            let app = router_with_store(store);
            app.clone().oneshot(open_req("sess_persist", 1.0, 5, 3600)).await.unwrap();
            // consume some budget so the persisted state is non-trivial
            let v = body_json(
                app.clone()
                    .oneshot(check_model_req("sess_persist", "claude-haiku-4-5", 1000, 500))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(v["decision"], "allow");
        }
        // Reopen the same path
        let store = Store::open(&dir).unwrap();
        let app = router_with_store(store);
        // Reopening with same session_id returns 200 (existing) and preserves counters.
        let resp = app.clone().oneshot(open_req("sess_persist", 1.0, 5, 3600)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert!(v["calls_remaining"].as_u64().unwrap() < 5, "counters should persist");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn expired_session_denies() {
        let app = app();
        app.clone().oneshot(open_req("sess_expired", 1.0, 5, 0)).await.unwrap();
        // ttl_seconds=0 → expires_at_unix == now → now >= expires_at_unix on the next check
        let v = body_json(
            app.clone()
                .oneshot(check_model_req("sess_expired", "claude-haiku-4-5", 100, 50))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["reason"], "session_expired");
    }

    #[tokio::test]
    async fn concurrent_checks_do_not_double_count() {
        // Budget: $0.05. Each opus call: 1000 input + 100 output =
        //   1000 * 15/1e6 + 100 * 75/1e6 = 0.015 + 0.0075 = 0.0225 USD.
        // Two fit (0.045); the third would exceed. With 50 concurrent requests
        // we must see EXACTLY 2 allows + 48 denies.
        let app = app();
        app.clone().oneshot(open_req("sess_race", 0.05, 100, 3600)).await.unwrap();

        let mut handles = Vec::new();
        for _ in 0..50 {
            let app = app.clone();
            handles.push(tokio::spawn(async move {
                let resp = app
                    .oneshot(check_model_req("sess_race", "claude-opus-4-7", 1000, 100))
                    .await
                    .unwrap();
                body_json(resp).await
            }));
        }
        let mut allows = 0;
        let mut denies_usd = 0;
        for h in handles {
            let v = h.await.unwrap();
            match v["decision"].as_str().unwrap() {
                "allow" => allows += 1,
                "deny" => {
                    if v["reason"] == "session_budget_exhausted_usd" {
                        denies_usd += 1;
                    }
                }
                _ => panic!("unexpected decision"),
            }
        }
        assert_eq!(allows, 2, "exactly 2 calls fit in the budget");
        assert_eq!(denies_usd, 48, "the other 48 must be USD-exhausted denies");
    }

    fn kill_req(session_id: &str, bearer: Option<&str>) -> HttpRequest<Body> {
        let mut b = HttpRequest::builder()
            .method("POST")
            .uri(format!("/v1/session/{session_id}/kill"))
            .header("content-type", "application/json");
        if let Some(token) = bearer {
            b = b.header("authorization", format!("Bearer {token}"));
        }
        b.body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn kill_propagates_to_subsequent_checks() {
        // Open, kill, then a check returns deny:session_killed regardless of remaining budget.
        let app = app();
        app.clone().oneshot(open_req("sess_kill", 5.0, 10, 3600)).await.unwrap();

        let resp = app.clone().oneshot(kill_req("sess_kill", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let v = body_json(resp).await;
        assert_eq!(v["decision"], "killed");

        let v = body_json(
            app.clone()
                .oneshot(check_model_req("sess_kill", "claude-haiku-4-5", 100, 50))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["reason"], "session_killed");

        let v = body_json(
            app.clone().oneshot(check_tool_req("sess_kill", "filesystem.read")).await.unwrap(),
        )
        .await;
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["reason"], "session_killed");
    }

    #[tokio::test]
    async fn kill_returns_404_on_missing_session() {
        let app = app();
        let resp = app.oneshot(kill_req("sess_ghost", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn kill_requires_admin_token_when_configured() {
        // ADMIN_TOKEN set on AppState → wrong/missing bearer is 401; correct bearer succeeds.
        let app = router_with_store_and_admin(Store::temporary().unwrap(), Some("s3cret".into()));
        app.clone().oneshot(open_req("sess_admin", 5.0, 10, 3600)).await.unwrap();

        let resp = app.clone().oneshot(kill_req("sess_admin", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = app.clone().oneshot(kill_req("sess_admin", Some("wrong"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        let resp = app.clone().oneshot(kill_req("sess_admin", Some("s3cret"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // The session is now killed under admin auth.
        let v = body_json(
            app.clone()
                .oneshot(check_model_req("sess_admin", "claude-haiku-4-5", 100, 50))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(v["reason"], "session_killed");
    }

    #[tokio::test]
    async fn regex_target_pattern_anchors() {
        // Pattern is an anchored regex. The substring-match implementation
        // (replaced this run) would have allowed the second URL — the regex
        // implementation must deny it.
        let app = app();
        app.clone()
            .oneshot(open_with_pattern_req(
                "sess_re",
                "http.get",
                r"^https://api\.example\.com/.*",
            ))
            .await
            .unwrap();

        let v = body_json(
            app.clone()
                .oneshot(check_tool_target_req(
                    "sess_re",
                    "http.get",
                    "https://api.example.com/users",
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(v["decision"], "allow", "exact host matches anchored regex");

        let v = body_json(
            app.clone()
                .oneshot(check_tool_target_req(
                    "sess_re",
                    "http.get",
                    "https://evil.com/api.example.com/users",
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(v["decision"], "deny", "anchored regex denies subdomain spoof");
        assert_eq!(v["reason"], "tool_not_in_allowlist");
    }

    fn open_req_with_proxy_secret(session_id: &str, proxy_secret: Option<&str>) -> HttpRequest<Body> {
        let mut b = HttpRequest::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json");
        if let Some(s) = proxy_secret {
            b = b.header("x-rapidapi-proxy-secret", s);
        }
        b.body(Body::from(
            serde_json::to_vec(&serde_json::json!({
                "session_id": session_id,
                "limits": {"max_usd": 5.0, "max_input_tokens": 1000, "max_output_tokens": 1000, "max_calls": 10, "ttl_seconds": 3600},
                "tool_allowlist": []
            }))
            .unwrap(),
        ))
        .unwrap()
    }

    #[tokio::test]
    async fn proxy_secret_gates_session_and_check_but_not_kill() {
        // proxy_secret configured → /v1/session and /v1/check require X-RapidAPI-Proxy-Secret.
        // /v1/session/:id/kill is behind admin_token, not proxy_secret — must NOT require this header.
        let app = router_with_proxy(Store::temporary().unwrap(), Some("rapid-s3cret".into()));

        // No header → 401.
        let resp = app.clone().oneshot(open_req_with_proxy_secret("sess_proxy", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Wrong header → 401.
        let resp = app.clone().oneshot(open_req_with_proxy_secret("sess_proxy", Some("wrong"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // Correct header → 201 (session opens).
        let resp = app.clone().oneshot(open_req_with_proxy_secret("sess_proxy", Some("rapid-s3cret"))).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        // /v1/check with correct header → 200.
        let mut check = check_model_req("sess_proxy", "claude-haiku-4-5", 100, 50);
        check.headers_mut().insert("x-rapidapi-proxy-secret", "rapid-s3cret".parse().unwrap());
        let resp = app.clone().oneshot(check).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        // /v1/check without header → 401.
        let resp = app.clone().oneshot(check_model_req("sess_proxy", "claude-haiku-4-5", 100, 50)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

        // /v1/session/:id/kill WITHOUT proxy-secret header → must NOT be gated by the proxy mw.
        // admin_token is None here, so kill succeeds with 200 (or 404 if session lookup were off).
        let resp = app.clone().oneshot(kill_req("sess_proxy", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "kill endpoint is behind admin_token, not proxy_secret");
    }

    #[tokio::test]
    async fn audit_rows_persist_for_allow_and_deny() {
        // Open a session, fire 1 allow + 1 deny (unknown_model), then verify 2 audit rows
        // exist in sled under the `audit/` prefix with the bincode tuple shape spec'd in
        // `output/v1-spec-agent-firewall.md ## Storage / state`.
        let dir = std::env::temp_dir().join(format!("agent-firewall-audit-{}", Ulid::new()));
        {
            let store = Store::open(&dir).unwrap();
            let app = router_with_store(store);
            app.clone().oneshot(open_req("sess_audit", 5.0, 10, 3600)).await.unwrap();

            let v = body_json(
                app.clone()
                    .oneshot(check_model_req("sess_audit", "claude-haiku-4-5", 100, 50))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(v["decision"], "allow");

            let v = body_json(
                app.clone()
                    .oneshot(check_model_req("sess_audit", "unknown-model", 100, 50))
                    .await
                    .unwrap(),
            )
            .await;
            assert_eq!(v["decision"], "deny");
            assert_eq!(v["reason"], "unknown_model");
        }
        // Reopen sled directly to inspect persisted audit rows.
        let db = sled::Config::new().path(&dir).open().unwrap();
        let rows: Vec<_> = db
            .scan_prefix(b"audit/")
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        assert_eq!(rows.len(), 2, "exactly one audit row per /v1/check");

        let mut decisions: Vec<String> = rows
            .iter()
            .map(|(_, v)| {
                let (decision, _reason, sid, _ts, kind): (String, Option<String>, String, u64, String) =
                    bincode::deserialize(v).expect("decode audit row");
                assert_eq!(sid, "sess_audit");
                assert_eq!(kind, "model");
                decision
            })
            .collect();
        decisions.sort();
        assert_eq!(decisions, vec!["allow".to_string(), "deny".to_string()]);
        drop(db);
        std::fs::remove_dir_all(&dir).ok();
    }

    fn metrics_req() -> HttpRequest<Body> {
        HttpRequest::builder().method("GET").uri("/metrics").body(Body::empty()).unwrap()
    }

    #[tokio::test]
    async fn metrics_endpoint_records_check_decisions_kills_and_sessions() {
        // Spec § Metrics (line 158): /metrics exposes check_total{decision,reason},
        // check_latency_seconds, sessions_active, kills_total. This test drives 1 allow
        // + 1 deny + 1 kill against 2 sessions, then asserts the Prometheus text body
        // contains the expected counter lines and a sessions_active=2 gauge sample.
        let app = app();
        app.clone().oneshot(open_req("sess_m1", 5.0, 10, 3600)).await.unwrap();
        app.clone().oneshot(open_req("sess_m2", 5.0, 10, 3600)).await.unwrap();

        let v = body_json(app.clone().oneshot(check_model_req("sess_m1", "claude-haiku-4-5", 100, 50)).await.unwrap()).await;
        assert_eq!(v["decision"], "allow");
        let v = body_json(app.clone().oneshot(check_model_req("sess_m1", "unknown-model", 100, 50)).await.unwrap()).await;
        assert_eq!(v["decision"], "deny");
        let resp = app.clone().oneshot(kill_req("sess_m2", None)).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let resp = app.clone().oneshot(metrics_req()).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = String::from_utf8(resp.into_body().collect().await.unwrap().to_bytes().to_vec()).unwrap();

        assert!(body.contains(r#"check_total{decision="allow",reason=""} 1"#), "missing allow counter: {body}");
        assert!(body.contains(r#"check_total{decision="deny",reason="unknown_model"} 1"#), "missing deny counter: {body}");
        assert!(body.contains("kills_total 1"), "missing kills_total: {body}");
        assert!(body.contains("sessions_active 2"), "missing sessions_active=2 gauge: {body}");
        assert!(body.contains("check_latency_seconds_bucket"), "missing latency histogram: {body}");
    }
}
