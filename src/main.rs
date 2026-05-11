use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use ulid::Ulid;

mod cost;
mod policy;
mod session;
mod store;

use session::{Limits, Session, ToolRule};
use store::{Outcome, Store};

struct AppState {
    store: Store,
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

#[derive(Serialize)]
struct SessionView {
    session_id: String,
    tokens_used: u64,
    tokens_remaining: u64,
    usd_used: f64,
    usd_remaining: f64,
    calls_remaining: u64,
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

#[derive(Serialize)]
struct CheckResp {
    decision: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<&'static str>,
    session: SessionView,
    audit_id: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt().json().init();
    let sled_path = std::env::var("SLED_PATH").unwrap_or_else(|_| "data/firewall.sled".into());
    let store = Store::open(&sled_path).expect("open sled db");
    let state = Arc::new(AppState { store });
    let app = Router::new()
        .route("/v1/session", post(open_session))
        .route("/v1/check", post(check))
        .with_state(state);
    let port: u16 = std::env::var("PORT").ok().and_then(|s| s.parse().ok()).unwrap_or(8080);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::info!(?addr, %sled_path, "listening");
    axum::serve(listener, app).await.unwrap();
}

async fn open_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OpenSessionReq>,
) -> Response {
    match state
        .store
        .open_session(&req.session_id, req.limits, req.tool_allowlist, req.policy_id)
    {
        Ok(Outcome::Opened { session, is_new }) => {
            let view = view_from(&req.session_id, &session);
            let code = if is_new { StatusCode::CREATED } else { StatusCode::OK };
            (code, Json(view)).into_response()
        }
        Ok(_) => unreachable!("open_session returns Opened"),
        Err(e) => internal_error(e),
    }
}

async fn check(State(state): State<Arc<AppState>>, Json(req): Json<CheckReq>) -> Response {
    let audit_id = format!("evt_{}", Ulid::new());
    let sid = match &req {
        CheckReq::Model { session_id, .. } | CheckReq::Tool { session_id, .. } => session_id.clone(),
    };
    let outcome = match req {
        CheckReq::Model { model, projected_input_tokens, projected_output_tokens, .. } =>
            state.store.check_model(&sid, &model, projected_input_tokens, projected_output_tokens),
        CheckReq::Tool { tool_name, tool_target, .. } =>
            state.store.check_tool(&sid, &tool_name, tool_target.as_deref()),
    };
    match outcome {
        Ok(Outcome::Allow(s)) => decided(&s, &sid, "allow", None, audit_id),
        Ok(Outcome::Deny { session, reason }) => decided(&session, &sid, "deny", Some(reason), audit_id),
        Ok(Outcome::NotFound) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"decision":"deny","reason":"session_not_found","audit_id":audit_id})),
        ).into_response(),
        Ok(Outcome::Opened { .. }) => unreachable!("check never returns Opened"),
        Err(e) => internal_error(e),
    }
}

fn decided(s: &Session, sid: &str, decision: &'static str, reason: Option<&'static str>, audit_id: String) -> Response {
    (
        StatusCode::OK,
        Json(CheckResp {
            decision,
            reason,
            session: view_from(sid, s),
            audit_id,
        }),
    )
        .into_response()
}

fn internal_error(e: sled::Error) -> Response {
    tracing::error!(?e, "sled error");
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        Json(serde_json::json!({"decision":"deny","reason":"internal_error"})),
    )
        .into_response()
}

fn view_from(sid: &str, s: &Session) -> SessionView {
    let r = |x: f64| (x * 100.0).round() / 100.0;
    SessionView {
        session_id: sid.to_string(),
        tokens_used: s.tokens_used,
        tokens_remaining: s.tokens_remaining,
        usd_used: r(s.usd_used),
        usd_remaining: r(s.usd_remaining),
        calls_remaining: s.calls_remaining,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn router_with_store(store: Store) -> Router {
        let state = Arc::new(AppState { store });
        Router::new()
            .route("/v1/session", post(open_session))
            .route("/v1/check", post(check))
            .with_state(state)
    }

    fn app() -> Router {
        router_with_store(Store::temporary().unwrap())
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    fn open_req(session_id: &str, max_usd: f64, max_calls: u64, ttl: u64) -> Request<Body> {
        Request::builder()
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

    fn check_model_req(session_id: &str, model: &str, input: u64, output: u64) -> Request<Body> {
        Request::builder()
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

    fn check_tool_req(session_id: &str, tool_name: &str) -> Request<Body> {
        Request::builder()
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

    fn check_tool_target_req(session_id: &str, tool_name: &str, target: &str) -> Request<Body> {
        Request::builder()
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

    fn open_with_pattern_req(session_id: &str, tool_name: &str, target_pattern: &str) -> Request<Body> {
        Request::builder()
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
}
