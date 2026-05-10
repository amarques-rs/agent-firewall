use std::collections::HashMap;
use std::sync::Mutex;

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

use cost::estimate_usd;
use policy::tool_allowed;
use session::{Limits, Session, ToolRule};

#[derive(Default)]
struct AppState {
    sessions: Mutex<HashMap<String, Session>>,
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
        #[serde(default)]
        agent_id: Option<String>,
        model: String,
        projected_input_tokens: u64,
        projected_output_tokens: u64,
    },
    Tool {
        session_id: String,
        #[serde(default)]
        agent_id: Option<String>,
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

    let state = Arc::new(AppState::default());
    let app = Router::new()
        .route("/v1/session", post(open_session))
        .route("/v1/check", post(check))
        .with_state(state);

    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(8080);
    let addr = std::net::SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    tracing::info!(?addr, "listening");
    axum::serve(listener, app).await.unwrap();
}

async fn open_session(
    State(state): State<Arc<AppState>>,
    Json(req): Json<OpenSessionReq>,
) -> Response {
    let mut map = state.sessions.lock().unwrap();
    if let Some(existing) = map.get(&req.session_id) {
        (StatusCode::OK, Json(view_from(&req.session_id, existing))).into_response()
    } else {
        let s = Session::new(req.limits, req.tool_allowlist, req.policy_id);
        let v = view_from(&req.session_id, &s);
        map.insert(req.session_id.clone(), s);
        (StatusCode::CREATED, Json(v)).into_response()
    }
}

async fn check(State(state): State<Arc<AppState>>, Json(req): Json<CheckReq>) -> Response {
    let mut map = state.sessions.lock().unwrap();
    let audit_id = format!("evt_{}", Ulid::new());

    let sid = match &req {
        CheckReq::Model { session_id, .. } | CheckReq::Tool { session_id, .. } => session_id.clone(),
    };

    let Some(s) = map.get_mut(&sid) else {
        return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "decision": "deny",
                "reason": "session_not_found",
                "audit_id": audit_id,
            })),
        )
            .into_response();
    };

    if s.killed {
        return deny(s, &sid, "session_killed", audit_id);
    }
    if s.calls_remaining == 0 {
        return deny(s, &sid, "session_budget_exhausted_calls", audit_id);
    }

    match req {
        CheckReq::Model {
            model,
            projected_input_tokens,
            projected_output_tokens,
            ..
        } => {
            let Some(usd) = estimate_usd(&model, projected_input_tokens, projected_output_tokens)
            else {
                return deny(s, &sid, "unknown_model", audit_id);
            };
            let total_tokens = projected_input_tokens + projected_output_tokens;
            if total_tokens > s.tokens_remaining {
                return deny(s, &sid, "session_budget_exhausted_tokens", audit_id);
            }
            if usd > s.usd_remaining + f64::EPSILON {
                return deny(s, &sid, "session_budget_exhausted_usd", audit_id);
            }
            s.tokens_used += total_tokens;
            s.tokens_remaining -= total_tokens;
            s.usd_used += usd;
            s.usd_remaining -= usd;
            s.calls_remaining -= 1;
            allow(s, &sid, audit_id)
        }
        CheckReq::Tool {
            tool_name,
            tool_target,
            ..
        } => {
            if !tool_allowed(&s.tool_allowlist, &tool_name, tool_target.as_deref()) {
                return deny(s, &sid, "tool_not_in_allowlist", audit_id);
            }
            s.calls_remaining -= 1;
            allow(s, &sid, audit_id)
        }
    }
}

fn allow(s: &Session, sid: &str, audit_id: String) -> Response {
    (
        StatusCode::OK,
        Json(CheckResp {
            decision: "allow",
            reason: None,
            session: view_from(sid, s),
            audit_id,
        }),
    )
        .into_response()
}

fn deny(s: &Session, sid: &str, reason: &'static str, audit_id: String) -> Response {
    (
        StatusCode::OK,
        Json(CheckResp {
            decision: "deny",
            reason: Some(reason),
            session: view_from(sid, s),
            audit_id,
        }),
    )
        .into_response()
}

fn view_from(sid: &str, s: &Session) -> SessionView {
    SessionView {
        session_id: sid.to_string(),
        tokens_used: s.tokens_used,
        tokens_remaining: s.tokens_remaining,
        usd_used: round2(s.usd_used),
        usd_remaining: round2(s.usd_remaining),
        calls_remaining: s.calls_remaining,
    }
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    fn app() -> Router {
        let state = Arc::new(AppState::default());
        Router::new()
            .route("/v1/session", post(open_session))
            .route("/v1/check", post(check))
            .with_state(state)
    }

    async fn body_json(resp: Response) -> serde_json::Value {
        let bytes = resp.into_body().collect().await.unwrap().to_bytes();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[tokio::test]
    async fn opens_session_then_allow_then_deny_on_budget() {
        let app = app();

        let open = Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "session_id": "sess_smoke",
                    "limits": {
                        "max_usd": 0.10,
                        "max_input_tokens": 10000,
                        "max_output_tokens": 5000,
                        "max_calls": 5,
                        "ttl_seconds": 3600
                    },
                    "tool_allowlist": [{"tool_name": "filesystem.read"}]
                }))
                .unwrap(),
            ))
            .unwrap();

        let resp = app.clone().oneshot(open).await.unwrap();
        assert_eq!(resp.status(), StatusCode::CREATED);

        let check_allow = Request::builder()
            .method("POST")
            .uri("/v1/check")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "kind": "model",
                    "session_id": "sess_smoke",
                    "model": "claude-haiku-4-5",
                    "projected_input_tokens": 1000,
                    "projected_output_tokens": 500
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(check_allow).await.unwrap();
        let v = body_json(resp).await;
        assert_eq!(v["decision"], "allow");

        let check_deny = Request::builder()
            .method("POST")
            .uri("/v1/check")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "kind": "model",
                    "session_id": "sess_smoke",
                    "model": "claude-opus-4-7",
                    "projected_input_tokens": 9000,
                    "projected_output_tokens": 4500
                }))
                .unwrap(),
            ))
            .unwrap();
        let resp = app.clone().oneshot(check_deny).await.unwrap();
        let v = body_json(resp).await;
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["reason"], "session_budget_exhausted_usd");
    }

    #[tokio::test]
    async fn tool_allowlist_gating() {
        let app = app();
        let open = Request::builder()
            .method("POST")
            .uri("/v1/session")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "session_id": "sess_tool",
                    "limits": {
                        "max_usd": 5.00,
                        "max_input_tokens": 100000,
                        "max_output_tokens": 50000,
                        "max_calls": 10,
                        "ttl_seconds": 3600
                    },
                    "tool_allowlist": [
                        {"tool_name": "filesystem.read"}
                    ]
                }))
                .unwrap(),
            ))
            .unwrap();
        app.clone().oneshot(open).await.unwrap();

        let allowed = Request::builder()
            .method("POST")
            .uri("/v1/check")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "kind": "tool",
                    "session_id": "sess_tool",
                    "tool_name": "filesystem.read"
                }))
                .unwrap(),
            ))
            .unwrap();
        let v = body_json(app.clone().oneshot(allowed).await.unwrap()).await;
        assert_eq!(v["decision"], "allow");

        let denied = Request::builder()
            .method("POST")
            .uri("/v1/check")
            .header("content-type", "application/json")
            .body(Body::from(
                serde_json::to_vec(&serde_json::json!({
                    "kind": "tool",
                    "session_id": "sess_tool",
                    "tool_name": "filesystem.write"
                }))
                .unwrap(),
            ))
            .unwrap();
        let v = body_json(app.clone().oneshot(denied).await.unwrap()).await;
        assert_eq!(v["decision"], "deny");
        assert_eq!(v["reason"], "tool_not_in_allowlist");
    }
}
