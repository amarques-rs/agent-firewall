use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use sled::Db;

use crate::cost::estimate_usd;
use crate::policy::tool_allowed;
use crate::session::{Limits, Session, ToolRule};

pub enum Outcome {
    Opened { session: Session, is_new: bool },
    Allow(Session),
    Deny { session: Session, reason: &'static str },
    NotFound,
}

pub struct Store {
    db: Db,
}

impl Store {
    pub fn open<P: AsRef<Path>>(path: P) -> sled::Result<Self> {
        let db = sled::Config::new().path(path).open()?;
        Ok(Self { db })
    }

    #[cfg(test)]
    pub fn temporary() -> sled::Result<Self> {
        let db = sled::Config::new().temporary(true).open()?;
        Ok(Self { db })
    }

    fn now_unix() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }

    pub fn open_session(
        &self,
        session_id: &str,
        limits: Limits,
        allowlist: Vec<ToolRule>,
        policy_id: Option<String>,
    ) -> sled::Result<Outcome> {
        if let Some(bytes) = self.db.get(session_id)? {
            let s: Session = bincode::deserialize(&bytes).expect("decode session");
            return Ok(Outcome::Opened { session: s, is_new: false });
        }
        let s = Session::new(limits, allowlist, policy_id, Self::now_unix());
        let bytes = bincode::serialize(&s).expect("encode session");
        self.db.insert(session_id, bytes)?;
        Ok(Outcome::Opened { session: s, is_new: true })
    }

    fn with_session<F>(&self, session_id: &str, now: u64, mut f: F) -> sled::Result<Outcome>
    where
        F: FnMut(&mut Session) -> Outcome,
    {
        let mut outcome: Option<Outcome> = None;
        self.db
            .update_and_fetch(session_id.as_bytes(), |cur| -> Option<Vec<u8>> {
                let Some(bytes) = cur else {
                    outcome = Some(Outcome::NotFound);
                    return None;
                };
                let mut s: Session = bincode::deserialize(bytes).expect("decode session");
                if let Some(reason) = preflight_deny(&s, now) {
                    outcome = Some(Outcome::Deny { session: s, reason });
                    return Some(bytes.to_vec());
                }
                let o = f(&mut s);
                let next = match &o {
                    Outcome::Allow(_) => bincode::serialize(&s).expect("encode session"),
                    _ => bytes.to_vec(),
                };
                outcome = Some(o);
                Some(next)
            })?;
        Ok(outcome.expect("update_and_fetch always invokes closure"))
    }

    pub fn check_model(
        &self,
        session_id: &str,
        model: &str,
        projected_input: u64,
        projected_output: u64,
    ) -> sled::Result<Outcome> {
        let now = Self::now_unix();
        self.with_session(session_id, now, |s| {
            let Some(usd) = estimate_usd(model, projected_input, projected_output) else {
                return Outcome::Deny { session: s.clone(), reason: "unknown_model" };
            };
            let total = projected_input + projected_output;
            if total > s.tokens_remaining {
                return Outcome::Deny { session: s.clone(), reason: "session_budget_exhausted_tokens" };
            }
            if usd > s.usd_remaining + f64::EPSILON {
                return Outcome::Deny { session: s.clone(), reason: "session_budget_exhausted_usd" };
            }
            s.tokens_used += total;
            s.tokens_remaining -= total;
            s.usd_used += usd;
            s.usd_remaining -= usd;
            s.calls_remaining -= 1;
            Outcome::Allow(s.clone())
        })
    }

    pub fn check_tool(
        &self,
        session_id: &str,
        tool_name: &str,
        target: Option<&str>,
    ) -> sled::Result<Outcome> {
        let now = Self::now_unix();
        self.with_session(session_id, now, |s| {
            if !tool_allowed(&s.tool_allowlist, tool_name, target) {
                return Outcome::Deny { session: s.clone(), reason: "tool_not_in_allowlist" };
            }
            s.calls_remaining -= 1;
            Outcome::Allow(s.clone())
        })
    }
}

fn preflight_deny(s: &Session, now: u64) -> Option<&'static str> {
    if s.killed {
        return Some("session_killed");
    }
    if now >= s.expires_at_unix {
        return Some("session_expired");
    }
    if s.calls_remaining == 0 {
        return Some("session_budget_exhausted_calls");
    }
    None
}
