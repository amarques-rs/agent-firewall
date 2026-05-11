use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use sled::Db;

use crate::cost::estimate_usd;
use crate::policy::tool_allowed;
use crate::session::{Limits, Session, ToolRule};

pub enum CheckOutcome {
    Allow(Session),
    Deny { session: Session, reason: &'static str },
}

pub struct Store {
    db: Db,
}

impl Store {
    pub fn open<P: AsRef<Path>>(path: P) -> sled::Result<Self> {
        Ok(Self { db: sled::Config::new().path(path).open()? })
    }

    #[cfg(test)]
    pub fn temporary() -> sled::Result<Self> {
        Ok(Self { db: sled::Config::new().temporary(true).open()? })
    }

    fn now_unix() -> u64 {
        SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }

    pub fn open_session(&self, session_id: &str, limits: Limits, allowlist: Vec<ToolRule>, policy_id: Option<String>) -> sled::Result<(Session, bool)> {
        if let Some(bytes) = self.db.get(session_id)? {
            return Ok((bincode::deserialize(&bytes).expect("decode session"), false));
        }
        let s = Session::new(limits, allowlist, policy_id, Self::now_unix());
        self.db.insert(session_id, bincode::serialize(&s).expect("encode session"))?;
        Ok((s, true))
    }

    fn with_session<F>(&self, session_id: &str, now: u64, mut f: F) -> sled::Result<Option<CheckOutcome>>
    where
        F: FnMut(&mut Session) -> CheckOutcome,
    {
        let mut outcome: Option<CheckOutcome> = None;
        self.db.update_and_fetch(session_id.as_bytes(), |cur| -> Option<Vec<u8>> {
            let bytes = cur?;
            let mut s: Session = bincode::deserialize(bytes).expect("decode session");
            if let Some(reason) = preflight_deny(&s, now) {
                outcome = Some(CheckOutcome::Deny { session: s, reason });
                return Some(bytes.to_vec());
            }
            let o = f(&mut s);
            let next = match &o {
                CheckOutcome::Allow(_) => bincode::serialize(&s).expect("encode session"),
                _ => bytes.to_vec(),
            };
            outcome = Some(o);
            Some(next)
        })?;
        Ok(outcome)
    }

    pub fn check_model(&self, session_id: &str, audit_id: &str, model: &str, projected_input: u64, projected_output: u64) -> sled::Result<Option<CheckOutcome>> {
        let now = Self::now_unix();
        let outcome = self.with_session(session_id, now, |s| {
            let Some(usd) = estimate_usd(model, projected_input, projected_output) else {
                return CheckOutcome::Deny { session: s.clone(), reason: "unknown_model" };
            };
            let total = projected_input + projected_output;
            if total > s.tokens_remaining {
                return CheckOutcome::Deny { session: s.clone(), reason: "session_budget_exhausted_tokens" };
            }
            if usd > s.usd_remaining + f64::EPSILON {
                return CheckOutcome::Deny { session: s.clone(), reason: "session_budget_exhausted_usd" };
            }
            s.tokens_used += total;
            s.tokens_remaining -= total;
            s.usd_used += usd;
            s.usd_remaining -= usd;
            s.calls_remaining -= 1;
            CheckOutcome::Allow(s.clone())
        })?;
        if let Some(o) = &outcome { self.append_audit(audit_id, session_id, "model", now, o)?; }
        Ok(outcome)
    }

    pub fn check_tool(&self, session_id: &str, audit_id: &str, tool_name: &str, target: Option<&str>) -> sled::Result<Option<CheckOutcome>> {
        let now = Self::now_unix();
        let outcome = self.with_session(session_id, now, |s| {
            if !tool_allowed(&s.tool_allowlist, tool_name, target) {
                return CheckOutcome::Deny { session: s.clone(), reason: "tool_not_in_allowlist" };
            }
            s.calls_remaining -= 1;
            CheckOutcome::Allow(s.clone())
        })?;
        if let Some(o) = &outcome { self.append_audit(audit_id, session_id, "tool", now, o)?; }
        Ok(outcome)
    }

    fn append_audit(&self, audit_id: &str, sid: &str, kind: &str, ts: u64, o: &CheckOutcome) -> sled::Result<()> {
        let (decision, reason) = match o {
            CheckOutcome::Allow(_) => ("allow", None),
            CheckOutcome::Deny { reason, .. } => ("deny", Some(*reason)),
        };
        let row: (&str, Option<&str>, &str, u64, &str) = (decision, reason, sid, ts, kind);
        self.db.insert(format!("audit/{audit_id}").as_bytes(), bincode::serialize(&row).expect("encode audit"))?;
        Ok(())
    }

    pub fn kill(&self, session_id: &str) -> sled::Result<bool> {
        let mut found = false;
        self.db.update_and_fetch(session_id.as_bytes(), |cur| -> Option<Vec<u8>> {
            let bytes = cur?;
            let mut s: Session = bincode::deserialize(bytes).expect("decode session");
            s.killed = true;
            found = true;
            Some(bincode::serialize(&s).expect("encode session"))
        })?;
        Ok(found)
    }
}

fn preflight_deny(s: &Session, now: u64) -> Option<&'static str> {
    if s.killed { return Some("session_killed"); }
    if now >= s.expires_at_unix { return Some("session_expired"); }
    if s.calls_remaining == 0 { return Some("session_budget_exhausted_calls"); }
    None
}
