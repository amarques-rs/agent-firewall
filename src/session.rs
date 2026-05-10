use serde::Deserialize;

#[derive(Debug, Deserialize, Clone)]
pub struct Limits {
    pub max_usd: f64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_calls: u64,
    pub ttl_seconds: u64,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ToolRule {
    pub tool_name: String,
    #[serde(default)]
    pub target_pattern: Option<String>,
}

pub struct Session {
    pub tokens_used: u64,
    pub tokens_remaining: u64,
    pub usd_used: f64,
    pub usd_remaining: f64,
    pub calls_remaining: u64,
    pub tool_allowlist: Vec<ToolRule>,
    pub killed: bool,
    #[allow(dead_code)]
    pub policy_id: Option<String>,
}

impl Session {
    pub fn new(limits: Limits, tool_allowlist: Vec<ToolRule>, policy_id: Option<String>) -> Self {
        let tokens_remaining = limits.max_input_tokens + limits.max_output_tokens;
        Self {
            tokens_used: 0,
            tokens_remaining,
            usd_used: 0.0,
            usd_remaining: limits.max_usd,
            calls_remaining: limits.max_calls,
            tool_allowlist,
            killed: false,
            policy_id,
        }
    }
}
