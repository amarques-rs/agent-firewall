use regex::Regex;

use crate::session::ToolRule;

pub enum ToolMatch { Allow, NotInAllowlist, TargetBlocked }

// target_pattern is a regex. Anchoring (^...$) is the caller's responsibility;
// an invalid pattern denies (fail-closed), matching the wedge's deterministic-cap claim.
pub fn tool_allowed(allowlist: &[ToolRule], tool_name: &str, target: Option<&str>) -> ToolMatch {
    let mut found_name = false;
    for rule in allowlist {
        if rule.tool_name != tool_name { continue; }
        found_name = true;
        match (&rule.target_pattern, target) {
            (None, _) => return ToolMatch::Allow,
            (Some(pat), Some(t)) if Regex::new(pat).map(|re| re.is_match(t)).unwrap_or(false) => return ToolMatch::Allow,
            _ => continue,
        }
    }
    if found_name { ToolMatch::TargetBlocked } else { ToolMatch::NotInAllowlist }
}
