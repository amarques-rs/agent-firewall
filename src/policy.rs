use regex::Regex;

use crate::session::ToolRule;

// target_pattern is a regex. Anchoring (^...$) is the caller's responsibility;
// an invalid pattern denies (fail-closed), matching the wedge's deterministic-cap claim.
pub fn tool_allowed(allowlist: &[ToolRule], tool_name: &str, target: Option<&str>) -> bool {
    for rule in allowlist {
        if rule.tool_name != tool_name {
            continue;
        }
        match (&rule.target_pattern, target) {
            (None, _) => return true,
            (Some(pat), Some(t)) => {
                if Regex::new(pat).map(|re| re.is_match(t)).unwrap_or(false) {
                    return true;
                }
            }
            _ => continue,
        }
    }
    false
}
