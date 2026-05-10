use crate::session::ToolRule;

// v1: literal tool_name match; target_pattern is a substring check.
// Day 3 of the shipping plan upgrades target_pattern to a compiled regex.
pub fn tool_allowed(allowlist: &[ToolRule], tool_name: &str, target: Option<&str>) -> bool {
    for rule in allowlist {
        if rule.tool_name != tool_name {
            continue;
        }
        match (&rule.target_pattern, target) {
            (None, _) => return true,
            (Some(pat), Some(t)) if t.contains(pat) => return true,
            _ => continue,
        }
    }
    false
}
