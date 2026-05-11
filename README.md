# agent-firewall

Hard per-session limits on dollars, tokens, calls, time, and tools — enforced atomically before each LLM or tool call. Returns `allow` or one of eight `deny:*` reasons in sub-5ms.

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/built_with-Rust-orange.svg)](https://www.rust-lang.org/)
[![RapidAPI](https://img.shields.io/badge/listed_on-RapidAPI-1F2C5C.svg)](https://rapidapi.com/entrepreneurloop/api/agentfirewall)

## What this is

LLM agents fail in two shapes: **spend overruns** (the $4,200 OpenAI bill on a $500 budget) and **rogue tool calls** (an agent hitting an API it shouldn't). Both fail open by default — your code asks the model what to do next, and what to do next eats budget or touches systems you didn't intend.

Agent-firewall sits in front of your model + tool calls. You open a session with hard limits — dollars, input tokens, output tokens, calls, TTL, and a per-session tool allowlist. Every model call and tool call hits `POST /v1/check` first. The decision is taken on an atomic sled CAS — two concurrent checks against a $0.01 remaining budget will return at most one `allow`. Sub-5ms p99 on warm sessions. Hard deny when any limit is exceeded — not a soft warning, not a throttle.

## Quickstart

### 1. Open a session

```bash
curl -X POST https://agentfirewall.p.rapidapi.com/v1/session \
  -H "Content-Type: application/json" \
  -H "X-RapidAPI-Key: YOUR_KEY" \
  -H "X-RapidAPI-Host: agentfirewall.p.rapidapi.com" \
  -d '{
    "session_id": "sess_abc123",
    "limits": {
      "max_usd": 5.00,
      "max_input_tokens": 100000,
      "max_output_tokens": 50000,
      "max_calls": 200,
      "ttl_seconds": 3600
    },
    "tool_allowlist": [
      {"tool_name": "http.get", "target_pattern": "^https://api\\.example\\.com/"}
    ]
  }'
```

### 2. Check before every model or tool call

```bash
curl -X POST https://agentfirewall.p.rapidapi.com/v1/check \
  -H "Content-Type: application/json" \
  -H "X-RapidAPI-Key: YOUR_KEY" \
  -H "X-RapidAPI-Host: agentfirewall.p.rapidapi.com" \
  -d '{
    "kind": "model",
    "session_id": "sess_abc123",
    "model": "claude-opus-4-7",
    "projected_input_tokens": 2400,
    "projected_output_tokens": 1200
  }'
```

Returns `decision: "allow"` or `decision: "deny"` + a `reason`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| `POST` | `/v1/session` | Open a session with limits + tool allowlist |
| `POST` | `/v1/check` | Gate one model or tool call |
| `POST` | `/v1/session/{id}/kill` | Revoke instantly (admin auth) |
| `GET`  | `/metrics` | Prometheus metrics |

## Deny reasons

- `session_budget_exhausted_usd`
- `session_budget_exhausted_tokens`
- `session_budget_exhausted_calls`
- `session_expired`
- `session_killed`
- `tool_not_in_allowlist`
- `tool_target_blocked`
- `unknown_model`

## Pricing

Listed on RapidAPI: https://rapidapi.com/entrepreneurloop/api/agentfirewall

- Free — 1,000 checks/mo
- Basic ($9/mo) — 50,000 checks/mo
- Pro ($29/mo) — 250,000 checks/mo
- Ultra ($99/mo) — 1,500,000 checks/mo

## What this is NOT

- Not a prompt-injection blocker. Use Lakera or Llama Guard for that.
- Not a network egress firewall. Use Pipelock for that.
- Not an LLM gateway with routing or caching. Use Portkey for that.

It does one thing: enforce hard per-session limits that are atomic, auditable, and revocable.

## Run locally

```bash
cargo run --release
# Server listens on PORT (default 8080), persists state to SLED_PATH (default ./data/firewall.sled)
```

## Tests

```bash
cargo test
```

12 integration tests covering atomic CAS under 50-way concurrency, anchored-regex tool gating, kill propagation, proxy-secret middleware, audit-row persistence, and end-to-end metrics-text format assertion.

## License

MIT. See [LICENSE](LICENSE).

## Issues

https://github.com/amarques-rs/agent-firewall/issues
