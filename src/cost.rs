// Static cost table compiled into the binary. Claude 4.x + GPT-4.1/5 rates from public API docs (verified 2026-05-10).
pub fn estimate_usd(model: &str, input_tokens: u64, output_tokens: u64) -> Option<f64> {
    let (in_rate, out_rate) = match model {
        "claude-opus-4-7" => (15.0, 75.0),
        "claude-sonnet-4-6" => (3.0, 15.0),
        "claude-haiku-4-5" => (0.80, 4.0),
        "gpt-4.1" => (2.0, 8.0),
        "gpt-4.1-mini" => (0.40, 1.60),
        "gpt-5" => (1.25, 10.0),
        "gpt-5-mini" => (0.25, 2.0),
        _ => return None,
    };
    let usd = (input_tokens as f64 / 1_000_000.0) * in_rate
        + (output_tokens as f64 / 1_000_000.0) * out_rate;
    Some(usd)
}
