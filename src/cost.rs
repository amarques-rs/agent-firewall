// Static cost table compiled into the binary. v1 ships Claude 4.x rates
// from public API docs. GPT rates left as None until verified at build.
pub fn estimate_usd(model: &str, input_tokens: u64, output_tokens: u64) -> Option<f64> {
    let (in_rate, out_rate) = match model {
        "claude-opus-4-7" => (15.0, 75.0),
        "claude-sonnet-4-6" => (3.0, 15.0),
        "claude-haiku-4-5" => (0.80, 4.0),
        _ => return None,
    };
    let usd = (input_tokens as f64 / 1_000_000.0) * in_rate
        + (output_tokens as f64 / 1_000_000.0) * out_rate;
    Some(usd)
}
