use serde::Serialize;
use serde_json::Value;

#[derive(Debug, Serialize)]
pub struct Envelope<'a> {
    pub version: &'a str,
    pub status: &'a str,
    pub data: Value,
}

#[derive(Debug, Serialize)]
pub struct ErrorEnvelope<'a> {
    pub version: &'a str,
    pub status: &'a str,
    pub error: ErrorBody<'a>,
}

#[derive(Debug, Serialize)]
pub struct ErrorBody<'a> {
    pub code: &'a str,
    pub message: String,
    pub suggestion: Option<String>,
}

pub const VERSION: &str = "1";

pub fn ok(data: Value) -> String {
    let env = Envelope {
        version: VERSION,
        status: "ok",
        data,
    };
    serde_json::to_string(&env).unwrap_or_else(|_| "{}".to_string())
}

pub fn err(code: &str, message: impl Into<String>, suggestion: Option<&str>) -> String {
    let env = ErrorEnvelope {
        version: VERSION,
        status: "error",
        error: ErrorBody {
            code,
            message: message.into(),
            suggestion: suggestion.map(|s| s.to_string()),
        },
    };
    serde_json::to_string(&env).unwrap_or_else(|_| "{}".to_string())
}
