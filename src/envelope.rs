//! Output envelopes (agent-cli-framework, envelope version 1).
//! Success goes to stdout; errors go to stderr. `agent-info` is raw JSON.
use serde::Serialize;
use serde_json::Value;

pub const VERSION: &str = "1";

#[derive(Serialize)]
struct Success {
    version: &'static str,
    status: &'static str,
    data: Value,
}

#[derive(Serialize)]
struct Failure<'a> {
    version: &'static str,
    status: &'static str,
    error: ErrorBody<'a>,
}

#[derive(Serialize)]
struct ErrorBody<'a> {
    code: &'a str,
    message: String,
    suggestion: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    retryable: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<&'a Value>,
}

/// `{version, status: "success", data}`.
pub fn ok(data: Value) -> String {
    let envelope = Success {
        version: VERSION,
        status: "success",
        data,
    };
    serde_json::to_string(&envelope).expect("a JSON value always serializes")
}

/// `{version, status: "error", error: {code, message, suggestion, retryable?, details?}}`.
pub fn err(
    code: &str,
    message: impl Into<String>,
    suggestion: &str,
    retryable: Option<bool>,
    details: Option<&Value>,
) -> String {
    let envelope = Failure {
        version: VERSION,
        status: "error",
        error: ErrorBody {
            code,
            message: message.into(),
            suggestion,
            retryable,
            details,
        },
    };
    serde_json::to_string(&envelope).expect("strings and JSON values always serialize")
}
