/// Semantic exit codes (agent-cli-framework convention).
///
/// Agents read these to decide what to do without parsing stderr.
pub const SUCCESS: u8 = 0;
pub const TRANSIENT: u8 = 1;
#[allow(dead_code)]
pub const CONFIG: u8 = 2;
pub const BAD_INPUT: u8 = 3;
#[allow(dead_code)]
pub const RATE_LIMITED: u8 = 4;
pub const NOT_FOUND: u8 = 6;
