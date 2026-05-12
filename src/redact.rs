use std::io::{Read, Write};

/// A streaming literal-match redactor.
///
/// Only matches values that AKM itself provided. When a secret is detected, it
/// is replaced with the supplied replacement token (e.g. `[REDACTED:NAME]`).
///
/// Two properties:
/// 1. Secrets are sorted by descending length, so a longer secret always wins
///    over any of its prefixes. (Fixes "prefix collision" leak where a shorter
///    secret was a prefix of a longer one.)
/// 2. We keep `max_secret_len - 1` bytes of lookahead so a match cannot span a
///    read boundary.
pub struct Redactor {
    secrets: Vec<(String, String)>,
    max_secret_len: usize,
}

impl Redactor {
    pub fn new(secrets: Vec<(String, String)>) -> Self {
        let mut secrets: Vec<_> = secrets
            .into_iter()
            .filter(|(t, _)| t.len() >= 8)
            .collect();
        // Sort by descending length so longer secrets take priority.
        secrets.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        let max_secret_len = secrets.iter().map(|(t, _)| t.len()).max().unwrap_or(0);
        Self {
            secrets,
            max_secret_len,
        }
    }

    pub fn copy<R: Read, W: Write>(&self, mut input: R, mut output: W) -> std::io::Result<()> {
        if self.secrets.is_empty() {
            std::io::copy(&mut input, &mut output)?;
            return Ok(());
        }
        let mut buf = Vec::with_capacity(64 * 1024);
        let mut chunk = [0u8; 8192];
        loop {
            let n = input.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            self.flush_safe_region(&mut buf, &mut output)?;
        }
        self.flush_all(&mut buf, &mut output)?;
        Ok(())
    }

    fn try_match_at(&self, buf: &[u8], i: usize) -> Option<(usize, &str)> {
        for (token, repl) in &self.secrets {
            let tb = token.as_bytes();
            if i + tb.len() <= buf.len() && &buf[i..i + tb.len()] == tb {
                return Some((tb.len(), repl.as_str()));
            }
        }
        None
    }

    fn flush_safe_region<W: Write>(
        &self,
        buf: &mut Vec<u8>,
        out: &mut W,
    ) -> std::io::Result<()> {
        if buf.len() < self.max_secret_len {
            return Ok(());
        }
        let safe_end = buf.len() - (self.max_secret_len - 1);
        let mut i = 0;
        let mut emitted = 0;
        while i < safe_end {
            if let Some((mlen, repl)) = self.try_match_at(buf, i) {
                out.write_all(&buf[emitted..i])?;
                out.write_all(repl.as_bytes())?;
                i += mlen;
                emitted = i;
            } else {
                i += 1;
            }
        }
        let drain_to = emitted.max(safe_end);
        if emitted < drain_to {
            out.write_all(&buf[emitted..drain_to])?;
        }
        buf.drain(..drain_to);
        Ok(())
    }

    fn flush_all<W: Write>(&self, buf: &mut Vec<u8>, out: &mut W) -> std::io::Result<()> {
        let mut i = 0;
        let mut emitted = 0;
        while i < buf.len() {
            if let Some((mlen, repl)) = self.try_match_at(buf, i) {
                out.write_all(&buf[emitted..i])?;
                out.write_all(repl.as_bytes())?;
                i += mlen;
                emitted = i;
            } else {
                i += 1;
            }
        }
        if emitted < buf.len() {
            out.write_all(&buf[emitted..])?;
        }
        buf.clear();
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn redact_str(secrets: Vec<(&str, &str)>, input: &str) -> String {
        let pairs: Vec<(String, String)> = secrets
            .into_iter()
            .map(|(t, r)| (t.to_string(), r.to_string()))
            .collect();
        let r = Redactor::new(pairs);
        let mut out = Vec::new();
        r.copy(input.as_bytes(), &mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn full_match_in_line() {
        let out = redact_str(
            vec![("sk-test-1234567890abcdef", "[REDACTED:K]")],
            "VALUE=sk-test-1234567890abcdef\n",
        );
        assert_eq!(out, "VALUE=[REDACTED:K]\n");
    }

    #[test]
    fn multiple_matches() {
        let out = redact_str(
            vec![("supersecretkey", "[REDACTED]")],
            "a=supersecretkey, b=supersecretkey\n",
        );
        assert_eq!(out, "a=[REDACTED], b=[REDACTED]\n");
    }

    #[test]
    fn no_match() {
        let out = redact_str(
            vec![("notpresent12345", "[REDACTED]")],
            "hello world\n",
        );
        assert_eq!(out, "hello world\n");
    }

    #[test]
    fn short_tokens_skipped() {
        let out = redact_str(vec![("abc", "[X]")], "abc 123\n");
        assert_eq!(out, "abc 123\n");
    }

    #[test]
    fn prefix_collision_longer_wins() {
        // Reproduces Codex finding #8: shorter secret was a prefix of longer
        // secret, first-match-wins leaked the suffix.
        let out = redact_str(
            vec![("abcdefgh", "[SHORT]"), ("abcdefghij", "[LONG]")],
            "abcdefghij\n",
        );
        assert_eq!(out, "[LONG]\n");
    }

    #[test]
    fn prefix_collision_order_independent() {
        let out = redact_str(
            vec![("abcdefghij", "[LONG]"), ("abcdefgh", "[SHORT]")],
            "abcdefghij\n",
        );
        assert_eq!(out, "[LONG]\n");
    }

    #[test]
    fn short_secret_after_long_is_caught() {
        // Long secret eats its match; remaining bytes still contain the short
        // secret and it should be redacted on a subsequent scan position.
        let out = redact_str(
            vec![
                ("longersecret_token_1234", "[L]"),
                ("shortone12345", "[S]"),
            ],
            "longersecret_token_1234 then shortone12345\n",
        );
        assert_eq!(out, "[L] then [S]\n");
    }
}
