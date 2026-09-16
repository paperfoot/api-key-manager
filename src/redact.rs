use std::io::{Read, Write};

/// A streaming literal-match redactor.
///
/// Only matches values that AKM itself provided. When a secret is detected, it
/// is replaced with the supplied replacement token (e.g. `[REDACTED:NAME]`).
///
/// Keep only a suffix that could still become a secret. Ordinary progress
/// output is forwarded immediately, even when a stored token is very long.
pub struct Redactor {
    secrets: Vec<(String, String)>,
}

impl Redactor {
    pub fn new(mut secrets: Vec<(String, String)>) -> Self {
        secrets.retain(|(value, _)| !value.is_empty());
        secrets.sort_by_key(|(value, _)| std::cmp::Reverse(value.len()));
        Self { secrets }
    }

    pub fn copy<R: Read, W: Write>(&self, mut input: R, mut output: W) -> std::io::Result<()> {
        let mut pending = Vec::new();
        let mut chunk = [0u8; 8192];
        loop {
            let n = match input.read(&mut chunk) {
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                result => result?,
            };
            pending.extend_from_slice(&chunk[..n]);
            self.flush(&mut pending, &mut output, n == 0)?;
            output.flush()?;
            if n == 0 {
                return Ok(());
            }
        }
    }

    fn flush<W: Write>(
        &self,
        pending: &mut Vec<u8>,
        output: &mut W,
        eof: bool,
    ) -> std::io::Result<()> {
        let mut i = 0;
        let mut emitted = 0;
        'scan: while i < pending.len() {
            let remaining = &pending[i..];
            for (value, replacement) in &self.secrets {
                let token = value.as_bytes();
                // A longer token may be a prefix collision with a shorter one.
                // Wait until that ambiguity is resolved, never emit its suffix.
                if !eof && remaining.len() < token.len() && token.starts_with(remaining) {
                    break 'scan;
                }
                if remaining.starts_with(token) {
                    output.write_all(&pending[emitted..i])?;
                    output.write_all(replacement.as_bytes())?;
                    i += token.len();
                    emitted = i;
                    continue 'scan;
                }
            }
            i += 1;
        }
        output.write_all(&pending[emitted..i])?;
        pending.drain(..i);
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
        let out = redact_str(vec![("notpresent12345", "[REDACTED]")], "hello world\n");
        assert_eq!(out, "hello world\n");
    }

    #[test]
    fn short_tokens_are_secrets_too() {
        let out = redact_str(vec![("abc", "[X]")], "abc 123\n");
        assert_eq!(out, "[X] 123\n");
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
            vec![("longersecret_token_1234", "[L]"), ("shortone12345", "[S]")],
            "longersecret_token_1234 then shortone12345\n",
        );
        assert_eq!(out, "[L] then [S]\n");
    }
}

#[cfg(test)]
mod boundary_tests {
    use super::*;
    struct Chunks {
        bytes: Vec<u8>,
        offset: usize,
        width: usize,
    }
    impl Read for Chunks {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let count = self
                .width
                .min(self.bytes.len() - self.offset)
                .min(buf.len());
            buf[..count].copy_from_slice(&self.bytes[self.offset..self.offset + count]);
            self.offset += count;
            Ok(count)
        }
    }
    #[test]
    fn matches_every_chunk_boundary_and_prefix_collision() {
        let input = "before abcdefghij abcdefgh z abc after";
        for width in 1..=input.len() {
            let mut output = Vec::new();
            Redactor::new(vec![
                ("abcdefgh".into(), "[S]".into()),
                ("abcdefghij".into(), "[L]".into()),
                ("abc".into(), "[T]".into()),
            ])
            .copy(
                Chunks {
                    bytes: input.as_bytes().to_vec(),
                    offset: 0,
                    width,
                },
                &mut output,
            )
            .unwrap();
            assert_eq!(
                String::from_utf8(output).unwrap(),
                "before [L] [S] z [T] after"
            );
        }
    }
}
