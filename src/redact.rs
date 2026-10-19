use std::io::{Read, Write};

/// A streaming literal-match redactor.
///
/// Only matches values that AKM itself provided. When a secret is detected, it
/// is replaced with the supplied replacement token (e.g. `[REDACTED:NAME]`).
///
/// Keep only a suffix that could still become a secret. Ordinary progress
/// output is forwarded immediately, even when a stored token is very long.
///
/// Only a position whose first two bytes begin some secret (or whose single
/// remaining byte does) can start a match or a held prefix. The scan jumps
/// between such positions (memchr for up to three distinct first bytes, then
/// a two-byte bitset) and checks only the secrets that start there.
pub struct Redactor {
    /// Longest first, so a longer secret wins over its own prefix.
    secrets: Vec<(Vec<u8>, Vec<u8>)>,
    /// Indices into `secrets` by first byte, longest first.
    by_first: Vec<Vec<usize>>,
    first: Box<[bool; 256]>,
    /// Bit `(a << 8) | b` is set when some secret starts with `a, b`.
    pairs: Box<[u64; 1024]>,
    finder: Finder,
}

enum Finder {
    None,
    One(u8),
    Two(u8, u8),
    Three(u8, u8, u8),
    Many,
}

impl Redactor {
    pub fn new(secrets: Vec<(String, String)>) -> Self {
        let mut secrets: Vec<(Vec<u8>, Vec<u8>)> = secrets
            .into_iter()
            .filter(|(value, _)| !value.is_empty())
            .map(|(value, replacement)| (value.into_bytes(), replacement.into_bytes()))
            .collect();
        secrets.sort_by_key(|(value, _)| std::cmp::Reverse(value.len()));
        let mut by_first = vec![Vec::new(); 256];
        let mut first = Box::new([false; 256]);
        let mut pairs = Box::new([0u64; 1024]);
        for (index, (value, _)) in secrets.iter().enumerate() {
            let a = usize::from(value[0]);
            by_first[a].push(index);
            first[a] = true;
            // A one-byte secret matches whatever follows it.
            let seconds = match value.get(1) {
                Some(b) => usize::from(*b)..usize::from(*b) + 1,
                None => 0..256,
            };
            for b in seconds {
                let bit = (a << 8) | b;
                pairs[bit >> 6] |= 1 << (bit & 63);
            }
        }
        let firsts: Vec<u8> = (0..=255u8)
            .filter(|b| !by_first[usize::from(*b)].is_empty())
            .collect();
        let finder = match *firsts.as_slice() {
            [] => Finder::None,
            [a] => Finder::One(a),
            [a, b] => Finder::Two(a, b),
            [a, b, c] => Finder::Three(a, b, c),
            _ => Finder::Many,
        };
        Self {
            secrets,
            by_first,
            first,
            pairs,
            finder,
        }
    }

    /// Offset of the next position in `haystack` that may start a secret:
    /// its first two bytes begin one, or it is the last byte.
    fn next_candidate(&self, haystack: &[u8]) -> Option<usize> {
        let mut i = 0;
        loop {
            // Dense first bytes are checked inline, sparse ones by search.
            if !self.first[usize::from(*haystack.get(i)?)] {
                let rest = &haystack[i..];
                i += match self.finder {
                    Finder::None => return None,
                    Finder::One(a) => memchr::memchr(a, rest)?,
                    Finder::Two(a, b) => memchr::memchr2(a, b, rest)?,
                    Finder::Three(a, b, c) => memchr::memchr3(a, b, c, rest)?,
                    Finder::Many => rest.iter().position(|b| self.first[usize::from(*b)])?,
                };
            }
            let Some(&second) = haystack.get(i + 1) else {
                return Some(i);
            };
            let bit = (usize::from(haystack[i]) << 8) | usize::from(second);
            if self.pairs[bit >> 6] & (1 << (bit & 63)) != 0 {
                return Some(i);
            }
            i += 1;
        }
    }

    pub fn copy<R: Read, W: Write>(&self, mut input: R, mut output: W) -> std::io::Result<()> {
        let mut pending = Vec::new();
        // read() returns whatever the pipe holds, so a large buffer adds no
        // latency; it only cuts syscalls for bulk output.
        let mut chunk = vec![0u8; 64 * 1024];
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
            match self.next_candidate(&pending[i..]) {
                Some(offset) => i += offset,
                None => {
                    i = pending.len();
                    break;
                }
            }
            let remaining = &pending[i..];
            for &index in &self.by_first[usize::from(remaining[0])] {
                let (token, replacement) = &self.secrets[index];
                // Cheap reject: a differing second byte rules out both a match
                // and a held prefix.
                if token.len() > 1 && remaining.len() > 1 && token[1] != remaining[1] {
                    continue;
                }
                if remaining.len() < token.len() {
                    // A longer token may be a prefix collision with a shorter
                    // one. Wait until that ambiguity is resolved; never emit
                    // its suffix.
                    if !eof && token.starts_with(remaining) {
                        break 'scan;
                    }
                    continue;
                }
                if remaining.starts_with(token) {
                    output.write_all(&pending[emitted..i])?;
                    output.write_all(replacement)?;
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

    /// Whole-input reference: at every position, the longest secret wins.
    fn reference(secrets: &[(String, String)], input: &[u8]) -> Vec<u8> {
        let mut sorted = secrets.to_vec();
        sorted.sort_by_key(|(value, _)| std::cmp::Reverse(value.len()));
        let (mut out, mut i) = (Vec::new(), 0);
        'scan: while i < input.len() {
            for (value, replacement) in &sorted {
                if input[i..].starts_with(value.as_bytes()) {
                    out.extend_from_slice(replacement.as_bytes());
                    i += value.len();
                    continue 'scan;
                }
            }
            out.push(input[i]);
            i += 1;
        }
        out
    }

    #[test]
    fn candidate_skipping_matches_the_reference_for_every_finder() {
        // One, two, three and many distinct first bytes exercise each finder.
        let all = ["ab", "abab", "ba", "cab", "dc", "bbbbbbbb", "a"];
        for count in [1, 2, 4, 5, 7] {
            let secrets: Vec<(String, String)> = all[..count]
                .iter()
                .enumerate()
                .map(|(n, v)| (v.to_string(), format!("<{n}>")))
                .collect();
            let mut seed = 0x2545_f491_u32 ^ count as u32;
            let input: Vec<u8> = (0..400)
                .map(|_| {
                    seed = seed.wrapping_mul(1_103_515_245).wrapping_add(12_345);
                    b"abcdx\n"[(seed >> 16) as usize % 6]
                })
                .collect();
            let expected = reference(&secrets, &input);
            for width in [1, 2, 3, 5, 7, 64, 400] {
                let mut output = Vec::new();
                Redactor::new(secrets.clone())
                    .copy(
                        Chunks {
                            bytes: input.clone(),
                            offset: 0,
                            width,
                        },
                        &mut output,
                    )
                    .unwrap();
                assert_eq!(output, expected, "{count} secrets, width {width}");
            }
        }
    }
}
