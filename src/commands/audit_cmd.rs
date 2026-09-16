use clap::Args as ClapArgs;
use serde_json::{json, Value};
use std::fs::File;
use std::io::{self, IsTerminal, Read, Seek, SeekFrom};
use std::path::Path;

use crate::audit;
use crate::cli::Global;
use crate::envelope;
use crate::error::{AkmError, Result};
use crate::exit;

const MAX_LIMIT: usize = 10_000;
const READ_BLOCK_SIZE: usize = 8 * 1024;
const MAX_RECORD_BYTES: usize = 1024 * 1024;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Number of most recent entries to print.
    #[arg(long, default_value_t = 50)]
    pub limit: usize,
}

pub fn run(args: Args, global: &Global) -> Result<u8> {
    if args.limit > MAX_LIMIT {
        return Err(AkmError::BadInput(format!(
            "--limit must be between 0 and {MAX_LIMIT}"
        )));
    }
    let path = audit::log_path();
    let entries = tail_records(&path, args.limit)?;

    let json_mode = global.json || !std::io::stdout().is_terminal();
    if json_mode {
        println!(
            "{}",
            envelope::ok(json!({ "entries": entries, "path": path.display().to_string() }))
        );
    } else {
        for entry in entries {
            println!("{entry}");
        }
    }
    Ok(exit::SUCCESS)
}

/// Read the most recent valid JSONL records without loading the full audit log.
/// A final line without a newline may still be in flight, so it is ignored.
fn tail_records(path: &Path, limit: usize) -> io::Result<Vec<Value>> {
    if limit == 0 {
        return Ok(Vec::new());
    }

    let mut file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error),
    };
    let mut position = file.seek(SeekFrom::End(0))?;
    if position == 0 {
        return Ok(Vec::new());
    }

    file.seek(SeekFrom::End(-1))?;
    let mut last_byte = [0u8; 1];
    file.read_exact(&mut last_byte)?;
    let mut skip_trailing_partial = last_byte[0] != b'\n';

    let mut newest_first = Vec::new();
    let mut suffix = Vec::new();

    while position > 0 && newest_first.len() < limit {
        let read_len = position.min(READ_BLOCK_SIZE as u64) as usize;
        position -= read_len as u64;
        file.seek(SeekFrom::Start(position))?;

        let mut block = vec![0u8; read_len];
        file.read_exact(&mut block)?;
        block.extend_from_slice(&suffix);

        let mut line_end = block.len();
        for newline in (0..block.len())
            .rev()
            .filter(|&index| block[index] == b'\n')
        {
            let line = &block[newline + 1..line_end];
            if skip_trailing_partial {
                skip_trailing_partial = false;
            } else if let Ok(record) = serde_json::from_slice::<Value>(line) {
                newest_first.push(record);
                if newest_first.len() == limit {
                    break;
                }
            }
            line_end = newline;
        }

        if newest_first.len() == limit {
            break;
        }
        if line_end > MAX_RECORD_BYTES {
            // Skip an oversized/corrupt line without retaining it in memory.
            suffix.clear();
            skip_trailing_partial = true;
        } else {
            suffix = block[..line_end].to_vec();
        }
    }

    if position == 0 && !skip_trailing_partial && newest_first.len() < limit {
        if let Ok(record) = serde_json::from_slice::<Value>(&suffix) {
            newest_first.push(record);
        }
    }

    newest_first.reverse();
    Ok(newest_first)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn ids(records: &[Value]) -> Vec<u64> {
        records
            .iter()
            .filter_map(|record| record.get("id").and_then(Value::as_u64))
            .collect()
    }

    #[test]
    fn empty_and_missing_logs_have_no_records() {
        let directory = tempfile::tempdir().unwrap();
        assert!(tail_records(&directory.path().join("missing.log"), 10)
            .unwrap()
            .is_empty());

        let file = NamedTempFile::new().unwrap();
        assert!(tail_records(file.path(), 10).unwrap().is_empty());
    }

    #[test]
    fn skips_malformed_and_trailing_partial_lines() {
        let mut file = NamedTempFile::new().unwrap();
        write!(file, "{{\"id\":1}}\nmalformed\n{{\"id\":2}}\n{{\"id\":3}}").unwrap();
        file.flush().unwrap();

        assert_eq!(ids(&tail_records(file.path(), 10).unwrap()), vec![1, 2]);
        assert_eq!(ids(&tail_records(file.path(), 1).unwrap()), vec![2]);
    }

    #[test]
    fn reads_records_across_block_boundaries() {
        let mut file = NamedTempFile::new().unwrap();
        let padding = "x".repeat(READ_BLOCK_SIZE + 257);
        writeln!(file, "{{\"id\":1,\"padding\":\"{padding}\"}}").unwrap();
        writeln!(file, "{{\"id\":2}}").unwrap();
        file.flush().unwrap();

        assert_eq!(ids(&tail_records(file.path(), 2).unwrap()), vec![1, 2]);
    }

    #[test]
    fn skips_oversized_corrupt_line_and_keeps_older_records() {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "{{\"id\":1}}").unwrap();
        file.write_all(&vec![b'x'; MAX_RECORD_BYTES * 2]).unwrap();
        writeln!(file).unwrap();
        writeln!(file, "{{\"id\":2}}").unwrap();
        file.flush().unwrap();
        assert_eq!(ids(&tail_records(file.path(), 5).unwrap()), vec![1, 2]);
    }

    #[test]
    fn zero_limit_returns_before_io() {
        let directory = tempfile::tempdir().unwrap();
        assert!(tail_records(directory.path(), 0).unwrap().is_empty());
        assert!(tail_records(directory.path(), 1).is_err());
    }

    #[test]
    fn stops_before_huge_historical_prefix() {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(&vec![b'x'; READ_BLOCK_SIZE * 256]).unwrap();
        writeln!(file).unwrap();
        writeln!(file, "{{\"id\":1}}").unwrap();
        writeln!(file, "{{\"id\":2}}").unwrap();
        writeln!(file, "{{\"id\":3}}").unwrap();
        file.flush().unwrap();

        assert_eq!(ids(&tail_records(file.path(), 2).unwrap()), vec![2, 3]);
    }

    #[test]
    fn rejects_limit_above_maximum_before_reading_log() {
        let result = run(
            Args {
                limit: MAX_LIMIT + 1,
            },
            &Global::default(),
        );
        assert!(matches!(result, Err(AkmError::BadInput(_))));
    }
}
