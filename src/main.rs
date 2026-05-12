use std::process::ExitCode;

mod audit;
mod cli;
mod commands;
mod envelope;
mod exit;
mod keychain;
mod redact;
mod skill;

fn main() -> ExitCode {
    let exit_code = cli::run();
    ExitCode::from(exit_code)
}
