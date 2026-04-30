mod audit;
mod cli;
mod crypto;
mod errors;
mod report;
mod scanner;
mod system_guard;
mod tui_app;
mod vault;

use anyhow::Result;
use clap::Parser;
use cli::Cli;

fn main() -> Result<()> {
    let cli = Cli::parse();
    cli::dispatch(cli)
}
