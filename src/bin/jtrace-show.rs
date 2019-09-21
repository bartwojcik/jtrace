extern crate jtrace;

use std::borrow::Borrow;
use std::error::Error;
use std::path::PathBuf;

use log::{debug, error, info, trace, warn};
use structopt::StructOpt;

use jtrace::{ExecutionPathEntry, ExecutionPathHeader};
use std::fs::File;

#[derive(StructOpt)]
/// Print to the stdout the saved execution path of a program.
struct Cli {
    /// File containing the saved execution path
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

fn run(args: Cli) -> Result<(), Box<dyn Error>> {
    let f = File::open(args.input)?;
    let f = BufReader::new(f);

    // read
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
fn main() {
    env_logger::init();
    let args = Cli::from_args();
    if let Err(top_e) = run(args) {
        error!("{}", top_e.to_string());
        let mut e: &dyn Error = top_e.borrow();
        while let Some(source) = e.source() {
            error!("Caused by: {}", source.to_string());
            e = source;
        }
    }
}