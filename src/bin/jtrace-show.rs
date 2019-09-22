extern crate jtrace;

use std::borrow::Borrow;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::mem::size_of;
use std::path::PathBuf;

use bincode::deserialize_from;
use log::{debug, error, info, trace, warn};
use structopt::StructOpt;
use zerocopy::LayoutVerified;

use jtrace::{ExecutionPathEntry, ExecutionPathHeader};

#[derive(StructOpt)]
/// Print to the stdout the saved execution path of a program.
struct Cli {
    /// File containing the saved execution path
    #[structopt(parse(from_os_str))]
    input: PathBuf,
}

fn handle_header<B: BufRead>(f: &mut B) -> Result<(), Box<dyn Error>> {
    let header: ExecutionPathHeader = deserialize_from(f)?;
    // print header info:
    println!("Root parent PID: {}", header.pid);
    print!("CLI: ");
    for s in header.args {
        print!("{} ", s);
    }
    print!("\n\n");
    Ok(())
}

fn handle_body<B: BufRead>(f: &mut B) -> Result<(), Box<dyn Error>> {
    println!("<PID> <ADDR> <TAKEN>");
    // loop and read log entries
    loop {
        let buf = f.fill_buf()?;
        let len = buf.len();
        if len == 0 {
            break;
        }
        handle_entry(buf, len);
        f.consume(len);
    }
    Ok(())
}

fn handle_entry(buf: &[u8], len: usize) {
    let mut start = 0;
    while len - start >= size_of::<ExecutionPathEntry>() {
        let entry_buf = &buf[start..start + size_of::<ExecutionPathEntry>()];
        let layout = LayoutVerified::<&[u8], ExecutionPathEntry>::new(entry_buf);
        // print entry info
        if let Some(entry) = layout {
            start += size_of::<ExecutionPathEntry>();
            println!("{} {:#x} {}", unsafe { entry.0 }, unsafe { entry.1 },
                     if entry.2 == 0 { "not taken" } else { "taken" });
//            println!("{} {:#x} {}", entry.0, entry.1, entry.2 > 0);
        }
//        println!("start: {} len: {}", start, len);
    }
}

fn run(args: Cli) -> Result<(), Box<dyn Error>> {
    let f = File::open(args.input)?;
    let mut f = BufReader::new(f);
    handle_header(&mut f)?;
    handle_body(&mut f)?;
    Ok(())
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