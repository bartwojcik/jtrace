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

fn handle_header<B: BufRead>(f: &mut B) -> Result<ExecutionPathHeader, Box<dyn Error>> {
    let header: ExecutionPathHeader = deserialize_from(f)?;
    // print header info:
    println!("Root parent PID: {}", header.pid);
    print!("CLI: ");
    for s in &header.args {
        print!("{} ", s);
    }
    print!("\n");
    println!("Memory map: ");
    println!("START\t\tEND\t\tOFFSET\t\tFLAGS\t\tFILENAME");
    for map in &header.maps {
        println!("{:#010x}\t{:#010x}\t{:#010x}\t{}\t\t{:?}",
                 map.range_start,
                 map.range_end,
                 map.offset,
                 map.flags,
                 map.pathname.as_ref());
    }
    print!("\n\n");
    Ok(header)
}

fn handle_body<B: BufRead>(f: &mut B, header: &ExecutionPathHeader) -> Result<(), Box<dyn Error>> {
    println!("PID\t\tADDR\t\tBRANCH");
    // loop and read log entries
    loop {
        let buf = f.fill_buf()?;
        let len = buf.len();
        if len == 0 {
            break;
        }
        let consumed = handle_entry(buf, header);
        f.consume(consumed);
    }
    Ok(())
}

fn get_start_for_offset(offset: usize, header: &ExecutionPathHeader) -> Option<usize> {
    for map in &header.maps {
        if offset > map.offset
            && offset < map.offset + (map.range_end - map.range_start)
            && map.flags.contains("x") {
            return Some(map.range_start);
        }
    }
    None
}

fn handle_entry(buf: &[u8], header: &ExecutionPathHeader) -> usize {
    let mut start = 0;
    while buf.len() - start >= size_of::<ExecutionPathEntry>() {
        let entry_buf = &buf[start..start + size_of::<ExecutionPathEntry>()];
        let layout = LayoutVerified::<&[u8], ExecutionPathEntry>::new(entry_buf);
        // print entry info
        if let Some(entry) = layout {
            start += size_of::<ExecutionPathEntry>();
            if let Some(addr_start) = get_start_for_offset(entry.1, header) {
                let addr = addr_start + entry.1;
                println!("{}\t\t{:#010x}\t{}", unsafe { entry.0 }, addr,
                         if entry.2 == 0 { "not taken" } else { "taken" });
            } else {
                println!("{}\t\tinvalid\t{}", unsafe { entry.0 },
                         if entry.2 == 0 { "not taken" } else { "taken" });
            }
        }
    }
    buf.len() - start
}

fn run(args: Cli) -> Result<(), Box<dyn Error>> {
    let f = File::open(&args.input)?;
    let mut f = BufReader::new(f);
    if let Some(filepath) = &args.input.to_str() {
        println!("Reading data from {}", filepath);
    }
    let header = handle_header(&mut f)?;
    handle_body(&mut f, &header)?;
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
