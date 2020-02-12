use std::borrow::Borrow;
use std::cmp::max;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::hash::BuildHasherDefault;
use std::io::{BufRead, BufReader};
use std::mem::size_of;
use std::path::PathBuf;

use ahash::AHasher;
use bincode::deserialize_from;
use libc::pid_t;
use log::{debug, error, info, trace, warn};
use structopt::StructOpt;
use zerocopy::LayoutVerified;

use jtrace::{ExecutionPathEntry, ExecutionPathHeader};

#[derive(StructOpt)]
/// Compare two saved execution paths of a program.
struct Cli {
    /// First file containing the saved execution path
    #[structopt(parse(from_os_str))]
    left_input: PathBuf,
    /// First file containing the saved execution path
    #[structopt(parse(from_os_str))]
    right_input: PathBuf,
}

const EXEC_LOG_SIZE: usize = 64 * 1024 * 1024;

type ExecutionEntry = (usize, u8);
type ExecutionLog = Vec<ExecutionEntry>;
type ExecutionMap = HashMap::<pid_t, ExecutionLog, BuildHasherDefault<AHasher>>;

fn read_entries<B: BufRead>(f: &mut B) -> Result<ExecutionMap,
    Box<dyn Error>> {
    let mut exec_log = ExecutionMap::with_capacity_and_hasher(
        16,
        BuildHasherDefault::<AHasher>::default(),
    );
    loop {
        let buf = f.fill_buf()?;
        if buf.len() == 0 {
            break;
        }
        let mut start = 0;
        while buf.len() - start >= size_of::<ExecutionPathEntry>() {
            let entry_buf = &buf[start..start + size_of::<ExecutionPathEntry>()];
            let layout = LayoutVerified::<&[u8], ExecutionPathEntry>::new(entry_buf);
            if let Some(path_entry) = layout {
                start += size_of::<ExecutionPathEntry>();
                // insert pid entry into the corresponding vector
                let vec = exec_log.entry(path_entry.0)
                    .or_insert_with(|| Vec::with_capacity(EXEC_LOG_SIZE));
                // pid is not needed here
                vec.push((path_entry.1, path_entry.2));
            }
        }
        f.consume(start);
    }
    Ok(exec_log)
}

// TODO possibly save pids order when tracing and create map based on this?
type AddrsSet = HashSet<usize, BuildHasherDefault<AHasher>>;
type PidUniqueMap = HashMap::<pid_t, AddrsSet, BuildHasherDefault<AHasher>>;
type PidMap = HashMap<pid_t, pid_t, BuildHasherDefault<AHasher>>;

const ADDR_SET_SIZE: usize = 1024;

fn unique_addrs(exec_map: &ExecutionMap) -> PidUniqueMap {
    let mut exec_map_uniques: PidUniqueMap =
        PidUniqueMap::with_capacity_and_hasher(exec_map.len(),
                                               BuildHasherDefault::<AHasher>::default());
    for (pid, log) in exec_map {
        let mut set = AddrsSet::with_capacity_and_hasher(ADDR_SET_SIZE,
                                                         BuildHasherDefault::<AHasher>::default());
        for entry in log {
            set.insert(entry.0);
        }
        exec_map_uniques.insert(*pid, set);
    }
    exec_map_uniques
}

fn map_by_set_similarity(left_map: &ExecutionMap, right_map: &ExecutionMap) -> PidMap {
    let mut pid_map = PidMap::with_capacity_and_hasher(
        max(left_map.len(), right_map.len()),
        BuildHasherDefault::<AHasher>::default(),
    );
    let left_uniques = unique_addrs(left_map);
    let mut right_uniques = unique_addrs(right_map);
    // map each left pid to the most similar right pid
    for (pid_l, uniques_l) in &left_uniques {
        let mut best_similarity = 0;
        let mut best_pid = 0;
        for (pid_r, uniques_r) in &right_uniques {
            let similarity = uniques_l.intersection(&uniques_r).count();
            if similarity > best_similarity {
                best_similarity = similarity;
                best_pid = *pid_r;
            }
        }
        if best_pid != 0 {
            pid_map.insert(*pid_l, best_pid);
            // one-to-one map
            right_uniques.remove(&best_pid);
        }
    }
    pid_map
}

fn run(args: Cli) -> Result<(), Box<dyn Error>> {
    let mut f_left = BufReader::new(File::open(&args.left_input)?);
    let mut f_right = BufReader::new(File::open(&args.right_input)?);
    if let Some(left_filepath) = &args.left_input.to_str() {
        if let Some(right_filepath) = &args.right_input.to_str() {
            println!("Reading data from:\n{}\n{}", left_filepath, right_filepath);
        }
    }
    let left_header: ExecutionPathHeader = deserialize_from(&mut f_left)?;
    let right_header: ExecutionPathHeader = deserialize_from(&mut f_right)?;
    let left_log = read_entries(&mut f_left)?;
    let right_log = read_entries(&mut f_right)?;
    let pid_map = map_by_set_similarity(&left_log, &right_log);
    // TODO
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
