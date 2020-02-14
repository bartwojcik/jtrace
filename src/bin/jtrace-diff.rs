use std::borrow::Borrow;
use std::cmp::{max, min};
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
    // TODO possibly construct a similarity matrix and match most similar globally, not in sequence
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

type DiffedExecutionLog = (ExecutionLog, Vec<bool>);

fn middle_snake(left_sequence: &[ExecutionEntry], right_sequence: &[ExecutionEntry])
                -> (i64, (i64, i64), (i64, i64)) {
    let n = left_sequence.len() as i64;
    let m = left_sequence.len() as i64;
    let size_max = n + m;
    let delta = n - m;
    let v_size = 2 * min(n, m) + 2;
    let mut v_f = vec![-1; v_size as usize];
    let mut v_b = vec![-1; v_size as usize];
    v_f[1] = 0;
    v_b[1] = 0;
    for d in 0..(size_max / 2 + (size_max % 2) + 1) {
        let mut k = -(d - 2 * max(0, d - m));
        while k <= d - 2 * max(0, d - n) {
            let mut x;
            // select better incoming path
            if k == -d || k != d
                && v_f[((k - 1) % v_size) as usize] < v_f[((k + 1) % v_size) as usize] {
                x = v_f[((k + 1) % v_size) as usize];
            } else {
                x = v_f[((k - 1) % v_size) as usize] + 1;
            }
            let mut y = x - k;
            // save the coordinates of the snake's starting point
            let x_i = x;
            let y_i = y;
            // follow the diagonals
            while x < n && y < m && left_sequence[x as usize] == right_sequence[y as usize] {
                x += 1;
                y += 1;
            }
            // fill the new best value
            v_f[(k % v_size) as usize] = x;
            let inverse_k = -(k - delta);
            if delta % 2 == 1 && inverse_k >= -(d - 1) && inverse_k <= (d - 1)
                && v_f[(k % v_size) as usize] + v_b[(inverse_k % v_size) as usize] >= n {
                return (2 * d - 1, (x_i, y_i), (x, y));
            }
            k += 2;
        }
        k = -(d - 2 * max(0, d - m));
        while k <= d - 2 * max(0, d - n) {
            let mut x;
            // select better incoming path
            if k == -d || k != d
                && v_b[((k - 1) % v_size) as usize] < v_b[((k + 1) % v_size) as usize] {
                x = v_b[((k + 1) % v_size) as usize];
            } else {
                x = v_b[((k - 1) % v_size) as usize] + 1;
            }
            let mut y = x - k;
            // save the coordinates of the snake's starting point
            let x_i = x;
            let y_i = y;
            // follow the diagonals
            while x < n && y < m
                && left_sequence[(n - x - 1) as usize] == right_sequence[(m - y - 1) as usize] {
                x += 1;
                y += 1;
            }
            // fill the new best value
            v_b[(k % v_size) as usize] = x;
            let inverse_k = -(k - delta);
            if delta % 2 == 1 && inverse_k >= -d && inverse_k <= d
                && v_b[(k % v_size) as usize] + v_b[(inverse_k % v_size) as usize] >= n {
                return (2 * d, (n - x, m - y), (n - x_i, m - y_i));
            }
            k += 2;
        }
    }
    unreachable!();
}

fn lcs(left_sequence: &[ExecutionEntry],
       right_sequence: &[ExecutionEntry],
       output: &mut ExecutionLog) {
    let n = left_sequence.len();
    let m = right_sequence.len();
    if n > 0 && m > 0 {
        let (d, (x, y), (u, v)) = middle_snake(left_sequence, right_sequence);
        let (x, y, u, v) = (x as usize, y as usize, u as usize, v as usize);
        if d > 1 {
            lcs(&left_sequence[0..x], &right_sequence[0..y], output);
            output.extend_from_slice(&left_sequence[x..u]);
            lcs(&left_sequence[u..n], &right_sequence[v..m], output);
        } else if right_sequence.len() > left_sequence.len() {
            output.extend_from_slice(&left_sequence[0..n]);
        } else {
            output.extend_from_slice(&right_sequence[0..m]);
        }
    }
}

/// Uses the recursive EW Myers's algorithm from the 1986 paper
/// 'AnO(ND) difference algorithm and its variations'
/// for finding the LCS.
/// Includes refinements from https://blog.robertelder.org/diff-algorithm/
/// see also:
/// https://github.com/RobertElderSoftware/roberteldersoftwarediff/blob/master/myers_diff_and_variations.py
fn find_lcs(left_log: &ExecutionLog, right_log: &ExecutionLog) -> ExecutionLog {
    let mut lcsed = ExecutionLog::new();
    lcs(left_log, right_log, &mut lcsed);
    lcsed
}


//fn find_difference(left_log: &ExecutionLog, right_log: &ExecutionLog)
//                   -> DiffedExecutionLog {
//
//}

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
    let left_map = read_entries(&mut f_left)?;
    let right_map = read_entries(&mut f_right)?;
    let pid_map = map_by_set_similarity(&left_map, &right_map);
    // find and print differences
    for (left_pid, right_pid) in pid_map {
//        let differences = find_difference(left_map.get(&left_pid).unwrap(),
//                                          right_map.get(&right_pid).unwrap());
        // TODO print differences
    }
    // TODO do not ignore unmapped pids
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
