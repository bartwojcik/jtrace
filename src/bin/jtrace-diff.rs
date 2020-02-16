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

fn mod_idx(n: i64, m: i64) -> usize {
    debug_assert!(m > 0, "divisor is negative");
    (((n % m) + m) % m) as usize
}

#[derive(Debug)]
enum DiffOperation {
    Deletion { pos_old: usize },
    Insertion { pos_old: usize, pos_new: usize },
}

type DiffResults = Vec<DiffOperation>;

// TODO possibly move to different module
/// Diff/LCS algorithm from E. Myers paper "An O(ND) Difference Algorithm and Its Variations":
/// http://www.xmailserver.org/diff2.pdf
/// Includes optimizations from:
/// https://github.com/RobertElderSoftware/roberteldersoftwarediff/blob/master/myers_diff_and_variations.py
fn diff<T: Eq + Clone>(left_sequence: &[T], right_sequence: &[T],
                       i: Option<usize>, j: Option<usize>,
                       v_f: &mut [i64], v_b: &mut [i64],
                       results: &mut DiffResults) {
    let i = i.unwrap_or(0);
    let j = j.unwrap_or(0);
    let l_len = left_sequence.len() as i64;
    let r_len = right_sequence.len() as i64;
    let sum_len = l_len + r_len;
    let v_size = 2 * min(l_len, r_len) + 2;
    // use a smaller slice into the same shared buffers
    let v_f = &mut v_f[0..v_size as usize];
    let v_b = &mut v_b[0..v_size as usize];
    if l_len > 0 && r_len > 0 {
        let delta = l_len - r_len;
        // zero out the (shared) v arrays
        v_f.iter_mut().for_each(|x| *x = 0);
        v_b.iter_mut().for_each(|x| *x = 0);
        // TODO ceil?
        for h in 0..sum_len / 2 + sum_len % 2 + 1 {
            // forward (step by 2)
            let mut k = -(h - 2 * max(0, h - r_len));
            while k <= h - 2 * max(0, h - l_len) {
                // indices into v array:
                let c_idx = mod_idx(k, v_size); // current k line
                let a_idx = mod_idx(k + 1, v_size); // k line above
                let b_idx = mod_idx(k - 1, v_size); // k line below
                // select the better incoming path
                let mut a = if k == -h || k != h && v_f[b_idx] < v_f[a_idx] {
                    v_f[a_idx]
                } else {
                    v_f[b_idx] + 1
                };
                // calculate y coordinate from k and x
                let mut b = a - k;
                // save the coordinates of the snake's starting point
                let (s, t) = (a, b);
                // move diagonally as much as possible
                while a < l_len && b < r_len
                    && left_sequence[a as usize] == right_sequence[b as usize] {
                    a += 1;
                    b += 1;
                }
                // update the "best x" array
                v_f[c_idx] = a;
                // v array index for current inverse k line
                let inverse_k = -k + delta;
                let inv_c_idx = mod_idx(inverse_k, v_size);
                // check for path overlap
                if sum_len % 2 == 1 && inverse_k >= -h + 1 && inverse_k <= h - 1
                    && v_f[c_idx] + v_b[inv_c_idx] >= l_len {
                    let (l_len, r_len) = (l_len as usize, r_len as usize);
                    let (d, x, y, u, v) = (2 * h - 1,
                                           s as usize, t as usize,
                                           a as usize, b as usize);
                    if d > 1 || x != u && y != u {
                        diff(&left_sequence[0..x], &right_sequence[0..y],
                             Some(i), Some(j),
                             v_f, v_b,
                             results);
                        diff(&left_sequence[u..l_len], &right_sequence[v..r_len],
                             Some(i + u), Some(j + v),
                             v_f, v_b,
                             results);
                        return;
                    } else if r_len > l_len {
                        diff(&[], &right_sequence[l_len..r_len],
                             Some(i + l_len), Some(j + l_len),
                             v_f, v_b,
                             results);
                        return;
                    } else if r_len < l_len {
                        diff(&left_sequence[r_len..l_len], &[],
                             Some(i + r_len), Some(j + r_len),
                             v_f, v_b,
                             results);
                        return;
                    }
                }
                k += 2;
            }
            // backward
            k = -(h - 2 * max(0, h - r_len));
            while k <= h - 2 * max(0, h - l_len) {
                let c_idx = mod_idx(k, v_size);
                let a_idx = mod_idx(k + 1, v_size);
                let b_idx = mod_idx(k - 1, v_size);
                let mut a = if k == -h || k != h && v_b[b_idx] < v_b[a_idx] {
                    v_b[a_idx]
                } else {
                    v_b[b_idx] + 1
                };
                let mut b = a - k;
                let (s, t) = (a, b);
                while a < l_len && b < r_len
                    && left_sequence[(l_len - a - 1) as usize]
                    == right_sequence[(r_len - b - 1) as usize] {
                    a += 1;
                    b += 1;
                }
                v_b[c_idx] = a;
                let inverse_k = -k + delta;
                let inv_c_idx = mod_idx(inverse_k, v_size);
                if sum_len % 2 == 0 && inverse_k >= -h && inverse_k <= h
                    && v_b[c_idx] + v_f[inv_c_idx] >= l_len {
                    let (l_len, r_len) = (l_len as usize, r_len as usize);
                    let (d, x, y, u, v) = (2 * h,
                                           l_len - a as usize, r_len - b as usize,
                                           l_len - s as usize, r_len - t as usize);
                    if d > 1 || x != u && y != u {
                        diff(&left_sequence[0..x], &right_sequence[0..y],
                             Some(i), Some(j),
                             v_f, v_b,
                             results);
                        diff(&left_sequence[u..l_len], &right_sequence[v..r_len],
                             Some(i + u), Some(j + v),
                             v_f, v_b,
                             results);
                        return;
                    } else if r_len > l_len {
                        diff(&[], &right_sequence[l_len..r_len],
                             Some(i + l_len), Some(j + l_len),
                             v_f, v_b,
                             results);
                        return;
                    } else if r_len < l_len {
                        diff(&left_sequence[r_len..l_len], &[],
                             Some(i + r_len), Some(j + r_len),
                             v_f, v_b,
                             results);
                        return;
                    }
                }
                k += 2;
            }
        }
    } else if l_len > 0 {
        for n in 0..l_len as usize {
            results.push(DiffOperation::Deletion { pos_old: i + n })
        }
    } else {
        for n in 0..r_len as usize {
            results.push(DiffOperation::Insertion { pos_old: i, pos_new: j + n })
        }
    }
}

fn find_difference<T: Eq + Clone>(left_sequence: &[T], right_sequence: &[T]) -> DiffResults {
    let v_size = 2 * min(left_sequence.len(), right_sequence.len()) + 2;
    let mut v_forward = vec![0; v_size as usize];
    let mut v_backward = vec![0; v_size as usize];
    let mut results = DiffResults::new();
    diff(left_sequence, right_sequence,
         None, None,
         &mut v_forward, &mut v_backward,
         &mut results);
    results
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

#[cfg(test)]
mod tests {
    use rand::{Rng, thread_rng};
    use rand::distributions::Alphanumeric;

    use super::*;

    fn apply_difference<T: Eq + Clone>(left_sequence: &[T], right_sequence: &[T],
                                       difference: &[DiffOperation]) -> Vec<T> {
        let mut result = Vec::<T>::new();
        let mut i = 0;
        let mut j = 0;
        while j < difference.len() {
            let next_pos = match difference[j] {
                DiffOperation::Deletion { pos_old: x } => x,
                DiffOperation::Insertion { pos_old: x, pos_new: _ } => x,
            };
            if i == next_pos {
                match difference[j] {
                    DiffOperation::Deletion { pos_old: _ } => {
                        i += 1;
                    }
                    DiffOperation::Insertion { pos_old: _, pos_new: x } =>
                        {
                            result.push(right_sequence[x].clone());
                        }
                };
                j += 1;
            } else {
                result.push(left_sequence[i].clone());
                i += 1;
            }
        }
        while i < left_sequence.len() {
            result.push(left_sequence[i].clone());
            i += 1;
        }
        result
    }

    fn test_two_strs(str1: &str, str2: &str, expected_diff_len: usize) {
        let seq1 = str1.as_bytes();
        let seq2 = str2.as_bytes();
        let difference = find_difference(seq1, seq2);
        let recon_seq2 = apply_difference(seq1, seq2, &difference);
        let recon_str2 = std::str::from_utf8(&recon_seq2).unwrap();
        assert!(recon_seq2 == seq2, "seq1: {}, seq2: {}, recon_seq2: {}", str1, str2, recon_str2);
        let actual = difference.len();
        assert!(actual == expected_diff_len, "difference len: {}, expected len: {}",
                actual, expected_diff_len);
    }

    #[test]
    fn test_str_from_paper() {
        test_two_strs("abcabba", "cbabac", 5);
    }

    #[test]
    fn test_str_from_paper_2() {
        test_two_strs("abcabbac", "cbabac", 4);
    }

    #[test]
    fn test_evil_case_1() {
        test_two_strs("nitWVMHDydSTnFbvsSFDTiQfUMFkLTyemjKVqWlTfZOESYyPYaJnpTqMfakxX",
                      "n8tWVMHDyd6TnFbvsSFDTiQ5UMF0LTy1mjKVqWlTf5OESYyPY8JnpTqMfak3X",
                      16);
    }

    const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    const DIGITSET: &[u8] = b"0123456789";

    fn random_string(len: usize) -> String {
        let mut rng = thread_rng();
        (0..len).map(|_| {
            let idx = rng.gen_range(0, CHARSET.len());
            CHARSET[idx] as char
        }).collect()
    }

    fn random_perturbation(source: &str, chance: f64) -> (String, usize) {
        let mut rng = thread_rng();
        let mut s: String = source.into();
        let mut modified = 0;
        s = s.chars().map(|c| {
            let p: f64 = rng.gen();
            if p <= chance {
                modified += 1;
                let idx = rng.gen_range(0, DIGITSET.len());
                DIGITSET[idx] as char
            } else {
                c
            }
        }).collect();
        (s, modified)
    }

    #[test]
    fn test_random_strs() {
        for i in 0..1000 {
            let mut rng = thread_rng();
            let str1 = random_string(rng.gen_range(10, 100));
            let (str2, modified) = random_perturbation(&str1, rng.gen_range(0.05, 0.5));
            test_two_strs(&str1, &str2, modified * 2);
        }
    }
}