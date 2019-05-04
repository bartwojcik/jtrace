use core::borrow::Borrow;
use std::error::Error;
use std::fs::read_to_string;
use std::io::Error as IoError;
use std::os::unix::process::CommandExt;
use std::process::Command;

use capstone::prelude::*;
use clap;
use fasthash::xx::Hash64;
use log::{debug, error, info, trace, warn};
use nix::sys::ptrace::{attach, cont, setoptions, traceme, Event, Options};
use nix::sys::uio::{process_vm_readv, IoVec, RemoteIoVec};
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::Pid;
use proc_maps::{get_process_maps, MapRange};
use std::collections::HashMap;
use structopt::StructOpt;

#[derive(StructOpt)]
/// Trace the execution path of a program.
struct Cli {
    /// PID of the process to attach to
    #[structopt(short = "p", long = "pid")]
    pid: Option<u32>,
    /// Trace child processes as they are created by currently traced processes
    #[structopt(short = "f", long = "follow")]
    follow: bool,
    /// The command to be executed
    #[structopt(raw(multiple = "true"))]
    command: Vec<String>,
}

#[cfg(target_os = "linux")]
fn main() {
    env_logger::init();

    let args = Cli::from_args();

    if let Err(top_e) = run(args) {
        error!("{}", top_e.to_string());
        let mut e: &Error = top_e.borrow();
        loop {
            if let Some(source) = e.source() {
                error!("Caused by: {}", source.to_string());
                e = source;
            } else {
                break;
            }
        }
    }
}

fn run(args: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let child_pid: Pid;
    let mut ptrace_options = Options::empty();

    if args.follow {
        ptrace_options |= Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_TRACECLONE;
    }

    if let Some(pid) = args.pid {
        // TODO support attaching to PID + all its current children with a flag?
        child_pid = Pid::from_raw(pid as i32);
        attach(child_pid)?;
        info!("Attached to {}", child_pid);
    } else if args.command.len() > 0 {
        ptrace_options |= Options::PTRACE_O_EXITKILL;
        // TODO implement passing environment variables to the command
        unsafe {
            let child = Command::new(args.command.first().unwrap())
                .args(&args.command[1..])
                .pre_exec(|| {
                    trace!("Child process initiating tracing");
                    if let Err(_) = traceme() {
                        return Err(IoError::last_os_error());
                    }
                    //                    trace!("Child process raising SIGSTOP");
                    //                    if let Err(_) = raise(Signal::SIGSTOP) {
                    //                        return Err(IoError::last_os_error());
                    //                    }
                    Ok(())
                })
                .spawn()?;
            child_pid = Pid::from_raw(child.id() as i32);
        }
        info!("Running {} attached in {}", args.command[0], child_pid);
    } else {
        // TODO implement this with structopt and panic here instead
        return Err(Box::new(clap::Error::with_description(
            "Either command or process PID must be given",
            clap::ErrorKind::MissingRequiredArgument,
        )));
    }
    let ptrace_options = ptrace_options;

    setoptions(child_pid, ptrace_options)?;
    trace!("Set tracing options for the tracee PID {}", child_pid);

    // TODO handle case with code being loaded dynamically in runtime (plugins)
    let code_regions = get_code_regions(child_pid)?;
    find_jumps(code_regions)?;
    set_branch_breakpoints(child_pid)?;

    trace(child_pid)
}

fn get_code_regions(pid: Pid) -> Result<Vec<(MapRange, Vec<u8>)>, Box<dyn std::error::Error>> {
    let maps = get_process_maps(pid.as_raw())?;
    trace!("Read tracee PID {} memory maps from procfs", pid);
    let original_cmdline = read_to_string(format!("/proc/{}/cmdline", pid))?;
    let original_cmd = original_cmdline.split('\0').next().unwrap_or("");
    trace!(
        "Retrieved \"{}\" as the tracee PID {} original first command line argument",
        original_cmd,
        pid
    );
    let mut code_maps_with_buffers: Vec<_> = maps
        .into_iter()
        .filter(|map| {
            trace!(
                "PID {}:\t{:x}-{:x}\t{}\t{:x}\t{}\t{}\t\t{}",
                pid,
                map.start(),
                map.start() + map.size(),
                map.flags,
                map.offset,
                map.dev,
                map.inode,
                map.filename().as_ref().map_or("", |s| &**s)
            );
            map.is_exec()
                && map
                    .filename()
                    .as_ref()
                    .map_or(false, |name| name.ends_with(original_cmd))
        })
        .map(|map| {
            let mut buf = Vec::<u8>::with_capacity(map.size());
            unsafe { buf.set_len(buf.capacity()) }
            (map, buf)
        })
        .collect();
    trace!(
        "Allocated {} buffers for tracee's memory regions",
        code_maps_with_buffers.len()
    );

    let mut local_iov = Vec::<IoVec<&mut [u8]>>::with_capacity(code_maps_with_buffers.len());
    let mut remote_iov = Vec::<RemoteIoVec>::with_capacity(code_maps_with_buffers.len());
    for (map, buf) in code_maps_with_buffers.iter_mut() {
        local_iov.push(IoVec::from_mut_slice(buf.as_mut_slice()));
        remote_iov.push(RemoteIoVec {
            base: map.start(),
            len: map.size(),
        })
    }
    let bytes_read = process_vm_readv(pid, local_iov.as_slice(), remote_iov.as_slice())?;
    trace!("Read {} bytes of the tracee's memory", bytes_read);
    if bytes_read != code_maps_with_buffers.iter().map(|(m, b)| m.size()).sum() {
        warn!(
            "process_vm_readv bytes written return value does not match expected value, continuing"
        );
    }

    Ok(code_maps_with_buffers)
}

//    for i in 0..255 {
//        println!(
//            "{}: {}",
//            i,
//            cs_x86.group_name(InsnGroupId(i)).unwrap_or("?".to_string())
//        );
//    }
const JUMP_GROUP: u8 = 1;
const BRANCH_RELATIVE_GROUP: u8 = 7;

struct BranchEntry {
    orig_ins: Vec<u8>,
}

const INITIAL_BRANCH_MAP_CAPACITY: usize = 4096;
const MAX_INSTRUCTION_SIZE: usize = 16;

fn find_jumps(code_regions: Vec<(MapRange, Vec<u8>)>) -> Result<(), Box<dyn std::error::Error>> {
    // TODO 32-bit mode?
    let cs_x86 = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()?;

    let mut branching_insns =
        HashMap::with_capacity_and_hasher(INITIAL_BRANCH_MAP_CAPACITY, Hash64);

    for (map, buf) in code_regions.iter() {
        let insns = cs_x86.disasm_all(buf.as_slice(), map.start() as u64)?;
        for ins in insns.iter() {
            if let Ok(detail) = cs_x86.insn_detail(&ins) {
                if detail
                    .groups()
                    .filter(|g| g.0 == JUMP_GROUP || g.0 == BRANCH_RELATIVE_GROUP)
                    .count()
                    == 2
                {
                    trace!("Instruction detected for trap tracing: {} ", ins);
                    let mut ins_bytes = Vec::with_capacity(MAX_INSTRUCTION_SIZE);
                    ins_bytes.extend_from_slice(ins.bytes());
                    let inserted = branching_insns.insert(
                        ins.address(),
                        BranchEntry {
                            orig_ins: ins_bytes,
                        },
                    );
                }
            }
        }
    }

    // TODO create a map with addresses as keys and instruction as values

    Ok(())
}

fn set_branch_breakpoints(pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
    // TODO and replace those instructions with one-byte trap syscalls

    Ok(())
}

fn trace(_pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
    let mut traced_processes = 1;
    loop {
        trace!("Tracer waiting");
        let wait_result = wait()?;
        let waited_pid = match wait_result {
            WaitStatus::Continued(pid) => {
                debug!("Continued: pid {}", pid);
                Some(pid)
            }
            WaitStatus::Exited(pid, ret) => {
                debug!("Exited: pid {}, ret {}", pid, ret);

                traced_processes -= 1;
                if traced_processes == 0 {
                    trace!("Last tracee exited, exiting");
                    return Ok(());
                }
                None
            }
            WaitStatus::PtraceEvent(pid, signal, value) => {
                let event = int_to_ptrace_event(value).unwrap();
                debug!(
                    "PtraceEvent: pid {}, signal {}, value {:?}",
                    pid, signal, event,
                );
                if let Event::PTRACE_EVENT_CLONE | Event::PTRACE_EVENT_FORK = event {
                    traced_processes += 1;
                }
                Some(pid)
            }
            WaitStatus::PtraceSyscall(pid) => {
                debug!("PtraceSyscall: pid {}", pid);
                Some(pid)
            }
            WaitStatus::Signaled(pid, signal, dumped) => {
                debug!(
                    "Signaled: pid {}, signal {}, dumped {}",
                    pid, signal, dumped
                );
                Some(pid)
            }
            WaitStatus::StillAlive => {
                warn!("WaitStatus::StillAlive should not happen in synchronous calls, continuing");
                None
            }
            WaitStatus::Stopped(pid, signal) => {
                debug!("Stopped: pid {}, signal {}", pid, signal);
                Some(pid)
            }
        };
        if let Some(pid) = waited_pid {
            trace!("Continuing PID {}", pid);
            cont(pid, None)?;
        }
    }
}

/// Converts an int value to a ptrace Event enum.
/// TODO remove and use proper value to int conversion when it becomes available
/// see https://internals.rust-lang.org/t/pre-rfc-enum-from-integer/6348
fn int_to_ptrace_event(value: i32) -> Option<Event> {
    match value {
        1i32 => Some(Event::PTRACE_EVENT_FORK),
        2i32 => Some(Event::PTRACE_EVENT_VFORK),
        3i32 => Some(Event::PTRACE_EVENT_CLONE),
        4i32 => Some(Event::PTRACE_EVENT_EXEC),
        5i32 => Some(Event::PTRACE_EVENT_VFORK_DONE),
        6i32 => Some(Event::PTRACE_EVENT_EXIT),
        7i32 => Some(Event::PTRACE_EVENT_SECCOMP),
        _ => None,
    }
}
