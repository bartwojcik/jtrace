use core::borrow::Borrow;
use std::error::Error;
use std::fs::read_to_string;
use std::io::Error as IoError;
use std::mem::transmute;
use std::os::unix::process::CommandExt;
use std::process::Command;

use capstone::prelude::*;
use clap;
use log::{debug, error, info, trace, warn};
use nix::sys::ptrace::{attach, cont, read, setoptions, traceme, write, Event, Options};
use nix::sys::signal::{SIGSTOP, SIGTRAP};
use nix::sys::uio::{process_vm_readv, IoVec, RemoteIoVec};
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::Pid;
use proc_maps::{get_process_maps, MapRange};
use std::ffi::c_void;
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

type CodeRegions = Vec<(MapRange, Vec<u8>)>;

fn get_code_regions(pid: Pid) -> Result<CodeRegions, Box<dyn std::error::Error>> {
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
    if bytes_read != code_maps_with_buffers.iter().map(|(m, _b)| m.size()).sum() {
        warn!("process_vm_readv bytes read return value does not match expected value, continuing");
    }

    Ok(code_maps_with_buffers)
}

const INITIAL_JUMP_VEC_CAPACITY: usize = 4096;
type JumpAddresses = Vec<(usize, u8)>;

fn find_jumps(code_regions: &CodeRegions) -> Result<JumpAddresses, Box<dyn std::error::Error>> {
    const JUMP_GROUP: u8 = 1;
    const BRANCH_RELATIVE_GROUP: u8 = 7;

    // TODO what about 32-bit mode?
    let cs_x86 = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()?;
    trace!("Created capstone object");

    let mut jump_addresses = Vec::with_capacity(INITIAL_JUMP_VEC_CAPACITY);
    trace!("Allocated Vec for found branch instructions");

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
                    jump_addresses.push((ins.address() as usize, ins.bytes().len() as u8));
                }
            }
        }
    }
    let jumps_before_dedup = jump_addresses.len();
    jump_addresses.sort_by(|a, b| a.0.cmp(&b.0));
    jump_addresses.dedup_by(|a, b| a.0 == b.0);
    debug_assert_eq!(
        jump_addresses.len(),
        jumps_before_dedup,
        "Same instruction was presented twice"
    );
    trace!(
        "Allocated Vec for branch instructions has {} entries",
        jump_addresses.len()
    );

    Ok(jump_addresses)
}

const TRAP_X86: u8 = 0xCC;

fn set_branch_breakpoints(
    pid: Pid,
    jump_addresses: &JumpAddresses,
) -> Result<(), Box<dyn std::error::Error>> {
    for (addr, _len) in jump_addresses.iter() {
        trace!("Replacing instruction at {:x} in tracee's memory", addr);
        let aligned_addr = addr / std::mem::size_of::<usize>() * std::mem::size_of::<usize>();
        let buf_offset = addr - aligned_addr;

        unsafe {
            let read = read(pid, aligned_addr as *const u64 as *mut c_void)?;
            let mut buf: [u8; std::mem::size_of::<usize>()] = transmute::<isize, _>(read as isize);
            buf[buf_offset] = TRAP_X86;
            write(
                pid,
                aligned_addr as *const u64 as *mut c_void,
                &buf[0] as *const u8 as *mut c_void,
            )?;
        }
    }

    Ok(())
}

fn handle_trap(
    pid: Pid,
    jump_addresses: &JumpAddresses,
    code_regions: &CodeRegions,
) -> Result<Pid, Box<dyn std::error::Error>> {
    // TODO get current IP

    // TODO check if SIGTRAP is one of our traps

    // TODO replace instruction/byte with the original one

    // TODO back IP by one byte

    // TODO step one instruction for this particular PID/child

    // TODO place trap back into the same place

    // TODO check if branch was taken or not - or alternatively just save the IP after stepping

    // TODO save results to branch log structure

    Ok(pid)
}

fn trace(
    _pid: Pid,
    jump_addresses: &JumpAddresses,
    code_regions: &CodeRegions,
) -> Result<(), Box<dyn std::error::Error>> {
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
                match signal {
                    SIGSTOP => Some(pid),
                    SIGTRAP => Some(handle_trap(pid, jump_addresses, code_regions)?),
                    // TODO handle every signal properly
                    _ => None,
                }
            }
        };
        if let Some(pid) = waited_pid {
            trace!("Continuing PID {}", pid);
            cont(pid, None)?;
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
    let jump_addresses = find_jumps(&code_regions)?;
    set_branch_breakpoints(child_pid, &jump_addresses)?;

    trace(child_pid, &jump_addresses, &code_regions)
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
