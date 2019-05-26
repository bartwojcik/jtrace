use core::borrow::Borrow;
use std::error::Error;
use std::ffi::c_void;
use std::fs::read_to_string;
use std::io::Error as IoError;
use std::os::unix::process::CommandExt;
use std::process::Command;
use std::{mem, ptr};

use capstone::prelude::*;
use clap;
use libc;
use log::{debug, error, info, trace, warn};
use nix::errno::Errno;
use nix::sys::ptrace::{
    attach, cont, read, setoptions, step, traceme, write, Event, Options, Request, RequestType,
};
use nix::sys::signal::{SIGCHLD, SIGSTOP, SIGTRAP};
use nix::sys::uio::{process_vm_readv, IoVec, RemoteIoVec};
use nix::sys::wait::{wait, waitpid, WaitStatus};
use nix::unistd::Pid;
use proc_maps::{get_process_maps, MapRange};
use std::collections::vec_deque::VecDeque;
use std::mem::transmute;
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

type MemoryRegion = (MapRange, Vec<u8>);
type MemoryRegions = Vec<MemoryRegion>;

fn get_code_regions(pid: Pid) -> Result<MemoryRegions, Box<dyn std::error::Error>> {
    let maps = get_process_maps(pid.as_raw())?;
    debug!("Read tracee {} memory maps from procfs", pid);
    let original_cmdline = read_to_string(format!("/proc/{}/cmdline", pid))?;
    let original_cmd = original_cmdline.split('\0').next().unwrap_or("");
    debug!(
        "Retrieved \"{}\" as the tracee {}'s original first command line argument",
        original_cmd, pid
    );
    let mut code_maps_with_buffers: Vec<_> = maps
        .into_iter()
        .filter(|map| {
            trace!(
                "tracee {}:\t{:#x}-{:#x}\t{}\t{:x}\t{}\t{}\t\t{}",
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
    debug!(
        "Allocated {} buffers for tracee {}'s memory regions",
        code_maps_with_buffers.len(),
        pid
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
    debug!("Read {} bytes of the tracee {}'s memory", bytes_read, pid);
    if bytes_read != code_maps_with_buffers.iter().map(|(m, _b)| m.size()).sum() {
        warn!("process_vm_readv bytes read return value does not match expected value, continuing");
        debug_assert!(false);
    }
    Ok(code_maps_with_buffers)
}

const INITIAL_JUMP_VEC_CAPACITY: usize = 4096;

type JumpAddresses = Vec<(usize, u8)>;

fn find_jumps(code_regions: &MemoryRegions) -> Result<JumpAddresses, Box<dyn std::error::Error>> {
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
    trace!(
        "Created Vec for jump addresses with {} initial capacity",
        jump_addresses.capacity()
    );
    for (map, buf) in code_regions {
        let mut pos = 0;
        // capstone iteration stops on invalid bytes, so loop is needed here
        while pos < map.size() {
            let insns = cs_x86.disasm_all(&buf[pos..], (map.start() + pos) as u64)?;
            if insns.is_empty() {
                pos += 1;
            } else {
                for ins in insns.iter() {
                    if let Ok(detail) = cs_x86.insn_detail(&ins) {
                        if detail
                            .groups()
                            .filter(|g| g.0 == JUMP_GROUP || g.0 == BRANCH_RELATIVE_GROUP)
                            .count()
                            == 2
                        {
                            debug!("Instruction detected for trap tracing: {} ", ins);
                            jump_addresses.push((ins.address() as usize, ins.bytes().len() as u8));
                        }
                    }
                    pos += ins.bytes().len();
                }
            }
        }
    }
    let jumps_before_dedup = jump_addresses.len();
    jump_addresses.sort_by_key(|s| s.0);
    jump_addresses.dedup_by_key(|s| s.0);
    debug_assert_eq!(
        jump_addresses.len(),
        jumps_before_dedup,
        "Same instruction was presented twice"
    );
    debug!(
        "Vec for branch instructions info has {}/{} entries",
        jump_addresses.len(),
        jump_addresses.capacity()
    );
    Ok(jump_addresses)
}

fn tracee_set_byte(pid: Pid, addr: usize, byte: u8) -> Result<(), Box<dyn std::error::Error>> {
    let aligned_addr = addr / std::mem::size_of::<usize>() * std::mem::size_of::<usize>();
    debug_assert_eq!(
        aligned_addr + addr % std::mem::size_of::<usize>(),
        addr,
        "Address alignment computed incorrectly"
    );
    let buf_offset = addr - aligned_addr;
    let read_word = read(pid, aligned_addr as *mut c_void)? as usize;
    let mut buf = read_word.to_ne_bytes();
    buf[buf_offset] = byte;
    let write_word = unsafe { transmute::<_, usize>(buf) };
    trace!(
        "Overwriting word at address {:#x}: {:#018x} with {:#018x}",
        aligned_addr,
        read_word,
        write_word
    );
    // This is tricky - although ptrace's signature says "void *data"
    // POKEDATA accepts the word to write by value
    write(pid, aligned_addr as *mut c_void, write_word as *mut c_void)?;
    debug_assert_eq!(
        read(pid, aligned_addr as *mut c_void)?.to_ne_bytes(),
        buf,
        "Read value is not equal to the written value"
    );
    Ok(())
}

fn tracee_get_byte(pid: Pid, addr: usize) -> Result<u8, Box<dyn std::error::Error>> {
    let aligned_addr = addr / std::mem::size_of::<usize>() * std::mem::size_of::<usize>();
    let buf_offset = addr - aligned_addr;
    let read_word = read(pid, aligned_addr as *mut c_void)? as usize;
    trace!(
        "Read word at address {:#x}: {:#018x}",
        aligned_addr,
        read_word
    );
    Ok(read_word.to_ne_bytes()[buf_offset])
}

// TODO remove this when nix/libc starts supporting setregs/getregs for musl targets
#[repr(C)]
struct Registers {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbp: u64,
    pub rbx: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub orig_rax: u64,
    pub rip: u64,
    pub cs: u64,
    pub eflags: u64,
    pub rsp: u64,
    pub ss: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    pub ds: u64,
    pub es: u64,
    pub fs: u64,
    pub gs: u64,
}

fn tracee_set_registers(pid: Pid, regs: &Registers) -> Result<(), Box<dyn std::error::Error>> {
    trace!("Writing tracee {}'s registers", pid);
    let res = unsafe {
        libc::ptrace(
            Request::PTRACE_SETREGS as RequestType,
            libc::pid_t::from(pid),
            ptr::null_mut::<c_void>(),
            regs as *const _ as *const c_void,
        )
    };
    Errno::result(res)
        .map(drop)
        .map_err(|x| Box::new(x) as Box<dyn std::error::Error>)
}

fn tracee_get_registers(pid: Pid) -> Result<Registers, Box<dyn std::error::Error>> {
    trace!("Reading tracee {}'s registers", pid);
    let regs: Registers = unsafe { mem::uninitialized() };
    let res = unsafe {
        libc::ptrace(
            Request::PTRACE_GETREGS as RequestType,
            libc::pid_t::from(pid),
            ptr::null_mut::<Registers>(),
            &regs as *const _ as *const c_void,
        )
    };
    Errno::result(res)?;
    Ok(regs)
}

fn tracee_save_registers(pid: Pid, regs: &mut Registers) -> Result<(), Box<dyn std::error::Error>> {
    trace!("Reading tracee {}'s registers", pid);
    let res = unsafe {
        libc::ptrace(
            Request::PTRACE_GETREGS as RequestType,
            libc::pid_t::from(pid),
            ptr::null_mut::<Registers>(),
            regs as *const _ as *const c_void,
        )
    };
    Errno::result(res)
        .map(drop)
        .map_err(|x| Box::new(x) as Box<dyn std::error::Error>)
}

const TRAP_X86: u8 = 0xCC;

fn set_branch_breakpoints(
    pid: Pid,
    jump_addresses: &JumpAddresses,
) -> Result<(), Box<dyn std::error::Error>> {
    for (addr, _len) in jump_addresses {
        trace!(
            "Setting a trap instruction at {:#x} in tracee {}'s memory",
            addr,
            pid
        );
        tracee_set_byte(pid, *addr, TRAP_X86)?;
    }
    Ok(())
}

fn region_for_address(addr: usize, code_regions: &MemoryRegions) -> Option<&MemoryRegion> {
    for region in code_regions {
        if addr > region.0.start() && addr < region.0.start() + region.0.size() {
            return Some(region);
        }
    }
    None
}

// TODO this should be more sophisticated
type ExecutionPathEntry = (Pid, usize, bool);
type ExecutionPathLog = VecDeque<ExecutionPathEntry>;

fn handle_trap(
    pid: Pid,
    jump_addresses: &JumpAddresses,
    code_regions: &MemoryRegions,
    execution_log: &mut ExecutionPathLog,
) -> Result<Pid, Box<dyn std::error::Error>> {
    let mut regs = tracee_get_registers(pid)?;
    let trap_addr = (regs.rip - 1) as usize;
    if let Ok(orig_instr_loc) = jump_addresses.binary_search_by_key(&trap_addr, |s| s.0) {
        let region = region_for_address(trap_addr, code_regions).unwrap();
        let region_offset = trap_addr - region.0.start();
        trace!(
            "Removing a trap at {:#x} in tracee {}'s memory",
            trap_addr,
            pid
        );
        tracee_set_byte(pid, trap_addr, region.1[region_offset])?;
        regs.rip -= 1;
        tracee_set_registers(pid, &regs)?;
        trace!("Stepping tracee {}", pid);
        step(pid, None)?;
        let wait_result = waitpid(pid, None)?;
        if let WaitStatus::Stopped(_pid, SIGTRAP) = wait_result {
            debug_assert_eq!(pid, _pid);
            trace!(
                "Setting a trap instruction at {:#x} in tracee {}'s memory",
                trap_addr,
                pid
            );
            tracee_set_byte(pid, trap_addr, TRAP_X86)?;
            tracee_save_registers(pid, &mut regs)?;
            let orig_instr_size = jump_addresses[orig_instr_loc].1;
            if regs.rip as usize == trap_addr + orig_instr_size as usize {
                execution_log.push_back((pid, trap_addr, false));
                trace!("Branch at {:#x} not taken by {}!", trap_addr, pid);
            } else {
                execution_log.push_back((pid, trap_addr, true));
                trace!("Branch at {:#x} taken by {}!", trap_addr, pid);
            }
        } else {
            warn!(
                "Continuing after not getting the expected SIGTRAP after stepping: {:?}",
                wait_result
            );
            debug_assert!(false);
        }
    } else {
        warn!(
            "Tracee SIGTRAP not caused by the tracer, RIP={:#x}",
            regs.rip as usize
        );
    }
    Ok(pid)
}

fn trace(
    _pid: Pid,
    jump_addresses: &JumpAddresses,
    code_regions: &MemoryRegions,
    execution_log: &mut ExecutionPathLog,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut traced_processes = 1;
    loop {
        trace!("Tracer waiting");
        let wait_result = wait()?;
        let waited_pid = match wait_result {
            WaitStatus::Continued(pid) => {
                debug!("PID {} Continued", pid);
                Some(pid)
            }
            WaitStatus::Exited(pid, ret) => {
                debug!("PID {} Exited: ret {}", pid, ret);
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
                    "PID {} PtraceEvent: signal {}, value {:?}",
                    pid, signal, event,
                );
                if let Event::PTRACE_EVENT_CLONE | Event::PTRACE_EVENT_FORK = event {
                    traced_processes += 1;
                }
                Some(pid)
            }
            WaitStatus::PtraceSyscall(pid) => {
                debug!("PID {} PtraceSyscall", pid);
                Some(pid)
            }
            WaitStatus::Signaled(pid, signal, dumped) => {
                debug!("PID {} Signaled: signal {}, dumped {}", pid, signal, dumped);
                Some(pid)
            }
            WaitStatus::StillAlive => {
                warn!("WaitStatus::StillAlive should not happen in synchronous calls, continuing");
                None
            }
            WaitStatus::Stopped(pid, signal) => {
                debug!("PID {} Stopped: signal {}", pid, signal);
                match signal {
                    SIGSTOP | SIGCHLD => Some(pid),
                    SIGTRAP => Some(handle_trap(
                        pid,
                        jump_addresses,
                        code_regions,
                        execution_log,
                    )?),
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

const INITIAL_EXECUTION_LOG_CAPACITY: usize = 134217728;

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
        // TODO implement passing user specified environment variables to the command
        unsafe {
            let child = Command::new(args.command.first().unwrap())
                .args(&args.command[1..])
                .pre_exec(|| {
                    trace!("Child process initiating tracing");
                    if let Err(_) = traceme() {
                        return Err(IoError::last_os_error());
                    }
                    Ok(())
                })
                .spawn()?;
            child_pid = Pid::from_raw(child.id() as i32);
        }
        info!("Running {} attached in PID {}", args.command[0], child_pid);
    } else {
        // TODO implement this with structopt and panic here instead
        return Err(Box::new(clap::Error::with_description(
            "Either command or process PID must be given",
            clap::ErrorKind::MissingRequiredArgument,
        )));
    }
    let ptrace_options = ptrace_options;
    setoptions(child_pid, ptrace_options)?;
    trace!("Set tracing options for tracee {}", child_pid);
    // TODO handle case with code being loaded dynamically in runtime (plugins)
    let code_regions = get_code_regions(child_pid)?;
    let jump_addresses = find_jumps(&code_regions)?;
    set_branch_breakpoints(child_pid, &jump_addresses)?;
    let mut execution_log = ExecutionPathLog::with_capacity(INITIAL_EXECUTION_LOG_CAPACITY);
    trace(
        child_pid,
        &jump_addresses,
        &code_regions,
        &mut execution_log,
    )
    // TODO remove breakpoints after canceling tracer for attach pid mode
}

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
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
