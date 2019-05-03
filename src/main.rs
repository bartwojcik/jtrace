use core::borrow::Borrow;
use std::error::Error;
use std::io::Error as IoError;
use std::os::unix::process::CommandExt;
use std::process::Command;

use capstone::prelude::*;
use clap;
use log::{debug, error, info, trace, warn};
use nix::sys::ptrace::{attach, cont, setoptions, traceme, Event, Options};
use nix::sys::uio::{process_vm_readv, IoVec, RemoteIoVec};
use nix::sys::wait::{wait, WaitStatus};
use nix::unistd::Pid;
use proc_maps::{get_process_maps, MapRange};
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

    // TODO handle case with code being loaded dynamically in runtime (plugins)
    get_code_regions(child_pid, &args.command[0])?;
    analyze_code()?;
    set_branch_breakpoints(child_pid, &args.command[0])?;

    trace(child_pid)
}

fn get_code_regions(
    pid: Pid,
    command: &str,
) -> Result<Vec<(MapRange, Vec<u8>)>, Box<dyn std::error::Error>> {
    let maps = get_process_maps(pid.as_raw())?;
    let mut code_maps_with_buffers: Vec<_> = maps
        .into_iter()
        .filter(|map| {
            return map
                .filename()
                .as_ref()
                .filter(|name| name.ends_with(command))
                .is_some();
        })
        .map(|map| {
            let mut buf = Vec::<u8>::with_capacity(map.size());
            unsafe { buf.set_len(buf.capacity()) }
            (map, buf)
        })
        .collect();

    let mut local_iov = Vec::<IoVec<&mut [u8]>>::with_capacity(code_maps_with_buffers.len());
    let mut remote_iov = Vec::<RemoteIoVec>::with_capacity(code_maps_with_buffers.len());
    for (map, buf) in code_maps_with_buffers.iter_mut() {
        local_iov.push(IoVec::from_mut_slice(buf.as_mut_slice()));
        remote_iov.push(RemoteIoVec {
            base: map.start(),
            len: map.size(),
        })
    }
    let bytes_written = process_vm_readv(pid, local_iov.as_slice(), remote_iov.as_slice())?;
    if bytes_written != code_maps_with_buffers.iter().map(|(m, b)| m.size()).sum() {
        warn!(
            "process_vm_readv bytes written return value does not match expected value, continuing"
        );
    }

    Ok(code_maps_with_buffers)
}

fn analyze_code() -> Result<(), Box<dyn std::error::Error>> {
    let cs_x86 = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()?;

    // TODO create a map with addresses as keys and instruction as values

    Ok(())
}

fn set_branch_breakpoints(pid: Pid, command: &str) -> Result<(), Box<dyn std::error::Error>> {
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
