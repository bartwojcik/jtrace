use core::borrow::Borrow;
use std::error::Error;
use std::ffi::CString;

use clap;
use log::{debug, error, info, trace, warn};
use nix::sys::ptrace::{attach, cont, getevent, setoptions, traceme, Event, Options};
use nix::sys::signal::{raise, Signal};
use nix::sys::wait::{wait, waitpid, WaitStatus};
use nix::unistd::ForkResult::Parent;
use nix::unistd::{execv, fork, Pid};
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

fn trace(pid: Pid) -> Result<(), Box<dyn std::error::Error>> {
    let mut traced_pids = vec![pid.as_raw()];
    loop {
        trace!("Tracer waiting");
        let wait_result = wait()?;
        if let Some(pid) = wait_result.pid() {
            if let Ok(_) = traced_pids.binary_search(&pid.as_raw()) {
                let waited_pid = match wait_result {
                    WaitStatus::Continued(pid) => {
                        debug!("Continued: pid {}", pid);
                        Some(pid)
                    }
                    WaitStatus::Exited(pid, ret) => {
                        debug!("Exited: pid {}, ret {}", pid, ret);
                        if let Ok(pos) = traced_pids.binary_search(&pid.as_raw()) {
                            traced_pids.swap_remove(pos);
                            if traced_pids.is_empty() {
                                return Ok(());
                            }
                        }
                        None
                    }
                    WaitStatus::PtraceEvent(pid, signal, value) => {
                        debug!(
                            "PtraceEvent: pid {}, signal {}, value {:?}",
                            pid,
                            signal,
                            int_to_ptrace_event(value).unwrap()
                        );
                        match getevent(pid) {
                            Ok(pid_raw) => {
                                if let Err(pos) = traced_pids.binary_search(&(pid_raw as i32)) {
                                    traced_pids.insert(pos, pid_raw as i32);
                                    trace!("Added {} to the list of traced PIDs", pid_raw);
                                } else {
                                    // TODO panic instead?
                                    warn!("New process's PID already traced, ignoring");
                                }
                            }
                            Err(_e) => {
                                // TODO panic instead?
                                warn!("PTRACE_GETEVENTMSG did not return a PID after fork, continuing");
                            }
                        };
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
                        panic!("WaitStatus::StillAlive should not happen in synchronous calls!");
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
        // TODO support attaching to PID + its all current children
        child_pid = Pid::from_raw(pid as i32);
        attach(child_pid)?;
        info!("Attached to {}", child_pid);
    } else if args.command.len() > 0 {
        let fork_result = fork()?;
        if let Parent { child } = fork_result {
            child_pid = child;
            info!("Running {} attached in {}", args.command[0], child_pid);
            ptrace_options |= Options::PTRACE_O_EXITKILL;
            waitpid(child_pid, None)?;
        } else {
            traceme()?;
            let command_args: Vec<CString> = args
                .command
                .into_iter()
                .map(|s| CString::new(s).unwrap())
                .collect();
            raise(Signal::SIGSTOP)?;
            // TODO implement passing environment variables to command
            execv(&command_args[0], &command_args[1..])?;
            panic!("Should never reach anything after execv!");
        }
    } else {
        // TODO implement this with structopt and panic here instead
        return Err(Box::new(clap::Error::with_description(
            "Either command or process PID must be given",
            clap::ErrorKind::MissingRequiredArgument,
        )));
    }
    let ptrace_options = ptrace_options;

    setoptions(child_pid, ptrace_options)?;
    cont(child_pid, None)?;

    trace(child_pid)
}

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
