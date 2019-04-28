use core::borrow::Borrow;
use std::error::Error;
use std::process::Command;

use clap;
use nix::sys::ptrace::{attach, cont, getevent, setoptions, Event, Options};
use nix::sys::wait::{wait, waitpid, WaitStatus};
use nix::unistd::Pid;
use structopt::StructOpt;

#[derive(StructOpt)]
/// Trace the execution path of a program.
struct Cli {
    /// The path to the executable
    #[structopt(parse(from_os_str))]
    path: Option<std::path::PathBuf>,
    /// PID of the process to attach to
    #[structopt(short = "p", long = "pid")]
    pid: Option<u32>,
    /// Trace child processes as they are created by currently traced processes
    #[structopt(short = "f", long = "follow")]
    follow: bool,
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

fn run(args: Cli) -> Result<(), Box<dyn std::error::Error>> {
    let child_pid: Pid;
    let mut ptrace_options = Options::empty();

    if args.follow {
        ptrace_options |= Options::PTRACE_O_TRACEFORK
            | Options::PTRACE_O_TRACEVFORK
            | Options::PTRACE_O_TRACECLONE;
    }
    if let Some(path) = args.path {
        let child = Command::new(&path).spawn()?;
        child_pid = Pid::from_raw(child.id() as i32);
        println!("Running {:?} in {}", path, child_pid);
        ptrace_options |= Options::PTRACE_O_EXITKILL;
    } else if let Some(pid) = args.pid {
        child_pid = Pid::from_raw(pid as i32);
        println!("Attaching to {}", child_pid);
    } else {
        // TODO implement this with structopt and panic here instead
        return Err(Box::new(clap::Error::with_description(
            "Either path to binary or process PID must be given",
            clap::ErrorKind::MissingRequiredArgument,
        )));
    }
    let ptrace_options = ptrace_options;

    attach(child_pid)?;
    waitpid(child_pid, None)?;
    println!("Attached to {}", child_pid);

    setoptions(child_pid, ptrace_options)?;
    cont(child_pid, None)?;

    let mut traced_pids = vec![child_pid.as_raw()];
    loop {
        let wait_result = wait()?;
        if let Some(pid) = wait_result.pid() {
            if let Ok(_) = traced_pids.binary_search(&pid.as_raw()) {
                let waited_pid = match wait_result {
                    WaitStatus::Continued(pid) => {
                        println!("Continued: pid {}", pid);
                        Some(pid)
                    }
                    WaitStatus::Exited(pid, ret) => {
                        println!("Exited: pid {}, ret {}", pid, ret);
                        if let Ok(pos) = traced_pids.binary_search(&pid.as_raw()) {
                            traced_pids.remove(pos);
                            if traced_pids.is_empty() {
                                return Ok(());
                            }
                        }
                        None
                    }
                    WaitStatus::PtraceEvent(pid, signal, value) => {
                        println!(
                            "PtraceEvent: pid {}, signal {}, value {:?}",
                            pid,
                            signal,
                            int_to_ptrace_event(value).unwrap()
                        );
                        match getevent(pid) {
                            Ok(pid_raw) => {
                                if let Err(pos) = traced_pids.binary_search(&(pid_raw as i32)) {
                                    traced_pids.insert(pos, pid_raw as i32);
                                } else {
                                    // TODO panic instead?
                                    eprintln!("New process's PID already traced, ignoring");
                                }
                            }
                            Err(e) => {
                                // TODO panic instead?
                                eprintln!("PTRACE_GETEVENTMSG did not return a PID after fork, continuing");
                            }
                        };
                        Some(pid)
                    }
                    WaitStatus::PtraceSyscall(pid) => {
                        println!("PtraceSyscall: pid {}", pid);
                        Some(pid)
                    }
                    WaitStatus::Signaled(pid, signal, dumped) => {
                        println!(
                            "Signaled: pid {}, signal {}, dumped {}",
                            pid, signal, dumped
                        );
                        Some(pid)
                    }
                    WaitStatus::StillAlive => {
                        panic!("WaitStatus::StillAlive should not happen in synchronous calls!");
                    }
                    WaitStatus::Stopped(pid, signal) => {
                        println!("Stopped: pid {}, signal {}", pid, signal);
                        Some(pid)
                    }
                };
                if let Some(pid) = waited_pid {
                    cont(pid, None)?;
                }
            }
        }
    }
}

fn main() {
    let args = Cli::from_args();

    if let Err(top_e) = run(args) {
        eprintln!("{}", top_e.to_string());
        let mut e: &Error = top_e.borrow();
        loop {
            if let Some(source) = e.source() {
                eprintln!("Caused by: {}", source.to_string());
                e = source;
            } else {
                break;
            }
        }
    }
}
