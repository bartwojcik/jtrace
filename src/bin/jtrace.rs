extern crate jtrace;

use std::borrow::Borrow;
use std::error::Error;
use std::io::Error as IoError;
use std::os::unix::process::CommandExt;
use std::process::Command;

use capstone::prelude::*;
use clap;
use log::{debug, error, info, trace, warn};
use nix::sys::ptrace::{attach, Options, setoptions, traceme};
use nix::unistd::Pid;
use structopt::StructOpt;

use jtrace::{analyze, ExecutionPathLog, get_memory_regions, set_branch_breakpoints, trace};

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


fn run(args: Cli) -> Result<(), Box<dyn Error>> {
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
    } else if !args.command.is_empty() {
        ptrace_options |= Options::PTRACE_O_EXITKILL;
        // TODO implement passing user specified environment variables to the command
        unsafe {
            let child = Command::new(args.command.first().unwrap())
                .args(&args.command[1..])
                .pre_exec(|| {
                    trace!("Child process initiating tracing");
                    if traceme().is_err() {
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
    let memory_regions = get_memory_regions(child_pid)?;
    // TODO what about 32-bit mode?
    let cs_x86 = Capstone::new()
        .x86()
        .mode(arch::x86::ArchMode::Mode64)
        .syntax(arch::x86::ArchSyntax::Intel)
        .detail(true)
        .build()?;
    trace!("Created capstone object");
    let (_reachable_code, jump_addresses) = analyze(child_pid, &memory_regions, &cs_x86)?;
    set_branch_breakpoints(child_pid, &jump_addresses)?;
    let mut execution_log = ExecutionPathLog::new(child_pid)?;
    trace(
        child_pid,
        &jump_addresses,
        &memory_regions,
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
        let mut e: &dyn Error = top_e.borrow();
        while let Some(source) = e.source() {
            error!("Caused by: {}", source.to_string());
            e = source;
        }
    }
}
