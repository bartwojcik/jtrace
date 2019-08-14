use core::borrow::Borrow;
use std::{mem, ptr};
use std::cmp::{max, min};
use std::cmp::Ordering::{Equal, Greater, Less};
use std::collections::HashMap;
use std::collections::vec_deque::VecDeque;
use std::error::Error;
use std::ffi::c_void;
use std::fmt;
use std::fs::read_to_string;
use std::hash::BuildHasherDefault;
use std::io::Error as IoError;
use std::iter::FromIterator;
use std::mem::{MaybeUninit, transmute};
use std::os::unix::process::CommandExt;
use std::process::Command;

use ahash::AHasher;
use capstone::arch::ArchOperand;
use capstone::arch::ArchOperand::X86Operand;
use capstone::arch::x86::X86OperandType;
use capstone::arch::x86::X86OperandType::*;
use capstone::Insn;
use capstone::prelude::*;
use clap;
use libc;
use log::{debug, error, info, trace, warn};
use nix::errno::Errno;
use nix::sys::ptrace::{
    attach, cont, Event, Options, read, Request, RequestType, setoptions, step, traceme, write,
};
use nix::sys::signal::{SIGCHLD, SIGSTOP, SIGTRAP};
use nix::sys::uio::{IoVec, process_vm_readv, RemoteIoVec};
use nix::sys::wait::{wait, waitpid, WaitStatus};
use nix::unistd::Pid;
use proc_maps::{get_process_maps, MapRange};
use structopt::StructOpt;

use InstructionType::*;

#[derive(Debug)]
pub enum ToolError {
    ArchitectureNotSupported,
    InvalidInstruction(usize),
    AddressOutsideRegion(usize),
    AddressResolutionError(usize),
}

impl Error for ToolError {}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ToolError::ArchitectureNotSupported => f.write_str("ArchitectureNotSupported"),
            ToolError::InvalidInstruction(addr) => f.write_str(&format!("InvalidInstruction({})", addr)),
            ToolError::AddressOutsideRegion(addr) => f.write_str(&format!("AddressOutsideRegion({})", addr)),
            ToolError::AddressResolutionError(addr) => f.write_str(&format!("AddressResolutionError({})", addr)),
        }
    }
}


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

fn tracee_get_byte(pid: Pid, addr: usize) -> Result<u8, Box<dyn std::error::Error>> {
    let aligned_addr = addr / std::mem::size_of::<usize>() * std::mem::size_of::<usize>();
    let buf_offset = addr - aligned_addr;
    let read_word = read(pid, aligned_addr as *mut c_void)? as usize;
    trace!("Read word at address {:#x}: {:#018x}", aligned_addr, read_word);
    Ok(read_word.to_ne_bytes()[buf_offset])
}

/// signature is somewhat weird because of: https://github.com/rust-lang/rust/issues/43408
fn tracee_read(pid: Pid, mut addr: usize, contents: &mut [u8])
               -> Result<(), Box<dyn std::error::Error>> {
    let to_read_size = contents.len();
    let mut read_bytes = 0;
    while read_bytes < to_read_size {
        let aligned_addr = addr / std::mem::size_of::<usize>() * std::mem::size_of::<usize>();
        debug_assert_eq!(aligned_addr + addr % std::mem::size_of::<usize>(), addr,
                         "Address alignment computed incorrectly");
        let mut buf_offset = addr - aligned_addr;
        let read_word = read(pid, aligned_addr as *mut c_void)? as usize;
        let buf = unsafe { transmute::<_, [u8; std::mem::size_of::<usize>()]>(read_word) };
        trace!("Read word at address {:#x}: {:#018x} (LE)", aligned_addr, read_word);
        while buf_offset < std::mem::size_of::<usize>() && read_bytes < to_read_size {
            contents[read_bytes] = buf[buf_offset];
            buf_offset += 1;
            read_bytes += 1;
        }
        addr += std::mem::size_of::<usize>() - (addr - aligned_addr);
    }
    Ok(())
}

fn tracee_set_byte(pid: Pid, addr: usize, byte: u8) -> Result<(), Box<dyn std::error::Error>> {
    let aligned_addr = addr / std::mem::size_of::<usize>() * std::mem::size_of::<usize>();
    debug_assert_eq!(aligned_addr + addr % std::mem::size_of::<usize>(), addr,
                     "Address alignment computed incorrectly");
    let buf_offset = addr - aligned_addr;
    let read_word = read(pid, aligned_addr as *mut c_void)? as usize;
    let mut buf = read_word.to_ne_bytes();
    buf[buf_offset] = byte;
    let write_word = unsafe { transmute::<_, usize>(buf) };
    trace!("Overwriting word at address {:#x}: {:#018x} with {:#018x}",
           aligned_addr, read_word, write_word);
    // This is tricky - although ptrace's signature says "void *data"
    // POKEDATA accepts the word to write by value
    write(pid, aligned_addr as *mut c_void, write_word as *mut c_void)?;
    debug_assert_eq!(read(pid, aligned_addr as *mut c_void)?.to_ne_bytes(), buf,
                     "Read value is not equal to the written value");
    Ok(())
}

fn tracee_write(pid: Pid, mut addr: usize, contents: &[u8])
                -> Result<(), Box<dyn std::error::Error>> {
    let to_write_size = contents.len();
    let mut written_bytes = 0;
    while written_bytes < to_write_size {
        let aligned_addr = addr / std::mem::size_of::<usize>() * std::mem::size_of::<usize>();
        debug_assert_eq!(aligned_addr + addr % std::mem::size_of::<usize>(), addr,
                         "Address alignment computed incorrectly");
        let mut buf_offset = addr - aligned_addr;
        let read_word = read(pid, aligned_addr as *mut c_void)? as usize;
        let mut buf = unsafe { transmute::<_, [u8; std::mem::size_of::<usize>()]>(read_word) };
        while buf_offset < std::mem::size_of::<usize>() && written_bytes < to_write_size {
            buf[buf_offset] = contents[written_bytes];
            buf_offset += 1;
            written_bytes += 1;
        }
        let write_word = unsafe { transmute::<_, usize>(buf) };
        trace!("Overwriting word at address {:#x}: {:#018x} (LE) with {:#018x} (LE)",
               aligned_addr, read_word, write_word);
        // This is tricky - although ptrace's signature says "void *data"
        // POKEDATA accepts the word to write by value
        write(pid, aligned_addr as *mut c_void, write_word as *mut c_void)?;
        debug_assert_eq!(
            unsafe { transmute::<_, [u8; std::mem::size_of::<usize>()]>(read(pid, aligned_addr as *mut c_void)?) },
            buf, "Read value is not equal to the written value");
        addr += std::mem::size_of::<usize>() - (addr - aligned_addr);
    }
    Ok(())
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
    // TODO use MaybeUninit when it works for structs
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

fn get_memory_regions(pid: Pid) -> Result<MemoryRegions, Box<dyn std::error::Error>> {
    let maps = get_process_maps(pid.as_raw())?;
    debug!("Read tracee {} memory maps from procfs", pid);
    let original_cmdline = read_to_string(format!("/proc/{}/cmdline", pid))?;
    let original_cmd = original_cmdline.split('\0').next().unwrap_or("");
    debug!(
        "Retrieved \"{}\" as the tracee {}'s original first command line argument",
        original_cmd, pid
    );
    let mut memory_maps_with_buffers: Vec<_> = maps
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
            map.inode != 0
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
        memory_maps_with_buffers.len(),
        pid
    );
    let mut local_iov = Vec::<IoVec<&mut [u8]>>::with_capacity(memory_maps_with_buffers.len());
    let mut remote_iov = Vec::<RemoteIoVec>::with_capacity(memory_maps_with_buffers.len());
    for (map, buf) in memory_maps_with_buffers.iter_mut() {
        local_iov.push(IoVec::from_mut_slice(buf.as_mut_slice()));
        remote_iov.push(RemoteIoVec {
            base: map.start(),
            len: map.size(),
        })
    }
    let bytes_read = process_vm_readv(pid, local_iov.as_slice(), remote_iov.as_slice())?;
    debug!("Read {} bytes of the tracee {}'s memory", bytes_read, pid);
    if bytes_read != memory_maps_with_buffers.iter().map(|(m, _b)| m.size()).sum() {
        warn!("process_vm_readv bytes read return value does not match expected value, continuing");
        debug_assert!(false);
    }
    memory_maps_with_buffers.sort_unstable_by_key(|(map, _buf)| map.start());
    Ok(memory_maps_with_buffers)
}

fn region_for_address(addr: usize, memory_regions: &MemoryRegions) -> Option<&MemoryRegion> {
    for region in memory_regions {
        if addr > region.0.start() && addr < region.0.start() + region.0.size() {
            return Some(region);
        }
    }
    None
}

const X86_MAX_INSTR_LEN: usize = 15;
const JUMP_GROUP: u8 = 1;
const CALL_GROUP: u8 = 2;
const RET_GROUP: u8 = 3;
const IRET_GROUP: u8 = 5;
//const BRANCH_RELATIVE_GROUP: u8 = 7;

fn is_group(detail: &InsnDetail, group_id: u8) -> bool {
    detail.groups().filter(|g| g.0 == group_id).count() == 1
}

fn is_ret(detail: &InsnDetail) -> bool {
    detail.groups().filter(|g| g.0 == RET_GROUP || g.0 == IRET_GROUP).count() > 0
}

const JMP_OPCODES: [u8; 3] = [0xffu8, 0xe9u8, 0xebu8];

fn is_unconditional_branch(detail: &InsnDetail, arch_detail: &ArchDetail) -> bool {
    let opcode = arch_detail.x86().unwrap().opcode()[0];
    let jmp_opcode =
        opcode == JMP_OPCODES[0] || opcode == JMP_OPCODES[1] || opcode == JMP_OPCODES[2];
    return is_group(detail, JUMP_GROUP) && jmp_opcode;
}

fn is_conditional_branch(detail: &InsnDetail, arch_detail: &ArchDetail) -> bool {
    let opcode = arch_detail.x86().unwrap().opcode()[0];
    let jmp_opcode =
        opcode == JMP_OPCODES[0] || opcode == JMP_OPCODES[1] || opcode == JMP_OPCODES[2];
    return is_group(detail, JUMP_GROUP) && !jmp_opcode;
}

fn get_destination_addr(pid: Pid, ins: &Insn, x86_oper: &X86OperandType)
                        -> Result<usize, Box<dyn std::error::Error>> {
    match *x86_oper {
        Imm(addr) => Ok(addr as usize),
        Mem(x86_op_mem) => {
            // TODO handle ljmp correctly
            let addr_location = ins.address() as usize + ins.bytes().len() + x86_op_mem.disp() as usize;
            let mut addr_buf = MaybeUninit::<[u8; 8]>::uninit();
            // is this UB? :P
            tracee_read(pid, addr_location, unsafe { &mut *addr_buf.as_mut_ptr() })?;
            let addr = unsafe { transmute::<_, usize>(addr_buf) };
            Ok(addr)
        }
        _ => Err(Box::new(ToolError::AddressResolutionError(ins.address() as usize))),
    }
}

enum InstructionType<'a> {
    Normal,
    UnconditionalJump(&'a X86OperandType),
    ConditionalJump(&'a X86OperandType),
    Call(&'a X86OperandType),
}

/// Checks if the given instruction is a unconditional jump, branch or a call.
fn analyze_instruction<'a>(
    ins: &Insn,
    detail: &InsnDetail,
    arch_detail: &ArchDetail,
    ops: &'a Vec<ArchOperand>,
    cs: &Capstone,
) -> InstructionType<'a> {
    let group_names = Vec::from_iter(detail.groups()
        .map(|g| cs.group_name(g).unwrap_or("".to_string())));
    trace!("\t{:#x}\t{} {}\t\tGroups:{:?}",
           ins.address(),
           ins.mnemonic().unwrap_or(""),
           ins.op_str().unwrap_or(""),
           group_names);
//    for (i, op) in ops.iter().enumerate() {
//        if let X86Operand(x86_operand) = op {
//            trace!("\t\t[Operand {}: {:?} (size: {})]", i, x86_operand.op_type, x86_operand.size);
//        }
//    }
    // TODO try to tackle non-immediate cases (e.g. jmp rax, jmp qword ptr [rax]?)
    // TODO handle rip manipulation as a jump?
    if ops.len() == 1 {
        if let X86Operand(x86_operand) = &ops[0] {
            let jump_operand = &x86_operand.op_type;
            if is_group(detail, JUMP_GROUP) {
                if is_unconditional_branch(detail, arch_detail) {
                    return UnconditionalJump(jump_operand);
                } else {
                    return ConditionalJump(jump_operand);
                }
            } else if is_group(detail, CALL_GROUP) {
                return Call(jump_operand);
            }
        }
    }
    Normal
}

fn get_entrypoint(
    _pid: Pid,
    memory_regions: &MemoryRegions,
    _cs: &Capstone,
) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    // TODO handle case when the header is not loaded into memory
    for (_map, buf) in memory_regions {
        for (loc, w) in buf.windows(xmas_elf::header::MAGIC.len()).enumerate() {
            if w == xmas_elf::header::MAGIC {
                if let Ok(header) = xmas_elf::header::parse_header(&buf[loc..]) {
                    if let xmas_elf::header::HeaderPt2::Header64(h64) = header.pt2 {
                        return Ok(Some(h64.entry_point as usize));
                    };
                }
            }
        }
    }
    Ok(None)
}

const MOV_ID: InsnIdInt = 449;
const RDI_ID: RegIdInt = 39;
const HLT_ID: InsnIdInt = 208;

fn find_main_address(
    _pid: Pid,
    entrypoint: Option<usize>,
    memory_regions: &MemoryRegions,
    cs: &Capstone,
) -> Result<Option<usize>, Box<dyn std::error::Error>> {
    // TODO support non-glibc binaries
    // TODO support non-x86_64 binaries
    // maybe extract from symbol table? what if binary is stripped?
    if let Some(entrypoint) = entrypoint {
        trace!("Searching for main at {:#x}", entrypoint);
        if let Some((map, buf)) = region_for_address(entrypoint, memory_regions) {
            // decode instructions until mov rdi
            let mut addr = entrypoint;
            'o: loop {
                let buf_offset = addr - map.start();
                let insns = cs.disasm_count(&buf[buf_offset..buf_offset + X86_MAX_INSTR_LEN],
                                            addr as u64, 1)?;
                if insns.is_empty() {
                    break 'o;
                }
                for ins in insns.iter() {
                    let detail = cs.insn_detail(&ins)?;
                    let arch_detail = detail.arch_detail();
                    let ops = arch_detail.operands();
                    if ins.id().0 == HLT_ID {
                        break 'o;
                    }
                    if ins.id().0 == MOV_ID && ops.len() == 2 {
                        if let (X86Operand(x86_op_1), X86Operand(x86_op_2)) = (&ops[0], &ops[1]) {
                            if let (Reg(reg_id), Imm(main_addr)) =
                            (&x86_op_1.op_type, &x86_op_2.op_type) {
                                if reg_id.0 == RDI_ID {
                                    return Ok(Some(*main_addr as usize))
                                }
                            }
                        }
                    }
                    addr += ins.bytes().len();
                }
            }
        }
    }
    Ok(None)
}

const INITIAL_REACHABE_CODE_CAPACITY: usize = 4096;
const INITIAL_XREFS_CAPACITY: usize = 16384;

// TODO change to Xrefs Vec<usize, usize>, or alternatively - a map?
type Addresses = Vec<usize>;
/// Entries have form: (start address, end address))
type ReachableCode = Vec<(usize, usize)>;
/// Entries have form: (address, instruction length)
type BranchAddresses = Vec<(usize, u8)>;

fn seek_xrefs(
    pid: Pid,
    memory_regions: &MemoryRegions,
    cs: &Capstone,
) -> Result<Addresses, Box<dyn std::error::Error>> {
    let mut dst_addrs = Addresses::with_capacity(INITIAL_XREFS_CAPACITY);
    for (map, buf) in memory_regions {
        trace!("Seeking xrefs in memory region: {:#?}", map);
        let mut addr = map.start();
        while addr < map.start() + map.size() {
            let buf_offset = addr - map.start();
            let insns = cs.disasm_all(&buf[buf_offset..], addr as u64)?;
            if insns.is_empty() {
                addr += 1;
                continue;
            }
            for ins in insns.iter() {
                let detail = cs.insn_detail(&ins)?;
                let arch_detail = detail.arch_detail();
                let ops = arch_detail.operands();
                let ins_type = analyze_instruction(&ins, &detail, &arch_detail, &ops, cs);

                match ins_type {
                    Normal => (),
                    Call(x86_op) | ConditionalJump(x86_op) | UnconditionalJump(x86_op) => {
                        let dst_addr = match get_destination_addr(pid, &ins, &x86_op) {
                            Ok(dst_addr) => dst_addr,
                            Err(e) => {
                                warn!("Error when getting destination address at {:x}: {}",
                                      addr, e);
                                addr += ins.bytes().len();
                                continue;
                            }
                        };
                        // if it is a jump or a call to an executable region
                        // then treat it as a valid address
                        if let Some((map, _buf)) = region_for_address(dst_addr, memory_regions) {
                            if map.is_exec() {
                                trace!("xref from {:#x} to {:#x}", ins.address(), dst_addr);
                                dst_addrs.push(dst_addr);
                            }
                        }
                    }
                }
                addr += ins.bytes().len();
            }
        }
    }
    debug!("Gathered {} xrefs", dst_addrs.len());
    Ok(dst_addrs)
}

fn add_code_block(start: usize, end: usize, reachable_code: &mut ReachableCode) {
    let comparator = |probe: &(usize, usize)| {
        if end < probe.0 {
            Less
        } else if start > probe.1 {
            Greater
        } else {
            Equal
        }
    };
    match reachable_code.binary_search_by(comparator) {
        Ok(i) => {
            reachable_code[i].0 = min(start, reachable_code[i].0);
            reachable_code[i].1 = max(end, reachable_code[i].1);
        }
        Err(i) => {
            reachable_code.insert(i, (start, end));
        }
    }
}

fn analyze_block(
    pid: Pid,
    start: usize,
    memory_regions: &MemoryRegions,
    processed: &mut HashMap<usize, bool, BuildHasherDefault<AHasher>>,
    reachable_code: &mut ReachableCode,
    branch_addresses: &mut BranchAddresses,
    cs: &Capstone,
) -> Result<bool, Box<dyn std::error::Error>> {
    let result;
    if let Some(&value) = processed.get(&start) {
        result = value;
    } else {
        result = analyze_block_uncached(pid, start, memory_regions, processed, reachable_code,
                                        branch_addresses, cs)?;
        processed.insert(start, result);
    }
    return Ok(result);
}

fn analyze_block_uncached(
    pid: Pid,
    start: usize,
    memory_regions: &MemoryRegions,
    processed: &mut HashMap<usize, bool, BuildHasherDefault<AHasher>>,
    reachable_code: &mut ReachableCode,
    branch_addresses: &mut BranchAddresses,
    cs: &Capstone,
) -> Result<bool, Box<dyn std::error::Error>> {
    if let Some((map, buf)) = region_for_address(start, memory_regions) {
        trace!("Analyzing block at {:#x}", start);
        let mut branch_addresses_buf = BranchAddresses::new();
        let mut addr = start;
        loop {
            // assume that the instruction does not cross region boundary
            debug_assert!(addr >= map.start() && addr < map.start() + map.size());
            let insns =
                cs.disasm_count(&buf[addr - map.start()..addr - map.start() + X86_MAX_INSTR_LEN],
                                addr as u64, 1)?;
            if insns.is_empty() {
                warn!("Invalid instruction detected at {:#x}, ignoring block", addr);
                return Ok(false);
            } else {
                for ins in insns.iter() {
                    let detail = cs.insn_detail(&ins)?;
                    let arch_detail = detail.arch_detail();
                    let ops = arch_detail.operands();
                    if is_ret(&detail) {
                        // ret means we have reached the end of the code block
                        branch_addresses.extend_from_slice(&branch_addresses_buf);
                        add_code_block(start, addr, reachable_code);
                        trace!("Block at {:#x} returns", start);
                        return Ok(true);
                    }
                    // TODO detect endless loops and exit syscall
                    match analyze_instruction(&ins, &detail, &arch_detail, &ops, cs) {
                        UnconditionalJump(_) => {
                            branch_addresses.extend_from_slice(&branch_addresses_buf);
                            add_code_block(start, addr, reachable_code);
                            return Ok(false);
                        }
                        ConditionalJump(_) => {
                            branch_addresses_buf.push((addr, ins.bytes().len() as u8));
                        }
                        Call(addr_op) => {
                            let target_addr = get_destination_addr(pid, &ins, &addr_op)?;
                            let _returns = analyze_block(pid, target_addr, memory_regions,
                                                         processed, reachable_code,
                                                         branch_addresses, cs)?;
                            // for now, assume all calls return
                            // TODO handle calls that do not return (have to handle plt first)
                            // call that does not return means we have reached
                            // the end of the code block
//                            if !returns {
//                                branch_addresses.extend_from_slice(&branch_addresses_buf);
//                                add_code_block(start, addr, reachable_code);
//                                return Ok(false);
//                            }
                            trace!("Back to analyzing block at {:#x}", start);
                        }
                        Normal => (),
                    }
                    addr += ins.bytes().len();
                }
            }
        }
    } else {
        // TODO
        trace!("Skipping analysis at {:#x}", start);
        // assume that it returns
        Ok(true)
    }
}

fn analyze(
    pid: Pid,
    memory_regions: &MemoryRegions,
    cs: &Capstone,
) -> Result<(ReachableCode, BranchAddresses), Box<dyn std::error::Error>> {
    let mut reachable_code = Vec::with_capacity(INITIAL_REACHABE_CODE_CAPACITY);
    let mut branch_addresses = Vec::with_capacity(INITIAL_REACHABE_CODE_CAPACITY);
    let mut processed = HashMap::<usize, bool, BuildHasherDefault<AHasher>>::with_capacity_and_hasher(
        INITIAL_REACHABE_CODE_CAPACITY,
        BuildHasherDefault::<AHasher>::default(),
    );
    info!("Seeking xrefs");
    let mut xrefs = seek_xrefs(pid, memory_regions, cs)?;
    let entrypoint = get_entrypoint(pid, memory_regions, cs)?;
    if let Some(entrypoint) = entrypoint {
        debug!("Entrypoint located at: {:#x}", entrypoint);
        xrefs.push(entrypoint);
    }
    if let Some(main_addr) = find_main_address(pid, entrypoint, memory_regions, cs)? {
        debug!("Main located at: {:#x}", main_addr);
        xrefs.push(main_addr);
    }
    info!("Analyze blocks");
    for addr in xrefs {
        analyze_block(pid, addr, memory_regions, &mut processed, &mut reachable_code,
                      &mut branch_addresses, cs)?;
    }
    trace!("Detected reachable code:");
    for (start, end) in reachable_code.iter() {
        trace!("From {:#x} to {:#x}", start, end);
    }
    branch_addresses.sort_unstable_by_key(|s| s.0);
    branch_addresses.dedup_by_key(|s| s.0);
    debug!(
        "Vec for branch instructions info has {}/{} entries",
        branch_addresses.len(),
        branch_addresses.capacity()
    );
    for (addr, size) in branch_addresses.iter() {
        trace!("Branch at {:#x} (len {})", addr, size);
    }
    Ok((reachable_code, branch_addresses))
}

const TRAP_X86: u8 = 0xCC;

fn set_branch_breakpoints(
    pid: Pid,
    jump_addresses: &BranchAddresses,
) -> Result<(), Box<dyn std::error::Error>> {
    for (addr, _len) in jump_addresses {
        debug!(
            "Setting a trap instruction at {:#x} in tracee {}'s memory",
            addr, pid
        );
        tracee_set_byte(pid, *addr, TRAP_X86)?;
    }
    Ok(())
}

// TODO this should be more sophisticated
type ExecutionPathEntry = (Pid, usize, bool);
type ExecutionPathLog = VecDeque<ExecutionPathEntry>;

fn handle_trap(
    pid: Pid,
    jump_addresses: &BranchAddresses,
    memory_regions: &MemoryRegions,
    execution_log: &mut ExecutionPathLog,
) -> Result<Pid, Box<dyn std::error::Error>> {
    let mut regs = tracee_get_registers(pid)?;
    let trap_addr = (regs.rip - 1) as usize;
    if let Ok(orig_instr_loc) = jump_addresses.binary_search_by_key(&trap_addr, |s| s.0) {
        let region = region_for_address(trap_addr, memory_regions).unwrap();
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
                trace!("Branch at {:#x} not taken by {}", trap_addr, pid);
            } else {
                execution_log.push_back((pid, trap_addr, true));
                trace!("Branch at {:#x} taken by {}", trap_addr, pid);
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
    jump_addresses: &BranchAddresses,
    memory_regions: &MemoryRegions,
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
                        memory_regions,
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

const INITIAL_EXECUTION_LOG_CAPACITY: usize = 134_217_728;

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
    let mut execution_log = ExecutionPathLog::with_capacity(INITIAL_EXECUTION_LOG_CAPACITY);
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
        let mut e: &Error = top_e.borrow();
        while let Some(source) = e.source() {
            error!("Caused by: {}", source.to_string());
            e = source;
        }
    }
}
