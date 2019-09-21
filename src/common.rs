use std::error::Error;
use std::fmt;

use libc::pid_t;
use serde::{Deserialize, Serialize};

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

#[derive(Serialize, Deserialize)]
pub struct ExecutionPathHeader {
    pub pid: pid_t,
    pub args: Vec<String>,
}

// TODO this should be more sophisticated?
// pid, address, (branch) taken
pub type ExecutionPathEntry = (pid_t, usize, bool);