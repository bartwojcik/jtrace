use std::error::Error;
use std::fmt;

use libc::pid_t;
use serde::{Deserialize, Serialize};
use zerocopy::{AsBytes, FromBytes, Unaligned};

#[derive(Debug)]
pub enum ToolError {
    AddressResolutionError(usize),
}

impl Error for ToolError {}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
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
// TODO address/offset should be the same between runs even with PIE and ASLR
#[derive(AsBytes, FromBytes, Unaligned)]
#[repr(packed)]
// pid, offset to executable, (branch) taken
pub struct ExecutionPathEntry(pub pid_t, pub usize, pub u8);
