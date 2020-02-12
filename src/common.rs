use std::error::Error;
use std::fmt;

use libc::pid_t;
use proc_maps::MapRange;
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

#[derive(Debug, Serialize, Deserialize)]
pub struct SerdeMapRange {
    pub range_start: usize,
    pub range_end: usize,
    pub offset: usize,
    pub flags: String,
    pub pathname: Option<String>,
}

impl SerdeMapRange {
    pub fn new(original: &MapRange) -> Self {
        SerdeMapRange {
            range_start: original.start(),
            range_end: original.start() + original.size(),
            offset: original.offset,
            flags: original.flags.clone(),
            pathname: original.filename().clone(),
        }
    }
}


#[derive(Serialize, Deserialize)]
pub struct ExecutionPathHeader {
    pub pid: pid_t,
    pub args: Vec<String>,
    pub maps: Vec<SerdeMapRange>,
}

#[derive(AsBytes, FromBytes, Unaligned, Clone, Copy)]
#[repr(packed)]
// pid, offset to executable, (branch) taken
pub struct ExecutionPathEntry(pub pid_t, pub usize, pub u8);
