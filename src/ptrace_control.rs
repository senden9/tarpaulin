use std::ptr;
use nix::sys::signal::Signal;
use nix::sys::ptrace::*;
use nix::libc::{c_void, c_long};
use nix::unistd::Pid;
use nix::Result;

const RIP: u8 = 128;

#[cfg(target_os = "macos")]
type AddressType = *mut nix::libc::c_char;
#[cfg(target_os = "linux")]
type AddressType = *mut c_void;

#[cfg(target_os = "macos")]
type DataType = nix::libc::c_int;
#[cfg(target_os = "linux")]
type DataType = *mut c_void;

pub fn trace_children(pid: Pid) -> Result<()> {
    //TODO need to check support.
    let options: Options = Options::PTRACE_O_TRACESYSGOOD |
        Options::PTRACE_O_TRACEEXEC | Options::PTRACE_O_TRACEEXIT |
        Options::PTRACE_O_TRACECLONE | Options::PTRACE_O_TRACEFORK |
        Options::PTRACE_O_TRACEVFORK;
    setoptions(pid, options)
}

pub fn detach_child(pid: Pid) -> Result<()> {
    detach(pid)
}

pub fn continue_exec(pid: Pid, sig: Option<Signal>) -> Result<()> {
    cont(pid, sig)
}

#[allow(deprecated)]
pub fn single_step(pid: Pid) -> Result<()> {
    step(pid, None)
}

#[allow(deprecated)]
pub fn read_address(pid: Pid, address:u64) -> Result<c_long> {
    read(pid, address as AddressType).map(|x| x as c_long)
}

#[allow(deprecated)]
pub fn write_to_address(pid: Pid,
                        address: u64,
                        data: i64) -> Result<()> {
    write(pid, address as AddressType, data as DataType)
}

#[allow(deprecated)]
pub fn current_instruction_pointer(pid: Pid) -> Result<c_long> {
    unsafe {
        ptrace(Request::PTRACE_PEEKUSER, pid, RIP as AddressType, ptr::null_mut())
    }
}

#[allow(deprecated)]
pub fn set_instruction_pointer(pid: Pid, pc: u64) -> Result<c_long> {
    unsafe {
        ptrace(Request::PTRACE_POKEUSER, pid, RIP as AddressType, pc as DataType)
    }
}

pub fn request_trace() -> Result<()> {
    traceme()
}

pub fn get_event_data(pid: Pid) -> Result<c_long> {
    getevent(pid)
}

