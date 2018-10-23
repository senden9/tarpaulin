use nix::sys::signal::Signal;
use nix::sys::ptrace::*;
use nix::libc::{c_void, c_long};
use nix::unistd::Pid;
use nix::errno::Errno;
use nix::Error;
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

#[cfg(target_os = "macos")]
const POKE_USER:Request = RequestType::PT_WRITE_U;
#[cfg(target_os = "linux")]
const POKE_USER:Request = Request::PTRACE_POKEUSER;
#[cfg(target_os = "macos")]
const PEEK_USER:Request = RequestType::PT_READ_U;
#[cfg(target_os = "linux")]
const PEEK_USER:Request = Request::PTRACE_PEEKUSER;


pub fn detach_child(pid: Pid) -> Result<()> {
    detach(pid)
}

pub fn continue_exec(pid: Pid, sig: Option<Signal>) -> Result<()> {
    cont(pid, sig)
}

pub fn single_step(pid: Pid) -> Result<()> {
    step(pid, None)
}

pub fn read_address(pid: Pid, address:u64) -> Result<c_long> {
    read(pid, address as AddressType).map(|x| x as c_long)
}

pub fn write_to_address(pid: Pid,
                        address: u64,
                        data: i64) -> Result<()> {
    write(pid, address as AddressType, data as DataType)
}

#[allow(deprecated)]
pub fn current_instruction_pointer(pid: Pid) -> Result<c_long> {
    let ret = unsafe {
        Errno::clear();
        libc::ptrace(PEEK_USER as RequestType, libc::pid_t::from(pid), RIP as AddressType, 0 as DataType)
    };

    match Errno::result(ret) {
        Ok(..) | Err(Error::Sys(Errno::UnknownErrno)) => Ok(ret),
        err @ Err(..) => err,
    }
}

#[allow(deprecated)]
pub fn set_instruction_pointer(pid: Pid, pc: u64) -> Result<()> {
    unsafe {
        Errno::clear();
        Errno::result(libc::ptrace(POKE_USER as RequestType, libc::pid_t::from(pid), RIP as AddressType, pc as DataType)).map(|_|())
    }
}

pub fn request_trace() -> Result<()> {
    traceme()
}

