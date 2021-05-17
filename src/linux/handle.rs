use std::convert::TryInto;
use std::io::Error;
use libc::{fcntl, F_GETFD, F_SETFD, FD_CLOEXEC};

pub fn set_handle_inheritance(handle: u64, allow_inherit: bool) -> Result<(), String> {
    let fd = match handle.try_into() {
        Ok(n) => n,
        Err(_) => return Err(format!("Invalid file descriptor {}, cannot set as inheritable", handle)),
    };
    let current_flags = unsafe { fcntl(fd, F_GETFD) };
    if current_flags < 0 {
        return Err(format!("fcntl(F_GETFD) failed with error {}", Error::last_os_error().raw_os_error().unwrap_or(0)));
    }
    let res = unsafe { fcntl(fd, F_SETFD, (current_flags & !FD_CLOEXEC) | if allow_inherit { 0 } else { FD_CLOEXEC }) };
    if res < 0 {
        return Err(format!("fcntl(F_SETFD, FD_CLOEXEC) failed with error {}", Error::last_os_error().raw_os_error().unwrap_or(0)));
    }
    Ok(())
}

pub fn get_handle_inheritance(handle: u64) -> Result<bool, String> {
    let fd = match handle.try_into() {
        Ok(n) => n,
        Err(_) => return Err(format!("Invalid file descriptor {}, cannot set as inheritable", handle)),
    };
    let current_flags = unsafe { fcntl(fd, F_GETFD) };
    if current_flags < 0 {
        return Err(format!("fcntl(F_GETFD) failed with error {}", Error::last_os_error().raw_os_error().unwrap_or(0)));
    }
    Ok((current_flags & FD_CLOEXEC) != 0)
}

