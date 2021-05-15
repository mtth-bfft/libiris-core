use std::convert::TryInto;
use winapi::um::handleapi::SetHandleInformation;
use winapi::um::winbase::HANDLE_FLAG_INHERIT;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::winnt::HANDLE;

pub(crate) fn allow_handle_inheritance(handle: u64) -> Result<(), String> {
    let res = unsafe { SetHandleInformation(handle as *mut _, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) };
    if res == 0 {
        return Err(format!("SetHandleInformation() failed with error {}", unsafe { GetLastError() }));
    }
    Ok(())
}
