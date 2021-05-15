use core::ptr::null_mut;
use winapi::ctypes::c_void;
use std::ffi::{CStr, CString};
use std::convert::TryInto;
use std::sync::atomic::{AtomicUsize, Ordering};
use winapi::um::processthreadsapi::{CreateProcessA, PROCESS_INFORMATION, GetProcessId, GetExitCodeProcess, TerminateProcess};
use winapi::um::synchapi::WaitForSingleObject;
use winapi::shared::winerror::ERROR_WAIT_NO_CHILDREN;
use winapi::um::handleapi::CloseHandle;
use winapi::um::winbase::{EXTENDED_STARTUPINFO_PRESENT, STARTUPINFOEXA, INFINITE, STARTF_FORCEOFFFEEDBACK, DETACHED_PROCESS};
use winapi::um::winnt::{HANDLE, SECURITY_CAPABILITIES};
use winapi::shared::minwindef::{DWORD, MAX_PATH};
use winapi::shared::basetsd::DWORD_PTR;
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::sysinfoapi::GetSystemWindowsDirectoryA;
use crate::Policy;
use crate::os::sid::Sid;
use crate::os::proc_thread_attribute_list::ProcThreadAttributeList;
use crate::process::CrossPlatformSandboxedProcess;

// Waiting for these constants from WinSDK to be included in winapi
const PROC_THREAD_ATTRIBUTE_HANDLE_LIST: DWORD_PTR = 0x20002;
const PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY: DWORD_PTR = 0x20007;
const PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES: DWORD_PTR = 0x20009;
const PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY: DWORD_PTR = 0x2000f;
const PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY: DWORD_PTR = 0x2000e;
const PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT: DWORD = 1;
const PROCESS_CREATION_CHILD_PROCESS_RESTRICTED: DWORD = 1;
const PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE: DWORD = 1;
const PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE: DWORD = 4;
const PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON: DWORD = 0x100;
const PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS: DWORD = 0x300;
const PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON: DWORD = 0x1000;
const PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON: DWORD = 0x10000;
const PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON: DWORD = 0x100000;
const PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON: DWORD = 0x10000000;

const MAX_USED_PROC_THREAD_ATTRIBUTES: DWORD = 5; // child process creation policy, mitigation policy, AppContainer, LPAC

static mut PER_PROCESS_APPCONTAINER_ID: std::sync::atomic::AtomicUsize = AtomicUsize::new(0);

pub(crate) struct OSSandboxedProcess {
    pid: u64,
    h_process: Option<HANDLE>,
    exit_code: Option<DWORD>,
}

impl CrossPlatformSandboxedProcess for OSSandboxedProcess {

    fn new(policy: &Policy, exe: &CStr, argv: &[&CStr], envp: &[&CStr]) -> Result<Self, String>
    {
        if argv.len() < 1 {
            return Err("Invalid argument: empty argv".to_owned());
        }

        // Build the full commandline with quotes to protect prevent C:\Program Files\a.exe to launch C:\Program.exe
        let mut cmdline = vec![b'"'];
        cmdline.extend_from_slice(exe.to_bytes());
        cmdline.push(b'"');
        for arg in &argv[1..] {
            let arg = arg.to_bytes();
            cmdline.push(b' ');
            if arg.contains(&b' ') {
                cmdline.push(b'"');
            }
            cmdline.extend_from_slice(arg);
            if arg.contains(&b' ') {
                cmdline.push(b'"');
            }
        }
        let cmdline = CString::new(cmdline).unwrap();

        // Build the concatenated environment block (NULL-terminated strings, the last one with a double-NULL terminator)
        let envblock: Vec<u8> = envp.iter().flat_map(|s| s.to_bytes_with_nul()).chain(std::iter::once(&0)).cloned().collect();

        // Build the starting directory as C:\Windows so that it doesn't keep a handle on any other directory
        let mut cwd = vec![0u8; MAX_PATH + 1];
        let res = unsafe { GetSystemWindowsDirectoryA(cwd.as_mut_ptr() as *mut _, cwd.len().try_into().unwrap()) };
        if res == 0 || res > cwd.len().try_into().unwrap() {
            return Err(format!("GetSystemDirectory() failed with error {}", unsafe { GetLastError() }));
        }
        cwd.truncate(res.try_into().unwrap());
        let cwd = CString::new(cwd).unwrap();

        // Fill a process creation parameter list
        let mut ptal = ProcThreadAttributeList::new(MAX_USED_PROC_THREAD_ATTRIBUTES)?;
        let mut start_info: STARTUPINFOEXA = unsafe { std::mem::zeroed() };
        start_info.StartupInfo.cb = std::mem::size_of_val(&start_info).try_into().unwrap();
        start_info.StartupInfo.dwFlags = STARTF_FORCEOFFFEEDBACK; // disable the "wait" cursor when starting this process
        start_info.lpAttributeList = ptal.as_ptr() as *const _ as *mut _;

        // Restrict inherited handles to only those explicitly allowed
        let handles_to_inherit = policy.get_inherited_resources().into_iter().map(|n| n as *mut c_void).collect::<Vec<HANDLE>>();
        println!(" [.] Setting handles to inherit: {:?}", &handles_to_inherit);
        ptal.set(PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles_to_inherit.as_ptr() as *const _, handles_to_inherit.len() * std::mem::size_of::<HANDLE>())?;

        // Always prevent child process creation, as it would break many security features we implement here
        let policy = PROCESS_CREATION_CHILD_PROCESS_RESTRICTED;
        //ptal.set(PROC_THREAD_ATTRIBUTE_CHILD_PROCESS_POLICY, &policy as *const _ as *const _, std::mem::size_of_val(&policy))?;

        // Always apply sane defaults for process mitigation policies
        let mut policy: DWORD = 0;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_DEP_ENABLE;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_SEHOP_ENABLE;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_FORCE_RELOCATE_IMAGES_ALWAYS_ON_REQ_RELOCS;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_HEAP_TERMINATE_ALWAYS_ON;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_BOTTOM_UP_ASLR_ALWAYS_ON;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_HIGH_ENTROPY_ASLR_ALWAYS_ON;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_STRICT_HANDLE_CHECKS_ALWAYS_ON;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_WIN32K_SYSTEM_CALL_DISABLE_ALWAYS_ON;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_EXTENSION_POINT_DISABLE_ALWAYS_ON; // loading extension DLLs will crash us if they are not win32k-filtering-aware or make syscalls with bad handles
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_PREFER_SYSTEM32_ALWAYS_ON;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_LOW_LABEL_ALWAYS_ON;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_IMAGE_LOAD_NO_REMOTE_ALWAYS_ON;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_FONT_DISABLE_ALWAYS_ON;
        //policy |= PROCESS_CREATION_MITIGATION_POLICY_PROHIBIT_DYNAMIC_CODE_ALWAYS_ON;
        //ptal.set(PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &policy as *const _ as *const _, std::mem::size_of_val(&policy))?;
        
        // Start as an AppContainer whenever possible
        let mut capabilities: SECURITY_CAPABILITIES = unsafe { std::mem::zeroed() };
        /*for i in 0.. {
            let appcontainer_name = format!("IrisAppContainer_{}_{}", std::process::id(), i);
            let name_buf: Vec<u16> = appcontainer_name.encode_utf16().chain(std::iter::once(0)).collect();
            let res = unsafe { CreateAppContainerProfile(name_buf.as_ptr() as *const _, name_buf.as_ptr() as *const _, name_buf.as_ptr() as *const _, null_mut(), 0, &mut capabilities.AppContainerSid as *mut _) };
            if res == 0 {
                break;
            }
            let err = unsafe { GetLastError() };
            if err == HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) as u32 {
                return Err(format!("CreateAppContainerProfile({}) failed with error {}", appcontainer_name, err));
            }
        }*/
        let appcontainer_id = unsafe { PER_PROCESS_APPCONTAINER_ID.fetch_add(1, Ordering::Relaxed) };
        let appcontainer_name = format!("IrisAppContainer_{}_{}", std::process::id(), appcontainer_id);
        let appcontainer_sid = Sid::from_appcontainer_name(&appcontainer_name)?;
        capabilities.AppContainerSid = appcontainer_sid.as_ptr();
        //ptal.set(PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, &capabilities as *const _ as *const _, std::mem::size_of_val(&capabilities))?;

        // Start as a Less Privileged AppContainer whenever possible
        let policy = PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;
        //ptal.set(PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY, &policy as *const _ as *const _, std::mem::size_of_val(&policy))?;

        // Start a child process (enable handle inheritance, but only because we set the allowed list explicitly earlier)
        let mut proc_info: PROCESS_INFORMATION = unsafe { std::mem::zeroed() };
        let res = unsafe { CreateProcessA(null_mut(), cmdline.as_ptr() as *mut _, null_mut(), null_mut(), 1, EXTENDED_STARTUPINFO_PRESENT | DETACHED_PROCESS, envblock.as_ptr() as *mut _, cwd.as_ptr() as *mut _, &mut start_info as *mut _ as *mut _, &mut proc_info as *mut _) };
        if res == 0 {
            return Err(format!("CreateProcess({}) failed with error {}", cmdline.to_string_lossy(), unsafe { GetLastError() }));
        }
        unsafe { CloseHandle(proc_info.hThread); }
        let pid = unsafe { GetProcessId(proc_info.hProcess) };
        if pid == 0 {
            return Err(format!("GetProcessId() failed with error {}", unsafe { GetLastError() }));
        }
        Ok(Self {
            pid: pid.into(),
            h_process: Some(proc_info.hProcess),
            exit_code: None,
        })
    }

    fn get_pid(&self) -> u64 {
        self.pid
    }

    fn wait_for_exit(&mut self) -> Result<u64, String> {
        if let Some(h_process) = self.h_process.take() {
            // Our child is still there, try to wait for it (indefinitely) to exit
            self.exit_code = Some(ERROR_WAIT_NO_CHILDREN);
            let res = unsafe { WaitForSingleObject(h_process, INFINITE) };
            if res != 0 {
                // Waiting failed, terminate as a best effort to avoid leaking the handle, ignoring any error
                unsafe { TerminateProcess(h_process, self.exit_code.unwrap()); }
                return Err(format!("WaitForSingleObject() failed with error {}", unsafe { GetLastError() }));
            }
            // Child has just exited and woken us up, try to get its exit code
            let mut exit_code = 0xFEFEFEFF;
            let res = unsafe { GetExitCodeProcess(h_process, &mut exit_code as *mut _) };
            unsafe { CloseHandle(h_process); }
            if res == 0 {
                return Err(format!("GetExitCodeProcess() failed with error {}", unsafe { GetLastError() }));
            }
            self.exit_code = Some(exit_code);
        }
        // Child has already exited, just return its exit code
        Ok(self.exit_code.unwrap().into())
    }

    fn has_exited(&self) -> bool {
        self.h_process.is_none()
    }
}
