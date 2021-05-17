use core::ffi::c_void;
use core::ptr::null;
use libc::c_int;
use std::ffi::{CStr, CString};
use std::io::Error;
use std::convert::TryInto;
use crate::Policy;
use crate::process::CrossPlatformSandboxedProcess;
use crate::set_handle_inheritance;

const DEFAULT_CLONE_STACK_SIZE: usize = 1 * 1024 * 1024;

pub struct OSSandboxedProcess {
    pid: u64,
    initial_thread_stack: Vec<u8>,
}

struct EntrypointParameters {
    exe: CString,
    argv: Vec<CString>,
    envp: Vec<CString>,
    allowed_file_descriptors: Vec<c_int>,
    execve_errno_pipe: c_int,
}

impl CrossPlatformSandboxedProcess for OSSandboxedProcess {

    fn new(policy: &Policy, exe: &CStr, argv: &[&CStr], envp: &[&CStr]) -> Result<Self, String>
    {
        if argv.len() < 1 {
            return Err("Invalid argument: empty argv".to_owned());
        }

        // Allocate a stack for the process' first thread to use
        let mut stack = vec![0; DEFAULT_CLONE_STACK_SIZE];
        let stack_end_ptr = stack.as_mut_ptr().wrapping_add(stack.len()) as *mut c_void;

        // Unshare as many namespaces as possible
        // (this might not be possible due to insufficient privilege level,
        // and/or kernel support for unprivileged or even privileged user namespaces)
        let clone_args = 0; //libc::CLONE_NEWUSER | libc::CLONE_NEWCGROUP | libc::CLONE_NEWIPC | libc::CLONE_NEWNET | libc::CLONE_NEWNS | libc::CLONE_NEWPID | libc::CLONE_NEWUTS;

        // Set up a pipe that will get CLOEXEC-ed if execve() succeeds, and otherwise be used to send us the errno
        let mut clone_error_pipes: Vec<c_int> = vec![-1, -1];
        let res = unsafe { libc::pipe(clone_error_pipes.as_mut_ptr()) };
        if res < 0 {
            return Err(format!("pipe() failed with code {}", Error::last_os_error()));
        }
        let (parent_pipe, child_pipe) = (clone_error_pipes[0], clone_error_pipes[1]);
        set_handle_inheritance(child_pipe.try_into().unwrap(), false)?; // set the pipe as CLOEXEC so it gets closed on successful execve()

        // Pack together everything that needs to be passed to the new process
        let entrypoint_params = EntrypointParameters {
            exe: exe.to_owned(),
            argv: argv.iter().map(|x| (*x).to_owned()).collect(),
            envp: envp.iter().map(|x| (*x).to_owned()).collect(),
            allowed_file_descriptors: policy.get_inherited_resources().iter().map(|n| *n as c_int).collect(),
            execve_errno_pipe: child_pipe,
        };
        let entrypoint_params = Box::leak(Box::new(entrypoint_params));

        let pid = unsafe {
            libc::clone(process_entrypoint, stack_end_ptr, clone_args, entrypoint_params as *const _ as *mut c_void)
        };

        // Drop the structure in the parent so it doesn't leak
        unsafe { Box::from_raw(entrypoint_params as *mut EntrypointParameters) };
        unsafe { libc::close(child_pipe); }

        if pid <= 0
        {
            unsafe { libc::close(parent_pipe); }
            return Err(format!("clone() failed with code {}", Error::last_os_error()));
        }

        let mut execve_errno = vec![0u8; 4];
        let res = unsafe { libc::read(parent_pipe, execve_errno.as_mut_ptr() as *mut _, execve_errno.len()) };
        if res > 0 {
            return Err(format!("execve() failed with code {}", u32::from_be_bytes(execve_errno[..].try_into().unwrap())));
        }

        println!(" [.] Worker PID={} created", pid);

        Ok(Self {
            pid: pid.try_into().unwrap(),
            initial_thread_stack: stack,
        })
    }

    fn get_pid(&self) -> u64
    {
        self.pid
    }

    fn wait_for_exit(&mut self) -> Result<u64, String>
    {
        Ok(0) // FIXME: implement based on the IPC event loop
    }

    fn has_exited(&self) -> bool
    {
        true // FIXME: implement based on the IPC event loop
    }
}

extern "C" fn process_entrypoint(args: *mut c_void) -> c_int
{
    let args = unsafe { Box::from_raw(args as *mut EntrypointParameters) };
    println!(" [.] Worker {} started with PID={}", args.exe.to_string_lossy(), unsafe { libc::getpid() });

    // Cleanup leftover file descriptors from our parent or from code injected into our process
    for entry in std::fs::read_dir("/proc/self/fd/").expect("unable to read /proc/self/fd/") {
        let entry = entry.expect("unable to read entry from /proc/self/fd/");
        if !entry.file_type().expect("unable to read file type from /proc/self/fd").is_symlink() {
            continue;
        }
        // Exclude the file descriptor from the read_dir itself (if we close it, we might
        // break the /proc/self/fd/ enumeration)
        let mut path = entry.path();
        loop {
            match std::fs::read_link(&path) {
                Ok(target) => path = target,
                Err(_) => break,
            }
        }
        if path.to_string_lossy() == format!("/proc/{}/fd", std::process::id()) {
            continue;
        }
        let fd = entry.file_name().to_string_lossy().parse::<i32>().expect("unable to parse file descriptor number from /proc/self/fd/");
        if fd == args.execve_errno_pipe {
            continue; // don't close the CLOEXEC pipe used to check if execve() worked, otherwise it loses its purpose
        }
        if !args.allowed_file_descriptors.contains(&fd) {
            println!(" [.] Cleaning up file descriptor {}", fd);
            unsafe { libc::close(fd); }
        }
    }
    
    let argv: Vec<*const i8> = args.argv.iter().map(|x| x.as_ptr()).chain(std::iter::once(null())).collect();
    let envp: Vec<*const i8> = args.envp.iter().map(|x| x.as_ptr()).chain(std::iter::once(null())).collect();
    unsafe { libc::execve(args.exe.as_ptr(), argv.as_ptr(), envp.as_ptr()) };

    let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
    let errno_bytes = (errno as u32).to_be_bytes();
    unsafe {
        libc::write(args.execve_errno_pipe, errno_bytes.as_ptr() as *const _, 4);
        libc::close(args.execve_errno_pipe);
    }

    errno as c_int
}

