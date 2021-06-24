use std::ffi::{CStr, CString};
use crate::Policy;
use crate::process::CrossPlatformSandboxedProcess;
use crate::os::process::OSSandboxedProcess;
use crate::os::handle::{is_handle_inheritable, set_handle_inheritable};
use iris_ipc::{MessagePipe, CrossPlatformMessagePipe};

// Name of the environment variable used to pass the IPC socket handle/file
// descriptor number to child processes
const IPC_HANDLE_ENV_NAME: &str = "SANDBOX_IPC_HANDLE";

pub struct Worker {
    process: OSSandboxedProcess,
}

impl Worker {
    pub fn new(policy: &Policy, exe: &CStr, argv: &[&CStr], envp: &[&CStr], stdin: Option<u64>, stdout: Option<u64>, stderr: Option<u64>) -> Result<Self, String>
    {
        let (mut broker_pipe, worker_pipe) = MessagePipe::new()?;
        let mut policy = policy.clone();
        for handle in worker_pipe.as_handles() {
            set_handle_inheritable(handle, true)?;
            policy.allow_inherit_resource(handle)?;
        }
        for handle in vec![stdin, stdout, stderr] {
            if let Some(handle) = handle {
                policy.allow_inherit_resource(handle)?;
            }
        }
        for handle in policy.get_inherited_resources() {
            // On Linux, exec() will close all CLOEXEC handles.
            // On Windows, CreateProcess() with bInheritHandles = TRUE doesn't automatically set the given handles as inheritable,
            // instead giving a ERROR_INVALID_PARAMETER if one of them is not.
            // We cannot just set the handles as inheritable behind the caller's back, since they might change this in another
            // thread. They have to get this right.
            if !is_handle_inheritable(handle)? {
                return Err(format!("Cannot make worker inherit handle {} which is not set as inheritable", handle));
            }
        }
        for env_var in envp {
            if env_var.to_string_lossy().starts_with(IPC_HANDLE_ENV_NAME) {
                return Err(format!("Workers cannot use the reserved {} environment variable", IPC_HANDLE_ENV_NAME));
            }
        }
        let mut envp = Vec::from(envp);
        let ipc_handle_var = CString::new(format!("{}={}", IPC_HANDLE_ENV_NAME, worker_pipe.as_handles().into_iter().map(|i| i.to_string()).collect::<Vec<String>>().join(","))).unwrap();
        envp.push(&ipc_handle_var);
        let process = OSSandboxedProcess::new(&policy, exe, argv, &envp, stdin, stdout, stderr)?;
        broker_pipe.set_remote_pid(process.get_pid());
        Ok(Self {
            process: process,
        })
    }

    pub fn get_pid(&self) -> u64 {
        self.process.get_pid()
    }

    pub fn wait_for_exit(&mut self) -> Result<u64, String> {
        self.process.wait_for_exit()
    }
}

