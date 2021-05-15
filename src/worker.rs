use std::ffi::{CStr, CString};
use crate::Policy;
use crate::process::CrossPlatformSandboxedProcess;
use crate::os::process::OSSandboxedProcess;
use crate::os::handle::allow_handle_inheritance;
use iris_ipc::{MessagePipe, CrossPlatformMessagePipe};

// Name of the environment variable used to pass the IPC socket handle/file
// descriptor number to child processes
const IPC_HANDLE_ENV_NAME: &str = "SANDBOX_IPC_HANDLE";

pub struct Worker {
    process: OSSandboxedProcess,
}

impl Worker {
    pub fn new(policy: &Policy, exe: &CStr, argv: &[&CStr], envp: &[&CStr]) -> Result<Self, String>
    {
        let (mut broker_pipe, worker_pipe) = MessagePipe::new()?;
        let mut policy = policy.clone();
        for handle in worker_pipe.as_handles() {
            allow_handle_inheritance(handle)?;
            policy.allow_inherit_resource(handle)?;
        }
        for env_var in envp {
            if env_var.to_string_lossy().starts_with(IPC_HANDLE_ENV_NAME) {
                return Err(format!("Worker environment cannot contain two {} environment variables", IPC_HANDLE_ENV_NAME));
            }
        }
        let mut envp = Vec::from(envp);
        let ipc_handle_var = CString::new(format!("{}={}", IPC_HANDLE_ENV_NAME, worker_pipe.as_handles().into_iter().map(|i| i.to_string()).collect::<Vec<String>>().join(","))).unwrap();
        envp.push(&ipc_handle_var);
        let process = OSSandboxedProcess::new(&policy, exe, argv, &envp)?;
        broker_pipe.set_remote_pid(process.get_pid());
        Ok(Self {
            process: process,
        })
    }

    pub fn wait_for_exit(&mut self) -> Result<u64, String>
    {
        self.process.wait_for_exit()
    }
}

