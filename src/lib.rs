// Common modules

mod process;
mod worker;

pub use worker::Worker;

// OS-specific modules

#[cfg_attr(target_os = "linux", path = "linux/mod.rs")]
#[cfg_attr(target_os = "windows", path = "windows/mod.rs")]
mod os;

// Re-exported symbols from dependencies
pub use iris_policy::Policy;

