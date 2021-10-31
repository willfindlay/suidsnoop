#![no_std]

#[derive(Clone, Copy)]
#[repr(C)]
pub struct Config {
    pub use_allowlist: bool,
    pub use_denylist: bool,
    pub dry_run: bool,
}

#[derive(Clone, Copy)]
#[repr(C)]
pub struct SuidEvent {
    pub path: [u8; 4096],
    pub uid: u32,
    pub gid: u32,
    pub denied: bool,
}

#[cfg(feature = "userspace")]
mod userspace {
    use super::*;

    unsafe impl aya::Pod for Config {}
    unsafe impl aya::Pod for SuidEvent {}
}
