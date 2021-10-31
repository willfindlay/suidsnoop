#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use aya_bpf::{
    cty::{c_int, c_long, c_void},
    helpers::{bpf_get_current_uid_gid, gen},
    macros::{lsm, map},
    maps::{Array, HashMap, PerCpuArray, PerfEventArray},
    programs::LsmContext,
};
use suidsnoop_common::{Config, SuidEvent};
use vmlinux::linux_binprm;

#[map]
static mut CONFIG: Array<Config> = Array::with_max_entries(1, 0);

#[map]
static mut ALLOWLIST: HashMap<u32, u8> = HashMap::with_max_entries(10240, 0);

#[map]
static mut DENYLIST: HashMap<u32, u8> = HashMap::with_max_entries(10240, 0);

#[map]
static mut EVENTS: PerfEventArray<SuidEvent> = PerfEventArray::with_max_entries(0, 0);

#[map]
static mut SCRATCH: PerCpuArray<SuidEvent> = PerCpuArray::with_max_entries(1, 0);

const EACCES: i32 = 13;
const EFAULT: i32 = 14;

#[lsm(name = "bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match unsafe { try_bprm_check_security(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_bprm_check_security(ctx: LsmContext) -> Result<i32, i32> {
    let bprm: *const linux_binprm = ctx.arg(0);
    let prev_ret: c_int = ctx.arg(1);
    let uid = bpf_get_current_uid_gid() as u32;
    let gid = (bpf_get_current_uid_gid() >> 32) as u32;

    // Filter on the event
    let mode: u16 = (*(*(*bprm).file).f_inode).i_mode;
    if !should_trace(mode) {
        return Ok(0);
    }

    // Fetch configuration
    let config = CONFIG.get(0).ok_or(-EFAULT)?;

    let denied = policy_decision(uid, config);
    // Ignore errors here for now, since the rest of the program is more important
    let _ = submit_event(&ctx, &*bprm, uid, gid, denied);

    // Forward previous return, if any
    if prev_ret != 0 {
        return Ok(prev_ret);
    }

    if config.dry_run {
        return Ok(0);
    }

    // Enforce policy
    match denied {
        true => Ok(-EACCES),
        false => Ok(0),
    }
}

unsafe fn submit_event(
    ctx: &LsmContext,
    bprm: &linux_binprm,
    uid: u32,
    gid: u32,
    denied: bool,
) -> Result<(), i32> {
    let event = SCRATCH.get_mut(0).ok_or(-EFAULT)?;
    event.uid = uid;
    event.gid = gid;
    event.denied = denied;
    let len =
        bpf_probe_read_str((*bprm).filename as *const _, &mut event.path).map_err(|e| e as i32)?;
    if len < event.path.len() {
        event.path[len] = 0u8;
    }

    EVENTS.output(ctx, event, 0);

    Ok(())
}

/// Returns true if we want to deny, otherwise false.
fn policy_decision(uid: u32, config: &Config) -> bool {
    let mut denied = false;

    // root is a special case
    if uid == 0 {
        return false;
    }

    // Apply allowlist
    if config.use_allowlist && unsafe { ALLOWLIST.get(&uid).is_some() } {
        denied = false;
    } else if config.use_allowlist {
        denied = true;
    }

    // Apply denylist
    if config.use_denylist && unsafe { DENYLIST.get(&uid).is_some() } {
        denied = true;
    }

    denied
}

#[inline]
fn s_isreg(mode: u16) -> bool {
    const S_IFMT: u16 = 0o00170000;
    const S_IFREG: u16 = 0o0100000;
    (mode & S_IFMT) == S_IFREG
}

#[inline]
fn s_isuid(mode: u16) -> bool {
    const S_ISUID: u16 = 0o0004000;
    (mode & S_ISUID) != 0
}

#[inline]
fn should_trace(mode: u16) -> bool {
    s_isreg(mode) && s_isuid(mode)
}

/// TODO: remove this when my bpf_probe_read_str patch gets merged upstream
#[inline]
pub unsafe fn bpf_probe_read_str(src: *const u8, dest: &mut [u8]) -> Result<usize, c_long> {
    let len = gen::bpf_probe_read_str(
        dest.as_mut_ptr() as *mut c_void,
        dest.len() as u32,
        src as *const c_void,
    );
    if len < 0 {
        return Err(-1);
    }

    let mut len = len as usize;
    if len > dest.len() {
        // this can never happen, it's needed to tell the verifier that len is
        // bounded
        len = dest.len();
    }
    Ok(len as usize)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
