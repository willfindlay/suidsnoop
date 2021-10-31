#![no_std]
#![no_main]

use aya_bpf::{
    macros::lsm,
    programs::LsmContext,
};

#[lsm(name="bprm_check_security")]
pub fn bprm_check_security(ctx: LsmContext) -> i32 {
    match unsafe { try_bprm_check_security(ctx) } {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

unsafe fn try_bprm_check_security(_ctx: LsmContext) -> Result<i32, i32> {
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
