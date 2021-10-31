use anyhow::{Context, Result};
use aya::programs::Lsm;
use aya::Btf;
use aya::{
    include_bytes_aligned,
    maps::{perf::AsyncPerfEventArray, Array, HashMap},
    util::online_cpus,
    Bpf,
};
use bytes::BytesMut;
use chrono::Local;
use groups::get_group_by_gid;
use passwd::Passwd;
use std::convert::{TryFrom, TryInto};
use structopt::clap::AppSettings;
use structopt::StructOpt;
use suidsnoop_common::{Config, SuidEvent};
use tokio::signal;

#[tokio::main]
async fn main() {
    if let Err(e) = try_main().await {
        eprintln!("error: {:#}", e);
    }
}

#[derive(Debug, StructOpt)]
#[structopt(
    name = "suidsnoop",
    about = "Report on suid usage and enforce suid security policy",
    global_settings = &[AppSettings::ColoredHelp],
)]
struct Args {
    /// A list of UIDs to allow invoking suid binaries. Missing UIDs are denied
    #[structopt(short = "u", long = "uid-allowlist")]
    allowed_uids: Vec<u32>,
    /// A list of UIDs to deny invoking suid binaries. Missing UIDs are allowed
    #[structopt(short = "U", long = "uid-denylist")]
    denied_uids: Vec<u32>,
    /// Log denials but don't actually deny
    #[structopt(short = "d", long = "dry-run")]
    dry_run: bool,
}

async fn try_main() -> Result<()> {
    let args = Args::from_args();

    #[cfg(debug_assertions)]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/debug/suidsnoop"
    ))?;
    #[cfg(not(debug_assertions))]
    let mut bpf = Bpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/suidsnoop"
    ))?;

    load_programs(&mut bpf)?;
    populate_maps(&mut bpf, &args)?;

    print_starting_info(&args);
    print_header();

    // Process events from the perf buffer
    let cpus = online_cpus()?;
    let num_cpus = cpus.len();
    let mut events = AsyncPerfEventArray::try_from(bpf.map_mut("EVENTS")?)?;
    for cpu in cpus {
        let mut buf = events.open(cpu, None)?;

        tokio::task::spawn(async move {
            let mut buffers = (0..num_cpus)
                .map(|_| BytesMut::with_capacity(10240))
                .collect::<Vec<_>>();

            loop {
                let events = buf.read_events(&mut buffers).await.unwrap();
                for i in 0..events.read {
                    // get timestamp
                    let now = Local::now();

                    // read the event
                    let buf = &mut buffers[i];
                    let ptr = buf.as_ptr() as *const SuidEvent;
                    let data = unsafe { ptr.read_unaligned() };

                    // parse out the data
                    let decision = match data.denied {
                        true => "DENIED",
                        false => "ALLOWED",
                    };
                    let pathname =
                        String::from_utf8(data.path.to_vec()).unwrap_or("Unknown".to_owned());

                    println!(
                        "{:<10} {:<8} {:<8} {:<16} {:<16} {:<32}",
                        now.format("%Y-%m-%d"),
                        now.format("%H:%M:%S"),
                        decision,
                        translate_uid(data.uid),
                        translate_gid(data.gid),
                        pathname,
                    );
                }
            }
        });
    }

    signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c event");

    eprintln!("Exiting...");

    Ok(())
}

fn load_programs(bpf: &mut Bpf) -> Result<()> {
    let btf = Btf::from_sys_fs()?;

    let program: &mut Lsm = bpf.program_mut("bprm_check_security")?.try_into()?;
    program.load("bprm_check_security", &btf)?;
    program.attach()?;

    Ok(())
}

fn populate_maps(bpf: &mut Bpf, args: &Args) -> Result<()> {
    let mut config_map: Array<_, Config> = bpf.map_mut("CONFIG")?.try_into()?;
    let config = Config {
        use_allowlist: !args.allowed_uids.is_empty(),
        use_denylist: !args.denied_uids.is_empty(),
        dry_run: args.dry_run,
    };
    config_map
        .set(0, config, 0)
        .context("Failed to update config map")?;

    let mut allowlist: HashMap<_, u32, u8> = bpf.map_mut("ALLOWLIST")?.try_into()?;
    for uid in &args.allowed_uids {
        allowlist
            .insert(*uid, 1, 0)
            .context("Failed to update allowlist")?;
    }

    let mut denylist: HashMap<_, u32, u8> = bpf.map_mut("DENYLIST")?.try_into()?;
    for uid in &args.denied_uids {
        denylist
            .insert(*uid, 1, 0)
            .context("Failed to update denylist")?;
    }

    Ok(())
}

/// Translate a UID to user name
fn translate_uid(uid: u32) -> String {
    match Passwd::from_uid(uid) {
        Some(user) => user.name,
        None => uid.to_string(),
    }
}

/// Translate a GID to group name
fn translate_gid(gid: u32) -> String {
    match get_group_by_gid(gid) {
        Some(group) => group.name,
        None => gid.to_string(),
    }
}

/// Print initial information based on user arguments
fn print_starting_info(args: &Args) {
    eprintln!("Tracing SUID binaries... Ctrl-C to exit");

    // Print message about allowed UIDs
    if !args.allowed_uids.is_empty() {
        eprintln!(
            "Allowing UIDs {:?} to invoke SUID binaries, denying all others",
            args.allowed_uids
        );
    }

    // Print message about denied UIDs
    if !args.denied_uids.is_empty() {
        eprintln!(
            "Denying UIDs {:?} to invoke SUID binaries",
            args.denied_uids
        );
    }
}

/// Print initial header for output
fn print_header() {
    eprintln!();
    println!(
        "{:<10} {:<8} {:<8} {:<16} {:<16} {:<32}",
        "DATE", "TIME", "ACTION", "USER", "GROUP", "BINARY"
    );
}
