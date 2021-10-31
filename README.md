# suidsnoop

> Log suid binaries and enforce per-uid suid policy.

`suidsnoop` is a tool for logging whenever a suid binary is executed on your system and
optionally enforcing a per-uid policy for suid binaries.

## Prerequisites

1. Install a rust stable toolchain: `rustup install stable`
1. Install a rust nightly toolchain: `rustup install nightly`
1. Install bpf-linker: `cargo install bpf-linker`

## Build and Install

```bash
git clone https://github.com/willfindlay/suidsnoop && cd suidsnoop
make install
```

Make sure `$HOME/.cargo/bin` is in your `$PATH`!

## Examples

Log all attempts to run suid binaries:
```bash
sudo suidsnoop
```

Allow uid 1000 and deny all others:
```bash
sudo suidsnoop -u 1000
```

Deny uid 1001 and allow all others:
```bash
sudo suidsnoop -U 1001
```

Do a dry run of a policy:
```bash
sudo suidsnoop -U 1001 -d
```
