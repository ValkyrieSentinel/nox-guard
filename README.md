# nox-guard

> STATUS: ACTIVE DEVELOPMENT. Expect breaking changes.

A low-level process tracing and monitoring system built with Rust, eBPF, and ptrace.

## What it does

nox-guard watches processes using eBPF tracepoints and ptrace. It attaches to running processes, intercepts ptrace requests, and logs or blocks suspicious behavior. A lightweight, programmable process watchdog between user space and the kernel.

## Architecture

- **nox-orchestrator** — main binary, CLI, process management
- **nox-guard-common** — shared types, PtraceArgs, events, eBPF map definitions
- **ebpf-probes** — eBPF programs with tracepoint hooks on ptrace syscalls
- **asm/core.asm** — low-level helpers

## What works

- eBPF tracepoint on ptrace syscalls (PTRACE_ATTACH, TRACEME, SEIZE)
- Ptrace event forwarding from kernel to user space via eBPF maps
- Process targeting by PID
- Panic-safe eBPF (custom panic handler, no unwinding in kernel)
- Workspace structure with separate crates

## What is missing

- No user-space CLI yet (orchestrator is a skeleton)
- No policy engine (cannot block/allow ptrace per rules)
- No persistent logging
- Limited ptrace request coverage
- No tests
- Probably needs kernel 5.15+

## Why Rust + eBPF

eBPF runs sandboxed code in the kernel without kernel modules. Rust gives memory safety and a sane build system. Together they are perfect for security tooling where a bug means a kernel panic.

## How to build

    git clone https://github.com/ValkyrieSentinel/nox-guard.git
    cd nox-guard
    cargo build
    make ebpf
    sudo ./target/debug/nox-orchestrator

## Requirements

- Linux kernel 5.15+
- Rust stable or nightly
- Clang + LLVM
- libbpf
- Root or CAP_BPF + CAP_PTRACE

## What is next

1. Policy engine (allow/deny ptrace per process)
2. User-space CLI with TUI
3. Persistent event log
4. More ptrace request coverage
5. Integration tests

## License

MIT.


