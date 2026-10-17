#![no_std]
#![no_main]

use aya_ebpf::{
    macros::{map, tracepoint},
    programs::TracePointContext,
    helpers::{
        bpf_get_current_comm,
        bpf_get_current_uid_gid,
        bpf_probe_read_user_str_bytes,
    },
    maps::PerfEventArray,
    EbpfContext,
};
use nox_guard_common::{ProcessExecEvent, MmapExecEvent, MemfdEvent, PtraceEvent};

#[repr(C)]
struct TracepointHeader {
    common_type: u16,
    common_flags: u8,
    common_preempt_count: u8,
    common_pid: i32,
    __syscall_nr: i32,
    _pad: i32,
}

#[repr(C)]
struct ExecveArgs {
    header: TracepointHeader,
    filename: u64,
    argv: u64,
    envp: u64,
}

#[repr(C)]
struct MmapArgs {
    header: TracepointHeader,
    addr: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: u64,
    pgoff: u64,
}

#[repr(C)]
struct MemfdCreateArgs {
    header: TracepointHeader,
    uname: u64,
    flags: u32,
    _pad: u32,
}

#[repr(C)]
struct PtraceArgs {
    header: TracepointHeader,
    request: u64,
    pid: u64,
}

#[map]
static EVENTS: PerfEventArray<ProcessExecEvent> = PerfEventArray::<ProcessExecEvent>::new(0);

#[map]
static MMAP_EVENTS: PerfEventArray<MmapExecEvent> = PerfEventArray::<MmapExecEvent>::new(0);

#[map]
static MEMFD_EVENTS: PerfEventArray<MemfdEvent> = PerfEventArray::<MemfdEvent>::new(0);

#[map]
static PTRACE_EVENTS: PerfEventArray<PtraceEvent> = PerfEventArray::<PtraceEvent>::new(0);

#[tracepoint]
pub fn nox_execve(ctx: TracePointContext) -> u32 {
    let args = unsafe { &*(ctx.as_ptr() as *const ExecveArgs) };
    let filename_ptr = args.filename as *const u8;

    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFFFFFF) as u32;

    let mut event = ProcessExecEvent {
        pid: ctx.pid(),
        ppid: 0,
        uid,
        comm: bpf_get_current_comm().unwrap_or([0; 16]),
        filename: [0u8; 256],
    };

    unsafe {
        let _ = bpf_probe_read_user_str_bytes(
            filename_ptr,
            &mut event.filename,
        );
    }

    let _ = EVENTS.output(&ctx, &event, 0);
    0
}

#[tracepoint]
pub fn nox_mmap(ctx: TracePointContext) -> u32 {
    let args = unsafe { &*(ctx.as_ptr() as *const MmapArgs) };

    if args.prot & 0x4 != 0 {
        let event = MmapExecEvent {
            pid: ctx.pid(),
            addr: args.addr,
            len: args.len,
            fd: args.fd as i64,
        };
        let _ = MMAP_EVENTS.output(&ctx, &event, 0);
    }
    0
}

#[tracepoint]
pub fn nox_memfd_create(ctx: TracePointContext) -> u32 {
    let args = unsafe { &*(ctx.as_ptr() as *const MemfdCreateArgs) };
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFFFFFF) as u32;

    let event = MemfdEvent {
        pid: ctx.pid(),
        uid,
        flags: args.flags,
    };
    let _ = MEMFD_EVENTS.output(&ctx, &event, 0);
    0
}

#[tracepoint]
pub fn nox_ptrace(ctx: TracePointContext) -> u32 {
    let args = unsafe { &*(ctx.as_ptr() as *const PtraceArgs) };

    if args.request == 16 || args.request == 0 || args.request == 0x4206 {
        let event = PtraceEvent {
            tracer_pid: ctx.pid(),
            target_pid: args.pid as u32,
        };
        let _ = PTRACE_EVENTS.output(&ctx, &event, 0);
    }
    0
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}