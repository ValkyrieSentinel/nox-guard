#![no_std]

#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProcessExecEvent {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
    pub filename: [u8; 256],
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MmapExecEvent {
    pub pid: u32,
    pub addr: u64,
    pub len: u64,
    pub fd: i64,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct MemfdEvent {
    pub pid: u32,
    pub uid: u32,
    pub flags: u32,
}

#[repr(C)]
#[derive(Copy, Clone)]
pub struct PtraceEvent {
    pub tracer_pid: u32,
    pub target_pid: u32,
}