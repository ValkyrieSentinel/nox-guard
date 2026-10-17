use aya::{
    include_bytes_aligned,
    maps::perf::{PerfEventArray, PerfEvent},
    programs::TracePoint,
    Ebpf,
};
use aya::util::online_cpus;
use log::{info, warn};
use nox_guard_common::{ProcessExecEvent, MmapExecEvent, MemfdEvent, PtraceEvent};
use tokio::signal;
use tokio::process::Command as TokioCommand;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;
use std::convert::TryInto;

#[tokio::main]
async fn main() -> Result<(), anyhow::Error> {
    env_logger::init();

    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };

    let mut bpf = Ebpf::load(include_bytes_aligned!(
        concat!(env!("CARGO_MANIFEST_DIR"), "/../ebpf-probes/ebpf/target/bpfel-unknown-none/release/libnox_ebpf.so")
    ))?;

    for (name, category, syscall) in [
        ("nox_execve", "syscalls", "sys_enter_execve"),
        ("nox_mmap", "syscalls", "sys_enter_mmap"),
        ("nox_memfd_create", "syscalls", "sys_enter_memfd_create"),
        ("nox_ptrace", "syscalls", "sys_enter_ptrace"),
    ] {
        let program: &mut TracePoint = bpf.program_mut(name).unwrap().try_into()?;
        program.load()?;
        program.attach(category, syscall)?;
        info!("✅ Attached [{}] to tracepoint [{}:{}]", name, category, syscall);
    }

    info!("🚀 Nox-Guard DFIR orchestrator successfully activated!");

    
    let mut events_array = PerfEventArray::try_from(bpf.take_map("EVENTS").unwrap())?;
    let mut mmap_array = PerfEventArray::try_from(bpf.take_map("MMAP_EVENTS").unwrap())?;
    let mut memfd_array = PerfEventArray::try_from(bpf.take_map("MEMFD_EVENTS").unwrap())?;
    let mut ptrace_array = PerfEventArray::try_from(bpf.take_map("PTRACE_EVENTS").unwrap())?;

    let cpus = online_cpus().map_err(|(msg, err)| anyhow::anyhow!("{}: {}", msg, err))?;
    let _counter = Arc::new(Mutex::new(HashMap::<String, usize>::new()));
    let mut handles = vec![];

    
    for cpu_id in cpus.clone() {
        let mut buf = match events_array.open(cpu_id, Some(4)) {
            Ok(b) => b,
            Err(_) => continue,
        };

        handles.push(tokio::spawn(async move {
            loop {
                let _ = tokio::task::block_in_place(|| {
                    buf.for_each(|event| {
                        if let PerfEvent::Sample { head, .. } = event {
                            let data = head;
                            if data.len() >= std::mem::size_of::<ProcessExecEvent>() {
                                let event_struct = unsafe {
                                    std::ptr::read_unaligned(
                                        data.as_ptr() as *const ProcessExecEvent
                                    )
                                };
                                let filename = String::from_utf8_lossy(&event_struct.filename).trim_matches('\0').to_string();
                                if !filename.is_empty() {
                                    let pid = event_struct.pid;
                                    let ppid = event_struct.ppid;
                                    let comm = String::from_utf8_lossy(&event_struct.comm).trim_matches('\0').to_string();
                                    tokio::spawn(async move {
                                        let entropy = tokio::fs::read(&filename).await.map(|b| calculate_entropy(&b)).unwrap_or(0.0);
                                        if entropy > 0.0 {
                                            if entropy > 7.2 {
                                                warn!("[HIGH ENTROPY / PACKED?] File: {} | Entropy: {:.2} | PID: {}", filename, entropy, pid);
                                            } else {
                                                info!("[EXECVE] PID: {}, PPID: {}, Comm: {}, File: {}, Entropy: {:.2}", 
                                                    pid, ppid, comm, filename, entropy);
                                            }
                                            let _ = TokioCommand::new("./nox-core").arg(&filename).output().await;
                                        }
                                    });
                                }
                            }
                        }
                    })
                });
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }));
    }

    for cpu_id in cpus.clone() {
        let mut buf = match mmap_array.open(cpu_id, Some(4)) {
            Ok(b) => b,
            Err(_) => continue,
        };
        handles.push(tokio::spawn(async move {
            loop {
                let _ = tokio::task::block_in_place(|| {
                    buf.for_each(|event| {
                        if let PerfEvent::Sample { head, .. } = event {
                            let data = head;
                            if data.len() >= std::mem::size_of::<MmapExecEvent>() {
                                let event_struct = unsafe {
                                    std::ptr::read_unaligned(
                                        data.as_ptr() as *const MmapExecEvent
                                    )
                                };
                                if event_struct.fd != -1 {
                                    warn!("[W^X VIOLATION] PID: {}, Addr: 0x{:x}, Len: {}, FD: {}", event_struct.pid, event_struct.addr, event_struct.len, event_struct.fd);
                                }
                            }
                        }
                    })
                });
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }));
    }

    for cpu_id in cpus.clone() {
        let mut buf = match memfd_array.open(cpu_id, Some(4)) {
            Ok(b) => b,
            Err(_) => continue,
        };
        handles.push(tokio::spawn(async move {
            loop {
                let _ = tokio::task::block_in_place(|| {
                    buf.for_each(|event| {
                        if let PerfEvent::Sample { head, .. } = event {
                            let data = head;
                            if data.len() >= std::mem::size_of::<MemfdEvent>() {
                                let event_struct = unsafe {
                                    std::ptr::read_unaligned(
                                        data.as_ptr() as *const MemfdEvent
                                    )
                                };
                                warn!("[FILELESS / MEMFD] PID: {}, UID: {}, Flags: 0x{:x}", event_struct.pid, event_struct.uid, event_struct.flags);
                            }
                        }
                    })
                });
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }));
    }

    
    for cpu_id in cpus {
        let mut buf = match ptrace_array.open(cpu_id, Some(4)) {
            Ok(b) => b,
            Err(_) => continue,
        };
        handles.push(tokio::spawn(async move {
            loop {
                let _ = tokio::task::block_in_place(|| {
                    buf.for_each(|event| {
                        if let PerfEvent::Sample { head, .. } = event {
                            let data = head;
                            if data.len() >= std::mem::size_of::<PtraceEvent>() {
                                let event_struct = unsafe {
                                    std::ptr::read_unaligned(
                                        data.as_ptr() as *const PtraceEvent
                                    )
                                };
                                warn!("[PTRACE INJECTION] Tracer PID: {} -> Target PID: {}", event_struct.tracer_pid, event_struct.target_pid);
                            }
                        }
                    })
                });
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        }));
    }

    tokio::select! {
        _ = signal::ctrl_c() => {
            info!("🛑 Stop signal received. Shutting down Nox-Guard...");
        }
    }

    Ok(())
}

fn calculate_entropy(data: &[u8]) -> f64 {
    if data.is_empty() { return 0.0; }
    let mut counts = [0usize; 256];
    for &byte in data { counts[byte as usize] += 1; }
    let len = data.len() as f64;
    counts.iter().filter(|&&c| c > 0).map(|&c| {
        let p = c as f64 / len;
        -p * p.log2()
    }).sum()
}