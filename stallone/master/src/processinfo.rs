use stallone_common::StallonePID;
use stallone_parsing::{MachineMetadata, MachineUname, ProcessInfo};
use std::{
    collections::HashMap,
    fs::read_link,
    os::unix::ffi::OsStrExt,
    path::{Path, PathBuf},
    time::SystemTime,
};

pub fn gather_machine_info(socket_path: PathBuf) -> MachineMetadata {
    MachineMetadata {
        started_at: SystemTime::now(),
        environment_vars: std::env::vars_os()
            .map(|(k, v)| {
                (
                    k.to_string_lossy().into_owned(),
                    v.to_string_lossy().into_owned(),
                )
            })
            .collect(),
        socket_path,
        stallone_master_pid: std::process::id(),
        hostname: String::from_utf8_lossy(gethostname::gethostname().as_bytes()).into_owned(),
        cpu_info: std::fs::read_to_string("/proc/cpuinfo").unwrap_or(String::new()),
        mem_info: std::fs::read_to_string("/proc/meminfo").unwrap_or(String::new()),
        machine_id: std::fs::read_to_string("/etc/machine-id").unwrap_or(String::new()),
        ip_addresses: {
            let mut out = HashMap::new();
            for (name, ip) in get_if_addrs::get_if_addrs()
                .unwrap_or(Vec::new())
                .into_iter()
                .map(|iface| (iface.name, iface.addr.ip()))
            {
                out.entry(name).or_insert(Vec::new()).push(ip);
            }
            out
        },
        uname: nix::sys::utsname::uname()
            .map(|uname| MachineUname {
                sys: uname.sysname().to_string_lossy().into_owned(),
                node: uname.nodename().to_string_lossy().into_owned(),
                release: uname.release().to_string_lossy().into_owned(),
                version: uname.version().to_string_lossy().into_owned(),
                machine: uname.machine().to_string_lossy().into_owned(),
            })
            .unwrap_or_default(),
    }
}

fn read_zero_suffixed_string(path: impl AsRef<Path>) -> std::io::Result<Vec<String>> {
    let path = path.as_ref();
    let mut buf = std::fs::read(path)?;
    while buf.last() == Some(&b'\0') {
        buf.pop();
    }
    Ok(buf
        .split(|byte| *byte == 0)
        .map(|x| String::from_utf8_lossy(x).into_owned())
        .collect())
}

pub(crate) fn gather_process_info(
    pid: u32,
    build_id: &[u8],
    parnet_stallone_pid: Option<StallonePID>,
) -> ProcessInfo {
    ProcessInfo {
        os_pid: pid,
        parent_pid: parnet_stallone_pid,
        build_id: build_id.to_vec(),
        exe_path: read_link(format!("/proc/{}/exe", pid))
            .map(|x| x.to_string_lossy().into_owned())
            .unwrap_or("".to_string()),
        cmdline: read_zero_suffixed_string(format!("/proc/{}/cmdline", pid)).unwrap_or_default(),
        cwd: read_link(format!("/proc/{}/cwd", pid))
            .map(|x| x.to_string_lossy().into_owned())
            .unwrap_or("".to_string()),
        environ: read_zero_suffixed_string(format!("/proc/{}/environ", pid)).unwrap_or_default(),
    }
}
