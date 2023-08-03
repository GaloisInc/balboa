//! This crate lets us notify systemd that our service is ready.
use stallone_common::{positioned_io_result, PositionedIOResult};
use std::os::unix::net::UnixDatagram;

const VAR_NAME: &'static str = "NOTIFY_SOCKET";

/// If systemd was used to invoke this process, notify systemd that the service is up and ready.
/// Then, unset the environment variable so that subprocesses won't think that they're the "leader"
/// of the service.
pub fn systemd_notify_ready() -> PositionedIOResult<()> {
    // Based on https://git.io/JfhmN
    if let Some(sock_path) = std::env::var_os(VAR_NAME) {
        std::env::remove_var(VAR_NAME);
        let sock = positioned_io_result!(UnixDatagram::unbound())?;
        positioned_io_result!(sock.send_to(b"READY=1", sock_path))?;
        Ok(())
    } else {
        // No NOITFY_SOCKET, so nothing will happen.
        Ok(())
    }
}

#[test]
fn test_systemd_notify_ready() {
    let tmp = tempfile::tempdir().unwrap();
    let sock_path = tmp.path().join("ns");
    assert!(std::env::var_os(VAR_NAME).is_none());
    assert!(systemd_notify_ready().is_ok());
    let sock = UnixDatagram::bind(&sock_path).unwrap();
    std::env::set_var(VAR_NAME, &sock_path);
    systemd_notify_ready().unwrap();
    assert!(std::env::var_os(VAR_NAME).is_none());
    let mut buf = vec![0; 1024];
    let n = sock.recv(&mut buf[..]).unwrap();
    let msg = &buf[0..n];
    assert_eq!(msg, b"READY=1");
}
