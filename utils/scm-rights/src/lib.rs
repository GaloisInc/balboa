use std::os::unix::{
    io::{AsRawFd, RawFd},
    net::UnixDatagram,
    prelude::FromRawFd,
};

/// Unfortunately, libc::CMSG_SPACE is not a const fn (in C it's implemented as a macro). We'd like
/// to allocate CMSG_SPACE(sizeof(int)) bytes, aligned for cmsghdr. However, we can't do that at
/// compile-time. As a result, we instead have a struct where the first field is a cmsghdr, so we
/// get the proper alignment, and then some extra bytes which we hope (and test) will be big enough
/// that we can store what we need it it.
#[repr(C)]
struct CmsgHdrWithSpace {
    header: libc::cmsghdr,
    space: [u8; 32],
}

impl Default for CmsgHdrWithSpace {
    fn default() -> Self {
        CmsgHdrWithSpace {
            header: libc::cmsghdr {
                cmsg_len: 0,
                cmsg_level: 0,
                cmsg_type: 0,
            },
            space: [0; 32],
        }
    }
}

fn assert_cmsg_header_size() -> usize {
    let cmsg_space = std::mem::size_of::<libc::cmsghdr>().max(unsafe {
        // SAFETY: there's nothing unsafe here.
        libc::CMSG_SPACE(std::mem::size_of::<libc::c_int>().try_into().unwrap())
    } as usize);
    assert!(std::mem::size_of::<CmsgHdrWithSpace>() >= cmsg_space);
    cmsg_space
}

/// Set close-on-exec for a file descriptor.
///
/// In situations where atomically creating the file descriptor and setting close-on-exec is
/// available (e.g. on Linux), that should be preferred.
pub fn set_close_on_exec(fd: i32) -> Result<(), i32> {
    unsafe {
        // Manually set close on exec.
        let flags = libc::fcntl(fd, libc::F_GETFD);
        if flags == -1 {
            let err = errno::errno().0;
            libc::close(fd);
            return Err(err);
        }
        if libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) == -1 {
            let err = errno::errno().0;
            libc::close(fd);
            return Err(err);
        }
    }
    Ok(())
}

pub trait ScmRightsExt: AsRawFd {
    fn sendmsg_file(&self, file: &impl AsRawFd, buf: &[u8]) -> std::io::Result<usize> {
        self.sendmsg_file_errno(file, buf)
            .map_err(std::io::Error::from_raw_os_error)
    }

    fn sendmsg_file_errno(&self, file: &impl AsRawFd, buf: &[u8]) -> Result<usize, i32> {
        let cmsg_space = assert_cmsg_header_size();
        let mut control_msg = CmsgHdrWithSpace::default();
        let mut iovec = libc::iovec {
            iov_base: buf.as_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let msghdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iovec,
            msg_iovlen: 1,
            msg_control: (&mut control_msg) as *mut _ as *mut libc::c_void,
            msg_controllen: cmsg_space as _,
            msg_flags: 0,
        };
        assert_eq!(std::mem::size_of::<libc::c_int>(), 4);
        let fd: i32 = file.as_raw_fd();
        unsafe {
            let mut cmsgp = libc::CMSG_FIRSTHDR(&msghdr);
            (*cmsgp).cmsg_len = libc::CMSG_LEN(4).try_into().unwrap();
            (*cmsgp).cmsg_level = libc::SOL_SOCKET;
            (*cmsgp).cmsg_type = libc::SCM_RIGHTS;
            std::slice::from_raw_parts_mut(libc::CMSG_DATA(cmsgp), 4)
                .copy_from_slice(&fd.to_ne_bytes()[..]);
        }
        loop {
            let n = unsafe { libc::sendmsg(self.as_raw_fd(), &msghdr, 0) };
            if n < 0 {
                let e = errno::errno().0;
                if e == libc::EINTR {
                    continue;
                }
                return Err(e);
            } else {
                return Ok(n as usize);
            }
        }
    }

    fn recvmsg_file(&self, buf: &mut [u8]) -> std::io::Result<(Option<RawFd>, usize)> {
        let cmsg_space = assert_cmsg_header_size();
        let mut control_msg = CmsgHdrWithSpace::default();
        let mut iovec = libc::iovec {
            iov_base: buf.as_mut_ptr() as *mut libc::c_void,
            iov_len: buf.len(),
        };
        let mut msghdr = libc::msghdr {
            msg_name: std::ptr::null_mut(),
            msg_namelen: 0,
            msg_iov: &mut iovec,
            msg_iovlen: 1,
            msg_control: &mut control_msg as *mut _ as *mut libc::c_void,
            msg_controllen: cmsg_space as _,
            msg_flags: 0,
        };
        #[cfg(target_os = "macos")]
        const FLAGS: libc::c_int = 0;
        #[cfg(target_os = "linux")]
        const FLAGS: libc::c_int = libc::MSG_CMSG_CLOEXEC;
        loop {
            let n = unsafe { libc::recvmsg(self.as_raw_fd(), &mut msghdr, FLAGS) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(e);
            }
            // TODO: in theory we should check beyond just the first cmsg hdr
            let cmsgp = unsafe { libc::CMSG_FIRSTHDR(&msghdr) };
            return if cmsgp == std::ptr::null_mut()
                || unsafe { (*cmsgp).cmsg_len }
                    != unsafe {
                        libc::CMSG_LEN(std::mem::size_of::<libc::c_int>().try_into().unwrap())
                            .try_into()
                            .unwrap()
                    }
                || unsafe { (*cmsgp).cmsg_level } != libc::SOL_SOCKET
                || unsafe { (*cmsgp).cmsg_type } != libc::SCM_RIGHTS
            {
                Ok((None, n as usize))
            } else {
                assert_eq!(std::mem::size_of::<libc::c_int>(), 4);
                let mut out_fd_buf: [u8; 4] = [0; 4];
                out_fd_buf.copy_from_slice(unsafe {
                    std::slice::from_raw_parts(libc::CMSG_DATA(cmsgp), 4)
                });
                // ne = native-endian
                let fd = i32::from_ne_bytes(out_fd_buf);
                #[cfg(target_os = "macos")]
                {
                    set_close_on_exec(fd).map_err(std::io::Error::from_raw_os_error)?;
                }
                Ok((Some(fd), n as usize))
            };
        }
    }
}
impl ScmRightsExt for UnixDatagram {}

#[test]
fn test_scm_rights() {
    use std::{
        io::{Read, Seek, SeekFrom, Write},
        os::unix::io::FromRawFd,
    };
    const SOCK_PATH: &'static str = "/tmp/stallone-test_scm_rights.sock";
    let _ = std::fs::remove_file(SOCK_PATH);
    let master = UnixDatagram::bind(SOCK_PATH).unwrap();
    let thr = std::thread::spawn(move || {
        let master = UnixDatagram::unbound().unwrap();
        master.connect(SOCK_PATH).unwrap();
        //master.send(b"hello").unwrap();
        let mut f = tempfile::tempfile().unwrap();
        f.write_all(b"cool").unwrap();
        f.seek(SeekFrom::Start(0)).unwrap();
        master.sendmsg_file(&f, b"hello").unwrap();
    });
    let mut buf = vec![0; 256];
    let out = master.recvmsg_file(&mut buf[..]).unwrap();
    if let (Some(fd), n) = out {
        assert_eq!(&buf[0..n], b"hello");
        let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut f_out = Vec::new();
        f.read_to_end(&mut f_out).unwrap();
        assert_eq!(&f_out[..], b"cool");
    } else {
        panic!("unexpected {:?}", out);
    }
    thr.join().unwrap();
}

/// This should be signal-safe.
// test_stallone.py depends on the name of this function.
pub fn make_tempfile_fd() -> Result<libc::c_int, i32> {
    #[cfg(target_os = "macos")]
    {
        let mut path: [u8; 18] = *b"/tmp/rocky.XXXXXX\0";
        let fd = unsafe {
            // SAFETY: path is null terminated.
            libc::mkstemp(path.as_mut_ptr() as *mut i8)
        };
        set_close_on_exec(fd)?;
        unsafe {
            // SAFETY: path is null-terminated.
            libc::unlink(path.as_ptr() as *const i8);
        }
        Ok(fd)
    }
    #[cfg(target_os = "linux")]
    {
        // TODO: investigate using huge pages
        let fd = unsafe {
            libc::syscall(
                libc::SYS_memfd_create,
                b"tmpfile\0".as_ptr(),
                libc::MFD_CLOEXEC,
            )
        };
        if fd < 0 {
            Err(errno::errno().0)
        } else {
            Ok(fd as i32)
        }
    }
}

pub fn make_tmpfile() -> std::io::Result<std::fs::File> {
    make_tempfile_fd()
        .map(|fd| unsafe {
            // SAFETY: fd is uniquely owned
            std::fs::File::from_raw_fd(fd)
        })
        .map_err(|errno| std::io::Error::from_raw_os_error(errno))
}
