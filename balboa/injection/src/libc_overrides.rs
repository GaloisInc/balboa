use crate::fd_state::FdState;
use crate::fd_table;
use crate::globals::balboa_interceptors;
use crate::globals::{BIND_IP_PRE_CONNECT, BIND_IP_PRE_CONNECT_EMPTY};
use balboa_rewriter::read_state::ReadIsPeek;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub use libc;

unsafe fn get_socket_addr(
    address: *const libc::sockaddr,
    len: libc::socklen_t,
) -> Option<SocketAddr> {
    match (*address).sa_family as i32 {
        libc::AF_INET if (len as usize) >= std::mem::size_of::<libc::sockaddr_in>() => {
            let address: libc::sockaddr_in = std::mem::transmute_copy(&*address);
            let ip = std::net::Ipv4Addr::from(u32::from_be(address.sin_addr.s_addr));
            let port = u16::from_be(address.sin_port);
            Some(SocketAddr::V4(SocketAddrV4::new(ip, port)))
        }
        libc::AF_INET6 if (len as usize) >= std::mem::size_of::<libc::sockaddr_in6>() => {
            let address: libc::sockaddr_in6 = std::mem::transmute_copy(&*address);
            let ip = std::net::Ipv6Addr::from(address.sin6_addr.s6_addr);
            let port = u16::from_be(address.sin6_port);
            // For some reason, flowinfo and scope_id seem to be in the native byte order.
            Some(SocketAddr::V6(SocketAddrV6::new(
                ip,
                port,
                address.sin6_flowinfo,
                address.sin6_scope_id,
            )))
        }
        _ => None,
    }
}

/// Interceptor code for the `write` function call.
pub unsafe fn balboa_write(
    write: unsafe extern "C" fn(
        fd: libc::c_int,
        buf: *const libc::c_void,
        count: libc::size_t,
    ) -> libc::ssize_t,
    fd: libc::c_int,
    buf: *const libc::c_void,
    count: libc::size_t,
) -> libc::ssize_t {
    // BEGIN SPECIAL HEADER.
    // We want to be very careful with stdout and stderr. Stderr, in particular, may be written
    // to during a panic. If we're not careful, then it'll cause an infinite loop (on Linux;
    // MacOS has first-class dynamic library interception support). As a result, for the write
    // function, we manually call balboa_initialize, but only after checking whether we're
    // dealing with STDERR or STDOUT. balboa_initialize() could be the cause of our panic.
    // TODO: eventually, just hit the write syscall directly, so we don't even need to deal with
    // the possibly error-causing RTLD_NEXT for the write() syscall wrapper.
    if fd == libc::STDERR_FILENO || fd == libc::STDOUT_FILENO {
        return write(fd, buf, count);
    }
    if let Some(handle) = fd_table::get(fd) {
        handle.rewrite_write(
            &[libc::iovec {
                iov_base: buf as *mut libc::c_void,
                iov_len: count,
            }],
            |new_buf| write(fd, new_buf.as_ptr() as *const libc::c_void, new_buf.len()),
        )
    } else {
        write(fd, buf, count)
    }
}

/// Interceptor code for the `read` function call.
pub unsafe fn balboa_read(
    read: unsafe extern "C" fn(
        fd: libc::c_int,
        buf: *mut libc::c_void,
        count: libc::size_t,
    ) -> libc::ssize_t,
    fd: libc::c_int,
    buf: *mut libc::c_void,
    count: libc::size_t,
) -> libc::ssize_t {
    if let Some(entry) = fd_table::get(fd) {
        entry.rewrite_readv(
            &[libc::iovec {
                iov_base: buf,
                iov_len: count,
            }],
            ReadIsPeek::default(),
            |new_buf| read(fd, new_buf.as_mut_ptr() as *mut libc::c_void, new_buf.len()),
        )
    } else {
        read(fd, buf, count)
    }
}

/// Interceptor code for the `send` function call.
pub unsafe fn balboa_send(
    send: unsafe extern "C" fn(
        fd: libc::c_int,
        buf: *const libc::c_void,
        count: libc::size_t,
        flags: libc::c_int,
    ) -> libc::ssize_t,
    fd: libc::c_int,
    buf: *const libc::c_void,
    count: libc::size_t,
    flags: libc::c_int,
) -> libc::ssize_t {
    if let Some(handle) = fd_table::get(fd) {
        handle.rewrite_write(
            &[libc::iovec {
                iov_base: buf as *mut libc::c_void,
                iov_len: count,
            }],
            |new_buf| {
                send(
                    fd,
                    new_buf.as_ptr() as *const libc::c_void,
                    new_buf.len(),
                    flags,
                )
            },
        )
    } else {
        send(fd, buf, count, flags)
    }
}

/// Interceptor code for the `recv` function call.
pub unsafe fn balboa_recv(
    recv: unsafe extern "C" fn(
        fd: libc::c_int,
        buf: *mut libc::c_void,
        count: libc::size_t,
        flags: libc::c_int,
    ) -> libc::ssize_t,
    fd: libc::c_int,
    buf: *mut libc::c_void,
    count: libc::size_t,
    flags: libc::c_int,
) -> libc::ssize_t {
    if let Some(entry) = fd_table::get(fd) {
        entry.rewrite_readv(
            &[libc::iovec {
                iov_base: buf,
                iov_len: count,
            }],
            ReadIsPeek::from_flags(flags),
            |new_buf| {
                recv(
                    fd,
                    new_buf.as_mut_ptr() as *mut libc::c_void,
                    new_buf.len(),
                    flags,
                )
            },
        )
    } else {
        recv(fd, buf, count, flags)
    }
}

/// Interceptor code for the `close` function call.
pub unsafe fn balboa_close(
    close: unsafe extern "C" fn(fd: libc::c_int) -> libc::c_int,
    fd: libc::c_int,
) -> libc::c_int {
    // It's important that we perform the close operation last, to prevent another FD from
    // being assigned this number before we've removed it.
    fd_table::remove(fd);
    fd_table::remove_from_accept_fd_set(fd);
    close(fd)
}

/// Interceptor code for the `connect` function call.
pub unsafe fn balboa_connect(
    connect: unsafe extern "C" fn(
        socket: libc::c_int,
        address: *const libc::sockaddr,
        len: libc::socklen_t,
    ) -> libc::c_int,
    socket: libc::c_int,
    address: *const libc::sockaddr,
    len: libc::socklen_t,
) -> libc::c_int {
    match (
        BIND_IP_PRE_CONNECT.load(Ordering::Relaxed),
        get_socket_addr(address, len),
    ) {
        (BIND_IP_PRE_CONNECT_EMPTY, _) => {}
        // We only perform this bind if the socket address is an INET socket where
        // the destination is
        (ip, Some(SocketAddr::V4(remote))) if remote.ip().octets()[0] == 127 => {
            let ip = Ipv4Addr::from(ip);
            let mut addr = std::mem::zeroed::<libc::sockaddr_in>();
            addr.sin_family = libc::AF_INET as libc::sa_family_t;
            // Since we need the u32 to be in big-endian byte order.
            addr.sin_addr = libc::in_addr {
                s_addr: u32::from_ne_bytes(ip.octets()),
            };
            let rc = libc::bind(
                socket,
                (&addr) as *const _ as *const _,
                std::mem::size_of_val(&addr) as libc::socklen_t,
            );
            if rc == 0 {
                stallone::debug!(
                    "able to bind before connecting",
                    ip: Ipv4Addr = ip,
                    fd: libc::c_int = socket,
                );
            } else {
                stallone::warn!(
                    "unable to bind before connecting",
                    ip: Ipv4Addr = ip,
                    errno: i32 = errno::errno().0,
                    fd: libc::c_int = socket,
                );
            }
        }
        (_, addr) => {
            stallone::debug!(
                "Not binding before connection",
                remote_addr: Option<SocketAddr> = addr,
            );
        }
    }
    let result = connect(socket, address, len);
    // EINPROGRESS is still okay.
    // TODO: check that this is SOCK_STREAM
    if result == 0 || (errno::errno().0 == libc::EINPROGRESS) {
        let old_errno = errno::errno();
        if let Some(remote) = get_socket_addr(address, len) {
            let result = balboa_interceptors().rewriters_for_tcp_client(remote);
            stallone::debug!(
                "For Server IP and Port, should we intercept that connection?",
                remote: SocketAddr = remote,
                decision: bool = result.is_some(),
            );
            if let Some((r, w)) = result {
                fd_table::insert(socket, Arc::new(FdState::new(r, w)));
            }
        }
        // It's possible that the operation of getting the rewriters sets the errno.
        errno::set_errno(old_errno);
    }
    result
}

/// Interceptor code for the `bind` function call.
pub unsafe fn balboa_bind(
    bind: unsafe extern "C" fn(
        socket: libc::c_int,
        address: *const libc::sockaddr,
        address_len: libc::socklen_t,
    ) -> libc::c_int,
    socket: libc::c_int,
    address: *const libc::sockaddr,
    address_len: libc::socklen_t,
) -> libc::c_int {
    let result = bind(socket, address, address_len);
    if result == 0 {
        if let Some(addr) = get_socket_addr(address, address_len) {
            let decision = balboa_interceptors().listen_on_addr(addr);
            stallone::debug!(
                "Should we intercept this bound socket?",
                addr: SocketAddr = addr,
                decision: bool = decision,
            );
            if decision {
                fd_table::add_to_accept_fd_set(socket);
            }
        }
    }
    result
}

/// Helper code for the `accept` and `accept4` function calls. Branches on calling
/// `accept4` whether or not the `flags` argument is present.
unsafe fn accept_helper(
    socket: libc::c_int,
    mut address: *mut libc::sockaddr,
    mut address_len: *mut libc::socklen_t,
    flags: Option<libc::c_int>,
) -> libc::c_int {
    let mut address_buf: libc::sockaddr = std::mem::zeroed();
    let mut address_len_buf: libc::socklen_t = 0;
    assert_eq!(address.is_null(), address_len.is_null());
    if address.is_null() {
        address = &mut address_buf;
        address_len = &mut address_len_buf;
    }
    let clientfd = match flags {
        Some(flags) => {
            #[cfg(target_os = "linux")]
            {
                libc::accept4(socket, address, address_len, flags)
            }
            #[cfg(target_os = "macos")]
            {
                let _ = flags;
                panic!("macos doesn't have anything that supports flags")
            }
        }
        None => libc::accept(socket, address, address_len),
    };
    // TODO: this is technically racy.
    if clientfd >= 0 && fd_table::is_in_accept_fd_set(socket) {
        if let Some(remote) = get_socket_addr(address, *address_len) {
            let result = balboa_interceptors().rewriters_for_tcp_server(remote);
            stallone::debug!(
                "For Client IP and Port, should we intercept that connection?",
                remote: SocketAddr = remote,
                decision: bool = result.is_some(),
            );
            if let Some((r, w)) = result {
                fd_table::insert(clientfd, Arc::new(FdState::new(r, w)));
            }
        }
    }
    // Make it obvious that these should exist for the duration of this function.
    std::mem::drop(address_len_buf);
    std::mem::drop(address_buf);
    clientfd
}

/// Interceptor code for the `accept` function call.
pub unsafe fn balboa_accept(
    _accept: unsafe extern "C" fn(
        socket: libc::c_int,
        address: *mut libc::sockaddr,
        address_len: *mut libc::socklen_t,
    ) -> libc::c_int,
    socket: libc::c_int,
    address: *mut libc::sockaddr,
    address_len: *mut libc::socklen_t,
) -> libc::c_int {
    accept_helper(socket, address, address_len, None)
}

/// Interceptor code for the `accept4` function call.
///
/// Same as `balboa_accept` but with additional `flags` argument.
pub unsafe fn balboa_accept4(
    _accept4: unsafe extern "C" fn(
        socket: libc::c_int,
        address: *mut libc::sockaddr,
        address_len: *mut libc::socklen_t,
        flags: libc::c_int,
    ) -> libc::c_int,
    socket: libc::c_int,
    address: *mut libc::sockaddr,
    address_len: *mut libc::socklen_t,
    flags: libc::c_int,
) -> libc::c_int {
    accept_helper(socket, address, address_len, Some(flags))
}

/// Interceptor code for the `sendto` function call.
pub unsafe fn balboa_sendto(
    sendto: unsafe extern "C" fn(
        socket: libc::c_int,
        buf: *const libc::c_void,
        len: libc::size_t,
        flags: libc::c_int,
        addr: *const libc::sockaddr,
        addrlen: libc::socklen_t,
    ) -> libc::ssize_t,
    socket: libc::c_int,
    buf: *const libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
    addr: *const libc::sockaddr,
    addrlen: libc::socklen_t,
) -> libc::ssize_t {
    if let Some(handle) = fd_table::get(socket) {
        handle.rewrite_write(
            &[libc::iovec {
                iov_base: buf as *mut libc::c_void,
                iov_len: len,
            }],
            |new_buf| {
                sendto(
                    socket,
                    new_buf.as_ptr() as *const libc::c_void,
                    new_buf.len(),
                    flags,
                    addr,
                    addrlen,
                )
            },
        )
    } else {
        sendto(socket, buf, len, flags, addr, addrlen)
    }
}

/// Interceptor code for the `writev` function call.
pub unsafe fn balboa_writev(
    writev: unsafe extern "C" fn(
        fd: libc::c_int,
        iov: *const libc::iovec,
        iovcnt: libc::c_int,
    ) -> libc::ssize_t,
    fd: libc::c_int,
    iov: *const libc::iovec,
    iovcnt: libc::c_int,
) -> libc::ssize_t {
    if let Some(handle) = fd_table::get(fd) {
        assert!(!iov.is_null());
        handle.rewrite_write(
            std::slice::from_raw_parts(iov, iovcnt as usize),
            |new_buf| {
                writev(
                    fd,
                    &libc::iovec {
                        iov_base: new_buf.as_ptr() as *mut libc::c_void,
                        iov_len: new_buf.len(),
                    },
                    1,
                )
            },
        )
    } else {
        writev(fd, iov, iovcnt)
    }
}

/// Interceptor code for the `readv` function call.
pub unsafe fn balboa_readv(
    readv: unsafe extern "C" fn(
        fd: libc::c_int,
        iov: *const libc::iovec,
        iovcnt: libc::c_int,
    ) -> libc::ssize_t,
    fd: libc::c_int,
    iov: *const libc::iovec,
    iovcnt: libc::c_int,
) -> libc::ssize_t {
    if let Some(handle) = fd_table::get(fd) {
        assert!(iovcnt >= 0);
        handle.rewrite_readv(
            std::slice::from_raw_parts(iov, iovcnt as usize),
            ReadIsPeek::default(),
            |new_buf| {
                readv(
                    fd,
                    &libc::iovec {
                        iov_base: new_buf.as_mut_ptr() as *mut libc::c_void,
                        iov_len: new_buf.len(),
                    },
                    1,
                )
            },
        )
    } else {
        readv(fd, iov, iovcnt)
    }
}

/// Interceptor code for the `recvmsg` function call.
pub unsafe fn balboa_recvmsg(
    recvmsg: unsafe extern "C" fn(
        fd: libc::c_int,
        msg: *mut libc::msghdr,
        flags: libc::c_int,
    ) -> libc::ssize_t,
    fd: libc::c_int,
    msg: *mut libc::msghdr,
    flags: libc::c_int,
) -> libc::ssize_t {
    if let Some(handle) = fd_table::get(fd) {
        handle.rewrite_readv(
            std::slice::from_raw_parts((*msg).msg_iov, (*msg).msg_iovlen as usize),
            ReadIsPeek::from_flags(flags),
            |new_buf| {
                let mut iov = [libc::iovec {
                    iov_base: new_buf.as_mut_ptr() as *mut libc::c_void,
                    iov_len: new_buf.len(),
                }];
                let mut new_msg = *msg;
                new_msg.msg_iov = iov.as_mut_ptr() as *mut libc::iovec;
                new_msg.msg_iovlen = 1;
                recvmsg(fd, &mut new_msg, flags)
            },
        )
    } else {
        recvmsg(fd, msg, flags)
    }
}

/// Interceptor code for the `sendmsg` function call.
pub unsafe fn balboa_sendmsg(
    sendmsg: unsafe extern "C" fn(
        fd: libc::c_int,
        msg: *const libc::msghdr,
        flags: libc::c_int,
    ) -> libc::ssize_t,
    fd: libc::c_int,
    msg: *const libc::msghdr,
    flags: libc::c_int,
) -> libc::ssize_t {
    #[cfg(target_os = "linux")]
    {
        // We need to disable TCP fast open if we're doing the bind before the connect.
        if (flags & libc::MSG_FASTOPEN) != 0
            && BIND_IP_PRE_CONNECT.load(Ordering::Relaxed) != BIND_IP_PRE_CONNECT_EMPTY
        {
            errno::set_errno(errno::Errno(libc::EOPNOTSUPP));
            return -1;
        }
    }
    if let Some(handle) = fd_table::get(fd) {
        handle.rewrite_write(
            std::slice::from_raw_parts((*msg).msg_iov, (*msg).msg_iovlen as usize),
            |buf| {
                let mut iov = [libc::iovec {
                    iov_base: buf.as_ptr() as *mut libc::c_void,
                    iov_len: buf.len(),
                }];
                let mut new_msg = *msg;
                new_msg.msg_iov = iov.as_mut_ptr() as *mut libc::iovec;
                new_msg.msg_iovlen = 1;
                sendmsg(fd, &new_msg, flags)
            },
        )
    } else {
        sendmsg(fd, msg, flags)
    }
}

/// Interceptor code for the `recvfrom` function call.
pub unsafe fn balboa_recvfrom(
    recvfrom: unsafe extern "C" fn(
        socket: libc::c_int,
        buf: *mut libc::c_void,
        len: libc::size_t,
        flags: libc::c_int,
        addr: *mut libc::sockaddr,
        addrlen: *mut libc::socklen_t,
    ) -> libc::ssize_t,
    socket: libc::c_int,
    buf: *mut libc::c_void,
    len: libc::size_t,
    flags: libc::c_int,
    addr: *mut libc::sockaddr,
    addrlen: *mut libc::socklen_t,
) -> libc::ssize_t {
    if let Some(entry) = fd_table::get(socket) {
        entry.rewrite_readv(
            &[libc::iovec {
                iov_base: buf,
                iov_len: len,
            }],
            ReadIsPeek::from_flags(flags),
            |new_buf| {
                recvfrom(
                    socket,
                    new_buf.as_mut_ptr() as *mut libc::c_void,
                    new_buf.len(),
                    flags,
                    addr,
                    addrlen,
                )
            },
        )
    } else {
        recvfrom(socket, buf, len, flags, addr, addrlen)
    }
}

/// Macro for injecting a [`crate::BalboaInterceptors`] implementation into a shared
/// library.
///
/// # Example
/// ```ignore
/// struct MyInterceptors;
/// impl BalboaInterceptors for MyInterceptors { /* ... */ }
/// balboa_inject!(MyInterceptors);
/// ```
#[macro_export]
macro_rules! balboa_inject {
    ($bi:ty) => { mod the_balboa_inject_module {
        use $crate::libc_overrides::libc;
        const RUN_ON_CUSTOM_STACK: bool = {
            use super::*;
            <$bi as $crate::BalboaInterceptors>::RUN_ON_CUSTOM_STACK
        };

        #[cfg(not(test))]
        #[used]
        #[no_mangle]
        #[cfg_attr(target_os = "macos", link_section = "__DATA,__mod_init_func")]
        #[cfg_attr(target_os = "linux", link_section = ".init_array")]
        pub static _BALBOA_INIT: extern "C" fn() = {
            use super::*;
            extern "C" fn do_the_init() {
                $crate::initialize_balboa_injection::<$bi>();
            }
            do_the_init
        };


        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALBOA_WRITE,
            $crate::libc_overrides::balboa_write,
            fn libc::write(
                fd: libc::c_int,
                buf: *const libc::c_void,
                count: libc::size_t
            ) -> libc::ssize_t
        );

        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALBOA_READ,
            $crate::libc_overrides::balboa_read,
            fn libc::read(
                fd: libc::c_int,
                buf: *mut libc::c_void,
                count: libc::size_t
            ) -> libc::ssize_t
        );

        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALBOA_CLOSE,
            $crate::libc_overrides::balboa_close,
            fn libc::close(
                fd: libc::c_int
            ) -> libc::c_int
        );

        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALBOA_CONNECT,
            $crate::libc_overrides::balboa_connect,
            fn libc::connect(
                socket: libc::c_int,
                address: *const libc::sockaddr,
                len: libc::socklen_t
            ) -> libc::c_int
        );

        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALBOA_BIND,
            $crate::libc_overrides::balboa_bind,
            fn libc::bind(
                socket: libc::c_int,
                address: *const libc::sockaddr,
                address_len: libc::socklen_t
            ) -> libc::c_int
        );

        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALBOA_ACCEPT,
            $crate::libc_overrides::balboa_accept,
            fn libc::accept(
                socket: libc::c_int,
                address: *mut libc::sockaddr,
                address_len: *mut libc::socklen_t
            ) -> libc::c_int
        );

        #[cfg(target_os="linux")]
        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALBOA_ACCEPT4,
            $crate::libc_overrides::balboa_accept4,
            fn libc::accept4(
                socket: libc::c_int,
                address: *mut libc::sockaddr,
                address_len: *mut libc::socklen_t,
                flags: libc::c_int
            ) -> libc::c_int
        );

        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALBOA_SENDTO,
            $crate::libc_overrides::balboa_sendto,
                fn libc::sendto(
                socket: libc::c_int,
                buf: *const libc::c_void,
                len: libc::size_t,
                flags: libc::c_int,
                addr: *const libc::sockaddr,
                addrlen: libc::socklen_t
            ) -> libc::ssize_t
        );

        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALBOA_RECVFROM,
            $crate::libc_overrides::balboa_recvfrom,
            fn libc::recvfrom(
                socket: libc::c_int,
                buf: *mut libc::c_void,
                len: libc::size_t,
                flags: libc::c_int,
                addr: *mut libc::sockaddr,
                addrlen: *mut libc::socklen_t
            ) -> libc::ssize_t
        );

        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALBOA_READV,
            $crate::libc_overrides::balboa_readv,
            fn libc::readv(
                fd: libc::c_int,
                iov: *const libc::iovec,
                iovcnt: libc::c_int
            ) -> libc::ssize_t
        );

        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALBOA_WRITEV,
            $crate::libc_overrides::balboa_writev,
            fn libc::writev(
                fd: libc::c_int,
                iov: *const libc::iovec,
                iovcnt: libc::c_int
            ) -> libc::ssize_t
        );

        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALOBA_RECVMSG,
            $crate::libc_overrides::balboa_recvmsg,
            fn libc::recvmsg(
                fd: libc::c_int,
                msg: *mut libc::msghdr,
                flags: libc::c_int
            ) -> libc::ssize_t
        );

        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALOBA_SENDMSG,
            $crate::libc_overrides::balboa_sendmsg,
            fn libc::sendmsg(
                fd: libc::c_int,
                msg: *const libc::msghdr,
                flags: libc::c_int
            ) -> libc::ssize_t
        );

        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALBOA_RECV,
            $crate::libc_overrides::balboa_recv,
            fn libc::recv(
                socket: libc::c_int,
                buf: *mut libc::c_void,
                len: libc::size_t,
                flags: libc::c_int
            ) -> libc::ssize_t
        );

        $crate::inject!(
            #[switch_stacks(RUN_ON_CUSTOM_STACK)]
            _BALBOA_SEND,
            $crate::libc_overrides::balboa_send,
            fn libc::send(
                socket: libc::c_int,
                buf: *const libc::c_void,
                len: libc::size_t,
                flags: libc::c_int
            ) -> libc::ssize_t
        );
    } };
}

// We ignore file descriptors sent using CMSG

// read, write, readv, writev, send, recv, close, shutdown, sendmsg, recvmsg, connect,
// accept, fdopen, accept4, recvfrom, recvmmsg, sendmmsg, pread, pwrite (this is valid
// with a zero position), preadv, pwritev, preadv2, pwritev2, dup, dup2, dup3
// fcntl is another way to dup a fd
// use fopencookie() to handle fdopen()
