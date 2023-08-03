use crossbeam_channel::SendError;
use snafu::Snafu;
use stallone_common::{
    positioned_io_result, protocol, scm_rights::ScmRightsExt, PositionedIOResult, StallonePID,
};
use std::{
    io::Read,
    os::unix::{
        io::{AsRawFd, FromRawFd},
        net::{UnixDatagram, UnixStream},
    },
};
pub(crate) fn start_socket_thread(
    socket: UnixDatagram,
    s_socket_events: crossbeam_channel::Sender<SocketEvent>,
) -> PositionedIOResult<()> {
    std::thread::spawn(move || {
        // The only possible error is a SendError, and it's okay to ignore that, and just exit.
        let fd = socket.as_raw_fd();
        let _ = SocketThread {
            sender: s_socket_events,
            socket,
            buffer: vec![0; protocol::BUFFER_SIZE],
            poll_fds: vec![nix::poll::PollFd::new(fd, nix::poll::PollFlags::POLLIN)],
            poll_tokens: vec![Some(PollToken::OurSocket)],
        }
        .run();
    });
    Ok(())
}

enum PollToken {
    OurSocket,
    StallonePid(StallonePID, UnixStream),
}

enum ProcessStatus {
    Alive,
    Dead,
}

pub(crate) enum SocketEvent {
    NewProcess(protocol::ProcessInfo),
    DeadProcess(StallonePID),
    NewThread(StallonePID, std::fs::File),
}

struct SocketThread {
    sender: crossbeam_channel::Sender<SocketEvent>,
    socket: UnixDatagram,
    buffer: Vec<u8>,
    poll_fds: Vec<nix::poll::PollFd>,
    // a None token means that the corresponding poll_fd is for -1
    poll_tokens: Vec<Option<PollToken>>,
}

fn empty_poll_fd() -> nix::poll::PollFd {
    nix::poll::PollFd::new(-1, nix::poll::PollFlags::empty())
}

// TODO: snafu isn't the right tool for this derivation.
#[derive(Debug, Snafu)]
enum SocketThreadGenericError {
    #[snafu(display("Read {} bytes from the process deathwatch", n))]
    ReadBytesFromProcessDeathwatch { n: usize },
}

impl SocketThread {
    fn process_status(
        poll_fd: &nix::poll::PollFd,
        stream: &mut UnixStream,
        buffer: &mut [u8],
    ) -> PositionedIOResult<ProcessStatus> {
        use nix::poll::PollFlags;
        match poll_fd.revents() {
            Some(flags)
                if flags
                    .intersects(PollFlags::POLLIN | PollFlags::POLLERR | PollFlags::POLLHUP) =>
            {
                loop {
                    match stream.read(buffer) {
                        Ok(0) => {
                            break Ok(ProcessStatus::Dead);
                        }
                        Ok(n) => {
                            break positioned_io_result!(Err(std::io::Error::new(
                                std::io::ErrorKind::Other,
                                SocketThreadGenericError::ReadBytesFromProcessDeathwatch { n }
                            )));
                        }
                        Err(e) => match e.kind() {
                            std::io::ErrorKind::Interrupted => {
                                continue;
                            }
                            std::io::ErrorKind::WouldBlock => {
                                break Ok(ProcessStatus::Alive);
                            }
                            _ => {
                                break positioned_io_result!(Err(e));
                            }
                        },
                    }
                }
            }
            _ => Ok(ProcessStatus::Alive),
        }
    }
    fn insert_process_watch(&mut self, pid: StallonePID, stream: UnixStream) {
        let fd = stream.as_raw_fd();
        debug_assert_eq!(self.poll_tokens.len(), self.poll_fds.len());
        for (token, pfd) in self.poll_tokens.iter_mut().zip(self.poll_fds.iter_mut()) {
            if token.is_none() {
                *token = Some(PollToken::StallonePid(pid, stream));
                *pfd = nix::poll::PollFd::new(fd, nix::poll::PollFlags::POLLIN);
                return;
            }
        }
        self.poll_tokens
            .push(Some(PollToken::StallonePid(pid, stream)));
        self.poll_fds
            .push(nix::poll::PollFd::new(fd, nix::poll::PollFlags::POLLIN));
    }
    fn handle_main_socket(&mut self) -> Result<(), SendError<SocketEvent>> {
        // In theory, we should check revents for the main socket. Ehh.
        loop {
            match self.socket.recvmsg_file(&mut self.buffer[..]) {
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    break Ok(());
                }
                Err(e) => {
                    log::warn!("Error on recvmsg_file(): {}", e);
                }
                Ok((None, n)) => {
                    log::warn!("Got a message (of length {}) without a file", n);
                }
                Ok((_, n)) if n == self.buffer.len() => {
                    log::warn!(
                        "Got a message of length {}, which is the max size. IGNORING IT",
                        self.buffer.len()
                    );
                }
                Ok((Some(fd), n)) => {
                    let buf = &self.buffer[0..n];
                    match protocol::Message::deserialize(buf) {
                        Err(_) => {
                            log::warn!("Unable to deserialize protocol message of size {}", n);
                        }
                        Ok(protocol::Message::ProcessInfo(pinfo)) => {
                            let stream = unsafe { UnixStream::from_raw_fd(fd) };
                            if let Err(e) = stream.set_nonblocking(true) {
                                log::warn!(
                                    "Unable to set process {:?} deathwatch non-blocking: {}",
                                    pinfo,
                                    e
                                );
                                continue;
                            }
                            let stallone_pid = pinfo.stallone_pid;
                            self.sender.send(SocketEvent::NewProcess(pinfo))?;
                            self.insert_process_watch(stallone_pid, stream);
                        }
                        Ok(protocol::Message::ThreadRingBuffer { stallone_pid }) => {
                            self.sender
                                .send(SocketEvent::NewThread(stallone_pid, unsafe {
                                    std::fs::File::from_raw_fd(fd)
                                }))?;
                        }
                    }
                }
            }
        }
    }
    fn run(mut self) -> Result<(), SendError<SocketEvent>> {
        // TODO: we might want this to be able to close even before the receiver closes.
        // TODO: consider using mio.
        // We want to make sure that death events (which come from monitoring other FDs) are
        // ordered AFTER non-death events. We do this by checking for death events BEFORE reading
        // non-death events. Rather than sending these death events immediately when we see them,
        // we instead buffer them, and then send them after draining the queue of non-death events.
        let mut send_queue = Vec::new();
        loop {
            debug_assert!(send_queue.is_empty());
            match nix::poll::poll(&mut self.poll_fds[..], -1) {
                Ok(_) => {}
                Err(nix::errno::Errno::EINTR) => {
                    continue;
                }
                Err(e) => {
                    // TODO: ratelimit this error?
                    // TODO: should this exit this thread?
                    log::warn!("Error: unable to poll {}", e);
                    continue;
                }
            }
            debug_assert_eq!(self.poll_tokens.len(), self.poll_fds.len());
            for (token, pfd) in self.poll_tokens.iter_mut().zip(self.poll_fds.iter_mut()) {
                match token {
                    Some(PollToken::OurSocket) => {
                        // We handle it separately; skip it!.
                    }
                    None => {
                        // Skip it!
                    }
                    Some(PollToken::StallonePid(pid, stream)) => {
                        match Self::process_status(pfd, stream, &mut self.buffer[..]) {
                            Ok(ProcessStatus::Alive) => {
                                // Do nothing.
                            }
                            Ok(ProcessStatus::Dead) => {
                                send_queue.push(SocketEvent::DeadProcess(*pid));
                                *pfd = empty_poll_fd();
                                *token = None;
                            }
                            Err(e) => {
                                log::warn!("Error checking process status of {:?}: {}", *pid, e);
                                // Pretend like the process is dead.
                                send_queue.push(SocketEvent::DeadProcess(*pid));
                                *pfd = empty_poll_fd();
                                *token = None;
                            }
                        }
                    }
                }
            }
            // See the comment above about why we've ordered things this way.
            // TODO: events from the main socket could, in theory, starve out the death events.
            // This is probably not worth mitigating at this time, but it would be in the future.
            self.handle_main_socket()?;
            for msg in send_queue.drain(..) {
                self.sender.send(msg)?;
            }
        }
    }
}
