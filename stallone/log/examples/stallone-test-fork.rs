use std::{os::unix::prelude::CommandExt, process::Command};

fn pid() -> u32 {
    std::process::id()
}

fn wait_for_child(child_pid: i32) {
    assert!(child_pid >= 0);
    let mut wstatus: libc::c_int = 0;
    if unsafe { libc::waitpid(child_pid, &mut wstatus, 0) } < 0 {
        panic!("waitpid failed!");
    }
    assert!(libc::WIFEXITED(wstatus));
    // Make sure that we catch it if the child fails.
    assert_eq!(libc::WEXITSTATUS(wstatus), 0);
}

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let follow_forks = args
        .get(1)
        .filter(|arg| arg.as_str() == "FOLLOW-FORKS")
        .is_some();
    let mut config = stallone::StalloneConfig::default();
    config.follow_forks = follow_forks;
    stallone::initialize(config);
    if !follow_forks {
        // First, we are going to test running stallone with follow_forks disabled.
        // We log a simple message to get started.
        stallone::info!("Non-follow-fork parent", pid: u32 = pid());
        // We'll start by forking this process.
        match unsafe { libc::fork() } {
            x if x < 0 => panic!("fork failed!"),
            0 => {
                // Inside the child process, we'll log an info line. This line shouldn't show up,
                // since stallone should be disabled in the forked child.
                stallone::info!(
                    "To quote The Beatles, \"You Won't See Me.\"",
                    pid: u32 = pid()
                );
                let fds: Vec<_> = std::fs::read_dir("/dev/fd").unwrap().collect();
                // Assert that the keepalive file descriptor has been closed.
                // There should be 5 FDs: stdin, stdout, stderr, the stallone datagram socket, and
                // the /dev/fd directory that we're iterating through.
                assert_eq!(fds.len(), 5, "{:?}", fds);
                std::process::exit(0);
            }
            child_pid => {
                // Back in the parent, we'll just wait for our forked child to exit.
                wait_for_child(child_pid);
            }
        }
        stallone::info!("Spawn follow-forks subprocess");
        // Now, let's spawn ourselves as a subprocess, passing the FOLLOW-FORKS option, so we end up
        // in the else of this if statement.
        let success = Command::new(std::env::current_exe().unwrap())
            .arg("FOLLOW-FORKS")
            .spawn()
            .unwrap()
            .wait()
            .unwrap()
            .success();
        assert!(success);
    } else {
        // Log a message in the parent.
        stallone::info!("Here I am in the parent", pid: u32 = pid());
        // Spawn a non-stallone child. We should observe the fork, followed by the subprocess
        // "dying" from stallone's perspective when the exec() occurs.
        let mut setup = Command::new("bash");
        setup
            .arg("-c")
            // We sleep for 0.3 seconds since we need the stallone master to record the event that
            // the keepalive socket has been closed by the exec() in a different epoch than the
            // "After wait" log event below. We don't have any good way of detecting this, so we
            // just sleep for now. I think that 0.3 seconds should be long enough in practice that
            // we (hopefully!) shouldn't see this test become flakey.
            .arg("echo BASH PID $$ ; sleep 0.3");
        // Force fork+exec instead of posix_spawn (which is fork+exec without the atfork handler).
        unsafe { setup.pre_exec(|| Ok(())) };
        let mut child = setup.spawn().unwrap();
        stallone::info!("After spawning", pid: u32 = pid());
        let success = child.wait().unwrap().success();
        assert!(success);
        stallone::info!("After wait", pid: u32 = pid());
        // Now we fork into a child.
        match unsafe { libc::fork() } {
            x if x < 0 => panic!("Fork failed!"),
            0 => {
                stallone::info!("Post fork child 1", pid: u32 = pid());
                match unsafe { libc::fork() } {
                    x if x < 0 => panic!("Fork failed!"),
                    0 => {
                        stallone::info!("Post fork, subchild", pid: u32 = pid());
                    }
                    child_pid => {
                        stallone::info!(
                            "Post fork child 2",
                            pid: u32 = pid(),
                            child_pid: i32 = child_pid,
                        );
                        wait_for_child(child_pid);
                    }
                }
            }
            child_pid => {
                stallone::info!(
                    "Post fork parent",
                    pid: u32 = pid(),
                    child_pid: i32 = child_pid
                );
                wait_for_child(child_pid);
            }
        }
    }
}
