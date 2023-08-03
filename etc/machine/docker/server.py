# This file will be run in all docker containers. It won't have access to any
# dependencies, so this file should exclusively use the Python standard library, and import no other
# modules.
#
# The goal of this module is to provide a server (which listens on a UNIX socket) to let us spawn
# and monitor subprocesses in the container. The standard docker API doesn't allow for all the
# monitoring and manipulation functionality that we need.
import json
import os
import shutil
import socket
import subprocess
from dataclasses import dataclass
from functools import wraps
from inspect import signature
from pathlib import Path
from socketserver import BaseRequestHandler, ThreadingUnixStreamServer
from threading import Lock
from typing import Any, List

_MAX_FDS = 3

# This is the list of subprocesses. We never remove from this list during the run of the container.
# This shouldn't be a problem for our use-case, though it is something to be aware of.
_process_list: List[subprocess.Popen[bytes]] = []
_process_list_lock = Lock()


def _get_proc(idx: int) -> subprocess.Popen[bytes]:
    with _process_list_lock:
        return _process_list[idx]


class _RockyDockerServerHandler(BaseRequestHandler):
    def handle(self) -> None:
        # The protocol for this server is to send a JSON blob with one of several commands.
        sock: socket.socket = self.request
        try:
            # We send the first byte along with the file descriptors, if there are any.
            first_byte, fds, _, _ = socket.recv_fds(sock, 1, _MAX_FDS)
            try:
                command_bytes = bytearray(first_byte)
                while True:
                    new_data = sock.recv(1024)
                    if len(new_data) > 0:
                        command_bytes.extend(new_data)
                    else:
                        break
                command = json.loads(command_bytes)
                which = command["which"]
                response: Any
                if which == "which":
                    response = str(Path(shutil.which(command["cmd"])).resolve())
                elif which == "terminate":
                    _get_proc(command["proc"]).terminate()
                    response = None
                elif which == "kill":
                    _get_proc(command["proc"]).kill()
                    response = None
                elif which == "wait":
                    timeout = command["timeout_seconds"]
                    proc = _get_proc(command["proc"])
                    if timeout == 0:
                        response = proc.poll()
                    else:
                        try:
                            response = proc.wait(timeout)
                        except subprocess.TimeoutExpired:
                            response = None
                elif which == "popen":
                    # The popen commands takes 3 file descriptors via SCM_RIGHTS to use as
                    # stdin, stdout, stderr.
                    proc = subprocess.Popen[bytes](
                        command["args"],
                        stdin=fds[0],
                        stdout=fds[1],
                        stderr=fds[2],
                        cwd=command["cwd"],
                        env=command["env"],
                    )
                    with _process_list_lock:
                        proc_idx = len(_process_list)
                        _process_list.append(proc)
                    response = proc_idx
                else:
                    raise Exception(f"Unknown command {which}")
                sock.sendall(json.dumps({"ok": response}).encode("ascii"))
            finally:
                for fd in fds:
                    os.close(fd)
        except Exception as e:
            sock.sendall(json.dumps({"Exception": str(e)}).encode("ascii"))
            raise


if __name__ == "__main__":
    import socket
    import sys

    print(f"Rocky docker server started {socket.gethostname()}")
    ThreadingUnixStreamServer(sys.argv[1], _RockyDockerServerHandler).serve_forever()
