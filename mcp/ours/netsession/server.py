#!/usr/bin/env python3
"""
netsession MCP — persistent TCP sessions for CTF.

Fills the gap Bash/pwndbg/ghidra don't:
  * hold a LIVE connection to a remote service across multiple tool calls
    (interactive pwn:  nc host port  ->  send payload, read reply, iterate)
  * catch and drive a reverse shell (start a listener, interact with what lands)

State lives in this long-running server process, so a session opened by one
tool call is still usable by the next call.

Tools:
  connect(host, port)            -> open a persistent TCP session
  listen(port)                   -> start a listener; caught conns become sessions
  sessions()                     -> list active sessions + listeners
  send(sid, data, newline=True)  -> send data (line by default)
  recv(sid, timeout=2.0, until="") -> drain buffered output (optionally until a marker)
  shell(sid, cmd, timeout=8.0)   -> send a command to a shell session, return its output
                                    (uses a random end-marker to frame raw shells)
  hexsend(sid, hexbytes)         -> send raw bytes given as hex (for binary pwn)
  close(sid)                     -> close a session/listener

Install:  pip install mcp
Run:      python3 server.py        (registered via mcpServers in settings.json)
"""
import socket
import threading
import time
import secrets
import binascii

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("netsession")

# sid -> {"sock":socket, "buf":bytearray, "lock":Lock, "peer":str, "kind":"conn"|"listener", "alive":bool}
_S = {}
_counter = 0
_glock = threading.Lock()


def _new_id(prefix):
    global _counter
    with _glock:
        _counter += 1
        return f"{prefix}{_counter}"


def _reader(sid, sock):
    """Background thread: pump socket bytes into the session buffer."""
    s = _S.get(sid)
    while s and s["alive"]:
        try:
            data = sock.recv(65536)
        except socket.timeout:
            continue          # read timeout is normal — keep the session alive
        except Exception:
            break
        if not data:
            break             # empty recv = peer closed
        with s["lock"]:
            s["buf"].extend(data)
    if s:
        s["alive"] = False


def _register_conn(sock, peer, kind="conn"):
    sid = _new_id("s")
    _S[sid] = {"sock": sock, "buf": bytearray(), "lock": threading.Lock(),
               "peer": peer, "kind": kind, "alive": True}
    threading.Thread(target=_reader, args=(sid, sock), daemon=True).start()
    return sid


def _drain(sid, timeout=2.0, until=""):
    """Return buffered output, waiting up to `timeout`s, optionally until a marker appears."""
    s = _S.get(sid)
    if not s:
        return None
    deadline = time.time() + timeout
    want = until.encode() if until else b""
    while time.time() < deadline:
        with s["lock"]:
            if want and want in s["buf"]:
                break
            if s["buf"] and not want:
                # give a brief grace for more bytes to arrive
                pass
        if s["buf"] and not want and time.time() > deadline - timeout + 0.4:
            break
        time.sleep(0.1)
    with s["lock"]:
        out = bytes(s["buf"])
        s["buf"].clear()
    return out.decode("utf-8", "replace")


@mcp.tool()
def connect(host: str, port: int) -> str:
    """Open a persistent TCP connection to host:port (like pwntools remote). Returns a session id."""
    try:
        sock = socket.create_connection((host, port), timeout=10)
        sock.settimeout(0.5)
        sid = _register_conn(sock, f"{host}:{port}")
        time.sleep(0.4)
        banner = _drain(sid, timeout=1.0)
        return f"session={sid} connected to {host}:{port}\n--- initial output ---\n{banner}"
    except Exception as e:
        return f"ERROR connecting to {host}:{port}: {e}"


@mcp.tool()
def listen(port: int) -> str:
    """Start a TCP listener on 0.0.0.0:port to catch a reverse shell. Returns a listener id; caught connections become sessions (check with sessions())."""
    try:
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("0.0.0.0", port))
        srv.listen(5)
        lid = _new_id("L")
        _S[lid] = {"sock": srv, "buf": bytearray(), "lock": threading.Lock(),
                   "peer": f"0.0.0.0:{port}", "kind": "listener", "alive": True}

        def _accept():
            while _S.get(lid) and _S[lid]["alive"]:
                try:
                    conn, addr = srv.accept()
                except Exception:
                    break
                conn.settimeout(0.5)
                csid = _register_conn(conn, f"{addr[0]}:{addr[1]}", kind="conn")
                with _S[lid]["lock"]:
                    _S[lid]["buf"].extend(f"[+] caught {addr[0]}:{addr[1]} as {csid}\n".encode())
        threading.Thread(target=_accept, daemon=True).start()
        return f"listener={lid} on 0.0.0.0:{port} — trigger your payload, then call sessions()"
    except Exception as e:
        return f"ERROR listening on {port}: {e}"


@mcp.tool()
def sessions() -> str:
    """List all active sessions and listeners."""
    if not _S:
        return "(no sessions)"
    lines = []
    for sid, s in _S.items():
        status = "alive" if s["alive"] else "dead"
        pend = len(s["buf"])
        lines.append(f"{sid}\t{s['kind']}\t{s['peer']}\t{status}\tbuffered={pend}B")
    return "\n".join(lines)


@mcp.tool()
def send(sid: str, data: str, newline: bool = True) -> str:
    """Send text to a session (adds a newline by default). Does not wait for a reply — use recv()."""
    s = _S.get(sid)
    if not s or s["kind"] == "listener":
        return f"ERROR: no active session {sid}"
    try:
        payload = data.encode() + (b"\n" if newline else b"")
        s["sock"].sendall(payload)
        return f"sent {len(payload)} bytes to {sid}"
    except Exception as e:
        return f"ERROR sending to {sid}: {e}"


@mcp.tool()
def hexsend(sid: str, hexbytes: str) -> str:
    """Send RAW bytes (given as a hex string, e.g. '41414141deadbeef') — for binary pwn payloads."""
    s = _S.get(sid)
    if not s or s["kind"] == "listener":
        return f"ERROR: no active session {sid}"
    try:
        raw = binascii.unhexlify(hexbytes.replace(" ", "").replace("\\x", ""))
        s["sock"].sendall(raw)
        return f"sent {len(raw)} raw bytes to {sid}"
    except Exception as e:
        return f"ERROR hexsend to {sid}: {e}"


@mcp.tool()
def recv(sid: str, timeout: float = 2.0, until: str = "") -> str:
    """Read buffered output from a session, waiting up to `timeout`s (or until `until` marker appears)."""
    out = _drain(sid, timeout=timeout, until=until)
    if out is None:
        return f"ERROR: no session {sid}"
    return out if out else "(no output)"


@mcp.tool()
def shell(sid: str, cmd: str, timeout: float = 8.0) -> str:
    """Run a command on a shell session (reverse shell or interactive shell) and return its output.
    Frames the output with a random end-marker so raw, prompt-less shells capture cleanly."""
    s = _S.get(sid)
    if not s or s["kind"] == "listener":
        return f"ERROR: no active shell session {sid}"
    marker = "___END_" + secrets.token_hex(6) + "___"
    try:
        with s["lock"]:
            s["buf"].clear()
        s["sock"].sendall(f"{cmd}; echo {marker}\n".encode())
    except Exception as e:
        return f"ERROR: {e}"
    out = _drain(sid, timeout=timeout, until=marker)
    # strip the marker (and anything after it)
    if marker in out:
        out = out.split(marker)[0]
    return out.rstrip("\n") if out.strip() else "(no output)"


@mcp.tool()
def close(sid: str) -> str:
    """Close a session or listener."""
    s = _S.pop(sid, None)
    if not s:
        return f"no session {sid}"
    s["alive"] = False
    try:
        s["sock"].close()
    except Exception:
        pass
    return f"closed {sid}"


if __name__ == "__main__":
    mcp.run()
