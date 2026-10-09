"""An owned Windows command console, isolated from server packet output.

The child receives its per-run credential in its environment, removes it before
reading input, and uses a bounded loopback protocol. Commands are text for
Console.execute, never shell input. Closing the window does not close Console
or release its synthetic players. Only the server owner calls close().
"""
from __future__ import annotations

import argparse
import asyncio
from contextlib import suppress
import ctypes
import json
import os
from pathlib import Path
import queue
import secrets
import socket
import struct
import subprocess
import sys
import threading
import unicodedata

from .console import MAX_COMMAND_BYTES


TOKEN_ENV = "OW08_COMMAND_WINDOW_TOKEN"
MAX_FRAME_BYTES = 32768
MAX_RESULT_BYTES = 16384
MAX_CONNECTIONS = 4
IO_TIMEOUT = 3
_WINDOWS = sys.platform == "win32"
_FAILED = "Command failed. Check server diagnostics."


def _safe_text(text):
    """Keep readable multiline help; expose terminal/bidi controls as escapes."""
    return "".join(
        char if char == "\n" or unicodedata.category(char) not in ("Cc", "Cf", "Cs")
        else (f"\\x{ord(char):02x}" if ord(char) <= 255 else f"\\u{ord(char):04x}")
        for char in text
    )


async def _receive(reader, *, limit=MAX_FRAME_BYTES):
    length, = struct.unpack("!I", await reader.readexactly(4))
    if not 0 < length <= limit:
        raise ValueError("invalid command frame length")
    try:
        value = json.loads((await reader.readexactly(length)).decode("utf-8"))
    except (ValueError, UnicodeError, RecursionError):
        raise ValueError("invalid command frame") from None
    if not isinstance(value, dict):
        raise ValueError("invalid command frame")
    return value


async def _send(writer, value):
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if not 0 < len(payload) <= MAX_FRAME_BYTES:
        raise ValueError("command frame exceeds limit")
    writer.write(struct.pack("!I", len(payload)) + payload)
    await asyncio.wait_for(writer.drain(), IO_TIMEOUT)


async def _close_writer(writer):
    writer.close()
    with suppress(Exception):
        await asyncio.wait_for(writer.wait_closed(), 0.5)


def _valid_command(line):
    return (isinstance(line, str) and not any(char in line for char in "\0\r\n")
            and len(line.encode("utf-8")) <= MAX_COMMAND_BYTES)


def _valid_token(token):
    return (isinstance(token, str) and len(token) == 64
            and all(char in "0123456789abcdef" for char in token))


class CommandWindow:
    """Owner handle returned by start_command_window; no account ownership."""

    def __init__(self, console, *, logger=print):
        self._console = console
        self._logger = logger
        self._token = secrets.token_hex(32)
        self._server = None
        self._port = None
        self._process = None
        self._watcher = None
        self._writers = set()
        self._handlers = set()
        self._claimed = False
        self._started = False
        self._closing = False
        self._ready = asyncio.Event()
        self._closed = asyncio.Event()
        self._close_lock = asyncio.Lock()

    async def _listen(self):
        self._server = await asyncio.start_server(
            self._handle, "127.0.0.1", 0, family=socket.AF_INET, limit=MAX_FRAME_BYTES + 4)
        self._port = self._server.sockets[0].getsockname()[1]

    @property
    def port(self):
        return self._port

    async def wait_closed(self):
        """Wait for child exit/disconnect, without changing server/accounts."""
        await self._closed.wait()

    def _mark_closed(self):
        if self._closed.is_set():
            return
        self._closed.set()
        if self._server:
            self._server.close()
        for writer in tuple(self._writers):
            writer.close()
        if self._started and not self._closing:
            self._logger("Command window closed; the server and synthetic players remain active.")

    async def _handle(self, reader, writer):
        task = asyncio.current_task()
        if (self._closing or self._closed.is_set() or self._claimed
                or len(self._writers) >= MAX_CONNECTIONS
                or writer.get_extra_info("peername")[0] != "127.0.0.1"):
            await _close_writer(writer)
            return
        self._handlers.add(task)
        self._writers.add(writer)
        authenticated = False
        try:
            hello = await asyncio.wait_for(_receive(reader, limit=512), IO_TIMEOUT)
            token = hello.get("auth")
            if (set(hello) != {"auth"} or not _valid_token(token) or self._claimed
                    or not secrets.compare_digest(token, self._token)):
                return
            # No await separates checking and claiming this one connection.
            self._claimed = authenticated = True
            self._token = None
            hello = token = None
            self._server.close()  # This one owned child never needs a reconnect.
            for other in tuple(self._writers):
                if other is not writer:
                    other.close()
            await _send(writer, {"ready": True})
            self._ready.set()
            while True:
                request = await _receive(reader)
                line = request.get("command")
                if set(request) != {"command"} or not _valid_command(line):
                    return
                try:
                    result = await self._console.execute(line)
                    if (not isinstance(result, str) or len(result.encode("utf-8")) > MAX_RESULT_BYTES
                            or len(json.dumps({"result": result}, ensure_ascii=False).encode("utf-8"))
                            > MAX_FRAME_BYTES):
                        result = _FAILED
                except Exception:
                    # Exceptions may contain command/password text. Never echo
                    # them or send them to the server's packet logger.
                    result = _FAILED
                await _send(writer, {"result": result})
        except (OSError, ValueError, UnicodeError, asyncio.IncompleteReadError, TimeoutError):
            pass
        finally:
            self._writers.discard(writer)
            self._handlers.discard(task)
            await _close_writer(writer)
            if authenticated:
                self._mark_closed()

    async def _watch_child(self):
        while self._process.poll() is None:
            await asyncio.sleep(0.1)
        self._mark_closed()

    async def close(self):
        """Close IPC and stop only this handle's owned Popen child, idempotently."""
        async with self._close_lock:
            self._closing = True
            self._token = None
            self._mark_closed()
            if self._server:
                await self._server.wait_closed()
            for task in tuple(self._handlers):
                task.cancel()
            if self._handlers:
                await asyncio.gather(*tuple(self._handlers), return_exceptions=True)
            if self._watcher:
                self._watcher.cancel()
                with suppress(asyncio.CancelledError):
                    await self._watcher
            if self._process is not None and self._process.poll() is None:
                try:
                    self._process.terminate()
                    await asyncio.to_thread(self._process.wait, timeout=2)
                except subprocess.TimeoutExpired:
                    with suppress(OSError, subprocess.TimeoutExpired):
                        self._process.kill()
                        await asyncio.to_thread(self._process.wait, timeout=2)
                except OSError:
                    pass  # The recorded child may have exited concurrently.


async def start_command_window(console, *, logger=print, startup_timeout=5):
    """Start a visible Windows command child, or return None for stdin fallback.

    Callers retain Console's lifetime. A successful handle's wait_closed()
    signals that interactive input ended; it never requests server shutdown.
    This function does not start stdin itself, avoiding competing readers.
    """
    if not _WINDOWS:
        logger("Command window requires Windows; using server stdin commands.")
        return None
    window = CommandWindow(console, logger=logger)
    waiters = []
    try:
        await window._listen()
        environment = os.environ.copy()
        environment[TOKEN_ENV] = window._token
        # Request visibility only for this explicitly enabled child. Leave
        # standard handles unset so its new console owns its keyboard/output.
        startup = subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW,
                                         wShowWindow=1)  # SW_SHOWNORMAL
        try:
            window._process = subprocess.Popen(
                [sys.executable, "-m", "ow08.command_window", "--port", str(window.port)],
                cwd=str(Path(__file__).resolve().parents[1]), env=environment,
                startupinfo=startup, creationflags=subprocess.CREATE_NEW_CONSOLE,
                close_fds=True, shell=False)
        finally:
            environment.pop(TOKEN_ENV, None)
        window._watcher = asyncio.create_task(window._watch_child())
        waiters = [asyncio.create_task(window._ready.wait()),
                   asyncio.create_task(window._closed.wait())]
        done, _ = await asyncio.wait(waiters, timeout=startup_timeout,
                                     return_when=asyncio.FIRST_COMPLETED)
        if not done or not window._ready.is_set() or window._closed.is_set():
            raise OSError("command window did not connect")
        window._started = True
        logger("Command window ready; server packet output remains in this window.")
        return window
    except (OSError, ValueError, TimeoutError):
        await window.close()
        logger("Command window could not start; using server stdin commands.")
        return None
    except BaseException:
        await window.close()
        raise
    finally:
        for task in waiters:
            task.cancel()
        if waiters:
            await asyncio.gather(*waiters, return_exceptions=True)


class _LineInput:
    """One daemon reader, requested once per prompt; never blocks child exit."""

    def __init__(self, stream):
        self.stream = stream
        self.requests = queue.Queue(maxsize=1)
        self.active = True
        self.thread = threading.Thread(target=self._run, name="ow08-command-window-input", daemon=True)
        self.thread.start()

    async def read(self):
        loop = asyncio.get_running_loop()
        future = loop.create_future()
        self.requests.put_nowait((loop, future))
        return await future

    @staticmethod
    def _deliver(future, value):
        if not future.done():
            future.set_result(value)

    def _run(self):
        while True:
            request = self.requests.get()
            if request is None:
                return
            loop, future = request
            try:
                line = self.stream.readline(MAX_COMMAND_BYTES + 2)
                if not isinstance(line, str):
                    raise ValueError("command input must be text")
                if not line:
                    value = ("eof", "")
                else:
                    oversized = len(line.rstrip("\r\n").encode("utf-8")) > MAX_COMMAND_BYTES
                    if oversized:
                        while line and not line.endswith("\n"):
                            line = self.stream.readline(MAX_COMMAND_BYTES + 2)
                        value = ("error", "Command exceeded the input limit; it was not executed.")
                    else:
                        value = ("line", line.rstrip("\r\n"))
            except Exception:
                value = ("eof", "Command input is unavailable.")
            if self.active:
                try:
                    loop.call_soon_threadsafe(self._deliver, future, value)
                except RuntimeError:
                    return

    def close(self):
        self.active = False
        with suppress(queue.Full):
            self.requests.put_nowait(None)


def _display(stream, text, *, prompt=False):
    stream.write(_safe_text(text) + ("" if prompt else "\n"))
    stream.flush()


def _set_title():
    if _WINDOWS:
        try:
            set_title = ctypes.WinDLL("kernel32", use_last_error=True).SetConsoleTitleW
            set_title.argtypes, set_title.restype = [ctypes.c_wchar_p], ctypes.c_int
            set_title("Overwatch 0.8 - Server Commands")
        except (OSError, AttributeError):
            pass  # A missing console/title API does not disable command input.


async def _run_child(port, token, *, input_stream=None, output_stream=None):
    """Child-only prompt; a socket EOF wakes it even while stdin is blocked."""
    input_stream = sys.stdin if input_stream is None else input_stream
    output_stream = sys.stdout if output_stream is None else output_stream
    writer = inputs = receiver = input_task = closed_task = None
    closed = asyncio.Event()
    pending = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection("127.0.0.1", port, family=socket.AF_INET, limit=MAX_FRAME_BYTES + 4),
            IO_TIMEOUT)
        await _send(writer, {"auth": token})
        token = None
        if await asyncio.wait_for(_receive(reader), IO_TIMEOUT) != {"ready": True}:
            raise ValueError("command connection rejected")

        async def receive_results():
            try:
                while True:
                    response = await _receive(reader)
                    result = response.get("result")
                    if (set(response) != {"result"} or not isinstance(result, str)
                            or len(result.encode("utf-8")) > MAX_RESULT_BYTES
                            or pending is None or pending.done()):
                        raise ValueError("invalid command response")
                    pending.set_result(result)
            except (OSError, ValueError, UnicodeError, asyncio.IncompleteReadError, TimeoutError):
                pass
            finally:
                if pending is not None and not pending.done():
                    pending.set_exception(ConnectionError("command connection closed"))
                closed.set()

        receiver = asyncio.create_task(receive_results())
        closed_task = asyncio.create_task(closed.wait())
        inputs = _LineInput(input_stream)
        _display(output_stream, "Server commands: .help. Closing this window leaves the server running.")
        while not closed.is_set():
            _display(output_stream, "> ", prompt=True)
            input_task = asyncio.create_task(inputs.read())
            await asyncio.wait((input_task, closed_task), return_when=asyncio.FIRST_COMPLETED)
            if closed.is_set():
                break
            event, line = await input_task
            if event != "line":
                if line:
                    _display(output_stream, line)
                if event == "eof":
                    break
                continue
            if not line.strip():
                continue
            if (not _valid_command(line)
                    or len(json.dumps({"command": line}, ensure_ascii=False).encode("utf-8"))
                    > MAX_FRAME_BYTES):
                _display(output_stream, "Invalid command input; it was not executed.")
                continue
            pending = asyncio.get_running_loop().create_future()
            await _send(writer, {"command": line})
            result = await pending
            pending = None
            if result:
                _display(output_stream, result)
        if closed.is_set():
            _display(output_stream, "Server command connection closed.")
        return 0
    except (OSError, ValueError, UnicodeError, asyncio.IncompleteReadError, TimeoutError):
        _display(output_stream, "Server command connection is unavailable.")
        return 1
    finally:
        token = None
        if inputs:
            inputs.close()
        if pending is not None and not pending.done():
            pending.cancel()
        for task in (receiver, input_task, closed_task):
            if task:
                task.cancel()
        await asyncio.gather(*(task for task in (receiver, input_task, closed_task) if task),
                             return_exceptions=True)
        if writer:
            await _close_writer(writer)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Owned local server command window")
    parser.add_argument("--port", type=int, required=True)
    args = parser.parse_args(argv)
    token = os.environ.pop(TOKEN_ENV, None)
    if not 1 <= args.port <= 65535 or not _valid_token(token):
        print("Command window must be started by the local server.", file=sys.stderr)
        return 1
    try:
        _set_title()
        operation = _run_child(args.port, token)
        token = None
        return asyncio.run(operation)
    except KeyboardInterrupt:
        return 0  # Ctrl+C here closes this child, not the server's Console.


if __name__ == "__main__":
    raise SystemExit(main())
