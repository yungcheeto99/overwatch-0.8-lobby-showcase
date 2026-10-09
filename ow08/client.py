"""Launch and observe our own beta client; optionally patch local TLS in memory.

Build-specific RVAs/signatures guard patches to the owned child process.
The executable on disk is preserved.
"""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from dataclasses import dataclass, field
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import struct
import subprocess
import time
from typing import Any, Callable, Iterable
import weakref


SUPPORTED_SHA256 = "21b761a5b48076728318290ee9d0be6ad1ee36af59e4b7aaefe7b7ac5bf2a68a"
_POPEN_TYPE = subprocess.Popen
_LAUNCHED_CHILDREN = weakref.WeakKeyDictionary()
_LOGIN_PATCH_PLANS = weakref.WeakKeyDictionary()


@dataclass(frozen=True)
class PatchSite:
    name: str
    rva: int
    original: bytes
    replacement: bytes
    phase: int


PATCH_SITES = (
    PatchSite("certificate-pin", 0x1100106, bytes.fromhex("ff5038"), b"\x90" * 3, 1),
    PatchSite("certificate-check", 0x110010D, bytes.fromhex("0f8578010000"), b"\x90" * 6, 1),
    PatchSite("curl-local-tls", 0x7C106, bytes.fromhex("7410"), bytes.fromhex("7510"), 2),
)

# Function extents from the supported executable's .pdata runtime-function
# table. The disk code is packed; capturing these small live functions gives
# aligned disassembly without reading unrelated process data.
_CONTEXT_RANGES = {
    "certificate-pin": (0x10FFDA0, 0x1100362),
    "certificate-check": (0x10FFDA0, 0x1100362),
    "curl-local-tls": (0x7BF70, 0x7C3B4),
}


@dataclass
class LaunchResult:
    process: subprocess.Popen
    events: list[dict[str, Any]] = field(default_factory=list)
    patch_records: list[dict[str, Any]] = field(default_factory=list)
    rsa_only: bool = False
    log_path: Path | None = None
    stdout_path: Path | None = None

    @property
    def returncode(self) -> int | None:
        return self.process.poll()


class ClientLaunchError(RuntimeError):
    def __init__(self, message: str, result: LaunchResult | None = None):
        super().__init__(message)
        self.result = result


def validate_local_endpoint(endpoint: str) -> str:
    """Accept only a literal loopback IP and explicit TCP port."""
    try:
        if endpoint.startswith("["):
            host, port_text = endpoint[1:].split("]:", 1)
        else:
            host, port_text = endpoint.rsplit(":", 1)
        address = ipaddress.ip_address(host)
        port = int(port_text)
    except (ValueError, TypeError, AttributeError) as exc:
        raise ClientLaunchError("BNet endpoint must be a literal loopback IP:port") from exc
    if not address.is_loopback or not 1 <= port <= 65535:
        raise ClientLaunchError("BNet endpoint must use a loopback IP and port 1..65535")
    return f"[{address}]:{port}" if address.version == 6 else f"{address}:{port}"


def _digest(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def validate_extra_args(extra_args: Iterable[str] | None) -> list[str]:
    """Validate separate game option tokens, never a shell command string."""
    if extra_args is None:
        return []
    if isinstance(extra_args, (str, bytes)):
        raise ClientLaunchError("extra_args must be an iterable of separate option strings")
    validated = []
    for argument in extra_args:
        if not isinstance(argument, str) or any(ord(char) < 32 or ord(char) == 127 for char in argument):
            raise ClientLaunchError("Extra client options must be strings without control characters")
        match = re.fullmatch(r"--([A-Za-z][A-Za-z0-9_.-]*)(?:=(.*))?", argument)
        if not match:
            raise ClientLaunchError("Extra client options must use --name or --name=value")
        name, value = match.groups()
        if name.casefold().endswith("bnetserver"):
            raise ClientLaunchError("An extra option cannot override the verified BNetServer endpoint")
        if name.casefold().endswith("lobbyserver"):
            if value is None:
                raise ClientLaunchError("lobbyServer requires an explicit literal loopback IP:port")
            argument = f"--{name}={validate_local_endpoint(value)}"
        validated.append(argument)
    return validated


def _redact_args(arguments: list[str]) -> list[str]:
    return [argument.split("=", 1)[0] + "=<redacted>"
            if "=" in argument and any(word in argument.split("=", 1)[0].casefold()
                                       for word in ("password", "token", "secret")) else argument
            for argument in arguments]


def _validate_patch_phases(phases: tuple[int, ...]) -> tuple[int, ...]:
    if (not isinstance(phases, tuple) or any(type(phase) is not int for phase in phases)
            or phases not in ((1,), (1, 2))):
        raise ClientLaunchError("patch_phases must be (1,) or (1, 2)")
    return phases


def _validate_local_rsa_modulus(modulus: bytes | None) -> bytes | None:
    if modulus is None:
        return None
    if not isinstance(modulus, bytes) or len(modulus) != 256:
        raise ClientLaunchError("Local RSA modulus must be exactly 256 little-endian bytes")
    if not modulus[-1] & 0x80 or not modulus[0] & 1:
        raise ClientLaunchError("Local RSA modulus must be an odd 2048-bit public modulus")
    return modulus


class _ModuleInfo(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("size", wintypes.DWORD), ("entry", ctypes.c_void_p)]


class _Windows:
    """Typed Windows calls, constructed only on Windows. Handles are never global."""

    def __init__(self):
        if os.name != "nt":
            raise ClientLaunchError("Client launching is supported on Windows only")
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.psapi = ctypes.WinDLL("psapi", use_last_error=True)
        self._function(self.kernel.OpenProcess, wintypes.HANDLE, [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD])
        self._function(self.kernel.CloseHandle, wintypes.BOOL, [wintypes.HANDLE])
        self._function(self.kernel.ReadProcessMemory, wintypes.BOOL,
                       [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)])
        self._function(self.kernel.WriteProcessMemory, wintypes.BOOL,
                       [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)])
        self._function(self.kernel.VirtualProtectEx, wintypes.BOOL,
                       [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)])
        self._function(self.kernel.FlushInstructionCache, wintypes.BOOL,
                       [wintypes.HANDLE, ctypes.c_void_p, ctypes.c_size_t])
        self._function(self.psapi.EnumProcessModulesEx, wintypes.BOOL,
                       [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), wintypes.DWORD])
        self._function(self.psapi.GetModuleInformation, wintypes.BOOL,
                       [wintypes.HANDLE, wintypes.HMODULE, ctypes.POINTER(_ModuleInfo), wintypes.DWORD])
        self._function(self.psapi.GetModuleFileNameExW, wintypes.DWORD,
                       [wintypes.HANDLE, wintypes.HMODULE, wintypes.LPWSTR, wintypes.DWORD])

    @staticmethod
    def _function(function, restype, argtypes):
        function.restype, function.argtypes = restype, argtypes

    @staticmethod
    def _check(ok, operation):
        if not ok:
            raise OSError(ctypes.get_last_error(), f"{operation} failed")

    def open_child(self, process: subprocess.Popen, *, write: bool = True):
        if process.poll() is not None:
            raise ClientLaunchError(f"Client exited before patching (code {process.returncode})")
        # Access is scoped to the live subprocess object created by launch_client.
        access = 0x0400 | 0x0010
        if write:
            access |= 0x0020 | 0x0008
        handle = self.kernel.OpenProcess(access, False, process.pid)
        self._check(handle, "OpenProcess")
        return handle

    def close(self, handle):
        self._check(self.kernel.CloseHandle(handle), "CloseHandle")

    def module(self, handle, expected_path: Path) -> tuple[int, int]:
        modules = (wintypes.HMODULE * 1024)()
        needed = wintypes.DWORD()
        self._check(self.psapi.EnumProcessModulesEx(handle, modules, ctypes.sizeof(modules), ctypes.byref(needed), 3),
                    "EnumProcessModulesEx")
        if needed.value < ctypes.sizeof(wintypes.HMODULE) or needed.value > ctypes.sizeof(modules):
            raise OSError("Cannot safely identify the client's main module")
        main = modules[0]
        filename = ctypes.create_unicode_buffer(32768)
        self._check(self.psapi.GetModuleFileNameExW(handle, main, filename, len(filename)), "GetModuleFileNameExW")
        if os.path.normcase(str(Path(filename.value).resolve())) != os.path.normcase(str(expected_path.resolve())):
            raise ClientLaunchError("Live main module does not match the executable launched")
        info = _ModuleInfo()
        self._check(self.psapi.GetModuleInformation(handle, main, ctypes.byref(info), ctypes.sizeof(info)),
                    "GetModuleInformation")
        return info.base, info.size

    def read(self, handle, address: int, count: int) -> bytes | None:
        buffer = ctypes.create_string_buffer(count)
        read = ctypes.c_size_t()
        ok = self.kernel.ReadProcessMemory(handle, address, buffer, count, ctypes.byref(read))
        return buffer.raw if ok and read.value == count else None

    def write(self, handle, address: int, data: bytes):
        old = wintypes.DWORD()
        self._check(self.kernel.VirtualProtectEx(handle, address, len(data), 0x40, ctypes.byref(old)), "VirtualProtectEx")
        try:
            buffer = ctypes.create_string_buffer(data, len(data))
            written = ctypes.c_size_t()
            self._check(self.kernel.WriteProcessMemory(handle, address, buffer, len(data), ctypes.byref(written)),
                        "WriteProcessMemory")
            if written.value != len(data):
                raise OSError(f"WriteProcessMemory wrote {written.value}/{len(data)} bytes")
        finally:
            ignored = wintypes.DWORD()
            try:
                self._check(self.kernel.VirtualProtectEx(handle, address, len(data), old.value, ctypes.byref(ignored)),
                            "Restore memory protection")
            finally:
                self._check(self.kernel.FlushInstructionCache(handle, address, len(data)), "FlushInstructionCache")
        if self.read(handle, address, len(data)) != data:
            raise OSError("Readback did not match the bytes written")

def validate_owned_client(result: LaunchResult, game: Path) -> str:
    """Verify a live child created by this launcher and the supported disk image."""
    if not isinstance(result, LaunchResult) or not isinstance(result.process, _POPEN_TYPE):
        raise ClientLaunchError("Patch preparation requires this launcher's LaunchResult child")
    game = Path(game).resolve()
    receipt = _LAUNCHED_CHILDREN.get(result.process)
    if receipt is None or receipt[0] != game:
        raise ClientLaunchError("Patch preparation requires a process owned by this launcher")
    if result.process.poll() is not None:
        raise ClientLaunchError("Client exited before patch preparation")
    fingerprint = _digest(game)
    if fingerprint != SUPPORTED_SHA256 or receipt[1] != fingerprint:
        raise ClientLaunchError(f"Patch preparation requires the supported unchanged executable SHA256: {fingerprint}")
    if ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ClientLaunchError("Patch preparation for this x64 client requires 64-bit Python")
    return fingerprint


def _rollback(api, handle, base: int, attempted: list[PatchSite], emit: Callable, process):
    for site in reversed(attempted):
        if process.poll() is not None:
            emit("rollback", site=site.name, state="child-exited-memory-discarded")
            continue
        address = base + site.rva
        current = api.read(handle, address, len(site.original))
        # A short failed write can leave a mixture of original/replacement bytes.
        controlled = current is not None and all(byte in (old, new) for byte, old, new in
                                               zip(current, site.original, site.replacement))
        if not controlled:
            emit("rollback", site=site.name, state="refused-unexpected-bytes", observed=current.hex() if current else None)
            continue
        try:
            api.write(handle, address, site.original)
            emit("rollback", site=site.name, state="restored", address=hex(address))
        except OSError as exc:
            emit("rollback", site=site.name, state="failed", error=str(exc))


def _capture_patch_context(api, handle, base: int, size: int, site: PatchSite, emit: Callable):
    """Read the known containing function, at most 1474 bytes, before patching."""
    start, end = _CONTEXT_RANGES.get(site.name, (site.rva, site.rva + len(site.original)))
    start, end = max(0, start), min(size, end)
    count = end - start
    data = api.read(handle, base + start, count)
    context = {"site": site.name, "rva": hex(start), "address": hex(base + start), "size": count,
               "signature_rva": hex(site.rva), "bytes": data.hex() if data is not None else None}
    if data is None:
        # A protection/page boundary can make the larger read fail. Preserve
        # readable 64-byte spans without widening the bounded code-only window.
        chunks = []
        for offset in range(0, count, 64):
            chunk_size = min(64, count - offset)
            chunk = api.read(handle, base + start + offset, chunk_size)
            chunks.append({"rva": hex(start + offset), "address": hex(base + start + offset),
                           "size": chunk_size, "bytes": chunk.hex() if chunk is not None else None})
        context["chunks"] = chunks
    emit("patch-context", **context)


def _ignore_cached_credentials(api, handle, base, size, process, deadline, emit):
    """Choose native web login in this owned beta process only.

    The challenge callback tests the AuthSystem token string's length. Verify
    the live owner, vtables and pre-challenge state, then use the beta's normal
    empty-string layout. Token bytes are never read or retained. Registry and
    user settings are untouched; this per-launch choice needs no secret receipt.
    """
    root_rva = 0x1833E18
    if root_rva + 8 > size:
        raise ClientLaunchError("Credentials startup root is outside the verified module")
    def number(address, count=8):
        value = api.read(handle, address, count)
        return int.from_bytes(value, "little") if value is not None and len(value) == count else None
    while time.monotonic() < deadline:
        if process.poll() is not None:
            raise ClientLaunchError("Client exited before native credentials startup")
        manager = number(base + root_rva)
        auth = number(manager + 0x178) if manager else None
        if auth and number(auth) == base + 0x15C46F8 and number(auth + 8) == manager:
            break
        time.sleep(0.01)
    else:
        raise ClientLaunchError("Native credentials startup owner did not become available")
    if (number(auth + 0x488) != base + 0x15C4AB0 or number(auth + 0x38, 1) != 0
            or number(auth + 0x28, 4) in (None, 15, 16)):
        raise ClientLaunchError("Native credentials startup is past the verified challenge boundary")
    length, capacity = number(auth + 0x478, 4), number(auth + 0x47C, 4)
    if length is None or capacity is None or not (0 <= length < capacity and 16 <= capacity <= 128):
        raise ClientLaunchError("Native credentials string metadata is unsupported")
    if length:
        storage = number(auth + 0x468) if capacity > 16 else auth + 0x468
        if not storage or storage < 65536:
            raise ClientLaunchError("Native credentials string has no verified storage")
        api.write(handle, storage, b"\0")
        api.write(handle, auth + 0x480, bytes(8))
        api.write(handle, auth + 0x478, bytes(4))
        if number(auth + 0x478, 4) != 0:
            raise ClientLaunchError("Native credentials startup did not clear the cached-token length")
    emit("native-credentials-startup", cached_credentials_ignored=bool(length))


def _patch_child(api, process, game: Path, deadline: float, emit: Callable, records: list, *,
                 patch_phases: tuple[int, ...] = (1, 2), on_patch_ready: Callable[[], None] | None = None,
                 local_rsa_modulus: bytes | None = None,
                 rsa_only: bool = False, force_credentials: bool = False):
    """Bounded selected-phase transaction, with rollback on any incomplete patch.

    The callback signals successful phase 1 only, before waiting for phase 2. An
    optional later phase-2 failure still rolls back the transaction. A callback
    exception also rolls back rather than leaving an incomplete launch running.
    """
    phases = _validate_patch_phases(patch_phases)
    modulus = _validate_local_rsa_modulus(local_rsa_modulus)
    if type(rsa_only) is not bool or (rsa_only and (modulus is None or phases != (1,))):
        raise ClientLaunchError("rsa_only requires the local modulus and phase 1")
    sites = () if rsa_only else PATCH_SITES
    if modulus is not None:
        from .local_rsa import MODULUS_RVA, ORIGINAL_MODULUS_LE
        sites += (PatchSite("local-rsa-modulus", MODULUS_RVA, ORIGINAL_MODULUS_LE, modulus, 1),)
    selected_sites = tuple(site for site in sites if site.phase in phases)
    handle = api.open_child(process)
    base = None
    attempted = []
    try:
        while time.monotonic() < deadline:
            if process.poll() is not None:
                raise ClientLaunchError(f"Client exited during module discovery (code {process.returncode})")
            try:
                base, size = api.module(handle, game)
                break
            except OSError:
                time.sleep(0.05)
        if base is None:
            raise ClientLaunchError("Timed out discovering the client's main module")
        if any(site.rva + len(site.original) > size for site in selected_sites):
            raise ClientLaunchError("Patch address is outside the verified main module")
        emit("module", base=hex(base), size=size, path=str(game))
        for phase in phases:
            phase_sites = [site for site in selected_sites if site.phase == phase]
            observed = {}
            emit("patch-wait", phase=phase)
            while time.monotonic() < deadline:
                if process.poll() is not None:
                    raise ClientLaunchError(f"Client exited waiting for unpacking (code {process.returncode})")
                observed = {site.name: api.read(handle, base + site.rva, len(site.original)) for site in phase_sites}
                if all(observed[site.name] == site.original for site in phase_sites):
                    break
                time.sleep(0.05)
            else:
                emit("patch-timeout", phase=phase, observed={name: value.hex() if value else None for name, value in observed.items()})
                raise ClientLaunchError(f"Timed out waiting for known unpacked bytes in patch phase {phase}")
            # Capture all contexts for this phase before its first write, since
            # the two certificate sites have overlapping surrounding functions.
            for site in phase_sites:
                _capture_patch_context(api, handle, base, size, site, emit)
            for site in phase_sites:
                address = base + site.rva
                # Do not accept another tool's already-patched bytes as originals.
                if api.read(handle, address, len(site.original)) != site.original:
                    raise ClientLaunchError(f"Bytes changed before patching {site.name}")
                attempted.append(site)  # Includes a potentially partial failed write.
                api.write(handle, address, site.replacement)
                record = {"site": site.name, "rva": hex(site.rva), "address": hex(address),
                          "original": site.original.hex(), "replacement": site.replacement.hex(), "state": "applied"}
                records.append(record)
                emit("patch", **record)
            emit("patch-phase-complete", phase=phase, count=len(phase_sites))
            if phase == 1 and force_credentials:
                _ignore_cached_credentials(api, handle, base, size, process, deadline, emit)
            if phase == 1 and on_patch_ready is not None:
                on_patch_ready()
        emit("patch-complete", count=len(records))
    except BaseException:
        if base is not None:
            _rollback(api, handle, base, attempted, emit, process)
        raise
    finally:
        api.close(handle)


def stop_client(process: subprocess.Popen):
    """Stop only the Popen child given to us, allowing a bounded exit wait."""
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def _restore_login_subset(result: LaunchResult, game: Path, *, tls_only: bool):
    """Validate every login site, then restore only the requested applied sites."""
    validate_owned_client(result, game)
    from .local_rsa import MODULUS_RVA, ORIGINAL_MODULUS_LE
    allowed = {site.name for site in PATCH_SITES[:2]} | {"local-rsa-modulus"}
    api = handle = None
    try:
        # Bind immutable replacement bytes to the original launch. A mutable
        # diagnostic receipt cannot substitute another launch's public key.
        plan = _LOGIN_PATCH_PLANS.get(result.process)
        expected_names = ({"local-rsa-modulus"} if result.rsa_only else allowed)
        if (type(result.rsa_only) is not bool or plan is None
                or {site.name for site in plan} != expected_names or len(plan) != len(expected_names)):
            raise ClientLaunchError("Temporary login restoration requires the exact TLS/RSA patch receipt")
        sites = {site.name: site for site in plan}
        records = [record for record in result.patch_records if record.get("site") in allowed]
        if {record["site"] for record in records} != expected_names or len(records) != len(expected_names):
            raise ClientLaunchError("Temporary login restoration requires the exact TLS/RSA patch receipt")
        for record in records:
            site = sites[record["site"]]
            if (record["state"] not in ("applied", "restored")
                    or int(record["rva"], 16) != site.rva
                    or bytes.fromhex(record["original"]) != site.original
                    or bytes.fromhex(record["replacement"]) != site.replacement):
                raise ClientLaunchError(f"Cannot safely restore {site.name}: receipt/live bytes changed")
            if site.name == "local-rsa-modulus" and (site.rva != MODULUS_RVA or site.original != ORIGINAL_MODULUS_LE):
                raise ClientLaunchError("Cannot safely restore the local RSA patch plan")
        api = _Windows()
        handle = api.open_child(result.process)
        base, size = api.module(handle, Path(game).resolve())
        # Already-restored sites are still checked live. This permits the TLS
        # checkpoint followed by RSA restoration without trusting stale flags.
        for record in records:
            site = sites[record["site"]]
            expected = site.original if record["state"] == "restored" else site.replacement
            if (site.rva + len(site.original) > size
                    or api.read(handle, base + site.rva, len(site.original)) != expected):
                raise ClientLaunchError(f"Cannot safely restore {record['site']}: receipt/live bytes changed")
        restored = []
        for record in reversed(records):
            if record["state"] == "restored" or (tls_only and record["site"] == "local-rsa-modulus"):
                continue
            site = sites[record["site"]]
            if api.read(handle, base + site.rva, len(site.original)) != site.replacement:
                raise ClientLaunchError(f"Bytes changed before restoring {site.name}")
            api.write(handle, base + site.rva, site.original)
            if api.read(handle, base + site.rva, len(site.original)) != site.original:
                raise ClientLaunchError(f"Original bytes did not read back after restoring {site.name}")
            record["state"] = "restored"
            restored.append(site.name)
        if restored:
            event = {"event": "tls-patches-restored" if tls_only else "login-patches-restored",
                     "pid": result.process.pid, "sites": restored}
            result.events.append(event)
            if result.log_path:
                with result.log_path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(event) + "\n")
    except BaseException:
        stop_client(result.process)
        raise
    finally:
        if handle is not None:
            api.close(handle)


def restore_tls_patches(result: LaunchResult, game: Path):
    """Restore the two checked TLS sites after TLS, retaining the local RSA key.

    The complete owned TLS/RSA plan is preflighted before any write, including
    sites already restored. A mismatch or failed write stops only this child.
    """
    _restore_login_subset(result, game, tls_only=True)


def _prepare_login_subset(result: LaunchResult, game: Path, *, tls_only: bool):
    """Check all owned login sites before reapplying the selected original plan."""
    validate_owned_client(result, game)
    from .local_rsa import MODULUS_RVA, ORIGINAL_MODULUS_LE
    allowed = {site.name for site in PATCH_SITES[:2]} | {"local-rsa-modulus"}
    api = handle = None
    try:
        plan = _LOGIN_PATCH_PLANS.get(result.process)
        expected_names = ({"local-rsa-modulus"} if result.rsa_only else allowed)
        if (type(result.rsa_only) is not bool or plan is None
                or {site.name for site in plan} != expected_names or len(plan) != len(expected_names)):
            raise ClientLaunchError("Login preparation requires the exact TLS/RSA patch receipt")
        sites = {site.name: site for site in plan}
        records = [record for record in result.patch_records if record.get("site") in allowed]
        if {record["site"] for record in records} != expected_names or len(records) != len(expected_names):
            raise ClientLaunchError("Login preparation requires the exact TLS/RSA patch receipt")
        for record in records:
            site = sites[record["site"]]
            if (record["state"] not in ("applied", "restored")
                    or int(record["rva"], 16) != site.rva
                    or bytes.fromhex(record["original"]) != site.original
                    or bytes.fromhex(record["replacement"]) != site.replacement):
                raise ClientLaunchError(f"Cannot safely prepare {site.name}: receipt/live bytes changed")
            if site.name == "local-rsa-modulus" and (site.rva != MODULUS_RVA or site.original != ORIGINAL_MODULUS_LE):
                raise ClientLaunchError("Cannot safely prepare the local RSA patch plan")
        api = _Windows()
        handle = api.open_child(result.process)
        base, size = api.module(handle, Path(game).resolve())
        for record in records:
            site = sites[record["site"]]
            expected = site.original if record["state"] == "restored" else site.replacement
            if (site.rva + len(site.original) > size
                    or api.read(handle, base + site.rva, len(site.original)) != expected):
                raise ClientLaunchError(f"Cannot safely prepare {site.name}: receipt/live bytes changed")
        prepared = []
        for record in records:
            is_rsa = record["site"] == "local-rsa-modulus"
            if record["state"] == "applied" or is_rsa == tls_only:
                continue
            site = sites[record["site"]]
            if api.read(handle, base + site.rva, len(site.original)) != site.original:
                raise ClientLaunchError(f"Bytes changed before preparing {site.name}")
            api.write(handle, base + site.rva, site.replacement)
            if api.read(handle, base + site.rva, len(site.replacement)) != site.replacement:
                raise ClientLaunchError(f"Replacement bytes did not read back after preparing {site.name}")
            record["state"] = "applied"
            prepared.append(site.name)
        if prepared:
            event = {"event": "tls-patches-prepared" if tls_only else "lobby-rsa-prepared",
                     "pid": result.process.pid, "sites": prepared}
            result.events.append(event)
            if result.log_path:
                with result.log_path.open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(event) + "\n")
    except BaseException:
        stop_client(result.process)
        raise
    finally:
        if handle is not None:
            api.close(handle)


def prepare_tls_patches(result: LaunchResult, game: Path):
    """Reapply this owned child's TLS sites before another local handshake.

    Check the original immutable TLS/RSA plan, every diagnostic receipt and all
    live sites before writing. Already-applied TLS is an idempotent checkpoint;
    the RSA site is validated but never changed. Any mismatch or failed write
    stops only the validated child, without accepting another process or key.
    """
    _prepare_login_subset(result, game, tls_only=True)


def prepare_lobby_rsa(result: LaunchResult, game: Path):
    """Reapply only the original local RSA plan before a validated referral.

    The native credentials form keeps its original RSA bytes. Once the server
    has validated local credentials, this owned launch may prepare its original
    local lobby modulus. All TLS/RSA receipts and live bytes are checked first;
    TLS remains unchanged and RSA state updates only after verified readback.
    """
    _prepare_login_subset(result, game, tls_only=False)


def restore_login_patches(result: LaunchResult, game: Path):
    """Restore remaining TLS/RSA bytes after encrypted channel acceptance.

    Accept checked originals from an earlier TLS checkpoint and the checked
    replacement modulus. Update receipts only after original-byte readback.
    """
    _restore_login_subset(result, game, tls_only=False)


def launch_client(game: Path, bnet_endpoint: str = "127.0.0.1:1119", patch_local_tls: bool = False,
                  log_path: Path | None = None, timeout: float = 30,
                  extra_args: Iterable[str] | None = None, *,
                  patch_phases: tuple[int, ...] = (1, 2),
                  on_patch_ready: Callable[[], None] | None = None,
                  on_started: Callable[[LaunchResult], None] | None = None,
                  local_rsa_modulus: bytes | None = None,
                  rsa_only: bool = False,
                  force_credentials: bool = False) -> LaunchResult:
    """Launch in the client directory and observe for at most ``timeout`` seconds.

    Default mode changes no memory. Opt-in patches require the exact supported
    SHA256, literal loopback endpoint, 64-bit Python, and exact live bytes. The
    successful process is left running and returned. On partial patch failure or
    Ctrl+C we roll back the attempted transaction and stop our own child. Errors
    after launch carry a ``result`` with the child and evidence collected so far.
    """
    endpoint = validate_local_endpoint(bnet_endpoint)
    arguments = validate_extra_args(extra_args)
    phases = _validate_patch_phases(patch_phases)
    modulus = _validate_local_rsa_modulus(local_rsa_modulus)
    if type(force_credentials) is not bool or (force_credentials and (modulus is None or phases != (1,))):
        raise ClientLaunchError("Native credentials startup requires local RSA and patch phase 1")
    if type(rsa_only) is not bool or (rsa_only and (patch_local_tls or modulus is None or phases != (1,))):
        raise ClientLaunchError("rsa_only requires a local modulus, phase 1 and original TLS")
    if modulus is not None and not (patch_local_tls or rsa_only):
        raise ClientLaunchError("Local RSA replacement requires explicit patch_local_tls or rsa_only opt-in")
    if on_patch_ready is not None and not callable(on_patch_ready):
        raise ClientLaunchError("on_patch_ready must be callable")
    if on_started is not None and not callable(on_started):
        raise ClientLaunchError("on_started must be callable")
    game = Path(game).resolve()
    if not 0 < timeout <= 300:
        raise ClientLaunchError("Observation timeout must be greater than zero and at most 300 seconds")
    if os.name != "nt":
        raise ClientLaunchError("Client launching is supported on Windows only")
    if not game.is_file():
        raise ClientLaunchError(f"Client executable does not exist: {game}")
    fingerprint = _digest(game)
    if (patch_local_tls or rsa_only) and fingerprint != SUPPORTED_SHA256:
        raise ClientLaunchError(f"Refusing memory patch: unsupported SHA256 {fingerprint}")
    if (patch_local_tls or rsa_only) and ctypes.sizeof(ctypes.c_void_p) != 8:
        raise ClientLaunchError("Memory patching this x64 client requires 64-bit Python")
    api = _Windows()
    if log_path is not None:
        log_path = Path(log_path).resolve()
        if log_path == game:
            raise ClientLaunchError("Diagnostic log cannot overwrite the executable")
        log_path.parent.mkdir(parents=True, exist_ok=True)
    stdout_path = log_path.with_suffix(".stdout.log") if log_path else None
    stdout = stdout_path.open("ab") if stdout_path else subprocess.DEVNULL
    try:
        process = subprocess.Popen([str(game), f"--BNetServer={endpoint}", *arguments], cwd=str(game.parent),
                                   stdout=stdout, stderr=subprocess.STDOUT)
    except OSError as exc:
        raise ClientLaunchError(f"Could not launch client: {exc}") from exc
    finally:
        if stdout_path:
            stdout.close()
    result = LaunchResult(process=process, log_path=log_path, stdout_path=stdout_path, rsa_only=rsa_only)
    _LAUNCHED_CHILDREN[process] = (game, fingerprint)
    if patch_local_tls or rsa_only:
        sites = list(PATCH_SITES[:2]) if patch_local_tls else []
        if modulus is not None:
            from .local_rsa import MODULUS_RVA, ORIGINAL_MODULUS_LE
            sites.append(PatchSite("local-rsa-modulus", MODULUS_RVA, ORIGINAL_MODULUS_LE, modulus, 1))
        _LOGIN_PATCH_PLANS[process] = tuple(sites)
    started = time.monotonic()

    def emit(event, **data):
        record = {"event": event, "elapsed_seconds": round(time.monotonic() - started, 3), **data}
        result.events.append(record)
        if log_path:
            with log_path.open("a", encoding="utf-8") as stream:
                stream.write(json.dumps(record, ensure_ascii=False) + "\n")

    try:
        emit("launch", pid=process.pid, game=str(game), sha256=fingerprint, bnet_endpoint=endpoint,
             patch_local_tls=patch_local_tls, patch_phases=phases, extra_args=_redact_args(arguments),
             local_rsa_modulus_sha256=hashlib.sha256(modulus).hexdigest() if modulus is not None else None,
             rsa_only=rsa_only,
             stdout_path=str(stdout_path) if stdout_path else None)
        if on_started is not None:
            on_started(result)
        deadline = started + timeout
        if patch_local_tls or rsa_only:
            _patch_child(api, process, game, deadline, emit, result.patch_records,
                         patch_phases=phases, on_patch_ready=on_patch_ready, local_rsa_modulus=modulus,
                         rsa_only=rsa_only, force_credentials=force_credentials)
        while True:
            sample = {"pid": process.pid, "returncode": process.poll()}
            emit("sample", **sample)
            if process.returncode is not None or time.monotonic() >= deadline:
                break
            time.sleep(min(1, max(0, deadline - time.monotonic())))
        emit("observation-complete", pid=process.pid, running=process.poll() is None, returncode=process.returncode)
        return result
    except KeyboardInterrupt:
        stop_client(process)
        emit("interrupted", pid=process.pid, returncode=process.poll())
        raise
    except Exception as exc:
        stop_client(process)
        emit("launch-failed", error=str(exc), returncode=process.poll())
        if isinstance(exc, ClientLaunchError):
            exc.result = result
            raise
        raise ClientLaunchError(str(exc), result=result) from exc
