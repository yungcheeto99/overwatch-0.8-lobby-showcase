"""Select an active IPv4 adapter without depending on a particular VPN."""
from __future__ import annotations

from dataclasses import dataclass
import ipaddress
import json
import socket
import subprocess


@dataclass(frozen=True)
class Adapter:
    name: str
    description: str
    address: str

    @property
    def virtual(self):
        # Hints affect ordering only. Unknown virtual adapters remain selectable.
        text = f"{self.name} {self.description}".casefold()
        return any(word in text for word in
                   ("virtual", "vpn", "easytier", "tailscale", "zerotier", "hamachi", "wireguard", "tap", "tun"))


def ipv4(value, *, loopback=False):
    address = ipaddress.IPv4Address(value)
    if (address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255"
            or (address.is_loopback and not loopback)):
        raise ValueError("Choose a specific LAN or virtual-network IPv4 address")
    return str(address)


def adapters():
    # .NET enumeration works without administrator rights and includes TAP/TUN
    # interfaces. No supplied paths or addresses enter the PowerShell program.
    command = r"""
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
$items = @([System.Net.NetworkInformation.NetworkInterface]::GetAllNetworkInterfaces() |
    Where-Object { $_.OperationalStatus -eq 'Up' } | ForEach-Object {
        $adapter = $_
        $adapter.GetIPProperties().UnicastAddresses |
            Where-Object { $_.Address.AddressFamily -eq 'InterNetwork' } | ForEach-Object {
                [pscustomobject]@{name=$adapter.Name; description=$adapter.Description; address=$_.Address.ToString()}
            }
    })
ConvertTo-Json -InputObject $items -Compress
"""
    try:
        process = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", command],
                                 capture_output=True, text=True, encoding="utf-8-sig", errors="replace", timeout=15,
                                 creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ValueError("Cannot list network adapters. Supply --server-ip with this PC's LAN/VPN address") from error
    if process.returncode:
        raise ValueError("Cannot list network adapters. Supply --server-ip with this PC's LAN/VPN address")
    found = []
    for item in json.loads(process.stdout or "[]"):
        try:
            found.append(Adapter(item["name"], item["description"], ipv4(item["address"])))
        except ValueError:
            pass  # Loopback is provided by --network local instead.
    return found


def route_address():
    # UDP connect selects a route without transmitting a packet.
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as connection:
            connection.connect(("192.0.2.1", 9))
            return connection.getsockname()[0]
    except OSError:
        return None


def select_address(network, requested=None, *, prompt=True):
    if network == "local":
        if requested not in (None, "auto", "127.0.0.1"):
            raise ValueError("--network local uses 127.0.0.1")
        return None
    if requested and requested != "auto":
        address = ipv4(requested)
        # Bind is the final authority, also allowing a newly connected adapter
        # when Windows adapter enumeration is temporarily unavailable.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as check:
            try:
                check.bind((address, 0))
            except OSError as error:
                raise ValueError(f"Server address {address} does not belong to an available local adapter") from error
        return address
    choices = adapters()
    choices.sort(key=lambda item: (item.virtual != (network == "virtual"), item.name.casefold(), item.address))
    if not choices:
        raise ValueError("No active LAN/VPN IPv4 adapter. Connect the network, then launch again")
    preferred = [item for item in choices if item.virtual == (network == "virtual")
                 and not ipaddress.IPv4Address(item.address).is_link_local]
    default = None
    if len(preferred) == 1:
        default = preferred[0]
    elif network == "lan":
        default = next((item for item in preferred if item.address == route_address()), None)
    if requested == "auto" or not prompt:
        if default is None:
            raise ValueError("Several network addresses are available. Supply --server-ip with the chosen adapter's IPv4")
        return default.address
    print("Active network addresses:", flush=True)
    for number, item in enumerate(choices, 1):
        print(f"  {number}. {item.address}  {item.name}", flush=True)
    default_number = choices.index(default) + 1 if default else None
    answer = input(f"Server address number{f' [{default_number}]' if default_number else ''}: ").strip()
    if not answer and default:
        return default.address
    if answer.isdecimal() and 1 <= int(answer) <= len(choices):
        return choices[int(answer) - 1].address
    raise ValueError("Choose one of the displayed network address numbers, or supply --server-ip")
