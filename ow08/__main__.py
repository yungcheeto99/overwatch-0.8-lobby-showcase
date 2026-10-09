"""The shareable build-24919 lobby: fixed server and owned-client launchers."""
from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
import struct
import sys

from .network import ipv4, select_address


ROOT = Path(__file__).resolve().parents[1]


def parser():
    root = argparse.ArgumentParser(description="Overwatch 0.8 showcase (Windows x64 Python 3.11+)")
    commands = root.add_subparsers(dest="command", required=True)
    for command in ("server", "client"):
        action = commands.add_parser(command, epilog="Batch options: --python PATH first, or --setup-only to install dependencies.")
        action.add_argument("--data-dir", type=Path, default=ROOT / "data",
                            help="local accounts, keys and saved certificate pins; relative paths start in the lobby folder")
        action.add_argument("--state", type=Path, help="local launcher rendezvous file (defaults inside data-dir)")
        action.add_argument("--capture", nargs="?", const=Path("captures"), type=Path,
                            help="enable captures, optionally in this directory (disabled by default)")
        action.add_argument("--no-prompt", action="store_true",
                            help="skip prompts and use standard mode; supply connection choices" if command == "server"
                            else "require launch arguments for interactive choices")
        action.add_argument("--remote-port", type=int, default=47325, help="gateway TCP port (internal for the public tunnel)")
        if command == "server":
            action.add_argument("--network", choices=("local", "lan", "virtual"), help="hosting network (prompt if omitted)")
            action.add_argument("--server-ip", "--remote-host", dest="server_ip", help="LAN adapter IPv4 or auto; virtual hosting assigns its identifier")
            action.add_argument("--port", type=int, default=3725, help="internal lobby port")
            action.add_argument("--bnet-port", type=int, default=1119, help="internal TLS bootstrap port")
            action.add_argument("--web-port", type=int, default=6969, help="internal HTTP login port")
            action.add_argument("--accounts", type=Path, help="account database (defaults inside data-dir)")
            action.add_argument("--invite", type=Path, help="also export a per-run private invite")
            action.add_argument("--packet-log", action=argparse.BooleanOptionalAction, default=True)
            action.add_argument("--command-window", action=argparse.BooleanOptionalAction, default=True,
                                help="separate command console; --no-command-window uses this window")
        else:
            action.add_argument("--network", choices=("local", "virtual"), help="local PC/LAN or public VPN tunnel (prompt if omitted)")
            action.add_argument("--game", type=Path, help="client folder or GameClientApp.exe (prompt if omitted)")
            action.add_argument("--server-ip", help="server IPv4 or printed public tunnel identifier; 127.0.0.1 joins locally")
            action.add_argument("--server-pin", help="expected server TLS SHA256; replaces a saved pin only when it matches")
            action.add_argument("--remote-invite", type=Path, help="optional private invite instead of IP discovery")
            action.add_argument("--observe-seconds", type=float, default=30, help="initial client preparation deadline")
    return root


def resolved(path):
    # Accept quoted paths pasted at a prompt; command-line quoting is handled
    # by Windows before argparse sees the value. Match the batch launchers even
    # when the module is started from another working directory.
    value = Path(str(path).strip().strip('"')).expanduser()
    return (value if value.is_absolute() else ROOT / value).resolve()


def prompt_value(label, default=None):
    answer = input(f"{label}{f' [{default}]' if default else ''}: ").strip().strip('"')
    return answer or default


def powershell_command(arguments):
    # Literal strings preserve paths containing spaces, quotes and shell
    # metacharacters when users paste the command into PowerShell.
    return "& " + " ".join("'" + str(argument).replace("'", "''") + "'" for argument in arguments)


def prepare(args):
    print(f"Server code: {ROOT}", flush=True)
    args.data_dir = resolved(args.data_dir)
    args.state = resolved(args.state) if args.state else args.data_dir / "local-menu-server.json"
    args.no_capture = args.capture is None
    args.capture_dir = resolved(args.capture) if args.capture is not None else args.data_dir / "captures"
    if not 1 <= args.remote_port <= 65535:
        raise ValueError("--remote-port must be between 1 and 65535")
    # These values keep the battle-tested runtime API fixed without exposing
    # experimental mode choices in the user-facing launcher.
    args.preset, args.config, args.auth_mode, args.rsa_only = "beta-menu", None, "credentials", False
    if args.command == "server":
        if args.network is None:
            if args.server_ip:
                args.network = "lan"
            elif args.no_prompt:
                raise ValueError("Supply --network local, lan or virtual")
            else:
                print("Network: 1. This PC  2. LAN  3. Virtual LAN/VPN (automatic public tunnel)")
                choice = prompt_value("Hosting network", "1")
                try:
                    args.network = {"1": "local", "2": "lan", "3": "virtual"}[choice]
                except KeyError:
                    raise ValueError("Choose hosting network 1, 2 or 3") from None
        args.extended = False
        if not args.no_prompt:
            print("Extended mode adds features that were scrapped or hidden before BlizzCon.")
            choice = prompt_value("Enable extended mode (y/n)", "n").casefold()
            if choice not in ("y", "yes", "n", "no"):
                raise ValueError("Choose y or n for extended mode")
            args.extended = choice in ("y", "yes")
        if args.network == "virtual":
            if args.server_ip not in (None, "auto", "127.0.0.1"):
                raise ValueError("Virtual hosting assigns a public identifier automatically; omit --server-ip")
            if args.invite:
                raise ValueError("Virtual hosting uses its public identifier; --invite is only for LAN hosting")
            args.remote_host = "127.0.0.1"
        else:
            args.remote_host = select_address(args.network, args.server_ip, prompt=not args.no_prompt)
        ports = (args.port, args.bnet_port, args.web_port)
        if any(not 1 <= port <= 65535 for port in ports) or len(set(ports)) != 3:
            raise ValueError("Internal lobby, bootstrap and login ports must be different and between 1 and 65535")
        args.accounts = resolved(args.accounts) if args.accounts else args.data_dir / "accounts.sqlite3"
        args.cert, args.key = args.data_dir / "localip.crt", args.data_dir / "localip.key"
        args.rsa_key = args.data_dir / "lobby-rsa.pem"
        if args.invite:
            args.invite = resolved(args.invite)
        address = ("assigned when the public tunnel connects" if args.network == "virtual"
                   else args.remote_host or "127.0.0.1")
        print(f"Network: {args.network}\nServer address: {address}\n"
              f"Extended features: {'enabled' if args.extended else 'disabled'}\n"
              f"Data: {args.data_dir}\nCaptures: {args.capture_dir if not args.no_capture else 'disabled'}", flush=True)
        command = [sys.executable, "-u", str(ROOT / "launch.py"), "server", "--network", args.network]
        if args.remote_host and args.network != "virtual":
            command += ["--server-ip", args.remote_host]
        for flag, value, default in (("--port", args.port, 3725), ("--bnet-port", args.bnet_port, 1119),
                                     ("--web-port", args.web_port, 6969)):
            if value != default:
                command += [flag, str(value)]
        if args.accounts != args.data_dir / "accounts.sqlite3":
            command += ["--accounts", str(args.accounts)]
        if args.invite:
            command += ["--invite", str(args.invite)]
        if not args.packet_log:
            command += ["--no-packet-log"]
        if not args.command_window:
            command += ["--no-command-window"]
    else:
        if args.game is None:
            if args.no_prompt:
                raise ValueError("Supply --game with the client folder or GameClientApp.exe")
            args.game = prompt_value("Client folder or GameClientApp.exe", str(ROOT.parent))
        if not args.game:
            raise ValueError("A client location is required")
        args.game = resolved(args.game)
        if args.game.is_dir():
            args.game /= "GameClientApp.exe"
        if not args.game.is_file():
            raise ValueError(f"Client executable does not exist: {args.game}")
        if args.server_ip and args.remote_invite:
            raise ValueError("Choose either --server-ip or --remote-invite")
        if args.server_pin and args.remote_invite:
            raise ValueError("--remote-invite already contains its certificate pin; use --server-pin with --server-ip")
        if args.network is None:
            if args.server_ip:
                public_url = args.server_ip.strip().casefold().startswith(("https://", "wss://"))
                args.network = "virtual" if public_url else "local"
            elif args.remote_invite:
                args.network = "local"
            elif args.no_prompt:
                raise ValueError("Supply --network local or virtual and --server-ip, or --remote-invite")
            else:
                print("Connection: 1. Local connection (this PC/LAN)  2. VPN connection (public tunnel)")
                choice = prompt_value("Connection type", "1")
                try:
                    args.network = {"1": "local", "2": "virtual"}[choice]
                except KeyError:
                    raise ValueError("Choose connection type 1 or 2") from None
        if args.network == "virtual" and args.remote_invite:
            raise ValueError("VPN connections use the host's public identifier; --remote-invite is only for LAN connections")
        if not args.server_ip and not args.remote_invite:
            if args.no_prompt:
                raise ValueError("Supply --server-ip with the host's IP or public tunnel identifier")
            args.server_ip = prompt_value("Server IP or public tunnel identifier (printed by Start-Server.bat)",
                                          "127.0.0.1" if args.network == "local" else None)
            if not args.server_ip:
                raise ValueError("The host's public tunnel identifier is required")
        if args.server_ip:
            if args.network == "virtual":
                from virtual import normalize_endpoint
                args.server_ip = normalize_endpoint(args.server_ip)
            else:
                args.server_ip = ipv4(args.server_ip, loopback=True)
                if args.server_ip == "127.0.0.1":
                    args.server_ip = None
                    if args.server_pin:
                        raise ValueError("--server-pin is used with a LAN server IP or public tunnel identifier")
        if args.remote_invite:
            args.remote_invite = resolved(args.remote_invite)
            if not args.remote_invite.is_file():
                raise ValueError(f"Remote invite does not exist: {args.remote_invite}")
        if not 5 <= args.observe_seconds <= 300:
            raise ValueError("--observe-seconds must be between 5 and 300")
        args.trust_file = args.data_dir / "server-pins.json"
        print(f"Client: {args.game}\nNetwork: {args.network}\nServer: {args.server_ip or args.remote_invite or '127.0.0.1'}\n"
              f"Captures: {args.capture_dir if not args.no_capture else 'disabled'}", flush=True)
        command = [sys.executable, "-u", str(ROOT / "launch.py"), "client", "--network", args.network,
                   "--game", str(args.game)]
        if args.observe_seconds != 30:
            command += ["--observe-seconds", str(args.observe_seconds)]
        command += (["--remote-invite", str(args.remote_invite)] if args.remote_invite
                    else ["--server-ip", args.server_ip or "127.0.0.1"])
        if args.server_pin:
            command += ["--server-pin", args.server_pin]
    if args.data_dir != ROOT / "data":
        command += ["--data-dir", str(args.data_dir)]
    if args.state != args.data_dir / "local-menu-server.json":
        command += ["--state", str(args.state)]
    if args.remote_port != 47325:
        command += ["--remote-port", str(args.remote_port)]
    if not args.no_capture:
        command += ["--capture", str(args.capture_dir)]
    print(f"Repeat (PowerShell): {powershell_command(command)}\n", flush=True)
    return args


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        if sys.platform != "win32" or sys.version_info < (3, 11) or struct.calcsize("P") != 8:
            raise ValueError("Use Windows x64 Python 3.11 or newer")
        prepare(args)
        from .split_launch import run_server, run_client
        return asyncio.run(run_server(args) if args.command == "server" else run_client(args)) or 0
    except KeyboardInterrupt:
        print("Stopped.", flush=True)
        return 0
    except (OSError, ValueError, RuntimeError, EOFError) as error:
        print(f"Startup failed: {error}", file=sys.stderr)
        return 2
    except ModuleNotFoundError as error:
        print(f"Missing dependency: {error.name}. Run the batch launcher to prepare Python dependencies.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
