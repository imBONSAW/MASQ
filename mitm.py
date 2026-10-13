#!/usr/bin/env python3
"""MASQ — transparent, kernel-speed MITM positioning for lab networks.

Phase-1 scope:
  * takeover without a single dropped packet on the target
  * transparent L3 forwarding in the kernel (near-zero added latency)
  * optional passive taps: dns / conn / pcap / live

Phase-2:  --gui opens a PyQt6 console (live packet view + live summary).
          The engine is the same; the GUI is just another shell (Zenmap-style).

Use only on networks you own or are explicitly authorized to test.
"""
import argparse
import json
import os
import signal
import sys
import threading
import time

BASE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE)

from core import dataplane, recon  # noqa: E402
from core.session import (SessionError, choose_iface, pid_alive,  # noqa: E402
                          state_path)

__version__ = "2.0.0"

try:
    from rich import box
    from rich.console import Console
    from rich.live import Live
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.table import Table
    _RICH = True
    _console = Console()
except Exception:
    _RICH = False
    _console = None

PLAIN = False  # set by --plain; forces classic text output

# single CLI palette (matches gui/theme.py intent):
# [*] ok -> green, [i] log -> blue, [!] error -> red, live status -> cyan
_STYLE = {"ok": "green", "log": "bright_blue", "err": "bold red",
          "live": "cyan", "dim": "dim", "title": "bold white"}
_PROTO_STYLE = {"DNS": "magenta", "TCP": "bright_blue", "UDP": "cyan",
                "ICMP": "yellow", "ARP": "dark_orange", "OTHER": "white"}


def _pkt_line(pkt):
    """One tshark-style line + style, no Qt (phone-safe)."""
    try:
        from scapy.layers.dns import DNS
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.l2 import ARP, Ether
    except Exception:
        return str(pkt.summary()) if hasattr(pkt, "summary") else str(pkt), "white"
    try:
        ts = time.strftime("%H:%M:%S", time.localtime(float(getattr(pkt, "time", time.time()))))
    except Exception:
        ts = "--:--:--"
    try:
        length = len(bytes(pkt))
    except Exception:
        try:
            length = int(getattr(pkt, "wirelen", 0) or 0)
        except Exception:
            length = 0
    try:
        if pkt.haslayer(ARP):
            a = pkt[ARP]
            op = "req" if int(a.op) == 1 else "rep" if int(a.op) == 2 else f"op{a.op}"
            return (f"{ts} ARP  {a.psrc} -> {a.pdst} {op} ({length})", _PROTO_STYLE["ARP"])
        if pkt.haslayer(IP):
            src, dst = str(pkt[IP].src), str(pkt[IP].dst)
            if pkt.haslayer(DNS):
                d = pkt[DNS]
                try:
                    q = d.qd.qname.decode(errors="replace").rstrip(".") if d.qd else "?"
                except Exception:
                    q = "?"
                direction = "resp" if int(d.qr) else "query"
                return (f"{ts} DNS  {src} -> {dst} {direction} {q} ({length})",
                        _PROTO_STYLE["DNS"])
            if pkt.haslayer(TCP):
                tc = pkt[TCP]
                return (f"{ts} TCP  {src}:{tc.sport} -> {dst}:{tc.dport} "
                        f"[{tc.flags}] seq={tc.seq} ({length})", _PROTO_STYLE["TCP"])
            if pkt.haslayer(UDP):
                u = pkt[UDP]
                return (f"{ts} UDP  {src}:{u.sport} -> {dst}:{u.dport} ({length})",
                        _PROTO_STYLE["UDP"])
            if pkt.haslayer(ICMP):
                ic = pkt[ICMP]
                return (f"{ts} ICMP {src} -> {dst} type={ic.type} code={ic.code} ({length})",
                        _PROTO_STYLE["ICMP"])
            try:
                proto = str(pkt.lastlayer().name).upper()
            except Exception:
                proto = "OTHER"
            return (f"{ts} {proto} {src} -> {dst} ({length})", _PROTO_STYLE["OTHER"])
        if pkt.haslayer(Ether):
            return (f"{ts} L2   {pkt[Ether].src} -> {pkt[Ether].dst} ({length})",
                    _PROTO_STYLE["OTHER"])
    except Exception:
        pass
    try:
        return (str(pkt.summary()), "white")
    except Exception:
        return ("undissected packet", "white")


def _packet_stream(session_holder, stop_ev):
    while not stop_ev.is_set():
        try:
            s = session_holder.get("s")
            tap = None
            if s is not None and getattr(s, "taps", None) is not None:
                tap = s.taps.get("live")
            if tap is None:
                stop_ev.wait(0.25)
                continue
            for _, pkt in tap.take_new(50):
                try:
                    line, style = _pkt_line(pkt)
                except Exception:
                    continue
                if _RICH and not PLAIN and _console:
                    _console.print(line, style=style)
                else:
                    print(line)
        except Exception:
            pass
        stop_ev.wait(0.25)


def _cprint(msg, kind="ok"):
    if _RICH and not PLAIN and _console:
        _console.print(msg, style=_STYLE.get(kind, "white"))
    else:
        print(msg)


def _log(msg):
    s = str(msg)
    if s.startswith("[!]"):
        _cprint(s, "err")
    elif s.startswith("[i]"):
        _cprint(s, "log")
    elif s.startswith("[*]"):
        _cprint(s, "ok")
    else:
        _cprint(s, "ok")


def require_root():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        sys.exit("[!] needs root:  sudo python3 mitm.py <cmd>")


def cmd_recon(args):
    require_root()
    info = recon.survey(iface=args.iface, target=args.target, scan=args.scan)
    if args.json:
        print(json.dumps(info, indent=2))
    else:
        recon.print_report(info)


def cmd_selftest(args):
    """Arm + verify + disarm the data plane. ARP is never touched."""
    require_root()
    try:
        iface = choose_iface(args.iface)
    except SessionError as e:
        sys.exit(f"[!] {e}")
    gw = recon.default_gateway(iface)
    if not gw:
        sys.exit(f"[!] interface {iface} has no IPv4 gateway")
    target = args.target or gw  # counters only; no ARP involved anywhere
    print(f"[*] selftest on {iface} (gw={gw}) — ARP is NOT touched")
    dp = dataplane.DataPlane(iface, gw, target)
    dp.arm()
    ok, problems = dp.verify()
    up, _ub, down, _db = dp.counters()
    print(f"[*] data plane armed; verify: {'OK' if ok else 'FAILED'}")
    for p in problems:
        print(f"    [!] {p}")
    print(f"[*] counters right now: up={up} down={down} (expected 0/0)")
    time.sleep(2)
    dp.disarm()
    print("[*] disarmed, sysctls/routes/rules restored. " +
          ("selftest passed." if ok else "see problems above."))


def _print_stats(s):
    mins = s["elapsed"] / 60
    up = s["up"] if s["up"] is not None else "?"
    down = s["down"] if s["down"] is not None else "?"
    src = s.get("counter_source", "")
    src_tag = f" [{src}]" if src and src != "nft" else ""
    extra = f"   mac changes: {s['mac_changes']}" if s["mac_changes"] else ""
    line = (f"    [{mins:6.1f}m] forwarded pkts  target->gw: {up:>10}   "
            f"gw->target: {down:>10}{src_tag}   arps: {s['arps']}   "
            f"refreshes: {s['refreshes']}   heals fixed: {s['heals']}{extra}")
    if s["heals"] == 0:
        _cprint(line, "live")
    else:
        _cprint(line, "err")


def _human(n):
    if n is None:
        return "?"
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024.0 or unit == "TB":
            return f"{int(f)} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024.0


def _rich_tables(console, dns_tap, conn_tap, pcap_tap):
    """Pretty end-of-session tables. Plain-text file is still saved for logs."""
    if dns_tap:
        s = dns_tap.summary()
        if not s["total"]:
            console.print("DNS  no queries — add --tap dns", style="dim")
        else:
            t = Table(title=f"DNS  {s['total']:,} queries / {s['unique']:,} unique",
                      show_header=True, header_style="bold bright_blue",
                      border_style="blue", title_style="bold white",
                      box=box.ROUNDED, pad_edge=False)
            t.add_column("domain", overflow="fold", style="white")
            t.add_column("hits", justify="right", style="green")
            for d, c in s["top_domains"][:12]:
                t.add_row(d, f"{c:,}")
            console.print(t)
    if conn_tap:
        s = conn_tap.summary()
        if not s["tcp"] and not s["udp"]:
            console.print("connections  none — add --tap conn", style="dim")
        else:
            t = Table(title=f"connections  tcp {s['tcp']:,} / udp {s['udp']:,}",
                      show_header=True, header_style="bold bright_blue",
                      border_style="blue", title_style="bold white",
                      box=box.ROUNDED, pad_edge=False)
            t.add_column("service", style="white")
            t.add_column("hits", justify="right", style="green")
            for label, c in s["services"][:8]:
                t.add_row(label, f"{c:,}")
            console.print(t)
            if s["top_dsts"]:
                amap = {}
                try:
                    amap = getattr(dns_tap, "addr_map", {}) if dns_tap else {}
                except Exception:
                    amap = {}
                t = Table(title="destinations",
                          show_header=True, header_style="bold bright_blue",
                          border_style="blue", title_style="bold white",
                          box=box.ROUNDED, pad_edge=False)
                t.add_column("ip", style="white")
                t.add_column("hint", overflow="fold", style="dim")
                t.add_column("hits", justify="right", style="green")
                for ip, c in s["top_dsts"][:10]:
                    t.add_row(ip, amap.get(ip, "(no dns hint)"), f"{c:,}")
                console.print(t)
    if pcap_tap:
        try:
            s = pcap_tap.summary()
            console.print(f"capture  {s['path']} ({_human(s['size'])})", style="dim")
        except Exception:
            pass


class _LiveBoard:
    """In-place live dashboard (rich.Live). Falls back to line logs when dumb."""

    def __init__(self, session, tap_names):
        self.session = session
        self.tap_names = tap_names or []
        self.live = None

    def _table(self, s):
        t = Table(show_header=False, box=box.ROUNDED, border_style="blue",
                  pad_edge=False, padding=(0, 1))
        t.add_column("k", style="dim", width=12)
        t.add_column("v", style="white")
        mins = s["elapsed"] / 60
        up = f"{s['up']:,}" if s["up"] is not None else "?"
        down = f"{s['down']:,}" if s["down"] is not None else "?"
        src = s.get("counter_source", "")
        if src and src != "nft":
            up += f" [{src}]"
            down += f" [{src}]"
        t.add_row("elapsed", f"{mins:5.1f}m")
        t.add_row("up", up)
        t.add_row("down", down)
        t.add_row("arp", f"ans {s['arps']}  ref {s['refreshes']}  heal {s['heals']}")
        try:
            taps = getattr(self.session, "taps", None)
            if taps is not None:
                d = taps.get("dns")
                c = taps.get("conn")
                if d is not None:
                    ds = d.summary()
                    t.add_row("dns", f"{ds['total']:,} q / {ds['unique']:,} dom")
                if c is not None:
                    cs = c.summary()
                    t.add_row("conn", f"tcp {cs['tcp']:,}  udp {cs['udp']:,}")
        except Exception:
            pass
        return t

    def __enter__(self):
        self.live = Live(self._table({"elapsed": 0, "up": 0, "down": 0,
                                       "arps": 0, "refreshes": 0, "heals": 0,
                                       "mac_changes": 0}),
                         console=_console, refresh_per_second=1)
        self.live.__enter__()
        return self

    def __exit__(self, *a):
        try:
            self.live.__exit__(*a)
        except Exception:
            pass

    def update(self, s):
        try:
            self.live.update(self._table(s))
        except Exception:
            pass

    def log(self, msg):
        _log(msg)


def _print_summary(session):
    """End-of-session report: totals, protocol mix, websites, destinations."""
    st, counts, taps = session.st, session.counts, session.taps
    up_p, up_b, down_p, down_b = counts
    dur = int(time.time() - st["started"]) if st else 0

    def cnt(p, b):
        return "n/a" if p is None else f"{p:,} pkts ({_human(b)})"

    lines = ["", "=" * 64, " SESSION SUMMARY", "=" * 64]
    lines.append(f" duration        : {dur // 60}m {dur % 60}s")
    lines.append(f" forwarded       : target->gw {cnt(up_p, up_b)}   "
                 f"gw->target {cnt(down_p, down_b)}")

    dns_tap = taps.get("dns") if taps else None
    conn_tap = taps.get("conn") if taps else None
    pcap_tap = taps.get("pcap") if taps else None

    if dns_tap:
        s = dns_tap.summary()
        base = (f" dns lookups     : {s['total']} queries, "
                f"{s['unique']} unique domains")
        if s["qtypes"]:
            qt = ", ".join(f"{k}:{v}" for k, v in s["qtypes"].items())
            base += f"  [{qt}]"
        lines.append(base)
        if s["top_domains"]:
            lines.append(" top domains:")
            for d, c in s["top_domains"]:
                lines.append(f"   {d:<44} {c:>6}")

    if conn_tap:
        s = conn_tap.summary()
        lines.append(f" new connections : tcp {s['tcp']}   udp flows {s['udp']}")
        if s["services"]:
            lines.append(" services:")
            for label, c in s["services"]:
                lines.append(f"   {label:<44} {c:>6}")
        if s["top_dsts"]:
            amap = getattr(dns_tap, "addr_map", {}) if dns_tap else {}
            lines.append(" top destinations:")
            for ip, c in s["top_dsts"]:
                hint = amap.get(ip, "(no dns hint)")
                lines.append(f"   {ip:<16} {hint:<28} {c:>6}")

    if pcap_tap:
        s = pcap_tap.summary()
        size = _human(s["size"]) if s["size"] is not None else "?"
        lines.append(f" capture         : {s['path']} ({size})")

    if not taps or not taps.active:
        lines.append(" (no taps were active — add --tap dns/conn/pcap for content stats)")

    lines.append("=" * 64)
    text = "\n".join(lines)
    if _RICH and not PLAIN and _console:
        _console.print(Rule(f"SESSION SUMMARY  {dur // 60}m {dur % 60}s", style="green"))
        _console.print(f"forwarded  target->gw {cnt(up_p, up_b)}   gw->target {cnt(down_p, down_b)}",
                       style="white")
        try:
            _rich_tables(_console, dns_tap, conn_tap, pcap_tap)
        except Exception:
            print(text)
    else:
        print(text)
    try:
        logs = os.path.join(BASE, "logs")
        os.makedirs(logs, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime(st["started"]))
        path = os.path.join(logs, f"summary_{ts}.txt")
        with open(path, "w") as f:
            f.write(text + "\n")
        print(f" [*] summary saved -> {path}")
    except OSError:
        pass
    try:
        data = session.snapshot_full(final=True)
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime(st["started"]))
        jpath = os.path.join(BASE, "logs", f"summary_{ts}.json")
        with open(jpath, "w") as f:
            json.dump(data, f, indent=2)
        print(f" [*] summary json  -> {jpath}")
        if getattr(session, "live_path", None):
            print(f" [*] live json     -> {session.live_path}")
    except (OSError, ValueError, AttributeError):
        pass


def cmd_start(args):
    require_root()
    if args.gui:
        from gui.app import run_gui
        run_gui(args)
        return

    global PLAIN
    PLAIN = bool(getattr(args, "plain", False))
    stream = bool(getattr(args, "show_packets", False))
    tap_names = list(args.tap or [])
    if stream and "live" not in tap_names:
        tap_names.append("live")
    # packet stream replaces the dashboard table (tshark-style, no flicker)
    use_live = bool(_RICH and not PLAIN and sys.stdout.isatty() and not stream)
    from core.session import MitmSession
    if use_live:
        _console.print(Panel(f"MASQ {__version__}  —  transparent positioning for lab networks",
                             style="green", box=box.ROUNDED))
        _console.print("Use only on networks you own or are explicitly authorized to test.",
                       style="bold red")
        cfg = Table(show_header=False, box=None, pad_edge=False, padding=(0, 1))
        cfg.add_column("k", style="dim")
        cfg.add_column("v", style="white")
        cfg.add_row("target", str(args.target))
        cfg.add_row("iface", str(args.iface or "auto"))
        cfg.add_row("taps", ", ".join(tap_names) or "none")
        if stream:
            cfg.add_row("view", "packets (live stream)")
        _console.print(Panel(cfg, title="session", border_style="blue", box=box.ROUNDED))
    else:
        _cprint("[*] starting session — ctrl+c restores everything.", "ok")
    session_holder = {}
    stop_stream = threading.Event()
    stream_thread = None

    def _make_session(log_fn):
        s = MitmSession(BASE, on_log=log_fn)
        session_holder["s"] = s
        return s

    def _stream_start():
        nonlocal stream_thread
        if stream:
            stream_thread = threading.Thread(target=_packet_stream,
                                             args=(session_holder, stop_stream),
                                             name="cli-packet-stream", daemon=True)
            stream_thread.start()

    def _stream_stop():
        stop_stream.set()
        try:
            if stream_thread is not None:
                stream_thread.join(timeout=1.0)
        except Exception:
            pass

    if use_live:
        tmp = _make_session(lambda m: _log(m))
        board = _LiveBoard(tmp, tap_names)
        with board:
            tmp.on_status = board.update
            signal.signal(signal.SIGINT, lambda *_: tmp.stop())
            signal.signal(signal.SIGTERM, lambda *_: tmp.stop())
            try:
                tmp.start(target=args.target, iface=args.iface, tap_names=tap_names,
                          refresh_interval=args.refresh_interval,
                          stats_interval=args.stats_interval)
            except SessionError as e:
                _cprint(f"[!] {e}", "err")
                sys.exit(1)
        _print_summary(tmp)
        return

    session = _make_session(_log)
    signal.signal(signal.SIGINT, lambda *_: session.stop())
    signal.signal(signal.SIGTERM, lambda *_: session.stop())
    session.on_status = _print_stats
    _stream_start()
    try:
        session.start(target=args.target, iface=args.iface, tap_names=tap_names,
                      refresh_interval=args.refresh_interval,
                      stats_interval=args.stats_interval)
    except SessionError as e:
        _stream_stop()
        sys.exit(f"[!] {e}")
    _stream_stop()
    _print_summary(session)


def cmd_status(args):
    sp = state_path()
    if not sp or not os.path.exists(sp):
        print("[*] no session state found (not running, nothing to restore)")
        return
    with open(sp) as f:
        st = json.load(f)
    alive = pid_alive(st.get("pid", 0))
    mins = (time.time() - st.get("started", time.time())) / 60
    print(f"session : pid={st.get('pid')} alive={alive} uptime={mins:.1f}m")
    print(f"  iface = {st['iface']}  target = {st['target_ip']} ({st['target_mac']})")
    print(f"  gw    = {st['gw_ip']} ({st['gw_mac']})")
    print(f"  taps  = {st.get('taps') or 'none'}")
    if alive:
        dp = dataplane.DataPlane(st["iface"], st["gw_ip"], st["target_ip"])
        up, _ub, down, _db = dp.counters()
        print(f"  forwarded pkts: target->gw={up}  gw->target={down}")


def cmd_stop(args):
    sp = state_path()
    if not sp or not os.path.exists(sp):
        print("[*] nothing to stop")
        return
    with open(sp) as f:
        st = json.load(f)
    pid = st.get("pid")
    if pid and pid_alive(pid):
        os.kill(int(pid), signal.SIGINT)
        print(f"[*] SIGINT sent to pid {pid}; it restores ARP on its way out")
        for _ in range(100):
            if not os.path.exists(sp):
                print("[*] clean shutdown complete")
                return
            time.sleep(0.2)
        print("[!] still shutting down; check 'sudo python3 mitm.py status'")
    else:
        cmd_restore(args)


def cmd_restore(args):
    from core import restore as restore_mod
    sp = state_path()
    if not sp or not os.path.exists(sp):
        print("[*] no state file; nothing to restore")
        return
    with open(sp) as f:
        st = json.load(f)
    print("[*] forcing restore from saved state ...")
    restore_mod.restore_from_state(st)
    os.remove(sp)
    print("[*] ARP entries and data plane restored")


def main():
    ap = argparse.ArgumentParser(
        prog="mitm.py", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("recon", help="survey the network before doing anything")
    p.add_argument("--iface")
    p.add_argument("--target", help="also ARP-probe this host (checks WiFi client isolation)")
    p.add_argument("--scan", action="store_true",
                   help="ARP-sweep the whole /24 (visible on the LAN)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_recon)

    p = sub.add_parser("start", help="take position between target and gateway")
    p.add_argument("--target", required=True)
    p.add_argument("--iface")
    p.add_argument("-g", "--gui", action="store_true",
                   help="open the PyQt6 console (live packets + live summary)")
    p.add_argument("--tap", action="append", dest="tap",
                   help="passive tap: dns | conn | pcap[=path]  (repeatable)")
    p.add_argument("--refresh-interval", type=float, default=10.0,
                   help="ARP re-assert interval in seconds (default 10, jittered)")
    p.add_argument("--stats-interval", type=float, default=5.0)
    p.add_argument("--plain", action="store_true",
                   help="plain text output (disable rich tables/colors)")
    p.add_argument("--show-packets", action="store_true",
                   help="live tshark-style packet stream (auto-enables live tap)")
    p.set_defaults(fn=cmd_start)

    p = sub.add_parser("status", help="show the running session")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("stop", help="stop the session and restore everything")
    p.set_defaults(fn=cmd_stop)

    p = sub.add_parser("restore", help="force-restore from the last session's saved state")
    p.set_defaults(fn=cmd_restore)

    p = sub.add_parser("selftest", help="arm+verify+disarm the data plane (no ARP touched)")
    p.add_argument("--iface")
    p.add_argument("--target", help="target IP for counters (default: gateway)")
    p.set_defaults(fn=cmd_selftest)

    args = ap.parse_args()
    args.fn(args)


if __name__ == "__main__":
    main()
