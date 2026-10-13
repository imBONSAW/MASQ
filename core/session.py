"""UI-agnostic MITM session engine.

The console CLI (mitm.py) and the PyQt6 GUI (gui/) are thin shells over this
module: they supply on_log/on_status callbacks and read the tap objects for
summaries. Lifecycle: resolve -> arm data plane -> verify -> save state ->
poison + responder -> taps -> stats loop -> full restore on any exit path.
"""
import json
import os
import sys
import threading
import time

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from core import dataplane, recon, restore as restore_mod  # noqa: E402
from taps.tap_manager import TapManager  # noqa: E402


class SessionError(Exception):
    pass


def state_path():
    for d in ("/run/masq", "/var/tmp/masq"):
        try:
            os.makedirs(d, exist_ok=True)
            p = os.path.join(d, ".probe")
            with open(p, "w") as f:
                f.write("x")
            os.remove(p)
            return os.path.join(d, "state.json")
        except OSError:
            continue
    return None


def pid_alive(pid):
    try:
        os.kill(int(pid), 0)
        return True
    except (OSError, ValueError, TypeError):
        return False


def choose_iface(requested, log=print):
    if requested:
        return requested
    cands = [i for i in recon.list_ifaces()
             if i["ip"] and i["state"] == "up"
             and not i["name"].startswith(("docker", "virbr", "br-"))]
    if len(cands) == 1:
        return cands[0]["name"]
    if cands:
        log("[!] several usable interfaces; pick one with --iface:")
        for i in cands:
            kind = "wifi" if i["wireless"] else "eth "
            log(f"      {i['name']}  {kind} {i['ip']}")
    else:
        log("[!] no usable interface found")
    raise SessionError("no interface selected")


class MitmSession:
    """One MITM session. start() blocks until stop() / Ctrl+C; always restores."""

    def __init__(self, base_dir=BASE, on_log=None, on_status=None, on_event=None):
        self.base_dir = base_dir
        self.on_log = on_log or print
        self.on_status = on_status or (lambda s: None)
        self.on_event = on_event or (lambda e: None)
        self.stop_event = threading.Event()
        self.taps = None
        self.engine = None
        self.dp = None
        self.st = None
        self.sp = None
        self.counts = (None, None, None, None)

    # ---- lifecycle -----------------------------------------------------------
    def start(self, target, iface=None, tap_names=None,
              refresh_interval=10.0, stats_interval=5.0,
              live_interval=1.0):
        log = self.on_log
        sp = state_path()

        # clean up after any previous crashed run
        if sp and os.path.exists(sp):
            try:
                with open(sp) as f:
                    old = json.load(f)
                if old.get("pid") and pid_alive(old["pid"]):
                    raise SessionError(f"already running (pid {old['pid']}); use 'stop' first")
                log("[*] stale state from a previous run; restoring it first ...")
                restore_mod.restore_from_state(old)
            except (OSError, ValueError):
                pass

        from core import position
        iface = choose_iface(iface, log)
        my_ip, my_mac = recon.iface_info(iface)
        gw_ip = recon.default_gateway(iface)
        if not (my_ip and my_mac):
            raise SessionError(f"interface {iface} has no usable IPv4 address")
        if not gw_ip:
            raise SessionError(f"interface {iface} has no IPv4 gateway; nothing to position against")
        if recon.is_wireless(iface):
            log("[i] wireless interface: each packet crosses the air twice; "
                "nothing breaks, but a wired attacker NIC is faster")

        log(f"[*] resolving real MACs (target={target}, gw={gw_ip}) on {iface} ...")
        target_mac = position.resolve_mac(target, iface)
        gw_mac = position.resolve_mac(gw_ip, iface)
        if not gw_mac:
            raise SessionError(f"gateway {gw_ip} did not answer ARP")
        if not target_mac:
            raise SessionError(f"target {target} did not answer ARP "
                               f"(offline, or AP client-isolation blocks us)")
        log(f"    target   {target}  {target_mac}")
        log(f"    gateway  {gw_ip}  {gw_mac}")
        log(f"    us       {my_ip}  {my_mac}")

        # data plane FIRST — forwarding must be fully live before the first ARP
        log("[*] arming data plane (ip_forward, sysctls, policy routing) ...")
        dp = dataplane.DataPlane(iface, gw_ip, target)
        try:
            dp.arm()
        except RuntimeError as e:
            raise SessionError(f"data plane failed to arm (ARP untouched): {e}")
        ok, problems = dp.verify()
        if not ok:
            dp.disarm()
            for p in problems:
                log(f"    [!] {p}")
            raise SessionError("data plane failed verification; aborted without touching ARP")
        for p in problems:
            log(f"    [!] {p}")

        st = {
            "pid": os.getpid(),
            "iface": iface,
            "my_ip": my_ip, "my_mac": my_mac,
            "gw_ip": gw_ip, "gw_mac": gw_mac,
            "target_ip": target, "target_mac": target_mac,
            "sysctls": dp.saved_sysctls,
            "ipt_inserted": dp._ipt_inserted,
            "cnt_inserted": dp._cnt_inserted,
            "started": time.time(),
            "taps": tap_names or [],
        }
        if sp:
            with open(sp, "w") as f:
                json.dump(st, f, indent=2)
        self.st, self.dp, self.sp = st, dp, sp

        self.engine = position.PositionEngine(iface, st, refresh_interval=refresh_interval,
                                              log=log)
        self.taps = TapManager(tap_names or [], iface, target, target_mac,
                               self.base_dir, log=log)

        try:
            self.engine.start()
            self.taps.start()
        except Exception as e:
            try:
                self.engine.stop()
            except Exception:
                pass
            self._cleanup()
            raise SessionError(f"failed to take position: {e}")

        log(f"[*] positioned between {target} and {gw_ip}. ctrl+c (or stop) restores everything.")
        ts = time.strftime("%Y%m%d_%H%M%S", time.localtime(st["started"]))
        self.live_path = os.path.join(self.base_dir, "logs", f"live_{ts}.json")
        try:
            os.makedirs(os.path.dirname(self.live_path), exist_ok=True)
        except OSError:
            self.live_path = None
        tick = stats_interval
        try:
            if live_interval and live_interval > 0:
                tick = min(stats_interval, live_interval)
        except TypeError:
            pass
        start_m = time.monotonic()
        last_status, last_live = start_m, start_m
        try:
            while not self.stop_event.wait(tick):
                now_m = time.monotonic()
                if live_interval and live_interval > 0 and now_m - last_live >= live_interval:
                    try:
                        self._write_live()
                    except OSError:
                        pass
                    last_live = now_m
                if now_m - last_status >= stats_interval:
                    self.on_status(self._status_snapshot())
                    last_status = now_m
        except KeyboardInterrupt:
            pass
        finally:
            try:
                if getattr(self, "live_path", None):
                    self._write_live(final=True)
            except OSError:
                pass
            self._cleanup()
        return self

    def stop(self):
        self.stop_event.set()

    def _emit_event(self, ev):
        ev = dict(ev or {})
        ev.setdefault("ts", time.strftime("%H:%M:%S"))
        try:
            self.on_event(ev)
        except Exception:
            pass

    # ---- introspection ----------------------------------------------------------
    def _status_snapshot(self):
        up = down = up_b = down_b = None
        if self.dp:
            up, up_b, down, down_b = self.dp.counters()
        eng = self.engine
        return {
            "elapsed": time.time() - self.st["started"] if self.st else 0.0,
            "up": up, "up_b": up_b, "down": down, "down_b": down_b,
            "counter_source": self.counter_source(),
            "arps": getattr(eng, "arps_answered", 0),
            "refreshes": getattr(eng, "refreshes", 0),
            "heals": getattr(eng, "heal_fixes", 0),
            "mac_changes": getattr(eng, "mac_changes", 0),
            "target_mac": self.st["target_mac"] if self.st else None,
            "iface": self.st["iface"] if self.st else None,
        }

    def counter_source(self):
        dp = getattr(self, "dp", None)
        if dp is None:
            return "none"
        if getattr(dp, "have_nft", False):
            return "nft"
        if getattr(dp, "_cnt_inserted", False):
            return "iptables"
        if getattr(dp, "_iface_base", None) is not None:
            return "iface-total"
        return "none"

    def snapshot_full(self, final=False):
        """Machine-readable session state (live.json / summary.json)."""
        snap = self._status_snapshot()
        st = self.st or {}
        dns = conn = pcap = None
        try:
            taps = getattr(self, "taps", None)
            if taps is not None:
                d = taps.get("dns")
                c = taps.get("conn")
                p = taps.get("pcap")
                if d is not None:
                    s = d.summary()
                    s["addr_map"] = dict(getattr(d, "addr_map", {}))
                    dns = s
                if c is not None:
                    conn = c.summary()
                if p is not None:
                    pcap = p.summary()
        except Exception:
            pass
        return {
            "v": 1,
            "final": bool(final),
            "ts": time.strftime("%H:%M:%S"),
            "started": st.get("started"),
            "elapsed": snap.get("elapsed", 0.0),
            "iface": st.get("iface"),
            "target": {"ip": st.get("target_ip"), "mac": st.get("target_mac")},
            "gateway": {"ip": st.get("gw_ip"), "mac": st.get("gw_mac")},
            "forwarded": {
                "up_pkts": snap.get("up"), "up_bytes": snap.get("up_b"),
                "down_pkts": snap.get("down"), "down_bytes": snap.get("down_b"),
                "source": snap.get("counter_source", "none"),
            },
            "arp": {
                "answered": snap.get("arps", 0),
                "refreshes": snap.get("refreshes", 0),
                "heals": snap.get("heals", 0),
                "mac_changes": snap.get("mac_changes", 0),
            },
            "taps": {"dns": dns, "conn": conn, "pcap": pcap},
            "live_path": getattr(self, "live_path", None),
        }

    def _write_live(self, final=False):
        path = getattr(self, "live_path", None)
        if not path:
            return
        data = self.snapshot_full(final=final)
        tmp = path + ".tmp"
        with open(tmp, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, path)

    def _cleanup(self):
        log = self.on_log
        log("[*] shutting down — restoring ARP and data plane ...")
        if self.taps:
            self.taps.stop()
        if self.engine:
            self.engine.stop()
        if self.dp and self.st:
            self.counts = self.dp.counters()   # read before disarm removes the table
            restore_mod.restore_arp(self.st)
            self.dp.disarm()
        if self.sp and os.path.exists(self.sp):
            os.remove(self.sp)
        log("[*] done. target and gateway are back on their real path.")
