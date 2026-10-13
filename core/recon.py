"""Passive-ish network survey: who's who, and can we even sit in the middle."""
import os
import platform
import re
import subprocess


def _run(cmd, timeout=15):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired):
        return 127, "", ""


def default_iface():
    rc, out, _ = _run(["ip", "route", "show", "default"])
    if rc == 0 and out:
        m = re.search(r"dev (\S+)", out)
        if m:
            return m.group(1)
    return None


def default_gateway(iface=None):
    # Android policy routing keeps the real default in table 1012, not main.
    for extra in ([], ["table", "1012"], ["table", "all"]):
        cmd = ["ip", "route", "show", "default"] + extra
        if iface:
            cmd += ["dev", iface]
        rc, out, _ = _run(cmd)
        if rc == 0 and out:
            m = re.search(r"via (\S+)", out)
            if m:
                return m.group(1)
    return None


def iface_ip(iface):
    rc, out, _ = _run(["ip", "-4", "addr", "show", "dev", iface])
    if rc == 0:
        m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)", out)
        if m:
            return m.group(1)
    return None


def iface_mac(iface):
    try:
        with open(f"/sys/class/net/{iface}/address") as f:
            return f.read().strip()
    except OSError:
        return None


def iface_info(iface):
    return iface_ip(iface), iface_mac(iface)


def is_wireless(iface):
    return (os.path.isdir(f"/sys/class/net/{iface}/wireless")
            or os.path.exists(f"/sys/class/net/{iface}/phy80211"))


def list_ifaces():
    out = []
    try:
        names = [n for n in os.listdir("/sys/class/net") if n != "lo"]
    except OSError:
        names = []
    for n in sorted(names):
        try:
            with open(f"/sys/class/net/{n}/operstate") as f:
                state = f.read().strip()
        except OSError:
            state = "?"
        out.append({
            "name": n,
            "ip": iface_ip(n),
            "mac": iface_mac(n),
            "state": state,
            "wireless": is_wireless(n),
        })
    return out


def survey(iface=None, target=None, scan=False):
    info = {
        "host": platform.node(),
        "kernel": platform.release(),
        "ifaces": list_ifaces(),
        "default_iface": iface or default_iface(),
    }
    chosen = iface or info["default_iface"]
    if chosen:
        info["gateway"] = default_gateway(chosen)
        if info["gateway"]:
            from core.position import resolve_mac  # scapy, imported lazily
            info["gateway_mac"] = resolve_mac(info["gateway"], chosen, timeout=2.0)
    if chosen and target:
        from core.position import resolve_mac
        mac = resolve_mac(target, chosen, timeout=2.0)
        rc, _, _ = _run(["ping", "-c", "1", "-W", "1", target])
        info["target"] = {
            "ip": target,
            "mac": mac,
            "ping_ok": rc == 0,
            "l2_reachable": mac is not None,
        }
    if scan and chosen:
        info["scan"] = arp_scan(chosen)
    return info


def arp_scan(iface):
    """Opt-in ARP sweep of our /24. Sends broadcast ARP requests — visible on the LAN."""
    net = iface_ip(iface)
    if not net:
        return []
    base = ".".join(net.split(".")[:3])
    from scapy.all import ARP, Ether, srp, conf
    conf.verb = 0
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, pdst=[f"{base}.{i}" for i in range(1, 255)])
    ans, _ = srp(pkt, iface=iface, timeout=2, inter=0.05, verbose=0)
    hosts, seen = [], set()
    for _s, r in ans:
        ip, mac = r[ARP].psrc, r[Ether].src
        if ip not in seen:
            seen.add(ip)
            hosts.append({"ip": ip, "mac": mac})
    hosts.sort(key=lambda h: tuple(int(x) for x in h["ip"].split(".")))
    return hosts


def print_report(info):
    print(f"host      : {info['host']}  (kernel {info['kernel']})")
    print("ifaces    :")
    for i in info["ifaces"]:
        kind = "wifi" if i["wireless"] else "eth "
        print(f"  {i['name']:<10} {i['state']:<9} {kind}  {i['ip'] or '-':<16} {i['mac'] or '-'}")
    if info.get("gateway"):
        print(f"default   : {info['default_iface']}  via {info['gateway']}"
              f"  ({info.get('gateway_mac') or 'no ARP reply'})")
    t = info.get("target")
    if t:
        print(f"target    : {t['ip']}")
        print(f"  mac     : {t['mac'] or 'NO REPLY'}")
        print(f"  ping    : {'ok' if t['ping_ok'] else 'no reply'}")
        if t["l2_reachable"]:
            print("  verdict : target answers ARP -> no client isolation between us; MITM is possible")
        else:
            print("  verdict : no ARP reply -> target offline, OR AP client-isolation blocks")
            print("            client-to-client frames. With isolation, a client cannot position")
            print("            itself in the middle (use a wired attacker NIC or the gateway).")
    s = info.get("scan")
    if s is not None:
        print(f"live hosts ({len(s)}):")
        for h in s:
            print(f"  {h['ip']:<16} {h['mac']}")
