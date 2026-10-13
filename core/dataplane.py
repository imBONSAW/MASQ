"""Kernel-speed transparent data plane.

Everything here is armed BEFORE the first ARP packet is sent, so the target
never sees a dropped packet during takeover. Traffic never touches Python:
the kernel forwards it; this module only prepares the kernel and counts it.
"""
import re
import shutil
import subprocess


def _run(cmd, input_text=None, timeout=10):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True,
                           input=input_text, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except (OSError, subprocess.TimeoutExpired) as e:
        return 127, "", str(e)


class DataPlane:
    TABLE = "masq"    # nftables inet table (accept + per-direction counters)
    RT_TABLE = 111         # policy-routing table used only for target traffic
    RT_PRIO = 3000

    SYSCTLS = [
        ("net.ipv4.ip_forward", "1"),
        ("net.ipv4.conf.all.send_redirects", "0"),
        ("net.ipv4.conf.all.accept_redirects", "0"),
        ("net.ipv4.conf.{iface}.send_redirects", "0"),
        ("net.ipv4.conf.{iface}.accept_redirects", "0"),
        # loose reverse-path filter: MITM traffic enters and leaves the same iface
        ("net.ipv4.conf.{iface}.rp_filter", "2"),
    ]

    def __init__(self, iface, gw_ip, target_ip):
        self.iface = iface
        self.gw_ip = gw_ip
        self.target_ip = target_ip
        self.saved_sysctls = {}
        self._ipt_inserted = False
        self._cnt_inserted = False
        self._iface_base = None
        self.have_nft = shutil.which("nft") is not None
        self.have_ipt = shutil.which("iptables") is not None

    def _read_iface(self):
        """(rx_bytes, rx_pkts, tx_bytes, tx_pkts) for self.iface, or Nones."""
        try:
            with open("/proc/net/dev") as f:
                for line in f:
                    if ":" not in line:
                        continue
                    name, _, vals = line.partition(":")
                    if name.strip() != self.iface:
                        continue
                    parts = vals.split()
                    if len(parts) < 10:
                        return None, None, None, None
                    rx_b, rx_p = int(parts[0]), int(parts[1])
                    tx_b, tx_p = int(parts[8]), int(parts[9])
                    return rx_b, rx_p, tx_b, tx_p
        except (OSError, ValueError):
            pass
        return None, None, None, None

    # ---- sysctl helpers ------------------------------------------------------
    def _read(self, name):
        try:
            with open("/proc/sys/" + name.replace(".", "/")) as f:
                return f.read().strip()
        except OSError:
            return None

    def _write(self, name, value):
        with open("/proc/sys/" + name.replace(".", "/"), "w") as f:
            f.write(value)

    # ---- arm / disarm ----------------------------------------------------------
    def arm(self):
        for templ, value in self.SYSCTLS:
            name = templ.format(iface=self.iface)
            cur = self._read(name)
            if cur is not None and cur != value:
                self.saved_sysctls[name] = cur
                self._write(name, value)
        if self.have_nft:
            try:
                self._arm_nft()
            except RuntimeError:
                # Android kernels often ship the nft binary without kernel
                # support (netlink cache init fails). Fall back to
                # iptables-only mode: forwarding still works, counters are n/a.
                self.have_nft = False
        if self.have_ipt:
            self._arm_ipt()
        self._arm_policy_routing()
        # baseline for iface-total fallback (Android: no per-target counters)
        rx_b, rx_p, tx_b, tx_p = self._read_iface()
        if rx_p is not None:
            self._iface_base = (rx_b, rx_p, tx_b, tx_p)

    def _arm_nft(self):
        _run(["nft", "delete", "table", "inet", self.TABLE])  # ignore "absent"
        script = (
            f"add table inet {self.TABLE}\n"
            f"add chain inet {self.TABLE} qmfwd "
            f"{{ type filter hook forward priority -5 ; }}\n"
            f"add rule inet {self.TABLE} qmfwd ip saddr {self.target_ip} "
            f"counter accept comment \"qm-up\"\n"
            f"add rule inet {self.TABLE} qmfwd ip daddr {self.target_ip} "
            f"counter accept comment \"qm-down\"\n"
        )
        rc, _, err = _run(["nft", "-f", "-"], input_text=script)
        if rc != 0:
            raise RuntimeError("nftables setup failed: " + err.strip())

    def _arm_ipt(self):
        # docker (and some firewalls) set FORWARD policy DROP; if so, target
        # traffic must be explicitly accepted before that policy can kill it
        rc, out, _ = _run(["iptables", "-S", "FORWARD"])
        self._ipt_inserted = (rc == 0 and "policy DROP" in out
                              and out.count("masq") < 2)
        if self._ipt_inserted:
            _run(["iptables", "-I", "FORWARD", "1", "-d", self.target_ip, "-j",
                  "ACCEPT", "-m", "comment", "--comment", "masq"])
            _run(["iptables", "-I", "FORWARD", "1", "-s", self.target_ip, "-j",
                  "ACCEPT", "-m", "comment", "--comment", "masq"])
        # phone fallback: no nft counters on Android kernels, so count with
        # two ACCEPT rules (safe with policy ACCEPT, just counts packets).
        # NOTE: no -m comment here: openela/Android kernels lack xt_comment.
        self._cnt_inserted = False
        if not self.have_nft and rc == 0 and out.count(self.target_ip) < 2:
            r1 = _run(["iptables", "-I", "FORWARD", "1", "-s", self.target_ip,
                       "-j", "ACCEPT"])
            r2 = _run(["iptables", "-I", "FORWARD", "1", "-d", self.target_ip,
                       "-j", "ACCEPT"])
            if r1[0] == 0 and r2[0] == 0:
                self._cnt_inserted = True

    def _arm_policy_routing(self):
        # target traffic must leave through THIS iface's gateway even when the
        # box has another default route with a lower metric (multi-homed VMs)
        _run(["ip", "rule", "del", "from", self.target_ip, "table", str(self.RT_TABLE)])
        _run(["ip", "route", "flush", "table", str(self.RT_TABLE)])
        rc, _, err = _run(["ip", "route", "replace", "default", "via", self.gw_ip,
                           "dev", self.iface, "table", str(self.RT_TABLE)])
        if rc != 0:
            raise RuntimeError("policy route failed: " + err.strip())
        rc, _, err = _run(["ip", "rule", "add", "from", self.target_ip,
                           "table", str(self.RT_TABLE), "priority", str(self.RT_PRIO)])
        if rc != 0:
            raise RuntimeError("policy rule failed: " + err.strip())

    def disarm(self):
        if self._ipt_inserted:
            _run(["iptables", "-D", "FORWARD", "-d", self.target_ip, "-j", "ACCEPT",
                  "-m", "comment", "--comment", "masq"])
            _run(["iptables", "-D", "FORWARD", "-s", self.target_ip, "-j", "ACCEPT",
                  "-m", "comment", "--comment", "masq"])
            self._ipt_inserted = False
        if self._cnt_inserted:
            _run(["iptables", "-D", "FORWARD", "-s", self.target_ip, "-j", "ACCEPT"])
            _run(["iptables", "-D", "FORWARD", "-d", self.target_ip, "-j", "ACCEPT"])
            # cleanup of the older comment-based variant, if it ever existed
            _run(["iptables", "-D", "FORWARD", "-s", self.target_ip, "-j", "ACCEPT",
                  "-m", "comment", "--comment", "masq-cnt-up"])
            _run(["iptables", "-D", "FORWARD", "-d", self.target_ip, "-j", "ACCEPT",
                  "-m", "comment", "--comment", "masq-cnt-down"])
            self._cnt_inserted = False
        _run(["ip", "rule", "del", "from", self.target_ip, "table", str(self.RT_TABLE)])
        _run(["ip", "route", "flush", "table", str(self.RT_TABLE)])
        if self.have_nft:
            _run(["nft", "delete", "table", "inet", self.TABLE])
        for name, value in self.saved_sysctls.items():
            try:
                self._write(name, value)
            except OSError:
                pass
        self.saved_sysctls = {}

    # ---- verification & stats ----------------------------------------------------
    def verify(self):
        ok, problems = True, []
        if self._read("net.ipv4.ip_forward") != "1":
            ok = False
            problems.append("ip_forward did not stick")
        if self.have_ipt:
            rc, out, _ = _run(["iptables", "-S", "FORWARD"])
            if rc == 0 and "policy DROP" in out and out.count("masq") < 2:
                ok = False
                problems.append("FORWARD policy is DROP but our accept rules are missing")
        return ok, problems

    def counters(self):
        """(up_pkts, up_bytes, down_pkts, down_bytes); iface-total fallback on Android."""
        if self.have_nft:
            rc, out, _ = _run(["nft", "list", "table", "inet", self.TABLE])
            if rc == 0:
                up = down = (None, None)
                for line in out.splitlines():
                    m = re.search(r"counter packets (\d+) bytes (\d+)", line)
                    if not m:
                        continue
                    if 'comment "qm-up"' in line:
                        up = (int(m.group(1)), int(m.group(2)))
                    elif 'comment "qm-down"' in line:
                        down = (int(m.group(1)), int(m.group(2)))
                if up != (None, None) or down != (None, None):
                    return up[0], up[1], down[0], down[1]
        ipt = self._counters_ipt()
        if ipt != (None, None, None, None):
            return ipt
        return self._counters_iface()

    def _counters_ipt(self):
        """Fallback for kernels without nft (Android): read iptables counters."""
        if not self.have_ipt:
            return None, None, None, None
        rc, out, _ = _run(["iptables", "-S", "FORWARD", "-v"])
        if rc != 0 or self.target_ip not in out:
            return None, None, None, None
        up = down = (None, None)
        pat_s = r"\s-s\s+" + re.escape(self.target_ip) + r"(?:/\d+)?"
        pat_d = r"\s-d\s+" + re.escape(self.target_ip) + r"(?:/\d+)?"
        for line in out.splitlines():
            if self.target_ip not in line:
                continue
            m = re.search(r"-c\s+(\d+)\s+(\d+)", line)
            if not m:
                continue
            if re.search(pat_s, line):
                up = (int(m.group(1)), int(m.group(2)))
            elif re.search(pat_d, line):
                down = (int(m.group(1)), int(m.group(2)))
            elif "masq-cnt-up" in line:
                up = (int(m.group(1)), int(m.group(2)))
            elif "masq-cnt-down" in line:
                down = (int(m.group(1)), int(m.group(2)))
        if up == (None, None) and down == (None, None):
            return self._counters_iface()
        up_p, up_b = up if up != (None, None) else (0, 0)
        down_p, down_b = down if down != (None, None) else (0, 0)
        return up_p, up_b, down_p, down_b

    def _counters_iface(self):
        """Last resort (Android): session delta of wlan0 totals, not per-target."""
        if self._iface_base is None:
            return None, None, None, None
        rx_b, rx_p, tx_b, tx_p = self._read_iface()
        if rx_p is None:
            return None, None, None, None
        b0, p0, tb0, tp0 = self._iface_base
        return (max(0, tx_p - tp0), max(0, tx_b - tb0),
                max(0, rx_p - p0), max(0, rx_b - b0))
