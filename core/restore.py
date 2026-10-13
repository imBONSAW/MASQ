"""Guaranteed cleanup: put both sides' ARP back, even after a crash."""
import time

from scapy.all import ARP, Ether, sendp


def restore_arp(st, rounds=4, gap=0.4):
    """Corrective unicast ARP: tell target and gateway each other's REAL mac."""
    iface = st["iface"]
    to_target = Ether(dst=st["target_mac"]) / ARP(
        op=2, psrc=st["gw_ip"], hwsrc=st["gw_mac"],
        pdst=st["target_ip"], hwdst=st["target_mac"])
    to_gw = Ether(dst=st["gw_mac"]) / ARP(
        op=2, psrc=st["target_ip"], hwsrc=st["target_mac"],
        pdst=st["gw_ip"], hwdst=st["gw_mac"])
    for i in range(rounds):
        sendp(to_target, iface=iface, verbose=0)
        sendp(to_gw, iface=iface, verbose=0)
        if i < rounds - 1:
            time.sleep(gap)


def restore_from_state(st):
    """Full cleanup for a crashed / stale session (state read from disk)."""
    try:
        restore_arp(st, rounds=2, gap=0.3)
    except Exception as e:
        print(f"[!] ARP restore failed: {e}")
    from core.dataplane import DataPlane
    dp = DataPlane(st["iface"], st["gw_ip"], st["target_ip"])
    dp.saved_sysctls = dict(st.get("sysctls", {}))
    dp._ipt_inserted = bool(st.get("ipt_inserted"))
    dp._cnt_inserted = bool(st.get("cnt_inserted", st.get("ipt_inserted")))
    # legacy states have no cnt flag but may have cnt rules: try cleanup anyway
    if "cnt_inserted" not in st:
        dp._cnt_inserted = True
    dp.disarm()
