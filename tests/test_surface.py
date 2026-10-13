"""Smoke tests: import + unit-level behavior after IPS removal.

These run WITHOUT root and WITHOUT touching any network — they verify the
modules load, expose the right surface, and the pure-logic helpers still
work. Live behavior (positioning) is covered by `mitm.py selftest`.
"""
import unittest


class SurfaceTests(unittest.TestCase):
    def test_positioning_modules_import(self):
        """Positioning core must import cleanly after IPS removal."""
        from core import dataplane, recon  # noqa: F401
        from taps import tap_manager  # noqa: F401
        # position/restore/session import scapy at module level; skip if absent
        try:
            import scapy  # noqa: F401
            from core import position, restore, session  # noqa: F401
        except ImportError:
            self.skipTest("scapy not installed (live modules)")

    def test_ips_modules_removed(self):
        """IPS modules must be gone (killer included: MITM is pure positioning)."""
        import importlib

        for mod in ("core.policy", "core.enforce", "core.killer"):
            with self.assertRaises(ImportError, msg=f"{mod} should be removed"):
                importlib.import_module(mod)

    def test_session_has_no_ips(self):
        """Session must not expose IPS state after removal."""
        try:
            import scapy  # noqa: F401
        except ImportError:
            self.skipTest("scapy not installed (session imports scapy)")
        from core.session import MitmSession

        self.assertFalse(hasattr(MitmSession, "set_profiles"))
        self.assertFalse(hasattr(MitmSession, "panic"))

    def test_dataplane_helpers(self):
        """Dataplane pure helpers must still work."""
        from core.dataplane import DataPlane

        dp = DataPlane("wlan0", "192.168.1.1", "192.168.1.129")
        # interface-counter parser is pure and testable offline
        self.assertTrue(callable(dp._read_iface))
        self.assertTrue(callable(dp._read))
        self.assertTrue(callable(dp._write))


if __name__ == "__main__":
    unittest.main()
