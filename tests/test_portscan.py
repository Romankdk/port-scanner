import json
import socket
import sys
import threading
import unittest

from portscan.__main__ import main
from portscan.report import render_json, render_text
from portscan.scanner import clean, parse_ports, parse_targets, scan_host, scan_port


# Windows retries a refused connection for about 2 seconds, longer than the 1s timeout,
# so closed ports are reported as "filtered" there. Open ports are unaffected.
CLOSED = "filtered" if sys.platform == "win32" else "closed"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class BannerServer:
    """A tiny local TCP server that greets each client with a banner."""

    def __init__(self, banner: bytes = b"SSH-2.0-TestServer\r\n"):
        self.banner = banner
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self._stop = False
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    conn.sendall(self.banner)
                except OSError:
                    pass

    def close(self):
        self._stop = True
        try:
            # On Linux, close() alone doesn't wake a thread blocked in accept(), so the port stays open.
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class ParseTests(unittest.TestCase):
    def test_ports_list_and_ranges(self):
        self.assertEqual(parse_ports("80,22,20-23,22"), [20, 21, 22, 23, 80])

    def test_ports_reject_bad_input(self):
        for bad in ("0", "70000", "90-80", "", "abc"):
            with self.assertRaises(ValueError):
                parse_ports(bad)

    def test_targets_cidr(self):
        self.assertEqual(parse_targets("10.0.0.0/30"), ["10.0.0.1", "10.0.0.2"])
        self.assertEqual(parse_targets("10.0.0.7/32"), ["10.0.0.7"])

    def test_targets_mixed_and_limit(self):
        self.assertEqual(parse_targets("a.local, 10.0.0.1"), ["a.local", "10.0.0.1"])
        with self.assertRaises(ValueError):
            parse_targets("10.0.0.0/16")

    def test_huge_ranges_rejected_fast(self):
        for spec in ("10.0.0.0/8", "0.0.0.0/0", "::/64"):
            with self.assertRaises(ValueError):
                parse_targets(spec)

    def test_clean_strips_escape_sequences(self):
        self.assertEqual(clean("\x1b]0;pwned\x07ok\x1b[2J"), "]0;pwnedok[2J")


class ScanTests(unittest.TestCase):
    def setUp(self):
        self.server = BannerServer()

    def tearDown(self):
        self.server.close()

    def test_open_port_with_banner(self):
        r = scan_port("127.0.0.1", self.server.port, timeout=1.0)
        self.assertEqual(r.state, "open")
        self.assertEqual(r.banner, "SSH-2.0-TestServer")

    def test_closed_port(self):
        self.assertEqual(scan_port("127.0.0.1", free_port(), timeout=1.0).state, CLOSED)

    def test_scan_host_counts(self):
        closed = free_port()
        res = scan_host("127.0.0.1", "127.0.0.1", [self.server.port, closed], timeout=1.0)
        self.assertEqual([p.port for p in res.open_ports], [self.server.port])
        self.assertEqual((res.scanned, res.closed + res.filtered), (2, 1))

    def test_reports(self):
        res = scan_host("127.0.0.1", "127.0.0.1", [self.server.port], timeout=1.0)
        text = render_text([res], color=False)
        self.assertIn(str(self.server.port), text)
        self.assertIn("Summary: 1 host(s), 1 open port(s)", text)
        data = json.loads(render_json([res]))
        self.assertEqual(data[0]["open_ports"][0]["banner"], "SSH-2.0-TestServer")

    def test_cli_rejects_bad_input(self):
        self.assertEqual(main(["127.0.0.1", "-p", "99999"]), 2)
        self.assertEqual(main(["127.0.0.1", "-t", "0"]), 2)
        self.assertEqual(main(["127.0.0.1", "-w", "0"]), 2)

    def test_hostile_banner_is_sanitized(self):
        self.server.close()
        self.server = BannerServer(b"\x1b[2JEvil\x07Banner\r\n")
        r = scan_port("127.0.0.1", self.server.port, timeout=1.0)
        self.assertNotIn("\x1b", r.banner)
        self.assertIn("EvilBanner", r.banner)

    def test_min_risk_keeps_counts_honest(self):
        import contextlib, io
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
            main(["127.0.0.1", "-p", str(self.server.port), "--min-risk", "critical", "--no-color"])
        self.assertIn("1 open (1 below --min-risk not shown)", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
