import contextlib
import io
import json
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path

from portscan import dnsutil, fingerprint, history, schedule
from portscan.__main__ import main, strip_schedule_args
from portscan.notify import command as notify_command
from portscan.report import render_html
from portscan.results import HostResult, PortResult
from portscan.scanner import scan_host, scan_port
from portscan.tlscheck import check as tls_check
from portscan.udp import scan_udp_port


def run_main(argv):
    out = io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
        code = main(argv)
    return code, out.getvalue()


class Server:
    """Local TCP server that greets (or answers) each client."""

    def __init__(self, greeting=b"", reply=b"", port=0):
        self.sock = socket.socket()
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", port))
        self.sock.listen()
        self.port = self.sock.getsockname()[1]
        self.greeting, self.reply = greeting, reply
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn:
                try:
                    if self.greeting:
                        conn.sendall(self.greeting)
                    if self.reply:
                        conn.settimeout(2)
                        if conn.recv(512):
                            conn.sendall(self.reply)
                except OSError:
                    pass

    def close(self):
        try:
            # On Linux, close() alone doesn't wake a thread blocked in accept(), so the port stays open.
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()


class FingerprintTests(unittest.TestCase):
    def test_signatures(self):
        cases = {
            b"SSH-2.0-OpenSSH_9.6\r\n": ("ssh", "2.0-OpenSSH_9.6"),
            b"220 mail.example ESMTP Postfix\r\n": ("smtp", "mail.example ESMTP Postfix"),
            b"220 (vsFTPd 3.0.5)\r\n": ("ftp", "(vsFTPd 3.0.5)"),
            b"+OK Dovecot ready.\r\n": ("pop3", "Dovecot ready."),
            b"* OK IMAP4rev1\r\n": ("imap", "IMAP4rev1"),
            b"RFB 003.008\n": ("vnc", "RFB 003.008"),
            b"-ERR unknown command 'HEAD'\r\n": ("redis", ""),
            b"ERROR\r\n": ("memcached", ""),
            b"HTTP/1.1 200 OK\r\nServer: nginx/1.25\r\n\r\n": ("http", "nginx/1.25"),
            b"HTTP/1.1 403 Forbidden\r\nServer: AirTunes/960\r\n\r\n": ("airplay", "AirTunes/960"),
            b"J\x00\x00\x00\n8.0.36\x00rest": ("mysql", "8.0.36"),
        }
        for raw, expected in cases.items():
            self.assertEqual(fingerprint.identify(raw), expected, raw)
        self.assertEqual(fingerprint.identify(b"N", fingerprint.POSTGRES_SSL_REQUEST)[0], "postgresql")
        self.assertIsNone(fingerprint.identify(b"N"))
        self.assertIsNone(fingerprint.identify(b""))

    def test_service_on_unexpected_port_is_identified(self):
        srv = Server(greeting=b"SSH-2.0-OpenSSH_9.6\r\n")
        try:
            r = scan_port("127.0.0.1", srv.port, timeout=1.0)
        finally:
            srv.close()
        self.assertEqual((r.service, r.identified, r.risk), ("ssh", True, "low"))
        self.assertIn("Identified as ssh", r.note)

    def test_silent_service_identified_by_probe(self):
        srv = Server(reply=b"-ERR unknown command 'HEAD', with args beginning with:\r\n")
        try:
            r = scan_port("127.0.0.1", srv.port, timeout=0.5)
        finally:
            srv.close()
        self.assertEqual((r.service, r.risk), ("redis", "critical"))


class DeviceTests(unittest.TestCase):
    def test_printer_raw_port_never_receives_data(self):
        received = []
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen()
        port = srv.getsockname()[1]

        def serve():
            conn, _ = srv.accept()
            with conn:
                conn.settimeout(1.5)
                try:
                    received.append(conn.recv(100))
                except OSError:
                    received.append(b"")

        t = threading.Thread(target=serve, daemon=True)
        t.start()
        from portscan import scanner
        old = scanner.NO_PROBE_PORTS
        scanner.NO_PROBE_PORTS = {port}
        try:
            r = scan_port("127.0.0.1", port, timeout=0.5)
        finally:
            scanner.NO_PROBE_PORTS = old
        t.join(2)
        srv.close()
        self.assertEqual(r.state, "open")
        self.assertEqual(received, [b""])  # nothing was sent, so nothing would print

    def test_http_speaking_device_keeps_its_name(self):
        from portscan import scanner, services
        srv = Server(reply=b"HTTP/1.1 200 OK\r\nServer: CUPS/2.4\r\n\r\n")
        services.SERVICES[srv.port] = ("ipp", "medium", "printer")
        try:
            r = scanner.scan_port("127.0.0.1", srv.port, timeout=0.5)
        finally:
            del services.SERVICES[srv.port]
            srv.close()
        self.assertEqual((r.service, r.product, r.identified), ("ipp", "CUPS/2.4", False))

    def test_auto_network(self):
        from portscan import scanner
        net = scanner.local_network()
        self.assertTrue(net.endswith(".0/24"), net)
        self.assertEqual(scanner.expand_auto("auto, 10.0.0.5"), f"{net},10.0.0.5")
        self.assertEqual(scanner.expand_auto("autoserver.local"), "autoserver.local")


class DnsTests(unittest.TestCase):
    def test_ptr_answer_with_compression(self):
        q = dnsutil.build_query("1.0.0.127.in-addr.arpa", dnsutil.PTR)
        answer = b"\xc0\x0c" + b"\x00\x0c\x00\x01\x00\x00\x00\x3c" + b"\x00\x0f" + dnsutil.encode_name("My-Mac.local")
        resp = bytearray(q + answer)
        resp[7] = 1  # ancount = 1
        self.assertEqual(dnsutil.first_ptr(bytes(resp)), "My-Mac.local")

    def test_pointer_loop_rejected(self):
        with self.assertRaises(ValueError):
            dnsutil.read_name(b"\xc0\x00", 0)

    def test_truncated_pointer_rejected(self):
        with self.assertRaises(ValueError):
            dnsutil.read_name(b"\x03abc\xc0", 0)


class UdpTests(unittest.TestCase):
    def test_open_and_closed(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        srv.bind(("127.0.0.1", 0))
        port = srv.getsockname()[1]

        def echo():
            data, addr = srv.recvfrom(512)
            srv.sendto(b"pong", addr)

        threading.Thread(target=echo, daemon=True).start()
        try:
            self.assertEqual(scan_udp_port("127.0.0.1", port, 1.0).state, "open")
        finally:
            srv.close()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.bind(("127.0.0.1", 0))
            closed = s.getsockname()[1]
        self.assertEqual(scan_udp_port("127.0.0.1", closed, 1.0).state, "closed")


@unittest.skipUnless(shutil.which("openssl"), "needs the openssl command to make a test certificate")
class TlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = tempfile.TemporaryDirectory()
        key, cert = f"{cls.dir.name}/k.pem", f"{cls.dir.name}/c.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", cert,
                        "-days", "5", "-subj", "/CN=test.local"], check=True, capture_output=True)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        cls.sock = socket.socket()
        cls.sock.bind(("127.0.0.1", 0))
        cls.sock.listen()
        cls.port = cls.sock.getsockname()[1]

        def serve():
            while True:
                try:
                    conn, _ = cls.sock.accept()
                except OSError:
                    return
                try:
                    with ctx.wrap_socket(conn, server_side=True) as t:
                        t.recv(10)
                except (OSError, ssl.SSLError):
                    pass

        threading.Thread(target=serve, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.sock.close()
        cls.dir.cleanup()

    def test_certificate_findings(self):
        info = tls_check("127.0.0.1", self.port, timeout=2.0)
        self.assertTrue(info["self_signed"])
        self.assertIn("CN=test.local", info["subject"])
        self.assertLess(info["days_left"], 30)
        issues = [text for _, text in info["issues"]]
        self.assertIn("Self-signed certificate (browsers will warn)", issues)
        self.assertIn("Certificate expires within 30 days", issues)

    def test_tls_detected_on_unknown_port(self):
        res = scan_host("127.0.0.1", "127.0.0.1", [self.port], timeout=1.0)
        p = res.open_ports[0]
        self.assertEqual(p.service, "tls")
        self.assertEqual(p.risk, "medium")  # raised from "low" by the certificate findings


def host(ip, *ports):
    return HostResult(host=ip, ip=ip, open_ports=list(ports), scanned=3)


class HistoryTests(unittest.TestCase):
    def test_compare(self):
        tls = {"version": "TLSv1.3"}
        prev = {"time": "t0", "tcp_ports": [22, 80, 443], "udp_ports": [],
                "hosts": [host("10.0.0.1", PortResult(22, "open", "ssh", "low"),
                               PortResult(443, "open", "https", "low", tls=tls)).to_dict()]}
        bad_tls = PortResult(443, "open", "https", "medium", tls=tls,
                             issues=["Self-signed certificate (browsers will warn)"])
        now = [host("10.0.0.1", PortResult(80, "open", "http", "medium"), bad_tls),
               host("10.0.0.9", PortResult(3389, "open", "rdp", "high"))]
        diff = history.compare(prev, now, [22, 80, 443], [])
        kinds = sorted((c.kind, c.port) for c in diff.changes)
        self.assertEqual(kinds, [("closed", "22/tcp"), ("new-host", ""), ("new-issue", "443/tcp"), ("opened", "80/tcp")])
        self.assertEqual(len(diff.alerts), 3)

    def test_failed_tls_check_is_not_reported_as_fixed(self):
        issue = "Self-signed certificate (browsers will warn)"
        prev = {"time": "t0", "tcp_ports": [443], "udp_ports": [],
                "hosts": [host("10.0.0.1", PortResult(443, "open", "https", "medium",
                                                      tls={"version": "TLSv1.2"}, issues=[issue])).to_dict()]}
        now = [host("10.0.0.1", PortResult(443, "open", "https", "low", tls={"error": "timed out"}))]
        self.assertEqual(history.compare(prev, now, [443], []).changes, [])

    def test_different_scan_depth_skips_service_comparison(self):
        prev = {"time": "t0", "tcp_ports": [22], "udp_ports": [], "options": {"banners": True, "tls": True},
                "hosts": [host("10.0.0.1", PortResult(22, "open", "ssh", "low", product="OpenSSH_9.6")).to_dict()]}
        now = [host("10.0.0.1", PortResult(22, "open", "ssh", "low"))]
        self.assertEqual(history.compare(prev, now, [22], [], {"banners": False, "tls": True}).changes, [])

    def test_device_back_after_missing_one_scan_is_not_new(self):
        p22 = PortResult(22, "open", "ssh", "low")
        older = [{"time": "t0", "hosts": [host("10.0.0.5", p22).to_dict()]}]
        prev = {"time": "t1", "tcp_ports": [22], "udp_ports": [], "hosts": []}
        diff = history.compare(prev, [host("10.0.0.5", p22)], [22], [], older=older)
        self.assertEqual([c.kind for c in diff.changes], ["back-host"])
        self.assertEqual(diff.alerts, [])

    def test_empty_scan_is_never_a_baseline(self):
        with tempfile.TemporaryDirectory() as d:
            history.save(Path(d), "net", [22], [], [])
            self.assertIsNone(history.latest(Path(d), "net"))

    def test_ports_not_scanned_both_times_are_not_compared(self):
        prev = {"time": "t0", "tcp_ports": [22], "udp_ports": [], "hosts": [host("10.0.0.1").to_dict()]}
        now = [host("10.0.0.1", PortResult(8080, "open", "http-proxy", "medium"))]
        self.assertEqual(history.compare(prev, now, [22, 8080], []).changes, [])

    def test_save_latest_and_cli_exit_code(self):
        srv = Server(greeting=b"SSH-2.0-test\r\n")
        try:
            with tempfile.TemporaryDirectory() as d:
                base = ["127.0.0.1", "--history-dir", d, "--no-names", "--diff", "-p"]
                code, _ = run_main(base + ["1"])  # baseline: nothing open on port 1
                self.assertEqual(code, 0)
                self.assertIsNotNone(history.latest(Path(d), "127.0.0.1"))
                code, _ = run_main(base + [f"1,{srv.port}"])  # new port, but not scanned before
                self.assertEqual(code, 0)
                code, out = run_main(base + [f"1,{srv.port}"])  # same again: no change
                self.assertEqual(code, 0)
                self.assertIn("No changes since the last scan", out)
                srv.close()
                code, out = run_main(base + [f"1,{srv.port}"])  # port went away
                self.assertEqual(code, 0)
                self.assertIn("is no longer open", out)
        finally:
            srv.close()

    def test_newly_opened_port_alerts_with_exit_code_3(self):
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        with tempfile.TemporaryDirectory() as d:
            argv = ["127.0.0.1", "--history-dir", d, "--no-names", "--diff", "-p", str(port)]
            self.assertEqual(run_main(argv)[0], 0)  # baseline: closed
            srv = Server(greeting=b"SSH-2.0-test\r\n", port=port)
            try:
                code, out = run_main(argv)
            finally:
                srv.close()
            self.assertEqual(code, 3)
            self.assertIn(f"+ 127.0.0.1 {port}/tcp: ssh (2.0-test) is now open", out)


class ReportTests(unittest.TestCase):
    def test_html_escapes_hostile_content(self):
        p = PortResult(80, "open", "http", "medium", "note", banner="<script>alert(1)</script>",
                       issues=["<img src=x onerror=alert(1)>"])
        h = HostResult("10.0.0.1", "10.0.0.1", name="<b>evil</b>", open_ports=[p])
        page = render_html([h], targets="<x>")
        self.assertNotIn("<script>alert", page)
        self.assertNotIn("<img", page)
        self.assertIn("&lt;script&gt;", page)
        self.assertIn("badge medium", page)

    def test_json_round_trip(self):
        h = HostResult("a", "10.0.0.1", open_ports=[PortResult(443, "open", tls={"version": "TLSv1.3"})])
        self.assertEqual(HostResult.from_dict(json.loads(json.dumps(h.to_dict()))), h)


class ScheduleTests(unittest.TestCase):
    def test_plist(self):
        argv = strip_schedule_args(["192.168.1.0/24", "--discover", "--schedule", "09:30"])
        self.assertEqual(argv, ["192.168.1.0/24", "--discover"])
        plist = schedule.build_plist("192.168.1.0/24", argv, "09:30", Path("/tmp/ps"))
        self.assertEqual(plist["StartCalendarInterval"], {"Hour": 9, "Minute": 30})
        args = plist["ProgramArguments"]
        self.assertEqual(args[1:4], ["-m", "portscan", "192.168.1.0/24"])
        for flag in ("--diff", "--notify", "--html", "--history-dir"):
            self.assertIn(flag, args)

    def test_user_flags_are_not_duplicated(self):
        args = schedule.scan_command(["net", "--html=/srv/x.html", "--history-dir=/srv/h"], Path("/tmp/ps"))
        self.assertEqual([a for a in args if a.startswith("--html")], ["--html=/srv/x.html"])
        self.assertEqual([a for a in args if a.startswith("--history-dir")], ["--history-dir=/srv/h"])

    def test_abbreviated_schedule_flag_rejected(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["127.0.0.1", "--sched", "09:00"])

    def test_bad_times_rejected(self):
        for bad in ("25:00", "9", "ab:cd"):
            with self.assertRaises(ValueError):
                schedule.parse_time(bad)
        self.assertEqual(run_main(["127.0.0.1", "--schedule", "99:99"])[0], 2)

    def test_notification_text_passed_as_arguments(self):
        cmd = notify_command('title "x"', 'msg" & do shell script "rm -rf ~')
        if cmd and cmd[0] == "osascript":
            self.assertEqual(cmd[-2:], ['msg" & do shell script "rm -rf ~', 'title "x"'])
            self.assertNotIn("rm -rf", " ".join(cmd[:-2]))


if __name__ == "__main__":
    unittest.main()
