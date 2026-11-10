import socket
import socketserver
import threading
import unittest
from unittest.mock import patch

from netdoctor.local import listeners
from netdoctor.model import Check, Proxy, custom_url
from netdoctor.network import bounded, https, proxy_handshake
from netdoctor.report import report, summary


class Fixture(socketserver.StreamRequestHandler):
    def handle(self):
        self.request.settimeout(3)
        try:
            if self.server.mode == "http":
                first = self.rfile.readline(512)
                if not first:
                    return
                self.server.seen.append(first)
                while self.rfile.readline(1024) not in (b"\r\n", b""):
                    pass
                self.wfile.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            elif self.server.mode == "socks":
                if self.rfile.read(3) != b"\x05\x01\x00":
                    return
                self.wfile.write(b"\x05\x00")
                if self.rfile.read(4) != b"\x05\x01\x00\x03":
                    return
                size = self.rfile.read(1)[0]
                self.server.seen.append(self.rfile.read(size))
                self.rfile.read(2)
                self.wfile.write(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x00\x00")
        except OSError:
            pass


class Tests(unittest.TestCase):
    def test_custom_and_proxy_validation(self):
        self.assertEqual(custom_url("example.com/a?token=abc#fragment"), "https://example.com/a?token=abc")
        for value in ("http://example.com", "https://user:pass@example.com", "bad host", "https://x:0"):
            with self.assertRaises(ValueError):
                custom_url(value)
        self.assertEqual(Proxy("SOCKS5", "::1", 123, "u@", "p:").url,
                         "socks5h://u%40:p%3A@[::1]:123")

    def test_direct_and_explicit_proxy_options(self):
        with patch("netdoctor.network.requests.Session") as session:
            opened = session.return_value.__enter__.return_value
            response = opened.get.return_value.__enter__.return_value
            response.status_code = 200
            response.raw.read.return_value = b"1.1.1.1"
            self.assertEqual(https("https://example.com", read_ip=True).ip, "1.1.1.1")
            self.assertIs(opened.trust_env, False)
            self.assertEqual(opened.get.call_args.kwargs["proxies"], {})
            proxy = Proxy("HTTP", "127.0.0.1", 7890)
            response.status_code = 403
            self.assertTrue(https("https://example.com", proxy).ok)
            self.assertFalse(https("https://example.com", proxy, require_2xx=True).ok)
            self.assertEqual(opened.get.call_args.kwargs["proxies"], {"https": proxy.url})
            self.assertIs(opened.get.call_args.kwargs["allow_redirects"], False)
            self.assertIs(opened.get.call_args.kwargs["verify"], True)

    def test_timeout(self):
        waiting = threading.Event()
        try:
            self.assertEqual(bounded(waiting.wait, 0.03, "timeout"), "timeout")
        finally:
            waiting.set()

    def test_loopback_listening_and_handshakes(self):
        for mode in ("closed", "http", "socks"):
            with self.subTest(mode=mode), socketserver.ThreadingTCPServer(("127.0.0.1", 0), Fixture) as server:
                server.mode, server.seen = mode, []
                server.daemon_threads = True
                port = server.server_address[1]
                thread = threading.Thread(target=server.serve_forever, daemon=True)
                thread.start()
                protocol = "SOCKS5" if mode == "socks" else "HTTP"
                proxy = Proxy(protocol, "127.0.0.1", port)
                try:
                    rows = listeners((port,))
                    self.assertTrue(rows[port])
                    self.assertTrue(any(x.pid and x.process.lower().endswith(".exe") for x in rows[port]))
                    self.assertEqual(proxy_handshake(proxy).ok, mode != "closed")
                    if mode == "http":
                        self.assertTrue(server.seen[0].startswith(b"CONNECT www.cloudflare.com:443 "))
                    if mode == "socks":
                        self.assertEqual(server.seen, [b"www.cloudflare.com"])
                finally:
                    server.shutdown()
                server.server_close()
                self.assertFalse(proxy_handshake(proxy).ok)

    def test_report_redaction_and_proxy_failure(self):
        local_proxy = Proxy("HTTP", "127.0.0.1", 19222, "verysecretuser", "verysecretpass")
        failed = Check(False, "代理连接失败")
        ok = Check(True, "成功")
        ip = Check(True, "已取得出口公网 IP", ip="8.8.8.8")
        result = ((19222,), {19222: []}, (), [], ok, ip, ok, failed, ip)
        self.assertIn("未监听", summary(result, local_proxy))
        self.assertIn("握手成功，但访问外网测试失败", summary(result, local_proxy))
        exported = report(result, local_proxy)
        for secret in ("verysecretuser", "verysecretpass", "8.8.8.8", "127.0.0.1"):
            self.assertNotIn(secret, exported)


if __name__ == "__main__":
    unittest.main()
