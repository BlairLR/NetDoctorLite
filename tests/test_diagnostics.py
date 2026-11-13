import socket
import socketserver
import threading
import unittest
from unittest.mock import patch

from netdoctor.local import listeners, local_proxy_addresses
from netdoctor.model import Check, DiagnosticResult, Listener, Proxy, SiteResult, custom_url
from netdoctor.network import bounded, detect_proxy, diagnose, error_check, https, proxy_handshake
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

    def test_cloudflare_location_matches_ip_and_ignores_data_center(self):
        with patch("netdoctor.network.requests.Session") as session:
            response = session.return_value.__enter__.return_value.get.return_value.__enter__.return_value
            response.status_code = 200
            response.raw.read.return_value = b"ip=8.8.8.8\nloc=US\ncolo=NRT\n"
            check = https("https://example.com", trace=True)
            self.assertEqual((check.ip, check.country_code), ("8.8.8.8", "US"))
            response.raw.read.return_value = b"ip=8.8.8.8\nloc=XX\ncolo=NRT\n"
            self.assertIsNone(https("https://example.com", trace=True).country_code)
            response.raw.read.return_value = b"ip=127.0.0.1\nloc=JP\n"
            self.assertIsNone(https("https://example.com", trace=True).country_code)

    def test_timeout(self):
        waiting = threading.Event()
        try:
            self.assertEqual(bounded(waiting.wait, 0.03, "timeout"), "timeout")
        finally:
            waiting.set()

    def test_auto_proxy_rediscovers_port_and_skips_listener_without_working_https(self):
        self.assertEqual(
            local_proxy_addresses("http=127.0.0.1:34567;https=[::1]:45678;"
                                  "socks5://user:password@127.0.0.1:50000;proxy.example:80"),
            (("127.0.0.1", 34567), ("::1", 45678)),
        )
        old = Listener(7890, "127.0.0.1", 1, "test.exe")
        new = Listener(34567, "0.0.0.0", 2, "test.exe")
        with (
            patch("netdoctor.network.windows_proxy", side_effect=[(), (("127.0.0.1", 34567),), ()]),
            patch("netdoctor.network.listeners",
                  side_effect=[{7890: [old]}, {7890: [old], 34567: [new]}, {7890: [old]}]),
            patch("netdoctor.network.request_check") as request,
        ):
            request.side_effect = lambda url, proxy, **kw: Check(proxy.port == 7890, "result")
            self.assertEqual(detect_proxy()[0].port, 7890)
            request.side_effect = lambda url, proxy, **kw: Check(
                proxy.port == 34567 and proxy.protocol == "SOCKS5", "result")
            picked, note = detect_proxy()
            self.assertEqual((picked.port, picked.protocol), (34567, "SOCKS5"))
            self.assertIn("34567", note)
            self.assertIsNone(detect_proxy()[0])

    def test_each_website_uses_the_selected_proxy_and_keeps_direct_result(self):
        proxy = Proxy("SOCKS5", "127.0.0.1", 23456)
        custom = "https://example.com/private?secret=redact"
        failed = Check(False, "连接超时")
        ok = Check(True, "收到 HTTPS 响应", code=200, ip="1.1.1.1")
        with (
            patch("netdoctor.network.configuration", return_value=()),
            patch("netdoctor.network.listeners", side_effect=lambda ports: {p: [] for p in ports}),
            patch("netdoctor.network.proxy_handshake", return_value=ok),
            patch("netdoctor.network.probe_site",
                  side_effect=lambda name, _: SiteResult(name, ok, failed, failed)),
            patch("netdoctor.network.request_check", return_value=ok) as request,
        ):
            result = diagnose(custom, proxy, lambda *_: None)
            request.assert_any_call(custom, proxy)
            request.assert_any_call("https://chatgpt.com/", proxy)
            self.assertEqual(sum(call.args[1:] == (proxy,) and not call.kwargs
                                 for call in request.call_args_list), 5)
        self.assertIn(23456, result.ports)
        self.assertTrue(all(not site.https.ok and site.proxy_https.ok for site in result.sites))
        exported = report(result, proxy)
        self.assertIn("\nChatGPT\n", exported)
        self.assertIn("代理 HTTPS：成功", exported)
        self.assertNotIn("secret=redact", exported)

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
        result = DiagnosticResult(
            ports=(19222,), listeners={19222: []}, settings=(), sites=[],
            direct_https=ok, direct_exit=ip, proxy_tunnel=ok, proxy_https=failed, proxy_exit=ip,
        )
        self.assertIn("未监听", summary(result, local_proxy))
        self.assertIn("代理隧道已建立，外网请求失败", summary(result, local_proxy))
        exported = report(result, local_proxy)
        for secret in ("verysecretuser", "verysecretpass", "8.8.8.8", "127.0.0.1"):
            self.assertNotIn(secret, exported)

    def test_request_error_categories_do_not_echo_proxy_data(self):
        from http.client import RemoteDisconnected
        import requests
        import socks
        from urllib3 import exceptions

        cases = (
            (requests.exceptions.ProxyError(exceptions.ProxyError("proxy", OSError(
                "Tunnel connection failed: 407 secret-proxy-name"))), "proxy_auth"),
            (OSError("Tunnel connection failed: 502 secret-proxy-name"), "proxy_tunnel"),
            (socks.GeneralProxyError("secret-proxy-name", socks.SOCKS5AuthError("auth")), "proxy_auth"),
            (requests.exceptions.SSLError("secret-proxy-name"), "tls"),
            (requests.exceptions.ReadTimeout("secret-proxy-name"), "timeout"),
            (RemoteDisconnected("secret-proxy-name"), "http_request"),
            (ConnectionRefusedError("secret-proxy-name"), "connection"),
        )
        for exc, kind in cases:
            with self.subTest(kind=kind):
                result = error_check(exc)
                self.assertEqual(result.kind, kind)
                self.assertNotIn("secret-proxy-name", result.detail)


if __name__ == "__main__":
    unittest.main()
