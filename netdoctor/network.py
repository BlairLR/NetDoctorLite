"""Network probes. Every request explicitly chooses its route."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from http.client import HTTPConnection, HTTPException
from ipaddress import ip_address
from queue import Empty, Queue
import base64
import socket
from threading import BoundedSemaphore, Thread
from time import monotonic
from urllib.parse import urlsplit

import requests
import socks

from .local import configuration, listeners, windows_proxy
from .model import COMMON_PORTS, IP_URL, ROUTE_URL, SITES, Check, Proxy, SiteResult, local_host

# System DNS and a slow trickle of bytes can outlast ordinary socket timeouts.
# Bound the caller's wait and cap the number of unfinished background probes.
_slots = BoundedSemaphore(24)


def bounded(call, seconds, fallback):
    if not _slots.acquire(blocking=False):
        return fallback
    result = Queue(maxsize=1)

    def invoke():
        try:
            result.put(call())
        except Exception:
            result.put(fallback)
        finally:
            _slots.release()

    try:
        Thread(target=invoke, daemon=True).start()
    except RuntimeError:
        _slots.release()
        return fallback
    try:
        return result.get(timeout=seconds)
    except Empty:
        return fallback


def error_reason(exc):
    if isinstance(exc, requests.exceptions.SSLError):
        return "TLS 握手或证书验证失败"
    if isinstance(exc, requests.exceptions.ProxyError):
        return "代理连接或隧道建立失败"
    if isinstance(exc, (requests.exceptions.Timeout, TimeoutError)):
        return "连接或读取超时"
    if isinstance(exc, socket.gaierror):
        return "DNS 解析失败"
    if isinstance(exc, ConnectionRefusedError):
        return "连接被拒绝"
    return "网络连接失败"


def https(url, proxy=None, *, read_ip=False, require_2xx=False, trace=False):
    start = monotonic()
    code = None

    def finish(ok, detail, ip=None):
        return Check(ok, detail, code, round((monotonic() - start) * 1000), ip)

    try:
        with requests.Session() as session:
            session.trust_env = False
            session.headers["Accept-Encoding"] = "identity"
            proxies = {"https": proxy.url} if proxy else {}
            with session.get(url, proxies=proxies, timeout=(3, 3), stream=True,
                             allow_redirects=False, verify=True) as response:
                code = response.status_code
                if (read_ip or require_2xx) and not 200 <= code < 300:
                    return finish(False, "目标未返回 HTTP 2xx")
                if not (read_ip or trace):
                    label = "收到 HTTPS 响应"
                    if code >= 400:
                        label += "；目标拒绝请求或服务出错"
                    return finish(True, label)
                # Read at most 128 bytes, without transparently inflating content.
                limit = 2048 if trace else 128
                raw = response.raw.read(limit, decode_content=False)
                try:
                    candidate = raw.decode("ascii").strip()
                    if trace:
                        candidate = next((line[3:] for line in candidate.splitlines()
                                          if line.startswith("ip=")), "")
                    value = ip_address(candidate)
                    if not value.is_global or "%" in str(value) or len(raw) >= limit:
                        raise ValueError
                except ValueError:
                    if trace:
                        return finish(True, "收到 HTTPS 响应")
                    return finish(False, "出口查询未返回有效公网 IP")
                if trace:
                    return finish(True, "收到 HTTPS 响应", str(value))
                return finish(True, "已取得出口公网 IP", str(value))
    except (requests.RequestException, OSError):
        # Handled below without ever including URL, credentials or proxy host.
        raise


def request_check(url, proxy=None, **kwargs):
    def run():
        start = monotonic()
        try:
            return https(url, proxy, **kwargs)
        except (requests.RequestException, OSError) as exc:
            return Check(False, error_reason(exc), ms=round((monotonic() - start) * 1000))
    return bounded(run, 8, Check(False, "请求超过等待上限或无法完成", ms=8000))


def probe_site(name, url):
    host = urlsplit(url).hostname
    records = bounded(lambda: socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM),
                      3, None)
    dns = Check(bool(records), "解析成功" if records else "DNS 解析失败或超时")

    def connect():
        if not records:
            return Check(False, "未检测：DNS 未解析")
        deadline = monotonic() + 4
        last_reason = "TCP 连接失败"
        for family, kind, proto, _, sockaddr in records:
            remaining = deadline - monotonic()
            if remaining <= 0:
                return Check(False, "TCP 连接超时")
            try:
                with socket.socket(family, kind, proto) as sock:
                    sock.settimeout(min(1.5, remaining))
                    sock.connect(sockaddr)
                    return Check(True, "连接成功")
            except OSError as exc:
                last_reason = error_reason(exc)
        return Check(False, last_reason)

    tcp = bounded(connect, 4.1, Check(False, "TCP 连接超时"))
    return SiteResult(name, dns, tcp, request_check(url))


def proxy_handshake(proxy, url=ROUTE_URL):
    # For an HTTPS destination the meaningful handshake is an accepted
    # CONNECT (HTTP or SOCKS5). No TLS or HTTP request is made here.
    parts = urlsplit(url)
    host, port = parts.hostname, parts.port or 443
    try:
        if proxy.protocol == "SOCKS5":
            with socks.create_connection((host, port), timeout=3,
                                         proxy_type=socks.SOCKS5,
                                         proxy_addr=proxy.host, proxy_port=proxy.port,
                                         proxy_rdns=True, proxy_username=proxy.username or None,
                                         proxy_password=proxy.password or None):
                pass
        else:
            headers = {}
            if proxy.username:
                token = base64.b64encode(
                    f"{proxy.username}:{proxy.password}".encode("latin-1")
                ).decode("ascii")
                headers["Proxy-Authorization"] = "Basic " + token
            conn = HTTPConnection(proxy.host, proxy.port, timeout=3)
            try:
                conn.set_tunnel(host, port, headers=headers)
                conn.connect()
            finally:
                conn.close()
        return Check(True, "代理已接受 CONNECT 隧道")
    except socks.SOCKS5AuthError:
        return Check(False, "SOCKS5 认证失败")
    except OSError as exc:
        if str(exc).startswith("Tunnel connection failed: 407"):
            return Check(False, "HTTP 代理需要认证或凭据无效（407）")
        if isinstance(exc, socks.ProxyError):
            return Check(False, "SOCKS5 协商或目标隧道失败")
        return Check(False, error_reason(exc))
    except (HTTPException, ValueError):
        return Check(False, "代理响应无效或目标隧道被拒绝")


def detect_proxy():
    configured = bounded(lambda: windows_proxy(include_local_ports=True), 2, ())
    ports = tuple(dict.fromkeys([port for _, port in configured] + list(COMMON_PORTS)))
    local = bounded(lambda: listeners(ports, include_proxy_processes=True), 3, None)
    if local is None:
        return None, "自动检测无法读取本机监听列表，请手动填写代理。"

    wildcard = {"0.0.0.0": "127.0.0.1", "::": "::1"}
    available = []
    for port, rows in local.items():
        for row in rows:
            host = wildcard.get(row.address, row.address)
            if local_host(host):
                available.append((host, port))
    endpoints = [address for address in configured if address in available]
    endpoints.extend(available)
    endpoints = list(dict.fromkeys(endpoints))[:8]
    if not endpoints:
        return None, "未发现候选本机代理端口，可手动填写代理。"

    candidates = [Proxy(protocol, host, port) for host, port in endpoints
                  for protocol in ("HTTP", "SOCKS5")]
    with ThreadPoolExecutor(max_workers=len(candidates)) as pool:
        checks = pool.map(lambda candidate: request_check(ROUTE_URL, candidate, require_2xx=True),
                          candidates)
        for candidate, check in zip(candidates, checks):
            if check.ok:
                return candidate, f"自动检测已选用 {candidate.protocol} · 本机端口 {candidate.port}。"
    return None, "候选端口有监听，但未验证到可访问外网的代理。请检查节点或手动填写认证。"


def diagnose(custom, proxy, progress):
    targets = SITES + ((("自定义网站", custom),) if custom else ())
    ports = tuple(sorted(set(COMMON_PORTS) | ({proxy.port} if proxy and
                         local_host(proxy.host) else set())))
    progress(5, "正在读取本机监听和代理设置")
    local = bounded(lambda: listeners(ports), 3, None)
    config = bounded(configuration, 3, ("代理设置读取超时或不可用",))
    progress(15, "正在检测网站直连")
    sites = [None] * len(targets)
    with ThreadPoolExecutor(max_workers=len(targets)) as pool:
        pending = {pool.submit(probe_site, *target): i for i, target in enumerate(targets)}
        for count, future in enumerate(as_completed(pending), 1):
            sites[pending[future]] = future.result()
            progress(15 + int(20 * count / len(targets)), f"网站直连 {count}/{len(targets)}")
    progress(40, "正在检测直连通路及出口")
    direct = request_check(ROUTE_URL, require_2xx=True, trace=True)
    direct_ip = (Check(True, "已从 Cloudflare 取得出口公网 IP", ip=direct.ip)
                 if direct.ip else request_check(IP_URL, read_ip=True))
    tunnel = via = via_ip = None
    if proxy:
        progress(55, "正在验证代理协议握手")
        tunnel = bounded(lambda: proxy_handshake(proxy), 6, Check(False, "握手超时或无法完成"))
        with ThreadPoolExecutor(max_workers=len(targets)) as pool:
            pending = {pool.submit(request_check, url, proxy): i
                       for i, (_, url) in enumerate(targets)}
            for count, future in enumerate(as_completed(pending), 1):
                i = pending[future]
                sites[i] = replace(sites[i], proxy_https=future.result())
                progress(55 + int(25 * count / len(targets)), f"网站代理 {count}/{len(targets)}")
        progress(85, "正在通过指定代理访问外网及查询出口")
        via = request_check(ROUTE_URL, proxy, require_2xx=True, trace=True)
        via_ip = (Check(True, "已从 Cloudflare 取得出口公网 IP", ip=via.ip)
                  if via.ip else request_check(IP_URL, proxy, read_ip=True))
    progress(100, "检测完成")
    return ports, local, config, sites, direct, direct_ip, tunnel, via, via_ip
