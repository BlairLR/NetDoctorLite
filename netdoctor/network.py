"""Network probes. Every request explicitly chooses its route."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import replace
from http.client import HTTPConnection, HTTPException
from ipaddress import ip_address
from queue import Empty, Queue
import base64
import re
import socket
import ssl
from threading import BoundedSemaphore, Thread
from time import monotonic
from urllib.parse import urlsplit

import requests
import socks
from urllib3 import exceptions as urllib_errors

from .local import configuration, listeners, windows_proxy
from .model import COMMON_PORTS, IP_URL, ROUTE_URL, SITES, Check, DiagnosticResult, Proxy, SiteResult, local_host

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


def error_check(exc, ms=None, *, tunnel=False):
    # requests and PySocks wrap lower-level errors. Use their types and only
    # extract the numeric CONNECT status from http.client's error message.
    pending = [exc]
    errors = []
    seen = set()
    while pending:
        error = pending.pop()
        if id(error) in seen:
            continue
        seen.add(id(error))
        errors.append(error)
        pending.extend(value for value in (
            error.__cause__, error.__context__, getattr(error, "reason", None),
            getattr(error, "socket_err", None), *error.args,
        ) if isinstance(value, BaseException))

    def matches(*types):
        return any(isinstance(error, types) for error in errors)

    connect_status = next(
        (match[1] for error in errors if isinstance(error, OSError)
         if (match := re.match(r"^Tunnel connection failed: ([0-9]{3})(?: |$)", str(error)))),
        None,
    )
    if connect_status == "407" or matches(socks.SOCKS5AuthError):
        kind, detail = "proxy_auth", "代理要求认证或凭据无效"
        if connect_status:
            detail += "（CONNECT 407）"
    elif connect_status:
        kind, detail = "proxy_tunnel", f"代理拒绝 CONNECT 隧道（{connect_status}）"
    elif matches(requests.exceptions.SSLError, urllib_errors.SSLError, ssl.SSLError):
        kind, detail = "tls", "TLS 握手或证书验证失败"
    elif matches(socket.gaierror, urllib_errors.NameResolutionError):
        kind, detail = "dns", "DNS 解析失败"
    elif matches(ConnectionRefusedError):
        kind, detail = "connection", "连接被拒绝"
    elif (matches(requests.exceptions.Timeout, urllib_errors.ReadTimeoutError, TimeoutError)
          or (matches(urllib_errors.ConnectTimeoutError)
              and not matches(urllib_errors.NewConnectionError))):
        kind, detail = "timeout", "连接或读取超时"
    elif matches(socks.ProxyConnectionError):
        kind, detail = "proxy_connection", "无法连接代理端口"
    elif matches(socks.ProxyError) or (tunnel and matches(HTTPException)):
        kind, detail = "proxy_tunnel", "代理协议协商或目标隧道建立失败"
    elif matches(requests.exceptions.ProxyError, urllib_errors.ProxyError):
        kind, detail = "proxy_connection", "无法连接代理或建立隧道"
    elif matches(urllib_errors.ProtocolError, requests.exceptions.ChunkedEncodingError,
                 requests.exceptions.ContentDecodingError, HTTPException):
        kind, detail = "http_request", "HTTP 请求失败，响应无效或连接提前关闭"
    else:
        kind, detail = "connection", "网络连接失败"
    return Check(False, detail, ms=ms, kind=kind)


def https(url, proxy=None, *, read_ip=False, require_2xx=False, trace=False):
    start = monotonic()
    code = None

    def finish(ok, detail, ip=None, country_code=None, kind=None):
        return Check(ok, detail, code, round((monotonic() - start) * 1000), ip, country_code, kind)

    try:
        with requests.Session() as session:
            session.trust_env = False
            session.headers["Accept-Encoding"] = "identity"
            proxies = {"https": proxy.url} if proxy else {}
            with session.get(url, proxies=proxies, timeout=(3, 3), stream=True,
                             allow_redirects=False, verify=True) as response:
                code = response.status_code
                server_kind = "http_forbidden" if code == 403 else "http_status" if code >= 400 else None
                server_detail = "服务器拒绝访问（HTTP 403）" if code == 403 else "服务器返回 HTTP 错误"
                if (read_ip or require_2xx) and not 200 <= code < 300:
                    return finish(False, server_detail if server_kind else "目标未返回 HTTP 2xx",
                                  kind=server_kind or "http_status")
                if not (read_ip or trace):
                    return finish(True, server_detail if server_kind else "收到 HTTPS 响应",
                                  kind=server_kind)
                # Read a bounded body without inflating content.
                limit = 2048 if trace else 128
                raw = response.raw.read(limit, decode_content=False)
                try:
                    candidate = raw.decode("ascii").strip()
                    country_code = None
                    if trace:
                        fields = dict(line.split("=", 1) for line in candidate.splitlines()
                                      if "=" in line)
                        candidate = fields.get("ip", "")
                        location = fields.get("loc", "")
                        if re.fullmatch(r"[A-Z]{2}", location) and location != "XX":
                            country_code = location
                    value = ip_address(candidate)
                    if not value.is_global or "%" in str(value) or len(raw) >= limit:
                        raise ValueError
                except ValueError:
                    if trace:
                        return finish(True, "收到 HTTPS 响应")
                    return finish(False, "出口查询未返回有效公网 IP")
                if trace:
                    return finish(True, "收到 HTTPS 响应", str(value), country_code)
                return finish(True, "已取得出口公网 IP", str(value))
    except (requests.RequestException, OSError):
        # Handled below without ever including URL, credentials or proxy host.
        raise


def request_check(url, proxy=None, **kwargs):
    def run():
        start = monotonic()
        try:
            return https(url, proxy, **kwargs)
        except (requests.RequestException, urllib_errors.HTTPError, OSError, HTTPException) as exc:
            return error_check(exc, round((monotonic() - start) * 1000))
    return bounded(run, 8, Check(False, "请求超过等待上限或无法完成", ms=8000, kind="timeout"))


def probe_site(name, url):
    host = urlsplit(url).hostname
    records = bounded(lambda: socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM),
                      3, None)
    dns = (Check(True, "解析成功") if records else
           Check(False, "DNS 解析失败或超时", kind="dns"))

    def connect():
        if not records:
            return Check(False, "未检测：DNS 未解析")
        deadline = monotonic() + 4
        last_check = Check(False, "TCP 连接失败", kind="connection")
        for family, kind, proto, _, sockaddr in records:
            remaining = deadline - monotonic()
            if remaining <= 0:
                return Check(False, "TCP 连接超时", kind="timeout")
            try:
                with socket.socket(family, kind, proto) as sock:
                    sock.settimeout(min(1.5, remaining))
                    sock.connect(sockaddr)
                    return Check(True, "连接成功")
            except OSError as exc:
                last_check = error_check(exc)
        return last_check

    tcp = bounded(connect, 4.1, Check(False, "TCP 连接超时", kind="timeout"))
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
    except (OSError, HTTPException) as exc:
        return error_check(exc, tunnel=True)
    except ValueError:
        return Check(False, "代理响应无效或目标隧道被拒绝", kind="proxy_tunnel")


def detect_proxy(candidate_ports=None):
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
    if candidate_ports is not None:
        candidate_ports.update(port for _, port in endpoints)
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


def diagnose(custom, proxy, progress, *, candidate_ports=()) -> DiagnosticResult:
    targets = SITES + ((("自定义网站", custom),) if custom else ())
    ports = tuple(sorted(set(COMMON_PORTS) | set(candidate_ports) | ({proxy.port} if proxy and
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
    direct_ip = (Check(True, "已从 Cloudflare 取得出口公网 IP", ip=direct.ip,
                       country_code=direct.country_code)
                 if direct.ip else request_check(IP_URL, read_ip=True))
    tunnel = via = via_ip = None
    if proxy:
        progress(55, "正在验证代理协议握手")
        tunnel = bounded(lambda: proxy_handshake(proxy), 6,
                         Check(False, "握手超时或无法完成", kind="timeout"))
        with ThreadPoolExecutor(max_workers=len(targets)) as pool:
            pending = {pool.submit(request_check, url, proxy): i
                       for i, (_, url) in enumerate(targets)}
            for count, future in enumerate(as_completed(pending), 1):
                i = pending[future]
                sites[i] = replace(sites[i], proxy_https=future.result())
                progress(55 + int(25 * count / len(targets)), f"网站代理 {count}/{len(targets)}")
        progress(85, "正在通过指定代理访问外网及查询出口")
        via = request_check(ROUTE_URL, proxy, require_2xx=True, trace=True)
        via_ip = (Check(True, "已从 Cloudflare 取得出口公网 IP", ip=via.ip,
                        country_code=via.country_code)
                  if via.ip else request_check(IP_URL, proxy, read_ip=True))
        if (not tunnel.ok and not via.ok and proxy.is_local and local is not None
                and not local.get(proxy.port)
                and tunnel.kind in {"connection", "timeout", "proxy_connection"}):
            tunnel = Check(False, f"本机端口 {proxy.port} 未监听", kind="port_not_listening")
    progress(100, "检测完成")
    return DiagnosticResult(
        ports=ports,
        listeners=local,
        settings=config,
        sites=sites,
        direct_https=direct,
        direct_exit=direct_ip,
        proxy_tunnel=tunnel,
        proxy_https=via,
        proxy_exit=via_ip,
    )
