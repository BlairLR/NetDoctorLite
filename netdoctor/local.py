"""Read-only inspection of local TCP listeners and Windows proxy settings."""

import ctypes as ct
from ctypes import wintypes as wt
from ipaddress import ip_address
import os
from urllib.parse import urlsplit

import psutil

from .model import Listener

ENV_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")
PROXY_PROCESSES = frozenset({
    "flclashcore.exe", "clash.exe", "clash-meta.exe", "mihomo.exe",
    "sing-box.exe", "xray.exe", "v2ray.exe", "hysteria.exe", "naive.exe",
    "sslocal.exe", "shadowsocks.exe", "trojan.exe",
})


def listeners(ports, *, include_proxy_processes=False):
    try:
        rows = psutil.net_connections(kind="tcp")
    except (psutil.Error, OSError, RuntimeError):
        return None
    results = {port: [] for port in ports}
    names = {}
    for row in rows:
        if row.status != psutil.CONN_LISTEN or not row.laddr:
            continue
        if row.laddr.port not in results and not include_proxy_processes:
            continue
        if row.pid not in names:
            try:
                names[row.pid] = psutil.Process(row.pid).name() if row.pid is not None else "未知"
            except (psutil.Error, OSError, RuntimeError):
                names[row.pid] = "无法读取"
        address = row.laddr.ip
        process = names[row.pid]
        if row.laddr.port in results or process.lower() in PROXY_PROCESSES:
            results.setdefault(row.laddr.port, []).append(
                Listener(row.laddr.port, address, row.pid, process))
    for group in results.values():
        group.sort(key=lambda row: (row.address, row.pid or 0))
    return results


def windows_proxy(*, include_local_ports=False):
    class Config(ct.Structure):
        _fields_ = [
            ("auto_detect", wt.BOOL), ("pac", ct.c_void_p),
            ("proxy", ct.c_void_p), ("bypass", ct.c_void_p),
        ]

    try:
        read = ct.WinDLL("winhttp", use_last_error=True).WinHttpGetIEProxyConfigForCurrentUser
        read.argtypes = [ct.POINTER(Config)]
        read.restype = wt.BOOL
        free = ct.WinDLL("kernel32").GlobalFree
        free.argtypes = [ct.c_void_p]
        free.restype = ct.c_void_p
        cfg = Config()
        try:
            if not read(ct.byref(cfg)):
                return () if include_local_ports else ("Windows 系统代理：无法读取当前用户设置",)
            if include_local_ports:
                return local_proxy_addresses(ct.wstring_at(cfg.proxy)) if cfg.proxy else ()
            return (
                f"Windows 手动代理：{'已启用（地址已隐藏）' if cfg.proxy else '未启用'}",
                f"Windows 自动检测：{'已启用' if cfg.auto_detect else '未启用'}",
                f"Windows PAC 脚本：{'已配置（地址已隐藏）' if cfg.pac else '未配置'}",
            )
        finally:
            for ptr in (cfg.pac, cfg.proxy, cfg.bypass):
                if ptr:
                    free(ptr)
    except (AttributeError, OSError):
        return () if include_local_ports else ("Windows 系统代理：无法读取",)


def local_proxy_addresses(settings):
    """Keep only local manual-proxy endpoints, without credentials."""
    endpoints = []
    for entry in settings.split(";"):
        scheme, sep, value = entry.partition("=")
        if sep and scheme.strip().lower() not in ("http", "https", "socks", "socks5"):
            continue
        value = (value if sep else entry).strip()
        try:
            parsed = urlsplit(value if "://" in value else "//" + value)
            if (parsed.scheme not in ("", "http", "socks5", "socks5h")
                    or "@" in parsed.netloc or not parsed.port or not parsed.hostname
                    or parsed.path or parsed.query or parsed.fragment):
                continue
            if parsed.hostname == "localhost":
                endpoints.extend((host, parsed.port) for host in ("127.0.0.1", "::1"))
            elif ip_address(parsed.hostname).is_loopback:
                endpoints.append((str(ip_address(parsed.hostname)), parsed.port))
        except ValueError:
            continue
    return tuple(dict.fromkeys(endpoints))


def registry_env(root, path):
    import winreg

    try:
        with winreg.OpenKey(root, path, access=winreg.KEY_READ) as key:
            result = {}
            for name in ENV_KEYS:
                try:
                    value, _ = winreg.QueryValueEx(key, name)
                    result[name] = "已设置" if value else "未设置"
                except FileNotFoundError:
                    result[name] = "未设置"
                except OSError:
                    result[name] = "无法读取"
            return result
    except FileNotFoundError:
        return dict.fromkeys(ENV_KEYS, "未设置")
    except OSError:
        return dict.fromkeys(ENV_KEYS, "无法读取")


def configuration():
    import winreg

    scopes = (
        ("当前进程", {key: "已设置" if os.environ.get(key) else "未设置" for key in ENV_KEYS}),
        ("当前用户", registry_env(winreg.HKEY_CURRENT_USER, r"Environment")),
        ("系统", registry_env(winreg.HKEY_LOCAL_MACHINE,
                              r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")),
    )
    return windows_proxy() + tuple(
        f"{scope}环境变量： " + "  /  ".join(f"{key} {values[key]}" for key in ENV_KEYS)
        for scope, values in scopes
    )
