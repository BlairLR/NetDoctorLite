"""Read-only inspection of local TCP listeners and Windows proxy settings."""

import ctypes as ct
from ctypes import wintypes as wt
import os

import psutil

from .model import Listener

ENV_KEYS = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")


def listeners(ports):
    try:
        rows = psutil.net_connections(kind="tcp")
    except (psutil.Error, OSError, RuntimeError):
        return None
    results = {port: [] for port in ports}
    names = {}
    for row in rows:
        if row.status != psutil.CONN_LISTEN or not row.laddr or row.laddr.port not in results:
            continue
        if row.pid not in names:
            try:
                names[row.pid] = psutil.Process(row.pid).name() if row.pid is not None else "未知"
            except (psutil.Error, OSError, RuntimeError):
                names[row.pid] = "无法读取"
        address = row.laddr.ip
        results[row.laddr.port].append(Listener(row.laddr.port, address, row.pid, names[row.pid]))
    for group in results.values():
        group.sort(key=lambda row: (row.address, row.pid or 0))
    return results


def windows_proxy():
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
                return ("Windows 系统代理：无法读取当前用户设置",)
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
        return ("Windows 系统代理：无法读取",)


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
