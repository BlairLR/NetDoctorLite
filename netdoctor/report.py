"""Display and report formatting. Reports intentionally omit sensitive values."""

from datetime import datetime
from ipaddress import ip_address

from .model import local_host
from .version import __version__


def status(check):
    return "成功" if check.ok else "失败"


def describe(check, *, show_ip=False):
    parts = [status(check), check.detail]
    if check.code is not None:
        parts.append(f"HTTP {check.code}")
    if check.ms is not None:
        parts.append(f"{check.ms} 毫秒")
    if show_ip and check.ip:
        parts.append(check.ip)
    return " · ".join(parts)


def port_rows(ports, local):
    for port in ports:
        if local is None:
            yield (str(port), "无法读取", "—", "—", "—")
        elif not local[port]:
            yield (str(port), "未监听", "—", "—", "—")
        else:
            for row in local[port]:
                yield (str(port), "正在监听", row.address,
                       str(row.pid) if row.pid is not None else "未知", row.process)


def summary(result, proxy, selection_note=""):
    _, local, _, sites, direct, _, tunnel, via, _ = result
    notes = [selection_note] if selection_note else []
    if direct.ok and via and via.ok:
        notes.append("直连和指定代理均可访问测试目标。")
    elif via and via.ok:
        notes.append("直连测试失败，但通过指定代理访问成功。")
    elif direct.ok:
        notes.append("外网直连正常（通路测试目标）。")
    else:
        notes.append("直连未能通过外网通路测试；请查看各网站结果。")
    failed = [s.name for s in sites if not s.dns.ok]
    if failed:
        notes.append("DNS 解析失败或超时：" + "、".join(failed) + "。")
    proxy_only = [s.name for s in sites if not s.https.ok and s.proxy_https and s.proxy_https.ok]
    if proxy_only:
        notes.append("直连未收到 HTTPS 响应，代理收到响应：" + "、".join(proxy_only) + "。")
    if proxy and via and not via.ok:
        is_local = local_host(proxy.host)
        if is_local and local is not None:
            if not local.get(proxy.port):
                notes.append("所选本地代理端口未监听，可能尚未启动。")
            else:
                notes.append("所选端口正在监听，但代理外网访问测试失败。")
        if tunnel and tunnel.ok:
            notes.append("代理握手成功，但访问外网测试失败。")
        else:
            notes.append("未验证代理握手，请检查协议、端口和认证。")
    return "\n".join(notes)


def route_rows(result):
    _, _, _, _, direct, direct_ip, tunnel, via, via_ip = result
    pairs = [("直连外网", direct), ("直连出口公网 IP", direct_ip)]
    if via is not None:
        pairs += [("代理协议握手", tunnel), ("代理访问外网", via), ("代理出口公网 IP", via_ip)]
    for name, check in pairs:
        yield name, check


def comparison(result):
    direct_ip, via_ip = result[5], result[8]
    if via_ip is None:
        return "未启用指定代理测试"
    if not direct_ip.ip or not via_ip.ip:
        return "至少一条通路未取得出口 IP，无法比较"
    if direct_ip.ip == via_ip.ip:
        return "两条通路出口 IP 相同；是否使用代理以指定代理请求为准"
    return "两条通路出口 IP 不同"


def report(result, proxy, selection_note=""):
    ports, local, config, sites, *_ = result
    lines = [f"NetDoctor Lite v{__version__} 网络诊断报告", datetime.now().astimezone().isoformat(timespec="seconds"),
             "", summary(result, proxy, selection_note), "", "【网站连接对比】"]
    for site in sites:
        proxy_status = describe(site.proxy_https) if site.proxy_https else "未检测"
        lines += [site.name, f"  直连 DNS：{describe(site.dns)}",
                  f"  直连 TCP 443：{describe(site.tcp)}",
                  f"  直连 HTTPS：{describe(site.https)}", f"  代理 HTTPS：{proxy_status}"]
    lines += ["", "【本机端口】", "端口 / 监听状态 / 地址 / PID / 进程"]
    for port, state, address, pid, process in port_rows(ports, local):
        if address != "—":
            try:
                addr = ip_address(address)
                if not (addr.is_loopback or addr.is_unspecified):
                    address = "已隐藏"
            except ValueError:
                address = "已隐藏"
        process = "".join(c if c.isprintable() else "?" for c in process)
        lines.append(" / ".join((port, state, address, pid, process)))
    lines += ["", "【系统代理及环境变量】", *config, "", "【外网通路】"]
    if proxy:
        lines.append(f"指定协议：{proxy.protocol}（地址和凭据已隐藏）")
    lines.extend(f"{name}：{describe(check)}" for name, check in route_rows(result))
    lines += [f"出口比较：{comparison(result)}", "",
              "已隐藏自定义网址、代理配置值及出口公网 IP。", ""]
    return "\n".join(lines)
