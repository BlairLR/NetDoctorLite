"""Compare two snapshots collected under the same test profile."""

from dataclasses import dataclass


class IncompatibleRuns(ValueError):
    pass


@dataclass(frozen=True)
class Change:
    metric: str
    before: str
    after: str
    verdict: str


def profile_mismatches(a, b, *, check_proxy=True):
    mismatches = []
    if a.targets != b.targets:
        mismatches.append("检测目标")
    if a.policy != b.policy:
        mismatches.append("检测参数版本")
    if a.mode != b.mode:
        mismatches.append("直连／代理检测模式")
    if check_proxy and (a.endpoint, a.auth) != (b.endpoint, b.auth):
        mismatches.append("实际代理端点、协议或认证方式")
    return mismatches


def compare_runs(before, after):
    mismatches = profile_mismatches(before.profile, after.profile)
    if mismatches:
        raise IncompatibleRuns("无法对比，以下项目不一致：" + "、".join(mismatches) + "。")
    old_result = before.result
    new_result = after.result
    if [s.name for s in old_result.sites] != [s.name for s in new_result.sites]:
        raise IncompatibleRuns("无法对比，两个记录的网站结果不完整或不一致。")

    rows = []
    for old, new in zip(old_result.sites, new_result.sites):
        rows.extend(check_changes(f"{old.name} · DNS", old.dns, new.dns))
        # TCP is skipped when local DNS did not produce an address.
        rows.extend(check_changes(f"{old.name} · TCP 443",
                                  old.tcp if old.dns.ok else None,
                                  new.tcp if new.dns.ok else None))
        rows.extend(check_changes(f"{old.name} · 直连 HTTPS", old.https, new.https))
        if old.proxy_https is not None or new.proxy_https is not None:
            rows.extend(check_changes(f"{old.name} · 代理 HTTPS", old.proxy_https, new.proxy_https))

    for label, old_http, new_http, old_ip, new_ip in (
        ("直连", old_result.direct_https, new_result.direct_https,
         old_result.direct_exit, new_result.direct_exit),
        ("代理", old_result.proxy_https, new_result.proxy_https,
         old_result.proxy_exit, new_result.proxy_exit),
    ):
        if old_http is None and new_http is None:
            continue
        rows.extend(check_changes(f"通路 · {label} HTTPS", old_http, new_http))
        for field, name in (("ip", "出口 IP"), ("country_code", "出口国家／地区（估算）")):
            old_value = getattr(old_ip, field, None)
            new_value = getattr(new_ip, field, None)
            if field == "ip" and old_value and new_value and old_ip.detail != new_ip.detail:
                verdict = "来源不同"
            elif old_value is None or new_value is None:
                verdict = "数据不足"
            else:
                verdict = "无变化" if old_value == new_value else "已变化"
            rows.append(Change(f"{label} · {name}", old_value or "未取得",
                               new_value or "未取得", verdict))
    return rows


def check_changes(name, old, new):
    def description(check):
        if check is None:
            return "未检测"
        return "成功" if check.ok else f"失败 · {check.detail}"

    if old is None or new is None:
        verdict = "数据不足"
    elif old.ok != new.ok:
        verdict = "改善" if new.ok else "恶化"
    elif description(old) != description(new):
        verdict = "已变化"
    else:
        verdict = "无变化"
    yield Change(name, description(old), description(new), verdict)

    if old and new and (old.code is not None or new.code is not None):
        a, b = old.code, new.code
        if a is None or b is None:
            verdict = "已变化"  # Reachability change is shown in the status row.
        elif a == b:
            verdict = "无变化"
        elif (200 <= a < 400) != (200 <= b < 400):
            verdict = "改善" if 200 <= b < 400 else "恶化"
        else:
            verdict = "已变化"
        yield Change(f"{name} · HTTP", str(a) if a is not None else "无响应",
                     str(b) if b is not None else "无响应", verdict)

    if (old and new and old.ok and new.ok and old.code == new.code
            and old.ms is not None and new.ms is not None):
        delta = new.ms - old.ms
        # A single run is noisy; small differences have no directional rating.
        tolerance = max(50, old.ms * 0.1)
        verdict = "无变化" if abs(delta) < tolerance else ("改善" if delta < 0 else "恶化")
        yield Change(f"{name} · 耗时", f"{old.ms} 毫秒", f"{new.ms} 毫秒", verdict)
    elif (old and old.ms is not None) or (new and new.ms is not None):
        yield Change(f"{name} · 耗时",
                     f"{old.ms} 毫秒" if old and old.ms is not None else "—",
                     f"{new.ms} 毫秒" if new and new.ms is not None else "—", "条件不同")
