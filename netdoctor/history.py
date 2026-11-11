"""Local, versioned snapshots of completed diagnostic runs."""

from dataclasses import asdict, dataclass
from datetime import datetime
import hashlib
from ipaddress import ip_address
import json
import msvcrt
import os
from pathlib import Path
from tempfile import NamedTemporaryFile
from uuid import uuid4

from .model import IP_URL, ROUTE_URL, SITES, Check, DiagnosticResult, Listener, Proxy, SiteResult

HISTORY_LIMIT = 40
SCHEMA_VERSION = 1
# Increase when probe parameters or the interpretation of results changes.
PROBE_POLICY = "https-get-no-redirect-tls-verified-v1"
VPN_STATES = ("未标记", "VPN 已连接", "VPN 未连接")
MODES = {"direct": "仅直连", "auto": "自动代理", "manual": "指定代理"}


def fingerprint(value):
    payload = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ProxyInfo:
    protocol: str
    port: int
    is_local: bool


@dataclass(frozen=True)
class Profile:
    targets: str
    policy: str
    mode: str
    endpoint: str | None
    auth: bool


def make_profile(custom, mode, proxy: Proxy | None):
    endpoint = fingerprint([proxy.protocol, proxy.host, proxy.port]) if proxy else None
    return Profile(fingerprint([SITES, custom, ROUTE_URL, IP_URL]), PROBE_POLICY,
                   mode, endpoint, bool(proxy and proxy.username))


@dataclass(frozen=True)
class Snapshot:
    id: str
    time: str
    vpn: str
    profile: Profile
    proxy: ProxyInfo | None
    note: str
    result: DiagnosticResult

    @property
    def mode_label(self):
        mode = MODES[self.profile.mode]
        if self.proxy:
            return f"{mode} · {self.proxy.protocol} · 端口 {self.proxy.port}"
        if self.profile.mode == "auto":
            return f"{mode} · 未选出代理"
        return mode

    @property
    def display_time(self):
        return datetime.fromisoformat(self.time).strftime("%Y-%m-%d %H:%M:%S %z")

    @classmethod
    def capture(cls, result: DiagnosticResult, custom, mode, proxy: Proxy | None, vpn, note, started):
        profile = make_profile(custom, mode, proxy)
        info = ProxyInfo(proxy.protocol, proxy.port, proxy.is_local) if proxy else None
        return cls(uuid4().hex, started, vpn, profile, info, note, result)


def encode_snapshot(snapshot):
    data = asdict(snapshot)
    result = data["result"]
    # Keep the schema 1 disk keys independent from the Python field names.
    data["result"] = {
        "ports": result["ports"],
        "listeners": result["listeners"],
        "settings": result["settings"],
        "sites": result["sites"],
        "direct": result["direct_https"],
        "direct_ip": result["direct_exit"],
        "tunnel": result["proxy_tunnel"],
        "via": result["proxy_https"],
        "via_ip": result["proxy_exit"],
    }
    return data


def decode_check(data):
    check = Check(**data)
    if (type(check.ok) is not bool or not isinstance(check.detail, str)
            or (check.code is not None and (type(check.code) is not int or not 100 <= check.code <= 599))
            or (check.ms is not None and (type(check.ms) is not int or check.ms < 0))):
        raise ValueError("Invalid diagnostic check")
    if check.ip is not None and not ip_address(check.ip).is_global:
        raise ValueError("Invalid public IP")
    return check


def decode_snapshot(data):
    values = data["result"]
    profile = Profile(**data["profile"])
    proxy = ProxyInfo(**data["proxy"]) if data["proxy"] is not None else None
    recorded = datetime.fromisoformat(data["time"])
    if (recorded.utcoffset() is None or profile.mode not in MODES or data["vpn"] not in VPN_STATES
            or not isinstance(data["id"], str) or not isinstance(data["note"], str)):
        raise ValueError("Invalid history metadata")
    ports = tuple(values["ports"])
    local = values["listeners"]
    if local is not None:
        local = {int(port): [Listener(**row) for row in rows] for port, rows in local.items()}
        if set(local) != set(ports):
            raise ValueError("Missing listener results")
    sites = [SiteResult(row["name"], decode_check(row["dns"]), decode_check(row["tcp"]),
                        decode_check(row["https"]),
                        decode_check(row["proxy_https"]) if row["proxy_https"] is not None else None)
             for row in values["sites"]]
    def route_check(key):
        raw = values[key]
        return decode_check(raw) if raw is not None else None

    direct = route_check("direct")
    direct_exit = route_check("direct_ip")
    tunnel = route_check("tunnel")
    via = route_check("via")
    proxy_exit = route_check("via_ip")
    if (direct is None or direct_exit is None
            or (via is not None and (tunnel is None or proxy_exit is None))):
        raise ValueError("Missing route results")
    result = DiagnosticResult(
        ports=ports,
        listeners=local,
        settings=tuple(values["settings"]),
        sites=sites,
        direct_https=direct,
        direct_exit=direct_exit,
        proxy_tunnel=tunnel,
        proxy_https=via,
        proxy_exit=proxy_exit,
    )
    return Snapshot(data["id"], data["time"], data["vpn"], profile, proxy, data["note"], result)


class HistoryError(Exception):
    pass


class HistoryStore:
    def __init__(self, path=None):
        default_root = Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local")
        self.path = Path(path) if path is not None else default_root / "NetDoctorLite" / "history.json"
        self.reload()

    def reload(self):
        self.records = ()
        self.baseline_id = None
        self.read_error = False
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            if data["schema"] != SCHEMA_VERSION:
                raise ValueError("Unsupported history schema")
            records = tuple(decode_snapshot(item) for item in data["records"])
            ids = {record.id for record in records}
            if len(ids) != len(records) or len(records) > HISTORY_LIMIT:
                raise ValueError("Invalid history record count")
            baseline_id = data["baseline_id"]
            if baseline_id is not None and baseline_id not in ids:
                raise ValueError("Unknown baseline")
        except FileNotFoundError:
            return
        except (OSError, ValueError, TypeError, KeyError, AttributeError):
            self.read_error = True
            return
        self.records = records
        self.baseline_id = baseline_id

    @property
    def baseline(self):
        return next((record for record in self.records if record.id == self.baseline_id), None)

    def save(self, snapshot):
        self._update(self._save, snapshot)

    def _save(self, snapshot):
        records = (snapshot,) + tuple(r for r in self.records if r.id != snapshot.id)
        if len(records) > HISTORY_LIMIT:
            # The baseline stays available even when older than the other entries.
            index = next(i for i in range(len(records) - 1, -1, -1)
                         if records[i].id != self.baseline_id)
            records = records[:index] + records[index + 1:]
        self._write(records, self.baseline_id)

    def set_baseline(self, record_id):
        self._update(self._set_baseline, record_id)

    def _set_baseline(self, record_id):
        if record_id is not None and not any(r.id == record_id for r in self.records):
            raise HistoryError("这次检测尚未保存到历史。")
        self._write(self.records, record_id)

    def delete(self, record_id):
        self.delete_many((record_id,))

    def delete_many(self, ids):
        self._update(self._delete, set(ids))

    def _delete(self, ids):
        records = tuple(r for r in self.records if r.id not in ids)
        baseline_id = None if self.baseline_id in ids else self.baseline_id
        self._write(records, baseline_id)

    def _update(self, operation, value):
        # Reload under the write lock so another instance's changes are preserved.
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.with_suffix(".lock").open("a+b") as lock:
                lock.seek(0)
                try:
                    msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
                except OSError as exc:
                    raise HistoryError("历史文件正在写入，请稍后重试。") from exc
                self.reload()
                if self.read_error:
                    raise HistoryError("历史文件无法读取。请先备份并移走 history.json。")
                operation(value)
        except OSError as exc:
            raise HistoryError("无法打开本地历史目录，请检查写入权限。") from exc

    def _write(self, records, baseline_id):
        payload = {"schema": SCHEMA_VERSION, "baseline_id": baseline_id,
                   "records": [encode_snapshot(record) for record in records]}
        temp_path = None
        try:
            with NamedTemporaryFile(mode="w", encoding="utf-8", dir=self.path.parent,
                                    prefix="history-", suffix=".tmp", delete=False) as output:
                temp_path = Path(output.name)
                json.dump(payload, output, ensure_ascii=False, separators=(",", ":"))
                output.flush()
                os.fsync(output.fileno())
            temp_path.replace(self.path)
        except OSError as exc:
            raise HistoryError("无法写入本地历史。请检查目录权限和可用磁盘空间。") from exc
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass
        self.records = records
        self.baseline_id = baseline_id
