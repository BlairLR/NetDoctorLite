from dataclasses import dataclass, field
from ipaddress import ip_address
import re
from urllib.parse import quote, urlsplit

COMMON_PORTS = (7890, 7891, 1080, 10808, 10809, 12450)
SITES = (
    ("GitHub", "https://github.com/"),
    ("Google", "https://www.google.com/"),
    ("OpenAI", "https://openai.com/"),
    ("Cloudflare", "https://www.cloudflare.com/"),
)
ROUTE_URL = "https://www.cloudflare.com/cdn-cgi/trace"
IP_URL = "https://api.ipify.org/"


def hostname(value: str) -> str:
    if "%" in value:
        raise ValueError
    try:
        return str(ip_address(value))
    except ValueError:
        host = value.encode("idna").decode("ascii").lower()
        labels = host.removesuffix(".").split(".")
        if len(host) > 253 or not all(
            re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
            for part in labels
        ):
            raise ValueError
        return host


def custom_url(value: str) -> str:
    if len(value) > 2048 or any(ord(c) < 33 or ord(c) == 127 for c in value):
        raise ValueError
    parts = urlsplit(value if "://" in value else "https://" + value)
    if parts.scheme != "https" or not parts.hostname or "@" in parts.netloc:
        raise ValueError
    hostname(parts.hostname)
    if parts.port == 0:
        raise ValueError
    return parts._replace(fragment="").geturl()


@dataclass(frozen=True)
class Proxy:
    protocol: str
    host: str = field(repr=False)
    port: int
    username: str = field(default="", repr=False)
    password: str = field(default="", repr=False)

    @property
    def url(self):
        host = f"[{self.host}]" if ":" in self.host else self.host
        auth = ""
        if self.username:
            auth = f"{quote(self.username, safe='')}:{quote(self.password, safe='')}@"
        scheme = "socks5h" if self.protocol == "SOCKS5" else "http"
        return f"{scheme}://{auth}{host}:{self.port}"


@dataclass(frozen=True)
class Check:
    ok: bool
    detail: str
    code: int | None = None
    ms: int | None = None
    ip: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class SiteResult:
    name: str
    dns: Check
    tcp: Check
    https: Check


@dataclass(frozen=True)
class Listener:
    port: int
    address: str
    pid: int | None
    process: str
