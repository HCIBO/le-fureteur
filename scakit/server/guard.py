from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class TargetError(ValueError):
    pass


def host_allowed(host: str, allowed: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for pat in allowed or []:
        pat = pat.lower().strip().rstrip(".")
        if not pat:
            continue
        if pat.startswith("*."):
            base = pat[2:]
            if host == base or host.endswith("." + base):
                return True
        elif host == pat:
            return True
    return False


def _bad_ip(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    if isinstance(a, ipaddress.IPv6Address) and a.ipv4_mapped:
        a = a.ipv4_mapped
    return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast or \
        a.is_unspecified or str(a) == "169.254.169.254"


def resolve(host: str) -> list[str]:
    try:
        return sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
    except socket.gaierror as ex:
        raise TargetError(f"Alan adı çözümlenemedi: {host}") from ex


def check_web_target(url: str, *, role: str, allowed_domains: list[str], allow_internal: bool,
                     resolver=None) -> str:
    p = urlparse(url.strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise TargetError("Yalnızca http:// veya https:// adresleri taranabilir")
    if p.username or p.password:
        raise TargetError("Adreste kullanıcı adı / parola olamaz")
    host = p.hostname
    if role == "customer" and not host_allowed(host, allowed_domains):
        raise TargetError(f"{host} organizasyonunuzun izinli alan adları arasında değil; yöneticinizden ekletin")
    if not allow_internal:
        try:
            ips = [host] if ipaddress.ip_address(host) else []
        except ValueError:
            ips = (resolver or resolve)(host)
        bad = [ip for ip in ips if _bad_ip(ip)]
        if bad:
            raise TargetError(f"İç ağ / ayrılmış adres engellendi ({', '.join(bad)}); yönetici ayarlarından "
                              "iç ağ taramasına izin verilmeli")
    return p._replace(fragment="").geturl()


import contextlib
import contextvars

_GUARD = contextvars.ContextVar("lf_outbound_guard", default=False)
_PROXIES = contextvars.ContextVar("lf_allowed_proxies", default=frozenset())


def allow_proxy(host: str | None, port: int) -> None:
    if host:
        _PROXIES.set(_PROXIES.get() | {(host.lower(), int(port))})
_installed = False


class BlockedAddress(OSError):
    pass


def _install() -> None:
    global _installed
    if _installed:
        return
    from urllib3.util import connection as uc
    original = uc.create_connection

    def guarded(address, *args, **kwargs):
        if not _GUARD.get():
            return original(address, *args, **kwargs)
        host, port = address[0], address[1]
        if (str(host).lower(), int(port)) in _PROXIES.get():
            return original(address, *args, **kwargs)
        try:
            infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
        except socket.gaierror as ex:
            raise BlockedAddress(f"Alan adı çözümlenemedi: {host}") from ex
        ips = []
        for info in infos:
            ip = info[4][0]
            if _bad_ip(ip):
                raise BlockedAddress(f"İç ağ / ayrılmış adres engellendi: {host} → {ip}")
            ips.append((info[0], ip))
        last = None
        for _fam, ip in ips:
            try:
                return original((ip, port), *args, **kwargs)
            except OSError as ex:
                last = ex
        raise last or BlockedAddress(f"Bağlanılamadı: {host}")

    uc.create_connection = guarded
    _installed = True


@contextlib.contextmanager
def outbound_guard(enabled: bool = True):
    _install()
    token = _GUARD.set(bool(enabled))
    try:
        yield
    finally:
        _GUARD.reset(token)


def checked_ips(host: str, port: int) -> list[str] | None:
    if not _GUARD.get():
        return None
    try:
        infos = socket.getaddrinfo(host, port, 0, socket.SOCK_STREAM)
    except socket.gaierror as ex:
        raise BlockedAddress(f"Alan adı çözümlenemedi: {host}") from ex
    ips = []
    for info in infos:
        ip = info[4][0]
        if _bad_ip(ip):
            raise BlockedAddress(f"İç ağ / ayrılmış adres engellendi: {host} → {ip}")
        if ip not in ips:
            ips.append(ip)
    if not ips:
        raise BlockedAddress(f"Alan adı çözümlenemedi: {host}")
    return ips
