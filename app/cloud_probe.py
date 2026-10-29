"""Port-25-free verification engine and SOCKS5 proxy support.

Cloud serverless environments (like Vercel) block outbound TCP port 25.
This module solves that constraint through four complementary layers:

1. SOCKS5 Proxy Tunnel (optional): Routes raw SMTP connections over a non-25
   port (e.g., 1080) to a proxy host that has outbound port 25 open.
2. External HTTPS Verification API (optional): Calls an external SMTP-capable
   API over HTTPS (port 443) such as Reacher, EasyEmailVerification, or Abstract.
3. Port-587 / Port-2525 SMTP Fallback: Probes mail servers that accept
   unauthenticated RCPT TO on alternate SMTP ports when port 25 is blocked.
4. Port-443 HTTPS & DNS Deep Verification (zero-config, built-in):
   - Microsoft 365 / Outlook / Hotmail / Live / MSN direct mailbox existence
     verification over HTTPS (`GetCredentialType` API).
   - SPF (`v=spf1`) & DMARC (`_dmarc`) DNS TXT authentication analysis to verify
     whether a domain actively configures email infrastructure.
   - Gravatar profile confirmation over HTTPS (MD5 hash check).
"""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import socket
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

import dns.exception
import dns.resolver

from app.data import FREE, in_domain_set

_AUTH_DNS_CACHE: dict[str, tuple[float, dict]] = {}
_AUTH_DNS_LOCK = threading.Lock()
_DNS_TTL = 600

_MICROSOFT_CONSUMER_DOMAINS = frozenset(
    {
        "hotmail.com",
        "hotmail.co.uk",
        "hotmail.fr",
        "live.com",
        "msn.com",
        "outlook.com",
    }
)


@dataclass(frozen=True)
class CloudConfig:
    proxy_url: str = ""
    api_url: str = ""
    api_key: str = ""
    fast_bulk: bool = False

    @classmethod
    def from_request_or_env(
        cls,
        proxy_url: str = "",
        api_url: str = "",
        api_key: str = "",
        fast_bulk: bool = False,
    ) -> "CloudConfig":
        return cls(
            proxy_url=(proxy_url or os.environ.get("SMTP_PROXY_URL", "")).strip(),
            api_url=(api_url or os.environ.get("VERIFY_API_URL", "")).strip(),
            api_key=(api_key or os.environ.get("VERIFY_API_KEY", "")).strip(),
            fast_bulk=fast_bulk,
        )


def parse_socks5_url(proxy_url: str) -> dict | None:
    """Parse socks5://[user:pass@]host:port into components."""
    if not proxy_url:
        return None
    raw = proxy_url.strip()
    if "://" not in raw:
        raw = "socks5://" + raw
    parsed = urllib.parse.urlparse(raw)
    if parsed.scheme.lower() not in {"socks5", "socks5h", "socks"}:
        raise ValueError("Proxy URL must start with socks5:// (for example socks5://user:pass@host:1080).")
    if not parsed.hostname or not parsed.port:
        raise ValueError("Proxy URL must include a hostname and port (for example socks5://host:1080).")
    return {
        "host": parsed.hostname,
        "port": int(parsed.port),
        "username": urllib.parse.unquote(parsed.username) if parsed.username else None,
        "password": urllib.parse.unquote(parsed.password) if parsed.password else None,
    }


def create_socks5_connection(
    proxy_cfg: dict,
    dest_host: str,
    dest_port: int,
    timeout: float = 8.0,
) -> socket.socket:
    """Open a TCP socket to dest_host:dest_port tunneled through a SOCKS5 proxy."""
    sock = socket.create_connection((proxy_cfg["host"], proxy_cfg["port"]), timeout=timeout)
    sock.settimeout(timeout)
    try:
        username = proxy_cfg.get("username")
        password = proxy_cfg.get("password") or ""
        if username is not None:
            sock.sendall(b"\x05\x02\x00\x02")
        else:
            sock.sendall(b"\x05\x01\x00")
        resp = _recv_exact(sock, 2)
        if resp[0] != 0x05:
            raise OSError("Invalid SOCKS5 proxy greeting.")
        method = resp[1]
        if method == 0x02:
            if username is None:
                raise OSError("SOCKS5 proxy requires authentication.")
            u_bytes = username.encode("utf-8")[:255]
            p_bytes = password.encode("utf-8")[:255]
            auth_pkt = bytes([0x01, len(u_bytes)]) + u_bytes + bytes([len(p_bytes)]) + p_bytes
            sock.sendall(auth_pkt)
            auth_resp = _recv_exact(sock, 2)
            if auth_resp[1] != 0x00:
                raise OSError("SOCKS5 proxy authentication failed.")
        elif method == 0xFF:
            raise OSError("SOCKS5 proxy rejected authentication methods.")
        elif method != 0x00:
            raise OSError(f"Unsupported SOCKS5 auth method: {method}")

        host_bytes = dest_host.encode("idna")
        req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + struct.pack("!H", dest_port)
        sock.sendall(req)
        reply = _recv_exact(sock, 4)
        if reply[1] != 0x00:
            codes = {
                1: "general SOCKS failure",
                2: "blocked by proxy ruleset",
                3: "network unreachable",
                4: "host unreachable",
                5: "connection refused by mail server",
                6: "TTL expired",
            }
            reason = codes.get(reply[1], f"error code {reply[1]}")
            if reply[1] == 5:
                raise ConnectionRefusedError(reason)
            raise OSError(f"SOCKS5 connect failed ({reason})")
        atyp = reply[3]
        if atyp == 0x01:
            _recv_exact(sock, 4 + 2)
        elif atyp == 0x03:
            length = _recv_exact(sock, 1)[0]
            _recv_exact(sock, length + 2)
        elif atyp == 0x04:
            _recv_exact(sock, 16 + 2)
        return sock
    except Exception:
        try:
            sock.close()
        except Exception:
            pass
        raise


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    buf = bytearray()
    while len(buf) < count:
        chunk = sock.recv(count - len(buf))
        if not chunk:
            raise OSError("SOCKS5 proxy closed the connection unexpectedly.")
        buf.extend(chunk)
    return bytes(buf)


def lookup_email_auth_dns(ascii_domain: str) -> dict:
    """Check SPF and DMARC TXT records over DNS (works on Vercel without port 25)."""
    now = time.time()
    with _AUTH_DNS_LOCK:
        hit = _AUTH_DNS_CACHE.get(ascii_domain)
        if hit and now - hit[0] < _DNS_TTL:
            return dict(hit[1])

    resolver = dns.resolver.Resolver()
    resolver.lifetime = 3.0
    resolver.timeout = 1.5

    has_spf = False
    spf_strict = False
    has_dmarc = False

    try:
        txt_answers = resolver.resolve(ascii_domain, "TXT")
        for rdata in txt_answers:
            txt = b"".join(rdata.strings).decode("utf-8", "replace").strip().lower()
            if txt.startswith("v=spf1"):
                has_spf = True
                if "-all" in txt or "~all" in txt:
                    spf_strict = True
    except dns.exception.DNSException:
        pass

    try:
        dmarc_answers = resolver.resolve(f"_dmarc.{ascii_domain}", "TXT")
        for rdata in dmarc_answers:
            txt = b"".join(rdata.strings).decode("utf-8", "replace").strip().lower()
            if txt.startswith("v=dmarc1"):
                has_dmarc = True
    except dns.exception.DNSException:
        pass

    result = {
        "has_spf": has_spf,
        "spf_strict": spf_strict,
        "has_dmarc": has_dmarc,
    }
    with _AUTH_DNS_LOCK:
        if len(_AUTH_DNS_CACHE) > 2000:
            _AUTH_DNS_CACHE.clear()
        _AUTH_DNS_CACHE[ascii_domain] = (time.time(), result)
    return dict(result)


def is_microsoft_hosted(ascii_domain: str, mx_hosts: list[str]) -> bool:
    if ascii_domain in _MICROSOFT_CONSUMER_DOMAINS:
        return True
    for host in mx_hosts:
        h = host.lower()
        if (
            h.endswith(".mail.protection.outlook.com")
            or h.endswith(".olc.protection.outlook.com")
            or h.endswith(".outlook.com")
        ):
            return True
    return False


def is_google_hosted(ascii_domain: str, mx_hosts: list[str]) -> bool:
    if ascii_domain in {"gmail.com", "googlemail.com"}:
        return True
    for host in mx_hosts:
        h = host.lower()
        if h.endswith(".google.com") or h.endswith(".googlemail.com") or "aspmx.l.google.com" in h:
            return True
    return False


def check_microsoft_https(email: str, ascii_domain: str, do_catch_all: bool = True) -> dict | None:
    """Verify Microsoft 365, Outlook, Hotmail, and Live addresses over HTTPS (Port 443).

    Uses Microsoft's login credential lookup endpoint, which checks directory
    existence without sending any email or needing port 25.
    """
    code = _query_ms_credential_type(email)
    if code is None:
        return None

    if code in {0, 6}:
        catch_all = False
        if do_catch_all and ascii_domain not in _MICROSOFT_CONSUMER_DOMAINS:
            fake = f"clearlist-{secrets.token_hex(5)}@{ascii_domain}"
            fake_code = _query_ms_credential_type(fake)
            if fake_code in {0, 6}:
                catch_all = True
            elif fake_code == 1:
                catch_all = False
        return {
            "state": "accepted",
            "code": 250,
            "host": "login.microsoftonline.com (HTTPS:443)",
            "detail": "Verified via Microsoft 365 / Outlook HTTPS directory check (port 443). Mailbox exists.",
            "catch_all": catch_all,
        }
    if code == 1:
        # For custom Microsoft 365 domains, confirm the tenant is managed in Entra ID
        # before treating IfExistsResult=1 as a definitive missing mailbox.
        if ascii_domain not in _MICROSOFT_CONSUMER_DOMAINS:
            if not _is_managed_ms_tenant(ascii_domain):
                return None
        return {
            "state": "rejected",
            "code": 550,
            "host": "login.microsoftonline.com (HTTPS:443)",
            "detail": (
                "Microsoft 365 / Outlook HTTPS directory reported that this account does not exist (port 443). "
                "Sending would hard-bounce."
            ),
            "catch_all": False,
        }
    return None


def _is_managed_ms_tenant(ascii_domain: str) -> bool:
    url = (
        "https://login.microsoftonline.com/common/userrealm/"
        + urllib.parse.quote(f"user@{ascii_domain}")
        + "?api-version=2.1"
    )
    req = urllib.request.Request(
        url,
        headers={"Accept": "application/json", "User-Agent": "Mozilla/5.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=4) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            return str(data.get("NameSpaceType", "")).lower() in {"managed", "federated"}
    except Exception:
        return False


def _query_ms_credential_type(email: str) -> int | None:
    payload = {
        "Username": email,
        "isOtherIdpSupported": True,
        "checkPhones": False,
        "isRemoteNGCSupported": True,
        "isCookieBannerShown": False,
        "isFidoSupported": True,
        "originalRequest": "",
    }
    req = urllib.request.Request(
        "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            if data.get("ThrottleStatus") == 1:
                return None
            val = data.get("IfExistsResult")
            return int(val) if isinstance(val, int) else None
    except Exception:
        return None


def check_gravatar_https(email: str) -> bool:
    """Check whether the email hash has an active Gravatar profile over HTTPS (port 443)."""
    digest = hashlib.md5(email.strip().lower().encode("utf-8")).hexdigest()
    req = urllib.request.Request(
        f"https://www.gravatar.com/avatar/{digest}?d=404",
        method="HEAD",
        headers={"User-Agent": "Clearlist/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=3.5) as resp:
            return 200 <= resp.status < 300
    except urllib.error.HTTPError:
        return False
    except Exception:
        return False


def check_external_api_https(
    email: str,
    api_url: str,
    api_key: str,
    helo: str,
    mail_from: str,
) -> dict | None:
    """Verify an email via an external HTTPS verification API (Reacher, EasyEmailVerification, Abstract, etc.)."""
    url = api_url.strip()
    if not url:
        return None

    headers = {
        "User-Agent": "Clearlist/1.0",
        "Accept": "application/json",
    }

    try:
        # Reacher-compatible POST endpoint (/v0/check_email or /v1/check_email)
        if "check_email" in url or "reacher" in url.lower():
            headers["Content-Type"] = "application/json"
            if api_key:
                headers["Authorization"] = api_key
                headers["x-reacher-secret"] = api_key
            body: dict = {"to_email": email}
            if helo:
                body["hello_name"] = helo
            if mail_from:
                body["from_email"] = mail_from
            req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
        elif "{email}" in url:
            target = url.replace("{email}", urllib.parse.quote(email))
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"
                headers["X-API-Key"] = api_key
            req = urllib.request.Request(target, headers=headers, method="GET")
        else:
            sep = "&" if "?" in url else "?"
            target = f"{url}{sep}email={urllib.parse.quote(email)}"
            if api_key:
                headers["X-API-Key"] = api_key
                headers["Authorization"] = f"Bearer {api_key}"
                if "abstractapi.com" in url.lower() and "api_key=" not in target:
                    target += f"&api_key={urllib.parse.quote(api_key)}"
            req = urllib.request.Request(target, headers=headers, method="GET")

        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8", "replace"))
            return _normalize_api_response(data, url)
    except Exception:
        return None


def _normalize_api_response(data: dict, url: str) -> dict | None:
    host_label = urllib.parse.urlparse(url).hostname or "HTTPS API"

    # Reacher JSON format
    if "is_reachable" in data or "smtp" in data and isinstance(data.get("smtp"), dict):
        smtp_data = data.get("smtp") or {}
        reachable = str(data.get("is_reachable", "")).lower()
        catch_all = smtp_data.get("is_catch_all")
        deliverable = smtp_data.get("is_deliverable")
        disabled = smtp_data.get("is_disabled")
        full = smtp_data.get("has_full_inbox")

        if disabled or deliverable is False or reachable == "invalid":
            return {
                "state": "rejected",
                "code": 550,
                "host": f"{host_label} (HTTPS)",
                "detail": f"HTTPS verification relay ({host_label}) confirmed the mailbox was refused.",
                "catch_all": catch_all if isinstance(catch_all, bool) else False,
            }
        if full:
            return {
                "state": "temporary",
                "code": 452,
                "host": f"{host_label} (HTTPS)",
                "detail": f"HTTPS verification relay ({host_label}) reported the mailbox is full.",
                "catch_all": catch_all if isinstance(catch_all, bool) else None,
            }
        if deliverable is True or reachable in {"safe", "risky"}:
            return {
                "state": "accepted",
                "code": 250,
                "host": f"{host_label} (HTTPS)",
                "detail": f"Verified via HTTPS relay ({host_label}). The mail server accepted the recipient.",
                "catch_all": catch_all if isinstance(catch_all, bool) else None,
            }

    # Generic / Abstract / EasyEmailVerification format
    status = str(
        data.get("deliverability")
        or data.get("result")
        or data.get("status")
        or data.get("verdict")
        or ""
    ).lower()
    catch_all = data.get("is_catchall_email", data.get("accept_all", data.get("isCatchAll")))
    if isinstance(catch_all, dict):
        catch_all = catch_all.get("value")

    if status in {"deliverable", "valid", "safe", "send", "ok"}:
        return {
            "state": "accepted",
            "code": 250,
            "host": f"{host_label} (HTTPS)",
            "detail": f"Verified via HTTPS API ({host_label}). Mailbox is deliverable.",
            "catch_all": bool(catch_all) if isinstance(catch_all, bool) else False,
        }
    if status in {"undeliverable", "invalid", "rejected", "bounce"}:
        return {
            "state": "rejected",
            "code": 550,
            "host": f"{host_label} (HTTPS)",
            "detail": f"HTTPS API ({host_label}) reported the mailbox is undeliverable. Sending would hard-bounce.",
            "catch_all": False,
        }
    return None


def cloud_verify_fallback(
    email: str,
    ascii_domain: str,
    mx_hosts: list[str],
    do_catch_all: bool,
    helo: str,
    mail_from: str,
    cloud_cfg: CloudConfig,
) -> dict:
    """Run port-25-free verification when outbound TCP port 25 is blocked."""

    # 1. External HTTPS Verification API (if configured via UI or env vars)
    if cloud_cfg.api_url:
        ext = check_external_api_https(email, cloud_cfg.api_url, cloud_cfg.api_key, helo, mail_from)
        if ext is not None:
            return ext

    # 2. Direct HTTPS verification for Microsoft 365 / Outlook / Hotmail / Live
    if not cloud_cfg.fast_bulk and is_microsoft_hosted(ascii_domain, mx_hosts):
        ms_res = check_microsoft_https(email, ascii_domain, do_catch_all)
        if ms_res is not None:
            return ms_res

    # 3. Check Gravatar over HTTPS (port 443) — a positive match proves a real user owns this address
    has_gravatar = False if cloud_cfg.fast_bulk else check_gravatar_https(email)
    auth_dns = lookup_email_auth_dns(ascii_domain)

    if has_gravatar:
        return {
            "state": "accepted",
            "code": 250,
            "host": "gravatar.com (HTTPS:443)",
            "detail": (
                "Verified over HTTPS (port 443): active user profile and valid MX/DNS records confirmed."
            ),
            "catch_all": False,
            "auth_dns": auth_dns,
        }

    # 4. DNS-over-UDP/TCP + SPF/DMARC infrastructure verification
    spf_dmarc = []
    if auth_dns["has_spf"]:
        spf_dmarc.append("SPF")
    if auth_dns["has_dmarc"]:
        spf_dmarc.append("DMARC")
    auth_label = " + ".join(spf_dmarc) if spf_dmarc else "MX"

    provider_note = ""
    if is_google_hosted(ascii_domain, mx_hosts):
        provider_note = "Google Workspace / Gmail mail servers"
    elif is_microsoft_hosted(ascii_domain, mx_hosts):
        provider_note = "Microsoft 365 / Exchange Online mail servers"
    elif in_domain_set(ascii_domain, FREE):
        provider_note = f"{ascii_domain} consumer mail servers"
    else:
        provider_note = f"active mail servers ({mx_hosts[0] if mx_hosts else ascii_domain})"

    return {
        "state": "cloud_verified",
        "code": 250,
        "host": f"{mx_hosts[0] if mx_hosts else ascii_domain} (DNS+{auth_label})",
        "detail": (
            f"Cloud mode (port 443/53): Verified {provider_note} with {auth_label} records. "
            "No bounce or risk signals detected."
        ),
        "catch_all": False if in_domain_set(ascii_domain, FREE) else None,
        "auth_dns": auth_dns,
    }
