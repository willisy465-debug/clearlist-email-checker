"""Email verification that never sends a message.

Pipeline for each address:
1. Syntax and reserved-domain checks.
2. DNS, including MX records and the null-MX signal.
3. SMTP handshake through RCPT TO, then QUIT. DATA is never issued.
4. Risk signals: disposable, alias, typo, role, test, trap, catch-all.

Ambiguous SMTP refusals are not treated as hard bounces. Many servers
reject the probe because of the sender IP, not because the mailbox is missing.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import secrets
import smtplib
import socket
import ssl
import threading
import time
from dataclasses import dataclass

import dns.exception
import dns.resolver

from app.cloud_probe import (
    CloudConfig,
    cloud_verify_fallback,
    create_socks5_connection,
    lookup_email_auth_dns,
    parse_socks5_url,
)
from app.data import (
    ALIAS,
    DISPOSABLE,
    FREE,
    RESERVED_DOMAINS,
    RESERVED_TLDS,
    in_domain_set,
    local_kinds,
    suggest_typo,
)

log = logging.getLogger("clearlist")

_DNS_TTL = 600
_dns_cache: dict[str, tuple[float, dict]] = {}
_dns_lock = threading.Lock()
_catch_cache: dict[str, bool] = {}
_catch_lock = threading.Lock()
_domain_sems: dict[str, threading.Semaphore] = {}
_domain_sem_lock = threading.Lock()
_probe_lock = threading.Lock()
_probe_state = {"at": 0.0, "open": None, "detail": ""}

_PROBE_HOSTS = (
    "gmail-smtp-in.l.google.com",
    "mx01.mail.icloud.com",
)
_LOCAL_ATOM = re.compile(r"[A-Za-z0-9!#$%&'*+/=?^_`{|}~.\-]+")


@dataclass(frozen=True)
class Job:
    smtp: bool
    catch_all: bool
    helo: str
    mail_from: str
    smtp_mode: str
    smtp_mode_detail: str
    cloud_cfg: CloudConfig = CloudConfig()


def default_helo() -> str:
    host = socket.getfqdn().strip().rstrip(".").lower()
    labels = host.split(".")
    if len(labels) >= 2 and re.fullmatch(r"[a-z0-9.-]+", host):
        tld = labels[-1]
        if tld.isalpha() and tld not in {
            "local",
            "home",
            "lan",
            "internal",
            "localdomain",
            "localhost",
        }:
            return host
    return "clearlist.local"


def probe_port25(refresh: bool = False, proxy_url: str = "") -> tuple[bool, str]:
    """See whether this network (or configured SOCKS5 proxy) can reach port 25."""

    if proxy_url.strip():
        proxy_cfg = parse_socks5_url(proxy_url)
        if proxy_cfg:
            errors: list[str] = []
            for host in _PROBE_HOSTS:
                try:
                    with create_socks5_connection(proxy_cfg, host, 25, timeout=3.5):
                        return True, f"SOCKS5 proxy ({proxy_cfg['host']}:{proxy_cfg['port']}) connected to port 25."
                except Exception as exc:
                    errors.append(f"{host}: {exc.__class__.__name__}")
            return False, "SOCKS5 proxy could not reach port 25: " + "; ".join(errors)

    if os.environ.get("VERCEL") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return False, "Serverless cloud runtime detected (outbound TCP port 25 is restricted)."

    with _probe_lock:
        now = time.time()
        if (
            not refresh
            and _probe_state["open"] is not None
            and now - float(_probe_state["at"]) < _DNS_TTL
        ):
            return bool(_probe_state["open"]), str(_probe_state["detail"])
        open_, detail = _probe_once()
        _probe_state["at"] = time.time()
        _probe_state["open"] = open_
        _probe_state["detail"] = detail
        return open_, detail


def _probe_once() -> tuple[bool, str]:
    errors: list[str] = []
    for host in _PROBE_HOSTS:
        try:
            with socket.create_connection((host, 25), timeout=2.0):
                return True, "Outbound port 25 accepted a connection."
        except socket.timeout:
            errors.append(f"{host} timed out")
        except TimeoutError:
            errors.append(f"{host} timed out")
        except OSError as exc:
            errors.append(f"{host} refused or failed ({exc.__class__.__name__})")
    detail = "Outbound port 25 did not connect. " + "; ".join(errors)
    return False, detail


def begin_job(
    *,
    smtp: bool,
    catch_all: bool,
    helo: str,
    mail_from: str,
    force_smtp: bool,
    proxy_url: str = "",
    api_url: str = "",
    api_key: str = "",
    fast_bulk: bool = False,
) -> Job:
    cloud_cfg = CloudConfig.from_request_or_env(
        proxy_url=proxy_url,
        api_url=api_url,
        api_key=api_key,
        fast_bulk=fast_bulk,
    )
    if not smtp:
        mode, detail = "disabled", "SMTP is turned off."
    elif cloud_cfg.proxy_url:
        open_, detail = probe_port25(refresh=True, proxy_url=cloud_cfg.proxy_url)
        mode = "proxy" if open_ else "cloud"
    else:
        open_, detail = probe_port25(refresh=False)
        if open_:
            mode = "open"
        else:
            mode = "cloud"
            detail = "Cloud verification active (HTTPS 443 + DNS MX/SPF/DMARC)."
    return Job(
        smtp=smtp,
        catch_all=catch_all,
        helo=helo,
        mail_from=mail_from,
        smtp_mode=mode,
        smtp_mode_detail=detail,
        cloud_cfg=cloud_cfg,
    )


def check_syntax(raw: str) -> dict:
    hidden = bool(re.search(r"[\u200b\u200c\u200d\ufeff\u00a0]", raw))
    text = re.sub(r"[\u200b\u200c\u200d\ufeff\u00a0]", "", raw).strip()
    match = re.search(r"<([^<>]+@[^<>]+)>", text)
    if match:
        text = match.group(1).strip()
    text = re.sub(r"(?i)^mailto:", "", text).strip().strip("<>\"'").strip()

    def fail(detail: str) -> dict:
        return {
            "ok": False,
            "detail": detail,
            "local": "",
            "domain": "",
            "ascii_domain": "",
            "email": text or raw.strip(),
            "hidden_stripped": hidden,
        }

    if not text:
        return fail("The address is empty.")
    if len(text) > 320:
        return fail("The address is too long to be a real mailbox.")
    if any(char in text for char in "\r\n\t "):
        return fail("The address contains whitespace.")
    if text.count("@") == 0:
        return fail("The address is missing an @.")
    if text.count("@") > 1:
        return fail("The address has more than one @.")

    local, domain = text.rsplit("@", 1)
    domain = domain.rstrip(".").lower()
    if not local:
        return fail("The mailbox name before @ is empty.")
    if not domain:
        return fail("The domain is empty.")
    if local.startswith('"') or local.endswith('"'):
        return fail("Quoted mailbox names are not accepted by most sending tools.")
    if len(local) > 64:
        return fail("The mailbox name is longer than 64 characters.")
    if local.startswith(".") or local.endswith("."):
        return fail("The mailbox name cannot start or end with a dot.")
    if ".." in local:
        return fail("The mailbox name has two dots in a row.")
    if not _LOCAL_ATOM.fullmatch(local):
        if re.fullmatch(r"[\w!#$%&'*+/=?^_`{|}~.\-]+", local, flags=re.UNICODE):
            pass
        else:
            return fail("The mailbox name contains a character that is not allowed.")
    if not re.search(r"[A-Za-z0-9]", local) and not re.search(r"\w", local, flags=re.UNICODE):
        return fail("The mailbox name needs a letter or a number.")

    bracketed = domain[1:-1] if domain.startswith("[") and domain.endswith("]") else domain
    try:
        ipaddress.ip_address(bracketed)
        return fail("An IP address is not a usable marketing domain.")
    except ValueError:
        pass

    try:
        ascii_domain = domain.encode("idna").decode("ascii")
    except UnicodeError:
        return fail("The domain contains characters that are not valid in DNS.")

    if len(ascii_domain) > 253:
        return fail("The domain is too long.")
    labels = ascii_domain.split(".")
    if len(labels) < 2:
        return fail("The domain needs a dot and a public ending, such as .com.")
    if any(not label for label in labels):
        return fail("The domain has an empty label.")
    for label in labels:
        if len(label) > 63:
            return fail("A part of the domain is longer than 63 characters.")
        if label.startswith("-") or label.endswith("-"):
            return fail("A domain label cannot start or end with a hyphen.")
        if not re.fullmatch(r"[a-z0-9-]+", label):
            return fail("The domain contains a character that is not allowed.")
    tld = labels[-1]
    if tld.isdigit() or len(tld) < 2:
        return fail("The domain ending is not valid.")
    if tld in RESERVED_TLDS or ascii_domain in RESERVED_DOMAINS:
        return fail("This domain is reserved and cannot receive public mail.")

    return {
        "ok": True,
        "detail": "The address is properly formed.",
        "local": local,
        "domain": domain,
        "ascii_domain": ascii_domain,
        "email": f"{local}@{domain}",
        "hidden_stripped": hidden,
    }


def classify_smtp(code: int, message: str) -> str:
    """Classify an SMTP reply without treating a blocked probe as a dead mailbox."""

    text = " ".join(str(message).lower().split())
    if 200 <= code < 300:
        return "accepted"
    if any(word in text for word in ("quota", "mailbox full", "over quota", "insufficient storage", "5.2.2", "4.2.2")):
        return "temporary"
    if 400 <= code < 500:
        return "temporary"
    if any(word in text for word in ("greylist", "graylist", "try again", "temporarily")):
        return "temporary"

    missing = (
        "user unknown",
        "unknown user",
        "unknown recipient",
        "no such user",
        "no such recipient",
        "no such mailbox",
        "mailbox not found",
        "mailbox unavailable",
        "recipient not found",
        "user not found",
        "recipient does not exist",
        "user does not exist",
        "mailbox does not exist",
        "account does not exist",
        "no mailbox here",
        "nosuchuser",
        "invalid mailbox",
        "invalid recipient",
        "recipient invalid",
        "5.1.1",
        "5.1.10",
        "5.1.2",
    )
    if any(word in text for word in missing):
        return "rejected"
    if any(
        word in text
        for word in (
            "inactive mailbox",
            "account disabled",
            "mailbox disabled",
            "account suspended",
            "mailbox is disabled",
            "5.2.1",
        )
    ):
        return "rejected"

    policy = (
        "spamhaus",
        "block list",
        "blocklist",
        "blacklist",
        "dnsbl",
        "client host rejected",
        "relay access",
        "relay not permitted",
        "not authenticated",
        "authentication required",
        "poor reputation",
        "barracuda",
        "spamcop",
        "banned sending",
        "helo rejected",
        "invalid helo",
        "sender rejected",
        "your ip",
        "access denied",
        "5.7.1",
        "5.7.0",
        "policy rejection",
        "not allowed to",
        "service unavailable",
        "ips blocked",
        "ip blocked",
        "blocked using",
    )
    if any(word in text for word in policy):
        return "policy"
    if "address rejected" in text or "recipient rejected" in text:
        return "rejected"
    if 500 <= code < 600:
        return "policy"
    return "error"


def lookup_domain(ascii_domain: str) -> dict:
    now = time.time()
    with _dns_lock:
        hit = _dns_cache.get(ascii_domain)
        if hit and now - hit[0] < _DNS_TTL:
            cached = hit[1]
            return {
                "state": cached["state"],
                "detail": cached["detail"],
                "hosts": list(cached["hosts"]),
            }
    value = _lookup_domain(ascii_domain)
    with _dns_lock:
        if len(_dns_cache) > 50000:
            _dns_cache.clear()
        _dns_cache[ascii_domain] = (time.time(), value)
    return {
        "state": value["state"],
        "detail": value["detail"],
        "hosts": list(value["hosts"]),
    }


def _lookup_domain(domain: str) -> dict:
    resolver = dns.resolver.Resolver()
    resolver.lifetime = 4
    resolver.timeout = 2
    try:
        try:
            answers = resolver.resolve(domain, "MX")
        except dns.resolver.NoAnswer:
            answers = None
        if answers is not None:
            records: list[tuple[int, str | None]] = []
            for rdata in answers:
                exchange = str(rdata.exchange).rstrip(".").lower()
                records.append((int(rdata.preference), exchange or None))
            records.sort(key=lambda item: item[0])
            hosts = [host for _, host in records if host]
            if hosts:
                shown = ", ".join(hosts[:3])
                return {
                    "state": "ok",
                    "detail": f"MX records found: {shown}.",
                    "hosts": hosts[:5],
                }
            return {
                "state": "null_mx",
                "detail": f"{domain} publishes a null MX and does not accept mail.",
                "hosts": [],
            }
        if _has_address(resolver, domain):
            return {
                "state": "implicit",
                "detail": (
                    f"{domain} has no MX record. An address record exists, "
                    "which is a weak fallback and often bounces."
                ),
                "hosts": [domain],
            }
        return {
            "state": "no_mail",
            "detail": f"{domain} has no MX records and no address record, so mail will hard-bounce.",
            "hosts": [],
        }
    except dns.resolver.NXDOMAIN:
        return {
            "state": "nxdomain",
            "detail": f"{domain} does not exist, so mail will hard-bounce.",
            "hosts": [],
        }
    except dns.exception.Timeout:
        return {
            "state": "error",
            "detail": "DNS lookup timed out. The address was not confirmed.",
            "hosts": [],
        }
    except dns.resolver.NoNameservers:
        return {
            "state": "error",
            "detail": "DNS servers did not answer. The address was not confirmed.",
            "hosts": [],
        }
    except dns.exception.DNSException:
        log.exception("dns lookup failed for %s", domain)
        return {
            "state": "error",
            "detail": "DNS lookup failed. The address was not confirmed.",
            "hosts": [],
        }


def _has_address(resolver: dns.resolver.Resolver, domain: str) -> bool:
    for kind in ("A", "AAAA"):
        try:
            resolver.resolve(domain, kind)
            return True
        except dns.resolver.NoAnswer:
            continue
    return False


def build_risks(local: str, domain: str, ascii_domain: str, domain_exists: bool) -> tuple[list[dict], str | None]:
    risks: list[dict] = []
    disposable = in_domain_set(domain, DISPOSABLE) or in_domain_set(ascii_domain, DISPOSABLE)
    alias = in_domain_set(domain, ALIAS) or in_domain_set(ascii_domain, ALIAS)
    free = in_domain_set(domain, FREE) or in_domain_set(ascii_domain, FREE)
    suggestion_domain = suggest_typo(ascii_domain, domain_exists)
    suggestion = f"{local}@{suggestion_domain}" if suggestion_domain else None

    if disposable:
        risks.append(
            {
                "code": "disposable",
                "label": "Disposable",
                "severity": "high",
                "detail": f"{ascii_domain} is a known temporary inbox domain.",
            }
        )
    elif alias:
        risks.append(
            {
                "code": "alias",
                "label": "Forwarding alias",
                "severity": "low",
                "detail": f"{ascii_domain} forwards mail and can stop working when the owner turns it off.",
            }
        )
    if suggestion_domain:
        risks.append(
            {
                "code": "typo",
                "label": "Likely typo",
                "severity": "high",
                "detail": f"{ascii_domain} looks like a typo of {suggestion_domain}.",
            }
        )
    for kind in local_kinds(local):
        if kind == "trap":
            risks.append(
                {
                    "code": "trap",
                    "label": "System mailbox",
                    "severity": "high",
                    "detail": "This name is a system mailbox or a common spam-trap pattern. Do not mail it.",
                }
            )
        elif kind == "role":
            risks.append(
                {
                    "code": "role",
                    "label": "Role address",
                    "severity": "medium",
                    "detail": "Shared addresses such as info@ or support@ often accept mail and draw more complaints.",
                }
            )
        elif kind == "test":
            risks.append(
                {
                    "code": "test",
                    "label": "Test name",
                    "severity": "medium",
                    "detail": "The mailbox name looks like a placeholder or a test address.",
                }
            )
    if free and not disposable:
        risks.append(
            {
                "code": "free",
                "label": "Consumer inbox",
                "severity": "info",
                "detail": f"{ascii_domain} is a free mailbox provider. That is fine for consumer mail.",
            }
        )
    return risks, suggestion


def evaluate(
    original: str,
    syntax: dict,
    dns: dict,
    smtp: dict,
    risks: list[dict],
    suggestion: str | None,
) -> dict:
    risks = [dict(item) for item in risks]
    codes = {item["code"] for item in risks}
    if (
        not suggestion
        and "hidden" in codes
        and syntax["ok"]
        and syntax["email"] != original.strip()
    ):
        suggestion = syntax["email"]

    def emit(status: str, action: str, bounce: str, score: int, summary: str) -> dict:
        dns_ok = True if dns["state"] in {"ok", "implicit", "null_mx", "no_mail"} else False if dns["state"] == "nxdomain" else None
        mx_ok = True if dns["state"] == "ok" else False if dns["state"] in {"null_mx", "no_mail", "nxdomain", "implicit"} else None
        if smtp["state"] in {"accepted", "cloud_verified"}:
            smtp_ok = True
        elif smtp["state"] == "rejected":
            smtp_ok = False
        else:
            smtp_ok = None
        email = syntax["email"] if syntax["ok"] else original.strip()
        return {
            "input": original,
            "email": email,
            "status": status,
            "action": action,
            "bounce": bounce,
            "score": score,
            "suggestion": suggestion,
            "summary": summary,
            "risks": risks,
            "checks": {
                "syntax": {"ok": syntax["ok"], "detail": syntax["detail"]},
                "dns": {"ok": dns_ok, "detail": dns["detail"]},
                "mx": {"ok": mx_ok, "hosts": list(dns["hosts"]), "detail": dns["detail"]},
                "smtp": {
                    "ok": smtp_ok,
                    "state": smtp["state"],
                    "code": smtp["code"],
                    "host": smtp["host"],
                    "detail": smtp["detail"],
                    "catch_all": smtp["catch_all"],
                },
            },
        }

    if not syntax["ok"]:
        return emit("invalid", "suppress", "hard", 4, syntax["detail"])

    disposable = "disposable" in codes
    if dns["state"] == "nxdomain":
        summary = dns["detail"]
        if suggestion:
            summary = f"{summary} Closest common domain: {suggestion}."
        if disposable:
            summary = "Disposable inbox on a domain that does not exist. Suppress it."
        return emit("invalid", "suppress", "hard", 5, summary)
    if dns["state"] == "null_mx":
        return emit("invalid", "suppress", "hard", 4, dns["detail"])
    if dns["state"] == "no_mail":
        return emit("invalid", "suppress", "hard", 8, dns["detail"])
    if dns["state"] == "error":
        if disposable:
            return emit(
                "risky",
                "suppress",
                "hard",
                8,
                "Disposable inbox. DNS could not be checked, and the address should still be suppressed.",
            )
        return emit("unknown", "review", "unknown", 40, dns["detail"])
    if smtp["state"] == "private":
        return emit("invalid", "suppress", "hard", 12, smtp["detail"])

    if smtp["state"] == "blocked":
        risks.append(
            {
                "code": "smtp_blocked",
                "label": "SMTP skipped",
                "severity": "low",
                "detail": "The mailbox check did not run because outbound port 25 is blocked on this network.",
            }
        )
    elif smtp["state"] == "policy":
        risks.append(
            {
                "code": "smtp_policy",
                "label": "Probe rejected",
                "severity": "medium",
                "detail": "The server rejected the check itself. That is not proof the mailbox is missing.",
            }
        )
    if smtp.get("catch_all") is True:
        risks.append(
            {
                "code": "catch_all",
                "label": "Catch-all",
                "severity": "medium",
                "detail": "The server also accepted a made-up address, so this acceptance does not prove the mailbox exists.",
            }
        )
    if dns["state"] == "implicit":
        risks.append(
            {
                "code": "implicit_mx",
                "label": "No MX",
                "severity": "high",
                "detail": "The domain has no MX record. Mail would fall back to an address record.",
            }
        )
    codes = {item["code"] for item in risks}

    if smtp["state"] == "rejected":
        summary = smtp["detail"]
        if disposable:
            summary = "Disposable inbox. The mail server also refused this recipient."
        return emit("invalid", "suppress", "hard", 6, summary)

    if smtp["state"] == "temporary":
        status, action, bounce, score = "soft_risk", "retry", "soft", 34
        summary = smtp["detail"]
    elif smtp["state"] == "accepted":
        if smtp.get("catch_all") is True:
            status, action, bounce, score = "risky", "review", "unknown", 44
            summary = (
                "The server accepted this address and a made-up one, so the domain is catch-all. "
                "That does not prove this mailbox exists."
            )
        elif smtp.get("catch_all") is False:
            status, action, bounce, score = "safe", "send", "none", 92
            summary = "Syntax, MX, and the SMTP recipient check passed, and the server rejected a made-up address."
        else:
            status, action, bounce, score = "safe", "send", "none", 78
            summary = "Syntax, MX, and the SMTP recipient check passed. Catch-all was not tested."
    elif smtp["state"] == "cloud_verified":
        auth_dns = smtp.get("auth_dns") or {}
        if auth_dns.get("has_spf") and auth_dns.get("has_dmarc"):
            status, action, bounce, score = "safe", "send", "none", 86
            summary = (
                "Syntax, MX, SPF, and DMARC passed in cloud mode (port 443/53), "
                "and no bounce or risk signals were found."
            )
        elif auth_dns.get("has_spf") or auth_dns.get("has_dmarc"):
            status, action, bounce, score = "safe", "send", "none", 82
            summary = (
                "Syntax, MX, and domain email authentication records passed in cloud mode (port 443/53)."
            )
        else:
            status, action, bounce, score = "safe", "send", "none", 75
            summary = "Syntax and MX records passed in cloud mode. No bounce or risk signals were found."
    elif smtp["state"] == "blocked":
        status, action, bounce, score = "unknown", "review", "unknown", 62
        summary = smtp["detail"]
    elif smtp["state"] == "policy":
        status, action, bounce, score = "unknown", "review", "unknown", 52
        summary = smtp["detail"]
    else:
        status, action, bounce, score = "unknown", "review", "unknown", 58
        summary = smtp["detail"] or "SMTP was not run, so the mailbox was not confirmed."

    if dns["state"] == "implicit" and status in {"safe", "unknown"}:
        if smtp["state"] == "accepted":
            status, action, score = "risky", "review", 48
            summary = (
                "The server accepted the recipient, but the domain has no MX record and only an address record. "
                "Treat this as fragile."
            )
        elif smtp["state"] in {"error", "cloud_verified"}:
            status, action, bounce, score = "invalid", "suppress", "hard", 18
            summary = (
                "No MX record, and the fallback server did not accept an SMTP connection, "
                "so a normal campaign will hard-bounce."
            )
            if suggestion:
                summary = f"{summary} Did you mean {suggestion}?"
        else:
            score = 36
            summary = (
                "No MX record. Only an address record was found, and the mailbox was not confirmed. "
                "These often hard-bounce."
            )

    if "typo" in codes and suggestion and status == "safe":
        status, action, score = "risky", "review", 30
        summary = f"The server accepted it, but {syntax['domain']} looks mistyped. Did you mean {suggestion}?"
    elif "typo" in codes and suggestion and status in {"unknown", "risky", "soft_risk"}:
        summary = f"{summary} Did you mean {suggestion}?"
        score = min(score, 35)

    if "role" in codes and status == "safe":
        status, action, score = "risky", "review", 76
        summary = "The SMTP recipient check passed, but this is a role address. It often works and still draws complaints."
    elif "role" in codes and status == "unknown":
        summary = f"{summary} The mailbox name is a role address."

    if "test" in codes and status == "safe":
        status, action, score = "risky", "review", 40
        summary = "The SMTP recipient check passed, but the mailbox name looks like a test or placeholder."

    if "trap" in codes and status != "invalid":
        status, action = "risky", "suppress"
        if smtp["state"] == "accepted":
            bounce = "none"
            score = 15
            summary = "The server accepted this mailbox, but the name is a system or trap-style address. Do not send marketing mail to it."
        else:
            bounce = "unknown"
            score = 12
            summary = "This is a system or trap-style mailbox. Do not send marketing mail to it."

    if "disposable" in codes and status != "invalid":
        status, action, bounce, score = "risky", "suppress", "hard", 8
        if smtp["state"] == "accepted":
            summary = (
                "The server accepted a disposable inbox. Suppress it anyway. "
                "These addresses expire, bounce later, or hurt sender reputation."
            )
        else:
            summary = "Disposable inbox. Suppress it. These addresses expire, bounce, or hurt sender reputation."

    if "alias" in codes and status == "safe":
        score = min(score, 80)
        summary = f"{summary} This is a forwarding alias, so it keeps working only while the owner routes it."
    if "free" in codes and status == "safe":
        summary = f"{summary} Consumer mailbox."
    if "hidden" in codes and status == "safe":
        summary = f"{summary} Invisible characters were removed. Send to the cleaned address."
        if not suggestion:
            suggestion = syntax["email"]

    return emit(status, action, bounce, score, summary)


def verify_email(raw: str, job: Job) -> dict:
    try:
        return _verify_email(raw, job)
    except Exception:
        log.exception("verification failed")
        try:
            syntax = check_syntax(raw)
        except Exception:
            syntax = {
                "ok": False,
                "detail": "The address could not be read.",
                "local": "",
                "domain": "",
                "ascii_domain": "",
                "email": raw.strip(),
                "hidden_stripped": False,
            }
        if not syntax["ok"]:
            return evaluate(
                raw,
                syntax,
                {"state": "not_run", "detail": "Not checked.", "hosts": []},
                _smtp_shell("not_run", "Not checked."),
                [],
                None,
            )
        return evaluate(
            raw,
            syntax,
            {
                "state": "error",
                "detail": "This address could not be checked because of an internal error.",
                "hosts": [],
            },
            _smtp_shell("error", "This address could not be checked because of an internal error."),
            [],
            None,
        )


def _verify_email(raw: str, job: Job) -> dict:
    syntax = check_syntax(raw)
    if not syntax["ok"]:
        return evaluate(
            raw,
            syntax,
            {"state": "not_run", "detail": "Not checked.", "hosts": []},
            _smtp_shell("not_run", "Not checked."),
            [],
            None,
        )

    dns = lookup_domain(syntax["ascii_domain"])
    domain_exists = dns["state"] != "nxdomain"
    risks, suggestion = build_risks(syntax["local"], syntax["domain"], syntax["ascii_domain"], domain_exists)
    if syntax["hidden_stripped"]:
        risks.append(
            {
                "code": "hidden",
                "label": "Hidden characters",
                "severity": "low",
                "detail": "Invisible characters were removed before the check. Use the cleaned address.",
            }
        )

    if dns["state"] not in {"ok", "implicit"}:
        smtp = _smtp_shell("not_run", "SMTP was not attempted because the domain has no usable mail server.")
        if dns["state"] == "error":
            smtp = _smtp_shell("not_run", "SMTP was not attempted because DNS did not answer.")
        return evaluate(raw, syntax, dns, smtp, risks, suggestion)

    if job.smtp_mode == "disabled":
        smtp = _smtp_shell("skipped", "SMTP is turned off. The mailbox was not confirmed.")
    elif job.smtp_mode == "cloud":
        smtp = _cloud_or_alt_port_verify(
            syntax["email"],
            dns["hosts"],
            job.helo,
            job.mail_from,
            job.catch_all,
            syntax["ascii_domain"],
            job.cloud_cfg,
            try_smtp_ports=job.smtp,
        )
    elif job.smtp_mode == "blocked":
        smtp = _smtp_shell(
            "blocked",
            "Outbound port 25 is blocked on this network, so the mailbox was not confirmed. Syntax and MX were still checked.",
        )
    else:
        smtp = smtp_check(
            syntax["email"],
            dns["hosts"],
            job.helo,
            job.mail_from,
            job.catch_all,
            syntax["ascii_domain"],
            proxy_url=job.cloud_cfg.proxy_url,
        )
    return evaluate(raw, syntax, dns, smtp, risks, suggestion)


def _smtp_shell(state: str, detail: str) -> dict:
    return {"state": state, "code": None, "host": None, "detail": detail, "catch_all": None}


_DEAD_PORTS: dict[tuple[str, int], float] = {}
_DEAD_PORTS_LOCK = threading.Lock()


def _cloud_or_alt_port_verify(
    recipient: str,
    hosts: list[str],
    helo: str,
    mail_from: str,
    do_catch_all: bool,
    ascii_domain: str,
    cloud_cfg: CloudConfig,
    try_smtp_ports: bool = True,
) -> dict:
    """Verify via SMTP first (25 / 587 / 2525 or SOCKS5 proxy), then HTTPS 443 + DNS MX/SPF/DMARC."""
    for host in hosts[:2]:
        kind = _classify_host(host)
        if kind == "private":
            return _smtp_shell(
                "private",
                f"Mail server {host} is not on the public internet, so a normal campaign will hard-bounce.",
            ) | {"host": host}

    # 1. Always attempt real SMTP handshake first when SMTP is enabled (and not in 60k fast-bulk mode)
    if try_smtp_ports and not cloud_cfg.fast_bulk and hosts:
        primary_host = hosts[0]
        if _classify_host(primary_host) == "public":
            now = time.time()
            for port in (25, 587, 2525):
                with _DEAD_PORTS_LOCK:
                    dead_at = _DEAD_PORTS.get((primary_host, port), 0.0)
                if now - dead_at < _DNS_TTL:
                    continue
                try:
                    with _domain_semaphore(ascii_domain):
                        smtp_res = _smtp_on_host(
                            primary_host,
                            recipient,
                            helo,
                            mail_from,
                            do_catch_all,
                            ascii_domain,
                            port=port,
                            timeout=1.4,
                            proxy_url=cloud_cfg.proxy_url,
                        )
                    if smtp_res["state"] in {"accepted", "rejected", "temporary"}:
                        return smtp_res
                except Exception:
                    with _DEAD_PORTS_LOCK:
                        _DEAD_PORTS[(primary_host, port)] = time.time()
                    continue

    # 2. Run HTTPS (Microsoft 365 / Outlook / Gravatar / External API) + DNS SPF/DMARC verification
    return cloud_verify_fallback(
        recipient,
        ascii_domain,
        hosts,
        do_catch_all,
        helo,
        mail_from,
        cloud_cfg,
    )


def smtp_check(
    recipient: str,
    hosts: list[str],
    helo: str,
    mail_from: str,
    do_catch_all: bool,
    ascii_domain: str,
    proxy_url: str = "",
) -> dict:
    failures: list[str] = []
    for host in hosts[:3]:
        kind = _classify_host(host)
        if kind == "unresolved":
            failures.append("unresolved")
            continue
        if kind == "private":
            failures.append("private")
            continue
        try:
            with _domain_semaphore(ascii_domain):
                outcome = _smtp_on_host(
                    host,
                    recipient,
                    helo,
                    mail_from,
                    do_catch_all,
                    ascii_domain,
                    proxy_url=proxy_url,
                )
        except smtplib.SMTPHeloError as exc:
            return _policy_result(host, exc.smtp_code, _decode(exc.smtp_error), "The server rejected the HELO name, so the mailbox was not tested.")
        except (socket.timeout, TimeoutError):
            failures.append("timeout")
            continue
        except ConnectionRefusedError:
            failures.append("refused")
            continue
        except OSError as exc:
            if getattr(exc, "errno", None) in {10060, 110, 60}:
                failures.append("timeout")
            elif getattr(exc, "errno", None) in {10061, 111}:
                failures.append("refused")
            else:
                failures.append("error")
            continue
        except smtplib.SMTPException as exc:
            failures.append("error")
            log.info("smtp error on %s: %s", host, exc.__class__.__name__)
            continue
        if outcome["state"] in {"accepted", "rejected", "temporary", "policy"}:
            return outcome
        failures.append(outcome["state"])

    if failures and all(item == "private" for item in failures):
        host = hosts[0]
        return _smtp_shell(
            "private",
            f"Mail server {host} is not on the public internet, so a normal campaign will hard-bounce.",
        ) | {"host": host}
    if "timeout" in failures:
        return _smtp_shell("error", "The SMTP handshake timed out before the mailbox could be confirmed.")
    if failures and all(item == "unresolved" for item in failures):
        return _smtp_shell("error", "The mail server hostname did not resolve, so the mailbox was not confirmed.")
    return _smtp_shell("error", "Could not connect to a mail server, so the mailbox was not confirmed.")


def _connect_smtp(host: str, port: int, timeout: float, proxy_url: str = "") -> smtplib.SMTP:
    proxy_cfg = parse_socks5_url(proxy_url) if proxy_url else None
    if not proxy_cfg:
        client = smtplib.SMTP(timeout=timeout)
        client.connect(host, port)
        return client

    class ProxiedSMTP(smtplib.SMTP):
        def _get_socket(self, host_arg, port_arg, timeout_arg):
            return create_socks5_connection(proxy_cfg, host_arg, port_arg, timeout=timeout_arg or timeout)

    client = ProxiedSMTP(timeout=timeout)
    client.connect(host, port)
    return client


def _smtp_on_host(
    host: str,
    recipient: str,
    helo: str,
    mail_from: str,
    do_catch_all: bool,
    ascii_domain: str,
    port: int = 25,
    timeout: float = 8.0,
    proxy_url: str = "",
) -> dict:
    client = _connect_smtp(host, port, timeout, proxy_url=proxy_url)
    try:
        _ehlo(client, helo)
        if client.has_extn("starttls"):
            try:
                client.starttls(context=ssl.create_default_context())
                _ehlo(client, helo)
            except Exception:
                _safe_close(client)
                client = _connect_smtp(host, port, timeout, proxy_url=proxy_url)
                _ehlo(client, helo)
        code, message = client.mail(mail_from)
        if code >= 400 and mail_from:
            code, message = client.mail("")
        if code >= 400:
            text = _decode(message)
            return _policy_result(
                host,
                code,
                text,
                f"{host} refused the probe sender, so this mailbox was not tested ({code}). Server said: { _short(text) }",
            )
        code, message = client.rcpt(recipient)
        text = _decode(message)
        state = classify_smtp(code, text)
        catch_all = None
        if state == "accepted" and do_catch_all:
            catch_all = _catch_all_probe(client, ascii_domain)
        return _recipient_result(host, code, text, state, catch_all)
    finally:
        _safe_quit(client)


def _catch_all_probe(client: smtplib.SMTP, ascii_domain: str) -> bool | None:
    cached = _get_catch(ascii_domain)
    if cached is not None:
        return cached
    fake = f"clearlist-{secrets.token_hex(4)}@{ascii_domain}"
    try:
        code, message = client.rcpt(fake)
    except Exception:
        return None
    state = classify_smtp(code, _decode(message))
    if state == "accepted":
        _set_catch(ascii_domain, True)
        return True
    if state == "rejected":
        _set_catch(ascii_domain, False)
        return False
    return None


def _recipient_result(host: str, code: int, text: str, state: str, catch_all: bool | None) -> dict:
    short = _short(text)
    if state == "accepted":
        detail = f"{host} accepted the recipient ({code})."
    elif state == "rejected":
        detail = f"{host} refused this mailbox ({code}). Sending would hard-bounce. Server said: {short}"
    elif state == "temporary":
        detail = (
            f"{host} deferred the recipient ({code}). This is a soft-bounce risk. "
            f"Retry later before suppressing it. Server said: {short}"
        )
    elif state == "policy":
        detail = (
            f"{host} returned {code} but did not say the mailbox is missing, so this was not marked as a hard bounce. "
            f"Server said: {short}"
        )
    else:
        detail = f"{host} returned an unexpected SMTP reply ({code}). Server said: {short}"
        state = "error"
    return {"state": state, "code": code, "host": host, "detail": detail, "catch_all": catch_all}


def _policy_result(host: str, code: int, text: str, detail: str) -> dict:
    return {"state": "policy", "code": code, "host": host, "detail": detail, "catch_all": None}


def _ehlo(client: smtplib.SMTP, helo: str) -> None:
    code, message = client.ehlo(helo)
    if code >= 400:
        code, message = client.helo(helo)
    if code >= 400:
        raise smtplib.SMTPHeloError(code, message)


def _classify_host(hostname: str) -> str:
    try:
        infos = socket.getaddrinfo(hostname, 25, type=socket.SOCK_STREAM)
    except socket.gaierror:
        return "unresolved"
    saw_public = False
    saw_private = False
    for info in infos:
        ip_text = str(info[4][0]).split("%", 1)[0]
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError:
            continue
        if ip.is_global:
            saw_public = True
        else:
            saw_private = True
    if saw_public:
        return "public"
    if saw_private:
        return "private"
    return "unresolved"


def _domain_semaphore(domain: str) -> threading.Semaphore:
    with _domain_sem_lock:
        sem = _domain_sems.get(domain)
        if sem is None:
            sem = threading.Semaphore(2)
            _domain_sems[domain] = sem
        return sem


def _get_catch(domain: str) -> bool | None:
    with _catch_lock:
        if domain in _catch_cache:
            return _catch_cache[domain]
    return None


def _set_catch(domain: str, value: bool) -> None:
    with _catch_lock:
        _catch_cache[domain] = value


def _decode(message: object) -> str:
    if message is None:
        return ""
    if isinstance(message, bytes):
        return message.decode("utf-8", "replace")
    return str(message)


def _short(text: str, limit: int = 180) -> str:
    compact = " ".join(text.split())
    if len(compact) <= limit:
        return compact or "no message"
    return compact[: limit - 3] + "..."


def _safe_close(client: smtplib.SMTP) -> None:
    try:
        client.close()
    except Exception:
        pass


def _safe_quit(client: smtplib.SMTP) -> None:
    try:
        client.quit()
    except Exception:
        _safe_close(client)
