"""Known domains and mailbox names used for risk checks.

Disposable domains are a curated set of well-known temporary inbox
providers, not an exhaustive dump. A subdomain of a listed domain matches.
"""

from __future__ import annotations

import re

DISPOSABLE = frozenset(
    {
        "10minutemail.com",
        "10minutemail.net",
        "20minutemail.com",
        "armyspy.com",
        "cuvox.de",
        "dayrep.com",
        "discard.email",
        "discardmail.com",
        "discardmail.de",
        "dispostable.com",
        "dodgeit.com",
        "dropmail.me",
        "einrot.com",
        "emailfake.com",
        "emailondeck.com",
        "fakeinbox.com",
        "fakemail.net",
        "filzmail.com",
        "fleckens.hu",
        "generator.email",
        "getairmail.com",
        "getnada.com",
        "grr.la",
        "guerrillamail.biz",
        "guerrillamail.com",
        "guerrillamail.de",
        "guerrillamail.info",
        "guerrillamail.net",
        "guerrillamail.org",
        "guerrillamailblock.com",
        "gustr.com",
        "harakirimail.com",
        "inboxkitten.com",
        "jetable.fr.nf",
        "jetable.org",
        "jourrapide.com",
        "maildrop.cc",
        "mailcatch.com",
        "mailforspam.com",
        "mailinator.com",
        "mailinator.net",
        "mailinator.org",
        "mailnesia.com",
        "mailnull.com",
        "meltmail.com",
        "mintemail.com",
        "moakt.com",
        "mohmal.com",
        "mytemp.email",
        "mytrashmail.com",
        "notmailinator.com",
        "pokemail.net",
        "rhyta.com",
        "safetymail.info",
        "sharklasers.com",
        "spam4.me",
        "spambog.com",
        "spambog.de",
        "spamgourmet.com",
        "spamgourmet.net",
        "spamgourmet.org",
        "superrito.com",
        "teleworm.us",
        "temp-mail.io",
        "temp-mail.org",
        "tempail.com",
        "tempemail.com",
        "tempemail.net",
        "tempinbox.com",
        "tempmail.com",
        "tempr.email",
        "throwawaymail.com",
        "tmail.io",
        "tmail.ws",
        "tmpmail.net",
        "tmpmail.org",
        "trash-mail.com",
        "trashmail.com",
        "trashmail.de",
        "trashmail.me",
        "trashmail.net",
        "trashmail.org",
        "yopmail.com",
        "yopmail.fr",
        "yopmail.net",
    }
)

# Forwarding aliases. They can accept mail and still expire later.
ALIAS = frozenset(
    {
        "33mail.com",
        "anonaddy.com",
        "anonaddy.me",
        "duck.com",
        "mozmail.com",
        "passmail.net",
        "privaterelay.appleid.com",
        "relay.firefox.com",
        "simplelogin.com",
        "simplelogin.fr",
    }
)

FREE = frozenset(
    {
        "aol.com",
        "att.net",
        "bellsouth.net",
        "comcast.net",
        "cox.net",
        "fastmail.com",
        "gmail.com",
        "gmx.com",
        "gmx.net",
        "googlemail.com",
        "hey.com",
        "hotmail.co.uk",
        "hotmail.com",
        "hotmail.fr",
        "icloud.com",
        "live.com",
        "mac.com",
        "mail.com",
        "me.com",
        "msn.com",
        "outlook.com",
        "pm.me",
        "proton.me",
        "protonmail.com",
        "qq.com",
        "rocketmail.com",
        "sbcglobal.net",
        "verizon.net",
        "web.de",
        "yahoo.co.uk",
        "yahoo.com",
        "yandex.com",
        "yandex.ru",
        "ymail.com",
        "zoho.com",
    }
)

# Explicit typo domains. These are suggested even when the typo domain exists,
# because a parked typo site can still accept SMTP and is rarely the intended recipient.
TYPOS = {
    "gamil.com": "gmail.com",
    "gmai.com": "gmail.com",
    "gmail.cm": "gmail.com",
    "gmail.co": "gmail.com",
    "gmail.con": "gmail.com",
    "gmail.om": "gmail.com",
    "gmaill.com": "gmail.com",
    "gmal.com": "gmail.com",
    "gmial.com": "gmail.com",
    "gnail.com": "gmail.com",
    "googlemail.co": "googlemail.com",
    "hotmai.com": "hotmail.com",
    "hotmail.co": "hotmail.com",
    "hotmail.con": "hotmail.com",
    "hotmal.com": "hotmail.com",
    "hotmial.com": "hotmail.com",
    "icloud.co": "icloud.com",
    "icloud.con": "icloud.com",
    "outlok.com": "outlook.com",
    "outloo.com": "outlook.com",
    "outlook.co": "outlook.com",
    "outlook.con": "outlook.com",
    "proton.con": "proton.me",
    "protonmail.con": "protonmail.com",
    "yahoo.co": "yahoo.com",
    "yahoo.con": "yahoo.com",
    "yahooo.com": "yahoo.com",
    "yaho.com": "yahoo.com",
    "yhaoo.com": "yahoo.com",
}

POPULAR = (
    "gmail.com",
    "googlemail.com",
    "hotmail.com",
    "icloud.com",
    "outlook.com",
    "proton.me",
    "protonmail.com",
    "yahoo.com",
)

# Exact mailbox names after dots, hyphens, and underscores are removed.
TRAP = frozenset(
    {
        "abuse",
        "blackhole",
        "bounce",
        "bounces",
        "devnull",
        "mailerdaemon",
        "nobody",
        "null",
        "postmaster",
        "spam",
        "spamtrap",
    }
)

ROLE = frozenset(
    {
        "accounts",
        "admin",
        "administrator",
        "billing",
        "careers",
        "contact",
        "customercare",
        "customerservice",
        "donotreply",
        "enquiries",
        "enquiry",
        "hello",
        "help",
        "helpdesk",
        "hostmaster",
        "hr",
        "info",
        "information",
        "inquiries",
        "inquiry",
        "jobs",
        "marketing",
        "media",
        "newsletter",
        "noc",
        "noreply",
        "office",
        "press",
        "reception",
        "root",
        "sales",
        "security",
        "service",
        "support",
        "sysadmin",
        "team",
        "webmaster",
    }
)

TEST = frozenset(
    {
        "abc",
        "abc123",
        "asdf",
        "demo",
        "example",
        "fake",
        "invalid",
        "qwerty",
        "sample",
        "temp",
        "test",
        "testing",
        "tmp",
    }
)

RESERVED_DOMAINS = frozenset({"example.com", "example.net", "example.org"})
RESERVED_TLDS = frozenset({"example", "invalid", "local", "localhost", "test"})


def in_domain_set(domain: str, pool: frozenset[str]) -> bool:
    domain = domain.lower().rstrip(".")
    if domain in pool:
        return True
    labels = domain.split(".")
    for index in range(1, len(labels) - 1):
        if ".".join(labels[index:]) in pool:
            return True
    return False


def local_kinds(local: str) -> list[str]:
    base = local.split("+", 1)[0]
    key = re.sub(r"[._-]", "", base).lower()
    if not key:
        return []
    if key in TRAP:
        return ["trap"]
    if key in ROLE:
        return ["role"]
    if key in TEST:
        return ["test"]
    return []


def damerau(left: str, right: str) -> int:
    if abs(len(left) - len(right)) > 1:
        return 2
    rows = len(left) + 1
    cols = len(right) + 1
    grid = [[0] * cols for _ in range(rows)]
    for i in range(rows):
        grid[i][0] = i
    for j in range(cols):
        grid[0][j] = j
    for i in range(1, rows):
        for j in range(1, cols):
            cost = 0 if left[i - 1] == right[j - 1] else 1
            grid[i][j] = min(
                grid[i - 1][j] + 1,
                grid[i][j - 1] + 1,
                grid[i - 1][j - 1] + cost,
            )
            if (
                i > 1
                and j > 1
                and left[i - 1] == right[j - 2]
                and left[i - 2] == right[j - 1]
            ):
                grid[i][j] = min(grid[i][j], grid[i - 2][j - 2] + 1)
    return grid[-1][-1]


def suggest_typo(domain: str, domain_exists: bool) -> str | None:
    """Suggest a popular domain for an obvious typo.

    The explicit map applies even when the typed domain exists, because typo
    domains are often parked and will accept SMTP. Edit-distance suggestions
    are only used when the domain does not exist, so a live domain is not
    rewritten just because it is one character from Gmail.
    """

    domain = domain.lower().rstrip(".")
    mapped = TYPOS.get(domain)
    if mapped and mapped != domain:
        return mapped
    if domain_exists or len(domain) < 10:
        return None
    for candidate in POPULAR:
        if abs(len(candidate) - len(domain)) > 1:
            continue
        if damerau(domain, candidate) == 1:
            return candidate
    return None
