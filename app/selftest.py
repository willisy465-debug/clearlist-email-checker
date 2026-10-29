"""Offline checks for syntax, SMTP classification, and the verdict table."""

from __future__ import annotations

from app.verifier import check_syntax, classify_smtp, evaluate
from app.data import in_domain_set, suggest_typo, DISPOSABLE


def syntax_ok(local: str = "jane", domain: str = "gmail.com") -> dict:
    result = check_syntax(f"{local}@{domain}")
    assert result["ok"], result
    return result


def dns(state: str, detail: str = "dns", hosts: list[str] | None = None) -> dict:
    return {"state": state, "detail": detail, "hosts": hosts or []}


def smtp(state: str, detail: str = "smtp", code: int | None = None, catch_all: bool | None = None) -> dict:
    return {"state": state, "code": code, "host": "mx.example.net", "detail": detail, "catch_all": catch_all}


def risk(code: str) -> dict:
    return {"code": code, "label": code, "severity": "high", "detail": code}


def main() -> None:
    assert not check_syntax("foo@")["ok"]
    assert "missing an @" in check_syntax("not-an-email")["detail"]
    assert not check_syntax("person@example.invalid")["ok"]
    assert not check_syntax("a@b")["ok"]
    assert check_syntax("Jane Doe <Jane@Gmail.com>")["email"] == "Jane@gmail.com"
    international = check_syntax("user@bücher.de")
    assert international["ok"], international
    assert international["ascii_domain"] == "xn--bcher-kva.de"

    assert classify_smtp(250, "OK") == "accepted"
    assert classify_smtp(550, "5.1.1 user unknown") == "rejected"
    assert classify_smtp(550, "5.7.1 Service unavailable; client blocked using Spamhaus") == "policy"
    assert classify_smtp(452, "Greylisted, try again later") == "temporary"
    assert classify_smtp(552, "5.2.2 mailbox full") == "temporary"
    assert classify_smtp(550, "recipient address rejected") == "rejected"
    assert classify_smtp(550, "relay access denied") == "policy"
    assert classify_smtp(550, "sender address invalid") == "policy"

    assert suggest_typo("gmial.com", True) == "gmail.com"
    assert suggest_typo("gmail.com", False) is None
    assert suggest_typo("gmial.co", False) is None
    close = suggest_typo("gnail.com", False)
    assert close == "gmail.com"
    assert in_domain_set("mailinator.com", DISPOSABLE)
    assert in_domain_set("a.mailinator.com", DISPOSABLE)
    assert not in_domain_set("gmail.com", DISPOSABLE)
    assert not in_domain_set("not-mailinator.com", DISPOSABLE)

    syntax = syntax_ok()
    mx = dns("ok", "MX records found: mx.example.net.", ["mx.example.net"])

    bad = evaluate("foo@", check_syntax("foo@"), dns("not_run"), smtp("not_run"), [], None)
    assert bad["action"] == "suppress" and bad["bounce"] == "hard"

    missing = evaluate("a@no-such.test", syntax, dns("nxdomain", "no-such.test does not exist."), smtp("not_run"), [], "a@gmail.com")
    assert missing["action"] == "suppress"
    assert "a@gmail.com" in missing["summary"]

    assert evaluate("a@x.com", syntax, dns("null_mx", "null"), smtp("not_run"), [], None)["action"] == "suppress"
    assert evaluate("a@x.com", syntax, dns("no_mail", "none"), smtp("not_run"), [], None)["bounce"] == "hard"

    implicit = evaluate("a@x.com", syntax, dns("implicit", "no mx", ["x.com"]), smtp("blocked", "port 25 blocked"), [], None)
    assert implicit["action"] == "review"
    implicit_down = evaluate("a@x.com", syntax, dns("implicit", "no mx", ["x.com"]), smtp("error", "connection failed"), [], None)
    assert implicit_down["action"] == "suppress" and implicit_down["bounce"] == "hard"

    refused = evaluate("a@x.com", syntax, mx, smtp("rejected", "refused", 550), [], None)
    assert refused["action"] == "suppress" and refused["bounce"] == "hard"

    accepted = evaluate("a@x.com", syntax, mx, smtp("accepted", "accepted", 250, False), [], None)
    assert accepted["action"] == "send" and accepted["status"] == "safe"

    catch = evaluate("a@x.com", syntax, mx, smtp("accepted", "accepted", 250, True), [], None)
    assert catch["action"] == "review" and catch["status"] == "risky"

    disposable = evaluate("a@mailinator.com", syntax, mx, smtp("accepted", "accepted", 250, False), [risk("disposable")], None)
    assert disposable["action"] == "suppress" and disposable["bounce"] == "hard"

    role = evaluate("info@x.com", syntax, mx, smtp("accepted", "accepted", 250, False), [risk("role")], None)
    assert role["action"] == "review" and role["status"] == "risky"

    trap = evaluate("postmaster@x.com", syntax, mx, smtp("accepted", "accepted", 250, False), [risk("trap")], None)
    assert trap["action"] == "suppress" and trap["bounce"] == "none"

    soft = evaluate("a@x.com", syntax, mx, smtp("temporary", "try later", 451), [], None)
    assert soft["action"] == "retry" and soft["bounce"] == "soft"

    policy = evaluate("a@x.com", syntax, mx, smtp("policy", "blocked probe", 550), [], None)
    assert policy["action"] == "review" and policy["status"] == "unknown"

    blocked = evaluate("a@x.com", syntax, mx, smtp("blocked", "port closed"), [], None)
    assert blocked["action"] == "review"

    error = evaluate("a@x.com", syntax, dns("error", "timed out"), smtp("not_run"), [], None)
    assert error["action"] == "review"
    disposable_dns = evaluate("a@mailinator.com", syntax, dns("error", "timed out"), smtp("not_run"), [risk("disposable")], None)
    assert disposable_dns["action"] == "suppress"

    private = evaluate("a@x.com", syntax, mx, smtp("private", "private mail host"), [], None)
    assert private["action"] == "suppress"

    typo = evaluate("a@gmial.com", syntax, mx, smtp("accepted", "accepted", 250, False), [risk("typo")], "a@gmail.com")
    assert typo["action"] == "review"
    typo_missing = evaluate("a@gmial.com", syntax, dns("nxdomain", "gmial.com does not exist."), smtp("not_run"), [risk("typo")], "a@gmail.com")
    assert typo_missing["action"] == "suppress"

    print("selftest ok")


if __name__ == "__main__":
    main()
