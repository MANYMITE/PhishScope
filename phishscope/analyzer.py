"""Explainable phishing-URL heuristics. Every check returns a weighted Flag."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit, unquote

from .data import (
    BRANDS,
    EXECUTABLE_EXTENSIONS,
    HOMOGLYPHS,
    MULTIPART_TLDS,
    SUSPICIOUS_KEYWORDS,
    SUSPICIOUS_TLDS,
    URL_SHORTENERS,
)

__all__ = ["Flag", "Report", "analyze"]


@dataclass
class Flag:
    name: str
    weight: int
    why: str


@dataclass
class Report:
    url: str
    flags: list[Flag] = field(default_factory=list)
    score: int = 0
    verdict: str = "CLEAN"

    @property
    def is_suspicious(self) -> bool:
        return self.score >= 20

    def to_dict(self) -> dict:
        return {
            "url": self.url,
            "score": self.score,
            "verdict": self.verdict,
            "flags": [{"name": f.name, "weight": f.weight, "why": f.why} for f in self.flags],
        }

    def summary(self) -> str:
        return f"[{self.verdict}] score={self.score} flags={len(self.flags)}"


def fold_homoglyphs(host: str) -> str:
    # paypa1.com -> paypal.com
    return "".join(HOMOGLYPHS.get(ch, ch) for ch in host.lower())


def registered_domain(host: str) -> str:
    # Small public-suffix approximation; good enough without a PSL dependency.
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in MULTIPART_TLDS:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _is_ipv4(host: str) -> bool:
    parts = host.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _script_mix(host: str) -> set[str]:
    scripts: set[str] = set()
    for ch in host:
        code = ord(ch)
        if code <= 0x7F:
            continue
        if 0x0400 <= code <= 0x04FF:
            scripts.add("cyrillic")
        elif 0x0370 <= code <= 0x03FF:
            scripts.add("greek")
        elif 0x4E00 <= code <= 0x9FFF or 0x3040 <= code <= 0x30FF:
            scripts.add("cjk")
        elif 0x0600 <= code <= 0x06FF:
            scripts.add("arabic")
        elif 0x0900 <= code <= 0x097F:
            scripts.add("devanagari")
        else:
            scripts.add("other")
    return scripts


def _brand_positions(host: str) -> list[tuple[str, str]]:
    # Where a brand name sits: the real domain, a subdomain label, or glued
    # inside the domain label.
    hits: list[tuple[str, str]] = []
    labels = host.split(".")
    reg = registered_domain(host)
    reg_labels = reg.split(".")
    if len(labels) < len(reg_labels):
        return hits
    sub_labels = labels[: len(labels) - len(reg_labels)]
    domain_label = reg_labels[0] if len(reg_labels) > 1 else ""

    for brand in BRANDS:
        if reg == brand or reg.startswith(brand + "."):
            hits.append((brand, "domain"))
        elif brand in sub_labels:
            hits.append((brand, "subdomain"))
        elif domain_label and brand in domain_label and domain_label != brand:
            hits.append((brand, "embedded"))
    return hits


def analyze(url: str) -> Report:
    url = url.strip()
    if not url:
        return Report(url=url)

    # urlsplit needs a scheme, and most people type bare hosts.
    if "://" not in url:
        url = "http://" + url
    try:
        parts = urlsplit(url)
    except ValueError:
        return _score(url, [Flag("unparseable-url", 30, "URL could not be parsed")])

    host = unquote(parts.hostname or "")
    path = unquote(parts.path or "")
    query = unquote(parts.query or "")
    scheme = parts.scheme.lower()
    flags: list[Flag] = []

    try:
        port = parts.port
    except ValueError:
        port = None
        flags.append(Flag("odd-port", 15, "malformed or non-standard port in URL"))

    if not host:
        return _score(url, flags + [Flag("no-host", 30, "URL has no hostname")])

    lowered = host.lower()
    folded = fold_homoglyphs(lowered)
    reg = registered_domain(lowered)
    reg_labels = reg.split(".")
    domain_label = reg_labels[0] if len(reg_labels) > 1 else reg
    tld = ".".join(reg_labels[1:]) if len(reg_labels) > 1 else ""
    subdomain_depth = len(lowered.split(".")) - len(reg_labels)

    seen_brands: set[str] = set()
    for brand, kind in _brand_positions(lowered):
        if kind == "domain":
            continue  # the real domain, nothing to flag
        seen_brands.add(brand)
        if kind == "subdomain":
            flags.append(Flag(
                "brand-in-subdomain", 35,
                f"'{brand}' appears as a subdomain label — real brands never sit "
                "left of their own domain"))
        else:
            flags.append(Flag(
                "brand-lookalike-domain", 45,
                f"domain label '{domain_label}' embeds '{brand}' but is not the real "
                f"{brand} domain (registered domain: {reg})"))

    if folded != lowered:
        for brand, kind in _brand_positions(folded):
            if brand in seen_brands:
                continue
            seen_brands.add(brand)
            weight = 45 if kind == "domain" else 35
            flags.append(Flag(
                "homoglyph-impersonation", weight,
                f"host folds to '{folded}' — characters substituted to look "
                f"exactly like {brand}"))

    if scripts := _script_mix(lowered):
        flags.append(Flag(
            "non-ascii-host", 40,
            f"hostname contains non-ASCII characters (scripts: "
            f"{', '.join(sorted(scripts))}) — classic homoglyph attack"))

    if any(label.startswith("xn--") for label in lowered.split(".")):
        flags.append(Flag(
            "punycode-host", 30,
            "hostname uses punycode (xn--) — rarely needed by real domains, "
            "commonly used to render lookalike scripts"))

    if _is_ipv4(lowered):
        flags.append(Flag(
            "raw-ip-host", 30,
            "bare IP address instead of a domain — typical of throwaway "
            "phishing/malware hosts"))

    if parts.username is not None:
        flags.append(Flag(
            "userinfo-trick", 45,
            "URL contains '@' userinfo — browsers ignore everything before '@', "
            "so the real host is whatever comes after it"))

    if tld and tld.split(".")[-1] in SUSPICIOUS_TLDS:
        flags.append(Flag(
            "suspicious-tld", 20,
            f".{tld} sits on the free/cheap registry list that is heavily "
            "represented in phishing campaigns"))

    if len(domain_label) > 4 and "-" in domain_label:
        flags.append(Flag(
            "hyphenated-domain", 10,
            f"registered domain label '{domain_label}' contains hyphens — often "
            "used to pad out lookalike domains"))

    if subdomain_depth >= 4:
        flags.append(Flag(
            "deep-subdomains", 15,
            f"{subdomain_depth} subdomain levels — long padded hostnames hide "
            "the real domain"))
    elif subdomain_depth == 3:
        flags.append(Flag(
            "deep-subdomains", 8,
            f"{subdomain_depth} subdomain levels — moderately unusual"))

    if len(lowered) > 60:
        flags.append(Flag(
            "very-long-host", 15,
            f"hostname is {len(lowered)} chars (>60) — padding to obscure the "
            "real domain"))
    if len(url) > 100:
        flags.append(Flag(
            "very-long-url", 8,
            f"URL is {len(url)} chars (>100)"))

    alnum = [c for c in domain_label if c.isalnum()]
    digits = [c for c in alnum if c.isdigit()]
    if alnum and digits and len(digits) / len(alnum) > 0.3:
        flags.append(Flag(
            "digit-heavy-domain", 15,
            f"domain label '{domain_label}' is digit-heavy — throwaway domains "
            "often use number soup"))

    # Skip TLS/port warnings on local dev hosts.
    is_local = lowered in ("localhost", "::1") or lowered.startswith("127.")
    if scheme == "http" and not is_local:
        flags.append(Flag(
            "no-tls", 10,
            "plain HTTP — no transport encryption, trivially intercepted"))
    if port is not None and port not in (80, 443) and not is_local:
        flags.append(Flag(
            "odd-port", 15,
            f"non-standard port {port} — sometimes used to evade scanning"))

    if reg in URL_SHORTENERS:
        flags.append(Flag(
            "url-shortener", 15,
            f"{reg} hides the final destination — expand it before trusting it"))

    for kw in SUSPICIOUS_KEYWORDS:
        if kw in f"{lowered}{path}?{query}".lower():
            flags.append(Flag(
                "phishing-keyword", 18,
                f"contains scam-pattern keyword '{kw}'"))
            break

    hit = next((e for e in EXECUTABLE_EXTENSIONS if path.lower().endswith(e)), None)
    if hit:
        flags.append(Flag(
            "executable-download", 40,
            f"direct link to '{hit}' — drive-by malware delivery pattern"))

    if parts.username and any(b in parts.username.lower() for b in BRANDS):
        flags.append(Flag(
            "brand-in-userinfo", 20,
            "brand name appears before the '@' — browsers ignore that part, "
            "so it exists purely to look convincing"))

    if not seen_brands and any(b in f"{path}?{query}".lower() for b in BRANDS):
        flags.append(Flag(
            "brand-in-path", 12,
            "a brand name appears only in the path/query — common in fake "
            "support and giveaway pages"))

    return _score(url, flags)


def _score(url: str, flags: list[Flag]) -> Report:
    total = min(100, sum(f.weight for f in flags))
    if total >= 70:
        verdict = "CRITICAL"
    elif total >= 40:
        verdict = "HIGH"
    elif total >= 20:
        verdict = "MEDIUM"
    elif total >= 10:
        verdict = "LOW"
    else:
        verdict = "CLEAN"
    return Report(url=url, flags=flags, score=total, verdict=verdict)
