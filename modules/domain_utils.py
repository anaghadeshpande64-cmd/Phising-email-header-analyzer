"""Small domain/hostname helpers shared by several modules.

Deliberately dependency-free. The registered-domain logic is a simplified
heuristic (no Public Suffix List) that handles the most common multi-part
suffixes such as ``co.uk`` or ``co.in``.
"""
from __future__ import annotations

import ipaddress
import unicodedata
from typing import Set

MULTI_PART_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au",
    "co.in", "net.in", "org.in", "gov.in", "co.jp", "co.nz", "com.br",
    "com.cn", "com.sg", "co.za", "com.mx", "co.kr", "com.tr", "com.hk",
    "com.my", "co.id", "com.pk", "com.bd",
}

# A few Cyrillic/Greek characters that look like Latin letters (IDN homographs).
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "ӏ": "l",
    "ο": "o", "ν": "v", "α": "a", "ρ": "p", "ɑ": "a",
}
_DIGIT_MAP = str.maketrans({"0": "o", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})


def normalize_host(host) -> str:
    """Lower-case a hostname and strip brackets, angle brackets and dots."""
    if not host:
        return ""
    return str(host).strip().strip("[]<>").strip(".").lower()


def is_ip_literal(host: str) -> bool:
    """True when ``host`` is an IPv4/IPv6 literal rather than a name."""
    try:
        ipaddress.ip_address(str(host).strip().strip("[]"))
        return True
    except ValueError:
        return False


def registered_domain(host: str) -> str:
    """Return an approximation of the registrable domain (e.g. ``a.b.example.com`` -> ``example.com``)."""
    host = normalize_host(host)
    if not host or is_ip_literal(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def domain_labels_without_suffix(host: str) -> list:
    """All labels of ``host`` except the public suffix (TLD / multi-part suffix)."""
    host = normalize_host(host)
    labels = host.split(".") if host else []
    if len(labels) >= 2 and ".".join(labels[-2:]) in MULTI_PART_SUFFIXES:
        return labels[:-2]
    return labels[:-1] if len(labels) > 1 else labels


def is_under(host: str, official: str) -> bool:
    """True when ``host`` equals ``official`` or is a subdomain of it."""
    host, official = normalize_host(host), normalize_host(official)
    return bool(host) and (host == official or host.endswith("." + official))


def skeleton_variants(text: str) -> Set[str]:
    """Normalise look-alike characters so ``examp1e`` and ``example`` compare equal.

    Returns a small set because ``1`` can stand in for either ``l`` or ``i``.
    """
    t = unicodedata.normalize("NFKC", (text or "").lower())
    t = "".join(_CONFUSABLES.get(c, c) for c in t)
    t = t.replace("rn", "m").replace("vv", "w").translate(_DIGIT_MAP)
    return {t.replace("1", "l"), t.replace("1", "i")}


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance (insert / delete / substitute)."""
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def has_mixed_scripts(text: str) -> bool:
    """True when letters from more than one script (e.g. Latin + Cyrillic) are mixed."""
    scripts = set()
    for ch in text or "":
        if ch.isalpha():
            try:
                scripts.add(unicodedata.name(ch).split()[0])
            except ValueError:
                continue
    return len(scripts & {"LATIN", "CYRILLIC", "GREEK"}) > 1
