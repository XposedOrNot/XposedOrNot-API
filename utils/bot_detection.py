"""Heuristic browser-impersonation detection for rate-limit hardening.

``classify_request`` scores how browser-impersonating a request looks;
``request_fingerprint`` derives an IP-independent fingerprint of the client
stack so a flagged fleet can be throttled as one bucket regardless of how many
IPs it rotates through.

Rationale (validated on live traffic): genuine Chromium browsers always send
Client Hints (``sec-ch-ua``) and Fetch Metadata (``Sec-Fetch-*``), plus a real
``Accept-Language`` and a rich ``Accept-Encoding`` (br/zstd). HTTP libraries
that spoof a browser User-Agent do not. Honest API clients (Dart, apify,
OrgBreachChecker, …) don't claim to be browsers, so they score 0 and are never
flagged — only *liars* are.
"""

import hashlib

_CHROMIUM_TOKENS = ("Chrome/", "Chromium/", "Edg/", "OPR/", "Brave/")

BOT_FLAG_THRESHOLD = 3


def _is_chromiumish(ua: str) -> bool:
    """True if the UA claims a Chromium-based browser."""
    return any(token in ua for token in _CHROMIUM_TOKENS)


def _claims_browser(ua: str) -> bool:
    """True if the UA claims to be a browser (all real browsers start so)."""
    return ua.startswith("Mozilla/")


def classify_request(headers) -> dict:
    """Score how browser-impersonating a request looks.

    Pure and side-effect free. Returns a dict with ``score`` (higher = more
    bot-like), ``reasons`` (list of triggered signals) and ``ua_family``.
    Detection only — callers decide what, if anything, to do.
    """
    ua = (headers.get("user-agent") or "").strip()
    reasons = []
    score = 0

    if not ua:
        return {"score": 1, "reasons": ["no-ua"], "ua_family": "none"}

    chromiumish = _is_chromiumish(ua)
    browsery = _claims_browser(ua)

    if not browsery:
        return {"score": 0, "reasons": [], "ua_family": "non-browser"}

    sec_ch_ua = headers.get("sec-ch-ua")
    has_fetch_meta = any(
        headers.get(h) for h in ("sec-fetch-site", "sec-fetch-mode", "sec-fetch-dest")
    )
    accept_language = headers.get("accept-language")
    accept_encoding = headers.get("accept-encoding") or ""

    if chromiumish and not sec_ch_ua:
        reasons.append("chromium-ua-without-client-hints")
        score += 3

    if not has_fetch_meta:
        reasons.append("browser-ua-without-fetch-metadata")
        score += 1

    if not accept_language:
        reasons.append("browser-ua-without-accept-language")
        score += 1

    if (
        accept_encoding
        and "br" not in accept_encoding
        and "zstd" not in accept_encoding
    ):
        reasons.append("browser-ua-thin-accept-encoding")
        score += 1

    family = "chromium" if chromiumish else "browser"
    return {"score": score, "reasons": reasons, "ua_family": family}


def request_fingerprint(headers) -> str:
    """Stable, IP-independent fingerprint of the client stack.

    Built from the User-Agent and the *shape* of its capability headers
    (which Client Hints / Fetch Metadata are present, plus Accept-Encoding).
    An impersonating fleet that rotates IPs but keeps the same tool produces a
    single fingerprint, so a fingerprint-keyed limit collapses it into one
    bucket. Pure and side-effect free.
    """
    ua = (headers.get("user-agent") or "").strip()
    hint_shape = "".join(
        "1" if headers.get(h) else "0"
        for h in (
            "sec-ch-ua",
            "sec-fetch-site",
            "sec-fetch-mode",
            "sec-fetch-dest",
            "accept-language",
        )
    )
    accept_encoding = headers.get("accept-encoding") or ""
    raw = f"{ua}|{hint_shape}|{accept_encoding}"
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]
