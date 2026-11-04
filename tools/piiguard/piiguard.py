#!/usr/bin/env python3
"""piiguard: offline PII / sensitive-personal-data scanner for agent transcripts.

Before sharing, logging, or exporting an agent run, check whether emails, phone
numbers, SSNs, payment cards, government IDs, bank details, dates of birth,
home addresses, or medical record numbers leaked into messages or tool results.

Complements tracesweep (credentials / API keys / tokens — not identity PII),
outfence (render-time exfil in model output), and pathfence (sensitive file
paths). Stdlib only; never connects to a network.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from urllib.parse import unquote

VERSION = "0.1.0"
SEVERITIES = ["info", "low", "medium", "high", "critical"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}

RULES = {
    "PG01": ("high", "Email address"),
    "PG02": ("high", "Phone number"),
    "PG03": ("critical", "US Social Security number (SSN)"),
    "PG04": ("critical", "Payment card number (Luhn-valid PAN)"),
    "PG05": ("high", "Government / passport / driver's-license ID"),
    "PG06": ("high", "Bank account / IBAN / routing number"),
    "PG07": ("medium", "Date of birth"),
    "PG08": ("medium", "Street / postal address"),
    "PG09": ("medium", "Medical record / health identifier"),
    "PG10": ("info", "Inventory of transcript segments scanned"),
}

# --- detectors ----------------------------------------------------------------

# Emails: avoid matching obvious non-PII like noreply@ or git commit noise lightly;
# still flag them — operators can --disable PG01. Skip image extensions after @.
EMAIL_RE = re.compile(
    r"(?<![A-Za-z0-9._%+-])"
    r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24})"
    r"(?![A-Za-z0-9._%+-])"
)

# Phones: US/NANP and simple international. Require enough digits; avoid timestamps.
PHONE_RE = re.compile(
    r"(?<!\d)"
    r"("
    r"(?:\+?1[\s\-.]*)?(?:\(?\d{3}\)?[\s\-.]*)\d{3}[\s\-.]*\d{4}"
    r"|"
    r"\+[1-9]\d{0,2}[\s\-.]?(?:\d[\s\-.]?){7,12}\d"
    r")"
    r"(?!\d)"
)

# SSN: XXX-XX-XXXX with invalid-group filters (000, 666, 9xx area; 00 group; 0000 serial)
SSN_RE = re.compile(
    r"(?<!\d)(\d{3}[-\s]?\d{2}[-\s]?\d{4})(?!\d)"
)
SSN_LABELED_RE = re.compile(
    r"(?i)\b(?:ssn|social\s*security(?:\s*(?:number|no\.?|#))?"
    r"|social\s*security\s*#)\s*[:#]?\s*(\d{3}[-\s]?\d{2}[-\s]?\d{4})\b"
)

# Payment cards: 13–19 digit runs with optional separators; validated by Luhn
CARD_RE = re.compile(
    r"(?<!\d)((?:\d[ \-]?){13,19})(?!\d)"
)

# Government IDs
PASSPORT_RE = re.compile(
    r"(?i)\b(?:passport\s*(?:no\.?|number|num|#)|passport|ppt)\s*[:#]?\s*"
    r"([A-Z0-9]{6,12})\b"
)
DL_RE = re.compile(
    r"(?i)\b(?:driver'?s?\s*lic(?:en[cs]e)?(?:\s*(?:no\.?|number|#))?|"
    r"dl\s*(?:number|#|no\.?)|license\s*(?:number|#|no\.?))\s*[:#]?\s*"
    r"([A-Z0-9\-]{5,20})\b"
)
NATIONAL_ID_RE = re.compile(
    r"(?i)\b(?:national\s*id|nid|taxpayer\s*id|itin|tax\s*id)\s*[:#]?\s*"
    r"([A-Z0-9\-]{6,18})\b"
)

# Bank
IBAN_RE = re.compile(
    r"\b([A-Z]{2}\d{2}[A-Z0-9]{10,30})\b"
)
ROUTING_RE = re.compile(
    r"(?i)\b(?:routing[\s_]*(?:number|no\.?|#)|aba[\s_]*(?:number|routing)?)"
    r"[\s\"']*[:#=]?[\s\"']*(\d{9})\b"
)
ACCOUNT_RE = re.compile(
    r"(?i)\b(?:bank[\s_]*)?account[\s_]*(?:number|no\.?|#)"
    r"[\s\"']*[:#=]?[\s\"']*(\d{6,17})\b"
)

# DOB
DOB_LABELED_RE = re.compile(
    r"(?i)\b(?:dob|date\s*of\s*birth|birth\s*date|born\s*on|birthday)\s*[:#]?\s*"
    r"("
    r"\d{4}[-/]\d{1,2}[-/]\d{1,2}"
    r"|"
    r"\d{1,2}[-/]\d{1,2}[-/]\d{2,4}"
    r"|"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Sept|Oct|Nov|Dec)[a-z]*\s+\d{1,2},?\s+\d{4}"
    r")\b"
)

# Street / postal address (US-oriented heuristic)
ADDRESS_RE = re.compile(
    r"(?i)\b(\d{1,5}\s+(?:[A-Z0-9][A-Za-z0-9.'\-]+\s+){0,4}"
    r"(?:Street|St\.?|Avenue|Ave\.?|Boulevard|Blvd\.?|Road|Rd\.?|Lane|Ln\.?|"
    r"Drive|Dr\.?|Court|Ct\.?|Way|Place|Pl\.?|Terrace|Ter\.?|Circle|Cir\.?)"
    r"(?:\s*,?\s*(?:Apt|Apartment|Suite|Ste\.?|Unit|#)\s*[A-Z0-9\-]+)?"
    r"(?:\s*,\s*[A-Za-z .'-]+,\s*[A-Z]{2}\s+\d{5}(?:-\d{4})?)?)"
)
ZIP_LABELED_RE = re.compile(
    r"(?i)\b(?:home\s*)?(?:address|zip\s*code|postal\s*code)\s*[:#]?\s*"
    r"([^\n,]{8,80})"
)

# Medical
MRN_RE = re.compile(
    r"(?i)\b(?:mrn|medical\s*record\s*(?:number|no\.?|#)|patient\s*id|"
    r"health\s*record\s*(?:number|#))"
    r"[\s\"']*[:#=]?[\s\"']*([A-Z0-9\-]{4,20})\b"
)
NPI_RE = re.compile(
    r"(?i)\b(?:npi|national\s*provider\s*(?:identifier|id))"
    r"[\s\"']*[:#=]?[\s\"']*(\d{10})\b"
)

# Roles / content extraction
TEXT_KEYS = {
    "content", "text", "message", "body", "output", "result", "value",
    "arguments", "input", "query", "data", "snippet", "page_content",
}


class Finding:
    __slots__ = (
        "rule", "severity", "source", "message", "turn", "role", "tool",
        "match", "span", "snippet",
    )

    def __init__(
        self, rule, source, message, match="", turn=None, role="", tool="",
        span=None, snippet="",
    ):
        self.rule = rule
        self.severity = RULES[rule][0]
        self.source = source
        self.message = message
        self.turn = turn
        self.role = role or ""
        self.tool = tool or ""
        self.match = match or ""
        self.span = span  # (start, end) in segment text, if known
        self.snippet = snippet or ""

    def to_dict(self):
        d = {
            "rule": self.rule,
            "severity": self.severity,
            "title": RULES[self.rule][1],
            "source": self.source,
            "message": self.message,
            "turn": self.turn,
            "role": self.role,
            "tool": self.tool,
            "match": _mask_match(self.rule, self.match),
        }
        if self.snippet:
            d["snippet"] = self.snippet
        return d


class Segment:
    __slots__ = ("source", "text", "turn", "role", "tool")

    def __init__(self, source, text, turn=None, role="", tool=""):
        self.source = source
        self.text = text if isinstance(text, str) else ""
        self.turn = turn
        self.role = role or ""
        self.tool = tool or ""


def _mask_match(rule: str, value: str) -> str:
    """Mask PII in report output (keep shape, hide most digits/chars)."""
    if not value:
        return ""
    v = value.strip()
    if rule == "PG01" and "@" in v:
        local, _, domain = v.partition("@")
        if len(local) <= 2:
            return "*@" + domain
        return local[0] + "***@" + domain
    if rule == "PG04":
        digits = re.sub(r"\D", "", v)
        if len(digits) >= 4:
            return "****-****-****-" + digits[-4:]
        return "****"
    if rule in ("PG03", "PG06"):
        digits = re.sub(r"\D", "", v)
        if len(digits) >= 4:
            return "*" * (len(digits) - 4) + digits[-4:]
        return "****"
    if len(v) <= 4:
        return "****"
    return v[:2] + "***" + v[-2:]


def _snippet(text: str, start: int, end: int, pad: int = 24) -> str:
    a = max(0, start - pad)
    b = min(len(text), end + pad)
    s = text[a:b]
    s = re.sub(r"\s+", " ", s).strip()
    if a > 0:
        s = "…" + s
    if b < len(text):
        s = s + "…"
    return s[:120]


def luhn_ok(digits: str) -> bool:
    """Return True if digit string passes the Luhn check."""
    if not digits.isdigit() or not (13 <= len(digits) <= 19):
        return False
    # Reject obvious non-cards (all same digit, ascending test junk without issuer shape)
    if len(set(digits)) == 1:
        return False
    total = 0
    reverse = digits[::-1]
    for i, ch in enumerate(reverse):
        n = ord(ch) - 48
        if i % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def make_luhn(prefix: str, length: int = 16) -> str:
    """Build a Luhn-valid PAN from a numeric prefix (for tests/examples only)."""
    if not prefix.isdigit():
        raise ValueError("prefix must be digits")
    if length < len(prefix) + 1 or length > 19:
        raise ValueError("bad length")
    body = prefix + ("0" * (length - len(prefix) - 1))
    # compute check digit
    total = 0
    reverse = body[::-1]
    for i, ch in enumerate(reverse):
        n = ord(ch) - 48
        # check digit is position 0 in reverse of full number → body positions
        # are odd indices when check digit is appended (i starts 0 on last body digit
        # which will be index 1 of full reverse)
        if i % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    check = (10 - (total % 10)) % 10
    return body + str(check)


def _ssn_plausible(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    if len(digits) != 9:
        return False
    area, group, serial = digits[:3], digits[3:5], digits[5:]
    if area == "000" or area == "666" or area[0] == "9":
        return False
    if group == "00" or serial == "0000":
        return False
    # Famous advertising / invalid placeholders sometimes still look real —
    # allow famous advertising placeholders through (operators can ignore); block all-zero-ish
    return True


def _iban_plausible(iban: str) -> bool:
    """MOD-97 IBAN check; also reject obviously fake country+short blobs."""
    s = re.sub(r"\s+", "", iban).upper()
    if not re.fullmatch(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}", s):
        return False
    if len(s) < 15 or len(s) > 34:
        return False
    # rearrange
    rearr = s[4:] + s[:4]
    nums = []
    for ch in rearr:
        if ch.isdigit():
            nums.append(ch)
        else:
            nums.append(str(ord(ch) - 55))
    try:
        return int("".join(nums)) % 97 == 1
    except ValueError:
        return False


def _phone_plausible(raw: str) -> bool:
    digits = re.sub(r"\D", "", raw)
    if digits.startswith("1") and len(digits) == 11:
        digits = digits[1:]
    if len(digits) == 10:
        # NANP: area can't start with 0/1
        if digits[0] in "01":
            return False
        # exchange normally can't start with 0/1, but allow 555-0xxx fictional
        if digits[3] in "01" and digits[:3] != "555":
            return False
        # avoid 1111111111-ish
        if len(set(digits)) <= 2:
            return False
        return True
    if 8 <= len(digits) <= 15 and digits[0] != "0":
        return True
    return False


def _looks_like_timestamp_or_id(raw: str) -> bool:
    """Heuristic: long digit runs that are clearly not phones (unix times etc.)."""
    digits = re.sub(r"\D", "", raw)
    if len(digits) == 10 and digits.startswith(("16", "17", "18")):
        # likely unix timestamp seconds ~2020-2030
        try:
            n = int(digits)
            if 1600000000 <= n <= 1899999999:
                return True
        except ValueError:
            pass
    return False


def _card_brand_ok(digits: str) -> bool:
    """Loose issuer-prefix filter to cut down false positives on random digit runs."""
    if digits.startswith("4") and len(digits) in (13, 16, 19):
        return True  # Visa
    if digits[:2] in {f"{i:02d}" for i in range(51, 56)} and len(digits) == 16:
        return True  # Mastercard
    if digits.startswith(("34", "37")) and len(digits) == 15:
        return True  # Amex
    if digits.startswith(("6011", "65")) and len(digits) == 16:
        return True  # Discover-ish
    if digits.startswith("35") and len(digits) == 16:
        return True  # JCB-ish
    if digits.startswith(("300", "301", "302", "303", "304", "305", "36", "38")) and len(digits) == 14:
        return True  # Diners
    # Allow other Luhn-valid 16-digit starting 2 (Mastercard 2-series)
    if digits.startswith("2") and len(digits) == 16:
        try:
            bin6 = int(digits[:6])
            if 222100 <= bin6 <= 272099:
                return True
        except ValueError:
            pass
    return False


# Example.com / reserved / documentation hosts still count as PII shape for
# sharing decisions; operators can disable. Skip only clearly non-email paths.
EMAIL_SKIP_LOCAL = {
    "noreply", "no-reply", "donotreply", "mailer-daemon", "postmaster",
}


def scan_text(text: str, source: str, turn=None, role="", tool="", disabled=None):
    """Return Finding list for one text segment."""
    disabled = set(disabled or [])
    findings = []
    if not text:
        return findings

    def add(rule, message, match, start, end):
        if rule in disabled:
            return
        findings.append(
            Finding(
                rule=rule,
                source=source,
                message=message,
                match=match,
                turn=turn,
                role=role,
                tool=tool,
                span=(start, end),
                snippet=_snippet(text, start, end),
            )
        )

    # Track spans already claimed by higher-severity rules to reduce double hits
    claimed = []

    def overlaps(a, b):
        return not (a[1] <= b[0] or b[1] <= a[0])

    def claim(span):
        claimed.append(span)

    def is_claimed(span):
        return any(overlaps(span, c) for c in claimed)

    # PG03 SSN (labeled first, then shape)
    if "PG03" not in disabled:
        for m in SSN_LABELED_RE.finditer(text):
            raw = m.group(1)
            if _ssn_plausible(raw):
                sp = (m.start(1), m.end(1))
                add("PG03", "Labeled SSN", raw, *sp)
                claim(sp)
        for m in SSN_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            # Prefer dashed form; bare 9 digits need separators or label context
            if "-" not in raw and " " not in raw:
                # require nearby label within 40 chars
                window = text[max(0, m.start() - 40): m.start()].lower()
                if not re.search(r"(ssn|social|taxpayer|itin)", window):
                    continue
            if _ssn_plausible(raw):
                add("PG03", "SSN-shaped number", raw, *sp)
                claim(sp)

    # PG04 cards
    if "PG04" not in disabled:
        for m in CARD_RE.finditer(text):
            raw = m.group(1)
            digits = re.sub(r"\D", "", raw)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if not luhn_ok(digits):
                continue
            if not _card_brand_ok(digits):
                continue
            add("PG04", "Luhn-valid payment card", raw, *sp)
            claim(sp)

    # PG01 emails
    if "PG01" not in disabled:
        for m in EMAIL_RE.finditer(text):
            raw = m.group(1)
            local = raw.split("@", 1)[0].lower()
            domain = raw.split("@", 1)[1].lower()
            if domain.endswith((".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js")):
                continue
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            msg = "Email address"
            if local in EMAIL_SKIP_LOCAL:
                msg = "Email address (noreply-style local-part)"
            add("PG01", msg, raw, *sp)

    # PG02 phones
    if "PG02" not in disabled:
        for m in PHONE_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _looks_like_timestamp_or_id(raw):
                continue
            if not _phone_plausible(raw):
                continue
            # Avoid matching card digit leftovers
            digits = re.sub(r"\D", "", raw)
            if len(digits) >= 13:
                continue
            add("PG02", "Phone number", raw, *sp)
            claim(sp)

    # PG05 government IDs
    if "PG05" not in disabled:
        for rx, label in (
            (PASSPORT_RE, "Passport number"),
            (DL_RE, "Driver's license number"),
            (NATIONAL_ID_RE, "National / tax ID"),
        ):
            for m in rx.finditer(text):
                raw = m.group(1)
                sp = (m.start(1), m.end(1))
                if is_claimed(sp):
                    continue
                if raw.upper().startswith("FAKE"):
                    # still PII-shaped for governance; keep
                    pass
                add("PG05", label, raw, *sp)
                claim(sp)

    # PG06 bank
    if "PG06" not in disabled:
        for m in IBAN_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            if _iban_plausible(raw):
                add("PG06", "IBAN", raw, *sp)
                claim(sp)
        for m in ROUTING_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            add("PG06", "ABA routing number", raw, *sp)
            claim(sp)
        for m in ACCOUNT_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            add("PG06", "Bank account number", raw, *sp)
            claim(sp)

    # PG07 DOB
    if "PG07" not in disabled:
        for m in DOB_LABELED_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            add("PG07", "Date of birth", raw, *sp)
            claim(sp)

    # PG08 address
    if "PG08" not in disabled:
        for m in ADDRESS_RE.finditer(text):
            raw = m.group(1)
            sp = (m.start(1), m.end(1))
            if is_claimed(sp):
                continue
            add("PG08", "Street address", raw, *sp)
            claim(sp)
        for m in ZIP_LABELED_RE.finditer(text):
            raw = m.group(1).strip().rstrip(".")
            sp = (m.start(1), m.start(1) + len(raw))
            if is_claimed(sp):
                continue
            # skip if already caught as street
            if len(raw) < 8:
                continue
            add("PG08", "Labeled address / postal field", raw, *sp)
            claim(sp)

    # PG09 medical
    if "PG09" not in disabled:
        for rx, label in ((MRN_RE, "Medical record number"), (NPI_RE, "NPI")):
            for m in rx.finditer(text):
                raw = m.group(1)
                sp = (m.start(1), m.end(1))
                if is_claimed(sp):
                    continue
                add("PG09", label, raw, *sp)
                claim(sp)

    return findings


def _stringify_content(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for part in content:
            if isinstance(part, str):
                parts.append(part)
            elif isinstance(part, dict):
                if part.get("type") == "text" and isinstance(part.get("text"), str):
                    parts.append(part["text"])
                elif isinstance(part.get("text"), str):
                    parts.append(part["text"])
                elif isinstance(part.get("content"), str):
                    parts.append(part["content"])
                else:
                    # tool_use / input blocks
                    for k in ("input", "arguments", "partial_json"):
                        if k in part:
                            v = part[k]
                            if isinstance(v, str):
                                parts.append(v)
                            else:
                                try:
                                    parts.append(json.dumps(v, ensure_ascii=False))
                                except (TypeError, ValueError):
                                    parts.append(str(v))
        return "\n".join(parts)
    if isinstance(content, dict):
        try:
            return json.dumps(content, ensure_ascii=False)
        except (TypeError, ValueError):
            return str(content)
    return str(content)


def _segments_from_message(msg: dict, source: str, turn: int):
    """Yield Segment objects from one message-like dict."""
    if not isinstance(msg, dict):
        return
    role = str(msg.get("role") or msg.get("type") or msg.get("author") or "")
    # OpenAI tool_calls on assistant
    if msg.get("tool_calls"):
        for tc in msg["tool_calls"]:
            if not isinstance(tc, dict):
                continue
            fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
            name = fn.get("name") or tc.get("name") or tc.get("tool") or ""
            args = fn.get("arguments", tc.get("arguments", tc.get("input", "")))
            if isinstance(args, (dict, list)):
                try:
                    args = json.dumps(args, ensure_ascii=False)
                except (TypeError, ValueError):
                    args = str(args)
            yield Segment(source, str(args or ""), turn=turn, role=role or "assistant", tool=str(name))
    # Anthropic content blocks
    content = msg.get("content", msg.get("text", msg.get("message")))
    if isinstance(content, list):
        for block in content:
            if not isinstance(block, dict):
                if isinstance(block, str) and block.strip():
                    yield Segment(source, block, turn=turn, role=role)
                continue
            btype = block.get("type") or ""
            if btype in ("tool_use", "function_call"):
                name = block.get("name") or ""
                inp = block.get("input", block.get("arguments", ""))
                if isinstance(inp, (dict, list)):
                    try:
                        inp = json.dumps(inp, ensure_ascii=False)
                    except (TypeError, ValueError):
                        inp = str(inp)
                yield Segment(source, str(inp or ""), turn=turn, role=role or "assistant", tool=str(name))
            elif btype == "tool_result":
                name = str(block.get("name") or block.get("tool_use_id") or "tool")
                yield Segment(
                    source,
                    _stringify_content(block.get("content", block.get("output", ""))),
                    turn=turn,
                    role="tool",
                    tool=name,
                )
            else:
                text = _stringify_content(block)
                if text.strip():
                    yield Segment(source, text, turn=turn, role=role)
        return
    # tool role message
    if role in ("tool", "function"):
        name = str(msg.get("name") or msg.get("tool_name") or "tool")
        yield Segment(source, _stringify_content(content), turn=turn, role="tool", tool=name)
        return
    text = _stringify_content(content)
    if text.strip():
        yield Segment(source, text, turn=turn, role=role)


def extract_segments(doc, source: str):
    """Normalize OpenAI / Anthropic / generic JSON into Segment list."""
    segs = []

    def from_messages(messages, src):
        if not isinstance(messages, list):
            return
        for i, msg in enumerate(messages):
            if isinstance(msg, str):
                segs.append(Segment(src, msg, turn=i, role="unknown"))
            elif isinstance(msg, dict):
                segs.extend(_segments_from_message(msg, src, i))

    if isinstance(doc, list):
        # JSONL already merged as list of events, or bare messages list
        if doc and all(isinstance(x, dict) and (
            "role" in x or "content" in x or "tool_calls" in x or "type" in x
        ) for x in doc[:5]):
            from_messages(doc, source)
        else:
            for i, item in enumerate(doc):
                if isinstance(item, str):
                    segs.append(Segment(source, item, turn=i))
                elif isinstance(item, dict):
                    segs.extend(_segments_from_message(item, source, i))
        return segs

    if not isinstance(doc, dict):
        if isinstance(doc, str):
            segs.append(Segment(source, doc, turn=0))
        return segs

    for key in ("messages", "events", "steps", "transcript", "items", "conversation", "data"):
        val = doc.get(key)
        if isinstance(val, list) and val:
            from_messages(val, source)
            if segs:
                return segs

    # single message object
    if any(k in doc for k in ("role", "content", "tool_calls")):
        segs.extend(_segments_from_message(doc, source, 0))
        if segs:
            return segs

    # fallback: scan whole JSON dump as text
    try:
        segs.append(Segment(source, json.dumps(doc, ensure_ascii=False), turn=0, role="document"))
    except (TypeError, ValueError):
        segs.append(Segment(source, str(doc), turn=0, role="document"))
    return segs


def load_path(path: str):
    """Load file into (doc_or_text, kind) where kind is json|jsonl|text."""
    if path == "-":
        raw = sys.stdin.read()
        source = "<stdin>"
    else:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            raw = f.read()
        source = path
    return parse_raw(raw, source)


def parse_raw(raw: str, source: str):
    stripped = raw.strip()
    if not stripped:
        return [], source, raw
    # JSONL?
    if source.endswith(".jsonl") or (
        "\n" in stripped and stripped[0] == "{" and not stripped.endswith("]")
    ):
        lines = [ln for ln in raw.splitlines() if ln.strip()]
        if lines and all(ln.lstrip().startswith("{") or ln.lstrip().startswith("[") for ln in lines[:5]):
            objs = []
            ok = True
            for ln in lines:
                try:
                    objs.append(json.loads(ln))
                except json.JSONDecodeError:
                    ok = False
                    break
            if ok and objs:
                return objs, source, raw
    if stripped[0] in "{[":
        try:
            return json.loads(stripped), source, raw
        except json.JSONDecodeError:
            pass
    return raw, source, raw


def collect_inputs(paths):
    """Expand dirs/files into list of paths ( '-' preserved )."""
    out = []
    for p in paths:
        if p == "-":
            out.append("-")
            continue
        if os.path.isdir(p):
            for root, _dirs, files in os.walk(p):
                for name in sorted(files):
                    if name.startswith("."):
                        continue
                    if name.endswith((".json", ".jsonl", ".txt", ".md", ".log")):
                        out.append(os.path.join(root, name))
        elif os.path.isfile(p):
            out.append(p)
        else:
            raise FileNotFoundError(p)
    return out


def analyze_paths(paths, disabled=None, as_text=False):
    disabled = set(disabled or [])
    all_findings = []
    segment_count = 0
    sources = []
    raws = []  # (source, raw_text) for redact

    for path in paths:
        doc, source, raw = load_path(path)
        sources.append(source)
        raws.append((source, raw, path))
        if as_text or isinstance(doc, str):
            text = doc if isinstance(doc, str) else raw
            # split paragraphs for attribution
            parts = re.split(r"\n\s*\n", text) if as_text else [text]
            segs = [
                Segment(source, p, turn=i, role="text")
                for i, p in enumerate(parts) if p.strip()
            ]
        else:
            segs = extract_segments(doc, source)
        segment_count += len(segs)
        for seg in segs:
            all_findings.extend(
                scan_text(
                    seg.text,
                    seg.source,
                    turn=seg.turn,
                    role=seg.role,
                    tool=seg.tool,
                    disabled=disabled,
                )
            )

    if "PG10" not in disabled:
        all_findings.append(
            Finding(
                rule="PG10",
                source=",".join(sources[:3]) + ("…" if len(sources) > 3 else ""),
                message="Scanned %d segment(s) across %d input(s)" % (segment_count, len(sources)),
                match="",
            )
        )
    return all_findings, raws, segment_count


def redact_text(raw: str, findings) -> str:
    """Replace matched PII spans in raw text with masked tokens.

    Only findings that carry a span and whose source matches a single-file raw
    are applied; for multi-segment JSON we re-scan the whole raw string.
    """
    # Re-derive spans against the full raw so JSON structure is preserved.
    local = scan_text(raw, source="redact", disabled={"PG10"})
    # Prefer critical/high replacements; sort by start descending
    spans = []
    for f in local:
        if f.span and f.match and f.rule != "PG10":
            spans.append((f.span[0], f.span[1], f.rule, f.match))
    spans.sort(key=lambda x: x[0], reverse=True)
    out = raw
    used = []
    for start, end, rule, match in spans:
        if any(not (end <= a or b <= start) for a, b in used):
            continue
        token = "[REDACTED:%s:%s]" % (rule, _mask_match(rule, match))
        out = out[:start] + token + out[end:]
        used.append((start, end))
    return out


def filter_findings(findings, min_severity="info"):
    floor = SEV_RANK[min_severity]
    return [f for f in findings if SEV_RANK[f.severity] >= floor]


def worst_severity(findings):
    if not findings:
        return None
    return max(findings, key=lambda f: SEV_RANK[f.severity]).severity


def format_text(findings):
    lines = []
    actionable = [f for f in findings if f.rule != "PG10"]
    inv = [f for f in findings if f.rule == "PG10"]
    if not actionable:
        lines.append("piiguard: no PII findings")
    else:
        lines.append("piiguard: %d finding(s)" % len(actionable))
    for f in sorted(
        actionable,
        key=lambda x: (-SEV_RANK[x.severity], x.rule, x.source, x.turn or -1),
    ):
        loc = f.source
        extras = []
        if f.turn is not None:
            extras.append("turn=%s" % f.turn)
        if f.role:
            extras.append("role=%s" % f.role)
        if f.tool:
            extras.append("tool=%s" % f.tool)
        if extras:
            loc = "%s (%s)" % (loc, ", ".join(extras))
        lines.append(
            "  [%s] %s %s: %s — %s"
            % (f.severity, f.rule, loc, f.message, _mask_match(f.rule, f.match) or "-")
        )
        if f.snippet:
            lines.append("           snippet: %s" % f.snippet)
    for f in inv:
        lines.append("  [%s] %s: %s" % (f.severity, f.rule, f.message))
    return "\n".join(lines) + "\n"


def _write_redacted(out_path, raws, findings_by_source=None):
    """Write redacted copies. out_path is file if one input, else directory."""
    if len(raws) == 1:
        source, raw, path = raws[0]
        text = redact_text(raw, None)
        if out_path in ("-", "/dev/stdout"):
            sys.stdout.write(text)
            return
        parent = os.path.dirname(os.path.abspath(out_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            f.write(text)
        return
    os.makedirs(out_path, exist_ok=True)
    for source, raw, path in raws:
        if path == "-":
            name = "stdin.txt"
        else:
            name = os.path.basename(path)
        dest = os.path.join(out_path, name)
        with open(dest, "w", encoding="utf-8") as f:
            f.write(redact_text(raw, None))


def main(argv=None):
    ap = argparse.ArgumentParser(
        prog="piiguard",
        description="Offline PII / sensitive-personal-data scanner for agent transcripts "
        "(emails, phones, SSN, cards, IDs, bank, DOB, address, medical). "
        "Complements tracesweep (secrets/API keys).",
    )
    ap.add_argument("paths", nargs="*", help="transcript files/dirs (.json/.jsonl/.txt), '-' for stdin")
    ap.add_argument("--as-text", action="store_true", help="treat inputs as plain text (paragraph = segment)")
    ap.add_argument("--disable", nargs="+", metavar="RULE", default=[], help="skip rule ids (e.g. PG10 PG01)")
    ap.add_argument("--json", action="store_true", help="JSON output")
    ap.add_argument(
        "--min-severity",
        default="info",
        choices=SEVERITIES,
        help="hide findings below this severity (default info)",
    )
    ap.add_argument(
        "--fail-on",
        default="high",
        choices=SEVERITIES + ["any", "none"],
        help="exit 1 if any finding >= severity (default high; any, none)",
    )
    ap.add_argument(
        "--redact",
        metavar="OUT",
        help="write redacted copy (file for one input, directory for many)",
    )
    ap.add_argument("--list-rules", action="store_true", help="print rules and exit")
    ap.add_argument("--version", action="version", version="piiguard %s" % VERSION)
    args = ap.parse_args(argv)

    if args.list_rules:
        for rid, (sev, title) in RULES.items():
            sys.stdout.write("%s\t%s\t%s\n" % (rid, sev, title))
        return 0

    if not args.paths:
        ap.print_usage(sys.stderr)
        sys.stderr.write("piiguard: error: at least one path (or '-') required\n")
        return 2

    try:
        inputs = collect_inputs(args.paths)
    except FileNotFoundError as e:
        sys.stderr.write("piiguard: error: not found: %s\n" % e)
        return 2
    if not inputs:
        sys.stderr.write("piiguard: error: no readable inputs\n")
        return 2

    disabled = set(args.disable or [])
    try:
        findings, raws, _n = analyze_paths(inputs, disabled=disabled, as_text=args.as_text)
    except OSError as e:
        sys.stderr.write("piiguard: error: %s\n" % e)
        return 2
    except ValueError as e:
        sys.stderr.write("piiguard: error: %s\n" % e)
        return 2

    shown = filter_findings(findings, args.min_severity)

    if args.redact:
        if len(raws) > 1 and os.path.isfile(args.redact):
            sys.stderr.write(
                "piiguard: error: --redact must be a directory when multiple inputs are given\n"
            )
            return 2
        try:
            _write_redacted(args.redact, raws)
        except OSError as e:
            sys.stderr.write("piiguard: error: redact write failed: %s\n" % e)
            return 2

    if args.json:
        payload = {
            "tool": "piiguard",
            "version": VERSION,
            "findings": [f.to_dict() for f in shown],
            "summary": {
                "count": len([f for f in shown if f.rule != "PG10"]),
                "worst": worst_severity([f for f in shown if f.rule != "PG10"]),
            },
        }
        sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
    else:
        sys.stdout.write(format_text(shown))

    actionable = [f for f in shown if f.rule != "PG10"]
    if args.fail_on == "none":
        return 0
    if args.fail_on == "any":
        return 1 if actionable else 0
    floor = SEV_RANK[args.fail_on]
    if any(SEV_RANK[f.severity] >= floor for f in actionable):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
