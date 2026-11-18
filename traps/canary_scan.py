"""Canary scanning over raw request bytes: the token as written and four disguised forms.

Forms (CLAUDE.md 4.2):
    exact      the token as written, also after percent-decoding
    reversed   the token written backwards
    hex        the token's bytes as hexadecimal digits, either letter case
    base64     the token's bytes in base64, standard or URL-safe alphabet, also when the
               token sits anywhere inside a longer text that was encoded as a whole
Anything else (another encoding, two encodings on top of each other, a token cut into
pieces or reworded) is not found.
"""
import base64
from urllib.parse import unquote_plus

UNREGISTERED = "UNREGISTERED_CANARY_PREFIX"
PREFIX = "CANARY_"
FORMS = ("exact", "reversed", "hex", "base64")
_URLSAFE = str.maketrans("+/", "-_")


def base64_cores(token: str) -> list[str]:
    """The base64 text that every encoding of a string containing token must contain,
    one entry per position the token can have inside a 3-byte group.

    Base64 turns 3 bytes into 4 characters, so the characters a token produces depend
    on where it starts (offset 0, 1 or 2 in a group) and on its neighbours at both
    ends. Each entry keeps only the characters fixed by the token alone."""
    data = token.encode("utf-8")
    cores = []
    for offset in range(3):
        encoded = base64.b64encode(b"\x00" * offset + data).decode("ascii").rstrip("=")
        start = (offset * 8 + 5) // 6            # first character holding only token bits
        whole = ((offset + len(data)) * 8) // 6  # characters filled entirely by known bits
        core = encoded[start:whole]
        if core:
            cores.append(core)
    return cores


def _variants(token: str) -> dict[str, list[str]]:
    """What to look for, per disguised form. hex is compared in lower case."""
    cores = base64_cores(token)
    return {"reversed": [token[::-1]],
            "hex": [token.encode("utf-8").hex()],
            "base64": cores + [c.translate(_URLSAFE) for c in cores]}


def scan_forms(raw: bytes, canaries: list[dict]) -> dict[str, list[str]]:
    """Registered canaries found in raw: {canary id: the forms it was found in}, each
    list in FORMS order. Empty when none was found."""
    text = raw.decode("utf-8", errors="replace")
    plain = (text, unquote_plus(text))
    # A JSON body may write "/" as "\/"; base64 text can contain "/".
    loose = plain + tuple(h.replace("\\/", "/") for h in plain)
    lowered = tuple(h.lower() for h in plain)
    found: dict[str, list[str]] = {}
    for canary in canaries:
        token = canary["token"]
        variants = _variants(token)
        forms = []
        if any(token in h for h in plain):
            forms.append("exact")
        if any(v in h for v in variants["reversed"] for h in plain):
            forms.append("reversed")
        if any(v in h for v in variants["hex"] for h in lowered):
            forms.append("hex")
        if any(v in h for v in variants["base64"] for h in loose):
            forms.append("base64")
        if forms:
            found[canary["id"]] = forms
    return found


def scan_for_canaries(raw: bytes, canaries: list[dict]) -> list[str]:
    """Return sorted ids of registered canaries found in raw, in any form.

    UNREGISTERED is returned only if the CANARY_ prefix appears and no registered
    token matched.
    """
    matched = sorted(scan_forms(raw, canaries))
    if matched:
        return matched
    text = raw.decode("utf-8", errors="replace")
    if any(PREFIX in h for h in (text, unquote_plus(text))):
        return [UNREGISTERED]
    return []
