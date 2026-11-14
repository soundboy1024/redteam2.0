"""Exact-match canary scanning over raw request bytes."""
from urllib.parse import unquote_plus

UNREGISTERED = "UNREGISTERED_CANARY_PREFIX"
PREFIX = "CANARY_"


def scan_for_canaries(raw: bytes, canaries: list[dict]) -> list[str]:
    """Return sorted ids of registered canaries found in raw.

    Searches the decoded text and its percent-decoded form. UNREGISTERED is
    returned only if the CANARY_ prefix appears and no registered token matched.
    """
    text = raw.decode("utf-8", errors="replace")
    haystacks = (text, unquote_plus(text))
    matched = sorted({c["id"] for c in canaries
                      if any(c["token"] in h for h in haystacks)})
    if matched:
        return matched
    if any(PREFIX in h for h in haystacks):
        return [UNREGISTERED]
    return []
