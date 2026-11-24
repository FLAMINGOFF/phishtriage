"""Look-alike domain detection: edit distance and homoglyphs.

``examp1e.edu``, ``exarnple.edu`` and ``ex<Cyrillic a>mple.edu`` all look like
``example.edu`` to a hurried reader. Three checks, any of which counts:

1. Edit distance 1-2 between the registered domains (``exmaple.edu``).
2. Edit distance 1-2 between the leftmost labels, if the protected label is long enough
   that a two-letter difference still means "looks like" (``examp1e.example``).
3. The *skeleton* of the domain (homoglyphs folded to Latin, ``rn`` to ``m``, ``1`` to
   ``l``...) equals the skeleton of a protected domain or label, or one label mixes
   Latin with Cyrillic/Greek letters (a script mix no legitimate name needs).
"""

from __future__ import annotations

import unicodedata
from dataclasses import dataclass

from rapidfuzz.distance import Levenshtein

from app.parsing.defang import defang_domain
from app.parsing.domains import registered_domain, to_unicode

MAX_DISTANCE = 2
MIN_LABEL_LENGTH = 5  # "mit" vs "mlt" is too short to call a look-alike by distance alone

# Characters that render (almost) like a Latin letter in common fonts, as code points so
# the source file stays ASCII. Based on Unicode's confusables.txt, trimmed to letters seen
# in phishing domains.
_CONFUSABLES = {
    # Cyrillic
    0x0430: "a",
    0x0432: "b",
    0x0435: "e",
    0x0455: "s",
    0x0456: "i",
    0x0457: "i",
    0x0458: "j",
    0x043A: "k",
    0x043E: "o",
    0x0440: "p",
    0x0441: "c",
    0x0443: "y",
    0x0445: "x",
    0x0501: "d",
    0x04BB: "h",
    0x04CF: "l",
    0x051B: "q",
    0x051D: "w",
    0x0442: "t",
    0x043D: "h",
    0x043C: "m",
    0x0433: "r",
    # Greek
    0x03B1: "a",
    0x03B5: "e",
    0x03B9: "i",
    0x03BA: "k",
    0x03BD: "v",
    0x03BF: "o",
    0x03C1: "p",
    0x03C4: "t",
    0x03C5: "u",
    0x03C7: "x",
    0x03C9: "w",
    # Latin look-alikes and digits
    0x0261: "g",
    0x0131: "i",
    0x0269: "i",
    0x01C0: "l",
    0x0031: "l",
    0x0030: "o",
    0x0033: "e",
    0x0035: "s",
    0x00DF: "ss",
}
_SEQUENCES = (("rn", "m"), ("vv", "w"), ("cl", "d"))
_SCRIPTS = ("LATIN", "CYRILLIC", "GREEK", "ARMENIAN", "CHEROKEE")


def skeleton(text: str) -> str:
    """Fold a (Unicode) domain to the Latin letters it looks like."""
    text = unicodedata.normalize("NFKC", text).casefold()
    text = "".join(_CONFUSABLES.get(ord(ch), ch) for ch in text)
    for sequence, replacement in _SEQUENCES:
        text = text.replace(sequence, replacement)
    return text


def mixed_script_label(domain: str) -> str | None:
    """The first label that mixes Latin with another alphabet, if any."""
    for label in to_unicode(domain).split("."):
        scripts: set[str] = set()
        for ch in label:
            if ch.isalpha():
                name = unicodedata.name(ch, "")
                scripts.update(s for s in _SCRIPTS if name.startswith(s))
        if len(scripts) > 1 and "LATIN" in scripts:
            return label
    return None


def _first_label(domain: str) -> str:
    return domain.split(".", 1)[0]


@dataclass(frozen=True)
class Lookalike:
    protected: str
    reason: str


def find_lookalike(domain: str, protected_domains: tuple[str, ...]) -> Lookalike | None:
    """Does ``domain`` imitate one of ``protected_domains`` (registered domains)?"""
    candidate = registered_domain(domain)
    if any(candidate == p or candidate.endswith("." + p) for p in protected_domains):
        return None  # it *is* ours
    unicode_candidate = to_unicode(candidate)
    label = _first_label(unicode_candidate)
    for protected in protected_domains:
        distance = Levenshtein.distance(unicode_candidate, protected)
        if 0 < distance <= MAX_DISTANCE:
            return Lookalike(protected, f"edit distance {distance} from {defang_domain(protected)}")
        protected_label = _first_label(protected)
        if len(protected_label) >= MIN_LABEL_LENGTH:
            distance = Levenshtein.distance(label, protected_label)
            if 0 < distance <= MAX_DISTANCE:
                return Lookalike(
                    protected, f"name '{label}' is {distance} edit(s) from '{protected_label}'"
                )
        # Same skeleton but different characters: homoglyphs. (An identical label under
        # another TLD, example.com vs example.edu, is not a homoglyph.)
        if skeleton(unicode_candidate) == skeleton(protected) or (
            len(protected_label) >= MIN_LABEL_LENGTH
            and label != protected_label
            and skeleton(label) == skeleton(protected_label)
        ):
            return Lookalike(protected, f"looks like {defang_domain(protected)} (homoglyphs)")
    mixed = mixed_script_label(domain)
    if mixed is not None:
        return Lookalike("", f"label '{mixed}' mixes Latin with another alphabet")
    return None
