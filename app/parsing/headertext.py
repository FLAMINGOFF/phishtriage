"""Small tokenisers for structured header values (RFC 5322 comments, quoted strings)."""

from __future__ import annotations


def unfold(value: str) -> str:
    """Collapse folding whitespace (CRLF + WSP) and runs of spaces into single spaces."""
    return " ".join(value.split())


def blank_comments(value: str) -> str:
    """Replace ``(comments)`` with spaces of the same length, honouring nesting,
    quoted strings and backslash escapes. Positions in the result match ``value``."""
    out: list[str] = []
    depth = 0
    in_quotes = False
    escaped = False
    for ch in value:
        if escaped:
            out.append(" " if depth else ch)
            escaped = False
            continue
        if ch == "\\":
            escaped = True
            out.append(" " if depth else ch)
            continue
        if in_quotes:
            out.append(ch)
            if ch == '"':
                in_quotes = False
            continue
        if ch == "(":
            depth += 1
            out.append(" ")
        elif ch == ")" and depth:
            depth -= 1
            out.append(" ")
        elif depth:
            out.append(" ")
        else:
            if ch == '"':
                in_quotes = True
            out.append(ch)
    return "".join(out)


def split_outside_quotes(value: str, sep: str = ";") -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    in_quotes = False
    for ch in value:
        if ch == '"':
            in_quotes = not in_quotes
        if ch == sep and not in_quotes:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts
