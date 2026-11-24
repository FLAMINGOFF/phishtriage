"""HTML handling: text extraction, link extraction and sanitising for display.

Two different jobs, two different tools:

* *Analysis* uses the standard-library ``HTMLParser`` to read hostile HTML as data:
  visible text, links (with their anchor text), forms and password fields.
* *Display* uses ``nh3`` (the Rust ``ammonia`` sanitiser) with an allow-list that keeps
  layout tags only. Every attribute that can load a resource or run code (``src``,
  ``href``, ``style``, event handlers) is dropped, so a tracking pixel cannot call home
  when an analyst opens the HTML view, and links are not clickable.
"""

from __future__ import annotations

from html.parser import HTMLParser

import nh3
from pydantic import BaseModel, Field

MAX_LINKS = 500
MAX_ANCHOR_TEXT = 500

_BLOCK_TAGS = {
    "address",
    "article",
    "aside",
    "blockquote",
    "br",
    "dd",
    "div",
    "dl",
    "dt",
    "fieldset",
    "figcaption",
    "figure",
    "footer",
    "form",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "header",
    "hr",
    "li",
    "main",
    "nav",
    "ol",
    "p",
    "pre",
    "section",
    "table",
    "td",
    "th",
    "tr",
    "ul",
}
_SKIP_CONTENT = {"script", "style", "head", "title", "noscript", "template"}
# (tag, attribute) pairs whose value is a URL worth extracting as an indicator.
_URL_ATTRIBUTES = {
    ("a", "href"),
    ("area", "href"),
    ("form", "action"),
    ("iframe", "src"),
    ("img", "src"),
    ("frame", "src"),
    ("embed", "src"),
    ("object", "data"),
    ("link", "href"),
    ("input", "formaction"),
    ("button", "formaction"),
}


class HtmlLink(BaseModel):
    tag: str
    url: str
    text: str = ""  # anchor text, only for <a>


class HtmlInfo(BaseModel):
    text: str
    links: list[HtmlLink] = Field(default_factory=list)
    form_count: int = 0
    password_inputs: int = 0
    meta_refresh: list[str] = Field(default_factory=list)


class _Extractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.chunks: list[str] = []
        self.links: list[HtmlLink] = []
        self.forms = 0
        self.passwords = 0
        self.meta_refresh: list[str] = []
        self._skip_depth = 0
        self._anchor: HtmlLink | None = None
        self._anchor_text: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {name.lower(): (value or "") for name, value in attrs}
        if tag in _SKIP_CONTENT:
            self._skip_depth += 1
        if tag in _BLOCK_TAGS:
            self.chunks.append("\n")
        if tag == "form":
            self.forms += 1
        if tag == "input" and values.get("type", "").strip().lower() == "password":
            self.passwords += 1
        if tag == "meta" and values.get("http-equiv", "").lower() == "refresh":
            content = values.get("content", "")
            _, _, target = content.partition("=")
            if target.strip():
                self.meta_refresh.append(target.strip().strip("'\""))
        for (link_tag, attr), value in ((k, values.get(k[1], "")) for k in _URL_ATTRIBUTES):
            if tag != link_tag or not value.strip() or len(self.links) >= MAX_LINKS:
                continue
            link = HtmlLink(tag=tag, url=value.strip())
            self.links.append(link)
            if tag == "a" and attr == "href":
                self._anchor, self._anchor_text = link, []

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.handle_starttag(tag, attrs)
        if tag in _SKIP_CONTENT:
            self._skip_depth = max(0, self._skip_depth - 1)

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_CONTENT:
            self._skip_depth = max(0, self._skip_depth - 1)
        if tag in _BLOCK_TAGS:
            self.chunks.append("\n")
        if tag == "a" and self._anchor is not None:
            text = " ".join("".join(self._anchor_text).split())
            self._anchor.text = text[:MAX_ANCHOR_TEXT]
            self._anchor = None

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.chunks.append(data)
        if self._anchor is not None:
            self._anchor_text.append(data)


def analyze_html(html: str) -> HtmlInfo:
    parser = _Extractor()
    try:
        parser.feed(html)
        parser.close()
    except (AssertionError, ValueError):  # HTMLParser can raise on pathological markup
        pass
    lines = (" ".join(line.split()) for line in "".join(parser.chunks).splitlines())
    text = "\n".join(line for line in lines if line)
    return HtmlInfo(
        text=text,
        links=parser.links,
        form_count=parser.forms,
        password_inputs=parser.passwords,
        meta_refresh=parser.meta_refresh,
    )


_SAFE_TAGS = {
    "a",
    "abbr",
    "b",
    "blockquote",
    "br",
    "caption",
    "center",
    "code",
    "col",
    "colgroup",
    "dd",
    "div",
    "dl",
    "dt",
    "em",
    "font",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "hr",
    "i",
    "li",
    "ol",
    "p",
    "pre",
    "s",
    "small",
    "span",
    "strong",
    "sub",
    "sup",
    "table",
    "tbody",
    "td",
    "tfoot",
    "th",
    "thead",
    "tr",
    "u",
    "ul",
}
_SAFE_ATTRIBUTES = {
    "*": {"align", "dir", "lang", "title"},
    "td": {"colspan", "rowspan"},
    "th": {"colspan", "rowspan"},
}


def sanitize_html(html: str) -> str:
    """Allow-list sanitising for the analyst's HTML view (see the module docstring)."""
    return nh3.clean(
        html,
        tags=_SAFE_TAGS,
        attributes=_SAFE_ATTRIBUTES,
        clean_content_tags={"script", "style", "noscript", "template", "title"},
        url_schemes=set(),
        link_rel=None,
        strip_comments=True,
    )
