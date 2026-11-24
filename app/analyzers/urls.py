"""Link analyzer: where the email's links really go. No link is ever visited."""

from __future__ import annotations

import re

from app.analyzers.base import AnalysisContext, Evidence, Hit, evidence, hit
from app.parsing.defang import defang_domain
from app.parsing.domains import has_public_suffix, parse_ip, registered_domain, to_ascii
from app.parsing.html import HtmlInfo, analyze_html
from app.parsing.iocs import email_urls, normalize_url, url_host

# A host name written in anchor text: "www.example.edu", "https://example.edu/login".
_TEXT_HOST = re.compile(
    r"(?i)(?:\b[a-z][a-z0-9+.-]{1,10}://)?((?:[a-z0-9\u00a1-\uffff](?:[a-z0-9\u00a1-\uffff-]{0,61}"
    r"[a-z0-9\u00a1-\uffff])?\.)+[a-z\u00a1-\uffff][a-z0-9\u00a1-\uffff-]{1,62})\.?(?=$|[/:?#\s)\],;])"
)


def _shown_hosts(text: str) -> list[str]:
    hosts = []
    for match in _TEXT_HOST.finditer(text[:500]):
        host = to_ascii(match.group(1).lower())
        if has_public_suffix(host):
            hosts.append(host)
    return hosts


def _text_href_mismatches(info: HtmlInfo) -> list[Evidence]:
    items = []
    for link in info.links:
        if link.tag != "a" or not link.text:
            continue
        target = normalize_url(link.url)
        target_host = url_host(target) if target else None
        if target_host is None:
            continue
        target_domain = registered_domain(target_host)
        for shown in _shown_hosts(link.text):
            if registered_domain(shown) != target_domain:
                items.append(
                    evidence(
                        "HTML link",
                        link.text,
                        f"text shows {defang_domain(shown)}, link goes to "
                        f"{defang_domain(target_host)}",
                        kind="url" if "://" in link.text else "domain",
                    )
                )
                break
    return items


def analyze(ctx: AnalysisContext) -> list[Hit]:
    email, policy = ctx.email, ctx.policy
    urls = email_urls(email)
    info = analyze_html(email.body_html) if email.body_html else None
    hits: list[Hit] = []

    malicious = []
    for url in urls:
        for result in ctx.intel.urls.get(url, ()):
            if result.is_malicious:
                count = f" ({result.malicious_count} engines)" if result.malicious_count else ""
                malicious.append(
                    evidence("URL", url, f"{result.provider}: malicious{count}", kind="url")
                )
    if malicious:
        hits.append(hit("URL_INTEL_MALICIOUS", malicious))

    if info is not None and (info.form_count or info.password_inputs):
        hits.append(
            hit(
                "URL_CREDENTIAL_FORM",
                [
                    evidence(
                        "HTML body",
                        f"{info.form_count} form(s), {info.password_inputs} password field(s)",
                        "form in the email body" if info.form_count else "password field",
                    )
                ],
            )
        )

    if info is not None and (mismatches := _text_href_mismatches(info)):
        hits.append(hit("URL_TEXT_HREF_MISMATCH", mismatches))

    ip_hosts, punycode, shorteners = [], [], []
    shortener_domains = set(policy.shortener_domains)
    for url in urls:
        host = url_host(url)
        if host is None:
            continue
        if parse_ip(host) is not None:
            ip_hosts.append(evidence("URL", url, f"host is an IP address ({host})", kind="url"))
            continue
        if any(label.startswith("xn--") for label in host.split(".")):
            punycode.append(evidence("URL", url, "punycode host name (xn--)", kind="url"))
        if host in shortener_domains or registered_domain(host) in shortener_domains:
            shorteners.append(evidence("URL", url, "link shortener", kind="url"))
    if ip_hosts:
        hits.append(hit("URL_IP_HOST", ip_hosts))
    if punycode:
        hits.append(hit("URL_PUNYCODE", punycode))
    if shorteners:
        hits.append(hit("URL_SHORTENER", shorteners))
    return hits
