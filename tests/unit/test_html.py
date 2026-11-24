"""HTML analysis (links, forms, text) and sanitising for display."""

from __future__ import annotations

from app.parsing.html import MAX_LINKS, analyze_html, sanitize_html


def test_analyze_html_links_and_forms() -> None:
    info = analyze_html(
        "<html><head><title>T</title><style>p{}</style>"
        '<meta http-equiv="Refresh" content="0; url=\'https://next.example/\'"></head>'
        "<body><p>Hello <b>you</b></p>"
        '<a href=" https://evil.example/login ">https://www.example.edu/</a>'
        '<form action="https://collect.example/post"><input type="PASSWORD"></form>'
        '<img src="https://track.example/p.gif"/><script>alert(1)</script>'
        "</body></html>"
    )
    assert info.text.splitlines() == ["Hello you", "https://www.example.edu/"]
    assert [(link.tag, link.url) for link in info.links] == [
        ("a", "https://evil.example/login"),
        ("form", "https://collect.example/post"),
        ("img", "https://track.example/p.gif"),
    ]
    assert info.links[0].text == "https://www.example.edu/"
    assert info.form_count == 1
    assert info.password_inputs == 1
    assert info.meta_refresh == ["https://next.example/"]


def test_analyze_html_is_bounded_and_tolerant() -> None:
    many = "".join(f'<a href="https://e.example/{i}">x</a>' for i in range(MAX_LINKS + 50))
    assert len(analyze_html(many).links) == MAX_LINKS
    assert analyze_html("<a href='x'>unclosed <div><<<>>>&#xZZ;").text
    assert analyze_html("").text == ""


def test_sanitize_drops_everything_active() -> None:
    dirty = (
        '<p onclick="x()" style="color:red" title="t">Hi <a href="https://evil.example">here</a>'
        '<img src="https://track.example/p.gif"><script>alert(1)</script>'
        '<iframe src="https://evil.example"></iframe><style>body{}</style>'
        '<form action="https://evil.example"><input name="pw"></form><!-- c --></p>'
    )
    clean = sanitize_html(dirty)
    for needle in (
        "onclick",
        "style",
        "href",
        "src",
        "script",
        "alert",
        "iframe",
        "<form",
        "<input",
        "<img",
        "<!--",
    ):
        assert needle not in clean
    assert 'title="t"' in clean
    assert "<a" in clean  # kept as text formatting, but not clickable
    assert "here" in clean


def test_sanitize_keeps_table_layout() -> None:
    clean = sanitize_html('<table><tr><td colspan="2" width="9">a</td></tr></table>')
    assert 'colspan="2"' in clean
    assert "width" not in clean
