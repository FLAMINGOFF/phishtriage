"""VirusTotal, URLhaus and RDAP clients against mocked HTTP (respx); never the network."""

from __future__ import annotations

import base64
import json
from datetime import UTC, datetime

import httpx
import pytest
import respx

from app.intel import rdap, urlhaus, virustotal
from app.intel.http import MAX_RESPONSE_BYTES, ProviderError, make_http_client
from app.intel.indicators import is_domain, is_sha256

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=UTC)
SHA = "a" * 64
URL = "http://login.evil.example/verify?u=1"
ALLOWED = {virustotal.HOST, urlhaus.HOST, "rdap.verisign.com"}
VT = virustotal.BASE_URL
UH = urlhaus.BASE_URL


@pytest.fixture
def http() -> httpx.Client:
    return make_http_client(ALLOWED, timeout=5)


@pytest.fixture
def vt(http: httpx.Client) -> virustotal.VirusTotalClient:
    return virustotal.VirusTotalClient(http, "vt-test-key", clock=lambda: NOW)


@pytest.fixture
def uh(http: httpx.Client) -> urlhaus.URLhausClient:
    return urlhaus.URLhausClient(http, "uh-test-key", clock=lambda: NOW)


def vt_report(**stats: int) -> dict[str, object]:
    return {
        "data": {
            "id": "x",
            "attributes": {
                "last_analysis_stats": stats,
                "reputation": -12,
                "last_analysis_date": 1_790_000_000,
                "names": ["confidential-salary-review.xlsm"],  # must not be stored
            },
        }
    }


# --------------------------------------------------------------------------- VirusTotal


def test_vt_file_hit(vt: virustotal.VirusTotalClient, http_mock: respx.Router) -> None:
    route = http_mock.get(f"{VT}/files/{SHA}").respond(
        json=vt_report(malicious=5, suspicious=1, harmless=0, undetected=60)
    )
    result = vt.file(SHA)
    assert route.called
    assert route.calls.last.request.headers["x-apikey"] == "vt-test-key"
    assert result.status == "hit"
    assert result.malicious_count == 5
    assert result.is_malicious
    assert result.detail == "5/66 engines flag it malicious, 1 suspicious"
    assert result.fetched_at == NOW
    # Only a small fixed subset of the answer is kept.
    assert set(result.raw) == {"last_analysis_stats", "reputation", "last_analysis_date"}
    assert "confidential" not in json.dumps(result.raw)


def test_vt_below_threshold_is_a_hit_but_not_malicious(
    vt: virustotal.VirusTotalClient, http_mock: respx.Router
) -> None:
    http_mock.get(f"{VT}/files/{SHA}").respond(json=vt_report(malicious=2, undetected=60))
    result = vt.file(SHA)
    assert result.status == "hit"
    assert not result.is_malicious  # the plan's threshold is 3 engines


def test_vt_clean_and_never_analysed(
    vt: virustotal.VirusTotalClient, http_mock: respx.Router
) -> None:
    http_mock.get(f"{VT}/domains/evil.example").respond(json=vt_report(harmless=70))
    assert vt.domain("evil.example").status == "clean"
    http_mock.get(f"{VT}/domains/new.example").respond(json=vt_report())
    assert vt.domain("new.example").status == "not_found"


def test_vt_url_lookup_is_a_get_by_identifier(
    vt: virustotal.VirusTotalClient, http_mock: respx.Router
) -> None:
    identifier = base64.urlsafe_b64encode(URL.encode()).decode().rstrip("=")
    assert virustotal.url_id(URL) == identifier
    route = http_mock.get(f"{VT}/urls/{identifier}").respond(404, json={"error": {}})
    result = vt.url(URL)
    assert result.status == "not_found"
    assert route.calls.last.request.method == "GET"  # never POST /urls: that submits a scan


def test_vt_has_no_upload_or_scan_method() -> None:
    public = {name for name in dir(virustotal.VirusTotalClient) if not name.startswith("_")}
    assert public == {"file", "url", "domain", "provider"}


@pytest.mark.parametrize(
    ("status", "message"),
    [
        (401, "authentication failed"),
        (403, "authentication failed"),
        (429, "rate limit or quota"),
        (503, r"provider error \(HTTP 503\)"),
        (418, r"unexpected response \(HTTP 418\)"),
    ],
)
def test_vt_http_errors(
    vt: virustotal.VirusTotalClient, http_mock: respx.Router, status: int, message: str
) -> None:
    http_mock.get(f"{VT}/files/{SHA}").respond(status, json={"error": {"code": "x"}})
    with pytest.raises(ProviderError, match=message):
        vt.file(SHA)


def test_vt_rejects_bad_indicators_without_a_request(vt: virustotal.VirusTotalClient) -> None:
    assert vt.file("not-a-hash").status == "skipped"
    assert vt.domain("evil.example/../../users").status == "skipped"
    assert vt.domain("ACME").status == "skipped"


def test_vt_invalid_json(vt: virustotal.VirusTotalClient, http_mock: respx.Router) -> None:
    http_mock.get(f"{VT}/files/{SHA}").respond(200, content=b"<html>")
    with pytest.raises(ProviderError, match="invalid response"):
        vt.file(SHA)
    http_mock.get(f"{VT}/files/{'b' * 64}").respond(200, json={"data": "nope"})
    with pytest.raises(ProviderError, match="invalid response"):
        vt.file("b" * 64)


# --------------------------------------------------------------------------- transport rules


def test_timeouts_and_network_errors(
    vt: virustotal.VirusTotalClient, http_mock: respx.Router
) -> None:
    http_mock.get(f"{VT}/files/{SHA}").mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(ProviderError, match="timed out"):
        vt.file(SHA)
    http_mock.get(f"{VT}/files/{'c' * 64}").mock(side_effect=httpx.ConnectError("refused"))
    with pytest.raises(ProviderError, match="network error"):
        vt.file("c" * 64)


def test_redirects_are_not_followed(
    vt: virustotal.VirusTotalClient, http_mock: respx.Router
) -> None:
    http_mock.get(f"{VT}/files/{SHA}").respond(
        302, headers={"Location": "https://attacker.example/"}
    )
    with pytest.raises(ProviderError, match="redirect"):
        vt.file(SHA)


def test_oversized_responses_are_refused(
    vt: virustotal.VirusTotalClient, http_mock: respx.Router
) -> None:
    http_mock.get(f"{VT}/files/{SHA}").respond(200, content=b"x" * (MAX_RESPONSE_BYTES + 1))
    with pytest.raises(ProviderError, match="too large"):
        vt.file(SHA)


def test_only_allowlisted_https_hosts(http: httpx.Client, http_mock: respx.Router) -> None:
    http_mock.get("https://attacker.example/").respond(200)
    with pytest.raises(ProviderError, match="non-allowlisted"):
        http.get("https://attacker.example/")
    with pytest.raises(ProviderError, match="non-allowlisted"):
        http.get(f"http://{virustotal.HOST}/api/v3/files/{SHA}")  # plain HTTP
    assert not http_mock.routes[0].called


# --------------------------------------------------------------------------- URLhaus


def test_urlhaus_url_hit(uh: urlhaus.URLhausClient, http_mock: respx.Router) -> None:
    route = http_mock.post(f"{UH}/url/").respond(
        json={
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "date_added": "2026-11-20 10:00:00 UTC",
            "tags": ["exe", "Emotet", 42],
            "urlhaus_reference": "https://urlhaus.abuse.ch/url/1/",
            "payloads": [{"filename": "secret.exe"}],
        }
    )
    result = uh.url(URL)
    request = route.calls.last.request
    assert request.headers["Auth-Key"] == "uh-test-key"
    assert request.content == b"url=http%3A%2F%2Flogin.evil.example%2Fverify%3Fu%3D1"
    assert result.status == "hit"
    assert result.is_malicious
    assert result.detail == "listed: malware_download, online"
    assert result.raw["tags"] == ["exe", "Emotet"]
    assert "payloads" not in result.raw


def test_urlhaus_not_listed_and_errors(uh: urlhaus.URLhausClient, http_mock: respx.Router) -> None:
    http_mock.post(f"{UH}/url/").respond(json={"query_status": "no_results"})
    assert uh.url(URL).status == "not_found"
    http_mock.post(f"{UH}/host/").respond(json={"query_status": "invalid_host"})
    with pytest.raises(ProviderError, match="invalid_host"):
        uh.host("evil.example")


def test_urlhaus_bad_key(uh: urlhaus.URLhausClient, http_mock: respx.Router) -> None:
    http_mock.post(f"{UH}/url/").respond(401, json={"query_status": "unknown_auth_key"})
    with pytest.raises(ProviderError, match="authentication failed"):
        uh.url(URL)


def test_urlhaus_host_hit(uh: urlhaus.URLhausClient, http_mock: respx.Router) -> None:
    route = http_mock.post(f"{UH}/host/").respond(
        json={"query_status": "ok", "url_count": "17", "firstseen": "2026-10-01 00:00:00 UTC"}
    )
    result = uh.host("198.51.100.14")
    assert route.calls.last.request.content == b"host=198.51.100.14"
    assert result.status == "hit"
    assert result.detail == "host listed with 17 malware URL(s)"
    assert result.raw["url_count"] == 17


# --------------------------------------------------------------------------- RDAP


def test_bundled_bootstrap_is_https_and_well_formed() -> None:
    servers = rdap.load_bootstrap()
    assert servers["com"] == "https://rdap.verisign.com/com/v1/"
    assert all(base.startswith("https://") and base.endswith("/") for base in servers.values())
    assert "rdap.verisign.com" in rdap.bootstrap_hosts(servers)
    for reserved in ("example", "test", "invalid", "localhost"):
        assert reserved not in servers


def test_bootstrap_loader_ignores_plain_http(tmp_path) -> None:
    path = tmp_path / "dns.json"
    path.write_text(
        json.dumps(
            {
                "services": [
                    [["aa"], ["http://rdap.aa.example/"]],
                    [["bb", "CC"], ["http://x.example/", "https://rdap.bb.example/v1"]],
                ]
            }
        )
    )
    assert rdap.load_bootstrap(path) == {
        "bb": "https://rdap.bb.example/v1/",
        "cc": "https://rdap.bb.example/v1/",
    }


@pytest.fixture
def rdap_client(http: httpx.Client) -> rdap.RdapClient:
    return rdap.RdapClient(http, {"com": "https://rdap.verisign.com/com/v1/"}, clock=lambda: NOW)


def test_rdap_registration_date(rdap_client: rdap.RdapClient, http_mock: respx.Router) -> None:
    route = http_mock.get("https://rdap.verisign.com/com/v1/domain/evil-login.com").respond(
        json={
            "ldhName": "EVIL-LOGIN.COM",
            "events": [
                {"eventAction": "expiration", "eventDate": "2027-11-20T00:00:00Z"},
                {"eventAction": "registration", "eventDate": "2026-11-20T08:15:00Z"},
            ],
            "entities": [{"vcardArray": ["vcard", [["fn", {}, "text", "Registrant Name"]]]}],
        }
    )
    result = rdap_client.registration("evil-login.com")
    assert route.calls.last.request.headers["Accept"] == "application/rdap+json"
    assert result.status == "hit"
    assert result.detail == "registered 2026-11-20"
    assert result.raw == {"domain": "evil-login.com", "registered": "2026-11-20T08:15:00+00:00"}


def test_rdap_missing_record_or_date(rdap_client: rdap.RdapClient, http_mock: respx.Router) -> None:
    http_mock.get("https://rdap.verisign.com/com/v1/domain/nothing.com").respond(404)
    assert rdap_client.registration("nothing.com").status == "not_found"
    http_mock.get("https://rdap.verisign.com/com/v1/domain/nodate.com").respond(
        json={"events": [{"eventAction": "registration", "eventDate": "yesterday"}]}
    )
    result = rdap_client.registration("nodate.com")
    assert result.status == "not_found"
    assert "no registration date" in (result.detail or "")


def test_rdap_unknown_tld_and_bad_names_are_skipped(rdap_client: rdap.RdapClient) -> None:
    assert rdap_client.registration("evil.example").detail == (
        "no RDAP server configured for .example"
    )
    assert rdap_client.registration("evil.example").status == "skipped"
    assert rdap_client.registration("a/b.com").status == "skipped"


def test_indicator_checks() -> None:
    assert is_sha256("0" * 64)
    assert not is_sha256("0" * 63)
    assert not is_sha256("G" * 64)
    assert is_domain("xn--pple-43d.com")
    assert not is_domain("evil.example?x=1")
    assert not is_domain("-bad.com")


def test_bootstrap_update_script_merges_only_https_and_named_tlds() -> None:
    from scripts.update_rdap_bootstrap import merge

    current = {"description": "d", "services": [[["com"], ["https://rdap.verisign.com/com/v1/"]]]}
    iana = {
        "publication": "2026-11-01T00:00:00Z",
        "services": [
            [["io", "ac"], ["https://rdap.identitydigital.services/rdap/"]],
            [["zz"], ["http://insecure.example/"]],
            [["com"], ["https://rdap.verisign.com/com/v1/"]],
        ],
    }
    merged = merge(current, iana, ["io", ".ZZ"])
    assert merged["description"] == "d"
    assert merged["publication"] == "2026-11-01T00:00:00Z"
    assert sorted(merged["services"]) == [
        [["com"], ["https://rdap.verisign.com/com/v1/"]],
        [["io"], ["https://rdap.identitydigital.services/rdap/"]],
    ]
