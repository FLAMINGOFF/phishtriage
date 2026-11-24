"""Real lookups of harmless, well-known indicators (one request per provider)."""

from __future__ import annotations

import os

import pytest

from app.intel import rdap, urlhaus, virustotal
from app.intel.http import make_http_client

pytestmark = pytest.mark.live

# The EICAR anti-virus test file: harmless, and flagged by nearly every engine.
EICAR_SHA256 = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"


def client(*hosts: str):
    return make_http_client(set(hosts), timeout=15)


def test_rdap_example_com_registration_date() -> None:
    servers = rdap.load_bootstrap()
    result = rdap.RdapClient(client(*rdap.bootstrap_hosts(servers)), servers).registration(
        "example.com"
    )
    assert result.status == "hit", result
    assert result.raw["registered"] < "2000"


@pytest.mark.skipif(not os.environ.get("VT_API_KEY"), reason="needs VT_API_KEY")
def test_virustotal_knows_eicar() -> None:
    vt = virustotal.VirusTotalClient(client(virustotal.HOST), os.environ["VT_API_KEY"])
    result = vt.file(EICAR_SHA256)
    assert result.status == "hit", result
    assert result.is_malicious


@pytest.mark.skipif(not os.environ.get("URLHAUS_AUTH_KEY"), reason="needs URLHAUS_AUTH_KEY")
def test_urlhaus_does_not_list_example_com() -> None:
    uh = urlhaus.URLhausClient(client(urlhaus.HOST), os.environ["URLHAUS_AUTH_KEY"])
    assert uh.host("example.com").status == "not_found"
