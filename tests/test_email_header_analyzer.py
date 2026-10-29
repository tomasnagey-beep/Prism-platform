import socket
from unittest.mock import Mock

import pytest
import requests

from modules import email_header_analyzer as eha

MODULE = eha.__name__  





class StubResponse:

    def __init__(self, status_code=200, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


class FakeIpInfoApi:

    def __init__(self, records):
        self.records = records
        self.lookups = []

    def get(self, url, timeout=None, proxies=None):
        ip = url.split("/")[3]           
        self.lookups.append(ip)
        if ip in self.records:
            return StubResponse(200, self.records[ip])
        return StubResponse(404, {"error": "not found"})


class FakeDnsResolver:

    def __init__(self, ptr_records):
        self.ptr_records = ptr_records

    def gethostbyaddr(self, ip):
        if ip not in self.ptr_records:
            raise socket.herror(1, "Unknown host")
        return (self.ptr_records[ip], [], [ip])




@pytest.fixture(autouse=True)
def no_network(monkeypatch):

    def _blocked(*args, **kwargs):
        raise AssertionError("real network access in a unit test")

    monkeypatch.setattr(f"{MODULE}.requests.get", _blocked)
    monkeypatch.setattr(f"{MODULE}.socket.gethostbyaddr", _blocked)
    monkeypatch.setattr(f"{MODULE}.get_proxies", lambda: None)




PHISHING_HEADERS = """\
Received: by mail-internal.google.com with SMTP id x1csp1;
\tTue, 27 Oct 2026 10:00:05 -0700 (PDT)
Received: from mail.evil-sender.ru (mail.evil-sender.ru [185.220.101.4])
\tby mx.google.com with ESMTPS id abc123;
\tTue, 27 Oct 2026 10:00:02 -0700 (PDT)
Received: from [192.168.1.20] (unknown [10.0.0.5])
\tby mail.evil-sender.ru with ESMTPSA;
\tTue, 27 Oct 2026 17:00:00 +0000
Authentication-Results: mx.google.com;
\tspf=softfail smtp.mailfrom=paypal.com;
\tdkim=none;
\tdmarc=fail header.from=paypal.com
From: PayPal <service@paypal.com>
To: victim@example.org
Reply-To: support@evil-sender.ru
Subject: Your account is limited
Date: Tue, 27 Oct 2026 17:00:00 +0000
Message-ID: <abc@evil-sender.ru>
X-Mailer: PHPMailer 6.0

"""

CLEAN_HEADERS = """\
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41])
\tby mx.example.org with ESMTPS;
\tWed, 28 Oct 2026 09:00:00 +0000
Authentication-Results: mx.example.org;
\tspf=pass smtp.mailfrom=gmail.com;
\tdkim=pass header.d=gmail.com;
\tdmarc=pass header.from=gmail.com
From: Alice <alice@gmail.com>
Reply-To: alice@gmail.com
To: bob@example.org
Subject: Lunch?

"""







# _reverse_dns  STUB

def test_reverse_dns_returns_hostname_from_stub(monkeypatch):
    monkeypatch.setattr(f"{MODULE}.socket.gethostbyaddr",
                        lambda ip: ("dns.google", [], [ip]))
    assert eha._reverse_dns("8.8.8.8") == "dns.google"


def test_reverse_dns_returns_none_when_lookup_fails(monkeypatch):
    def stub_fail(ip):
        raise socket.herror(1, "Unknown host")

    monkeypatch.setattr(f"{MODULE}.socket.gethostbyaddr", stub_fail)
    assert eha._reverse_dns("185.220.101.4") is None



# _geoip  STUB + MOCK

def test_geoip_maps_only_expected_fields_from_stubbed_response(monkeypatch):
    payload = {"ip": "8.8.8.8", "city": "Mountain View", "region": "California",
               "country": "US", "org": "AS15169 Google LLC",
               "loc": "37.4,-122.1", "postal": "94043"}
    monkeypatch.setattr(f"{MODULE}.requests.get",
                        lambda *a, **kw: StubResponse(200, payload))

    assert eha._geoip("8.8.8.8") == {
        "city": "Mountain View", "region": "California", "country": "US",
        "org": "AS15169 Google LLC", "loc": "37.4,-122.1",
    }


def test_geoip_calls_ipinfo_with_proxies_and_timeout(monkeypatch):
    proxies = {"https": "http://proxy.local:3128"}
    mock_get = Mock(return_value=StubResponse(200, {"country": "SK"}))
    mock_get_proxies = Mock(return_value=proxies)
    monkeypatch.setattr(f"{MODULE}.requests.get", mock_get)
    monkeypatch.setattr(f"{MODULE}.get_proxies", mock_get_proxies)

    eha._geoip("1.1.1.1")

    mock_get_proxies.assert_called_once_with()
    mock_get.assert_called_once_with("https://ipinfo.io/1.1.1.1/json",
                                     timeout=6, proxies=proxies)


@pytest.mark.parametrize("behaviour", [
    StubResponse(429, {"error": "rate limited"}),     
    requests.exceptions.Timeout("too slow"),          
])
def test_geoip_returns_empty_dict_on_error(monkeypatch, behaviour):
    mock_get = Mock()
    if isinstance(behaviour, Exception):
        mock_get.side_effect = behaviour
    else:
        mock_get.return_value = behaviour
    monkeypatch.setattr(f"{MODULE}.requests.get", mock_get)

    assert eha._geoip("8.8.8.8") == {}



# analyze_headers  FAKE + MOCK

def test_analyze_headers_phishing_email_with_fakes(monkeypatch):
    api = FakeIpInfoApi({"185.220.101.4": {"city": "Moscow", "country": "RU",
                                           "org": "AS1 Evil Hosting"}})
    dns = FakeDnsResolver({"185.220.101.4": "tor-exit.evil-sender.ru"})
    monkeypatch.setattr(f"{MODULE}.requests.get", api.get)
    monkeypatch.setattr(f"{MODULE}.socket.gethostbyaddr", dns.gethostbyaddr)

    result = eha.analyze_headers(PHISHING_HEADERS)

    assert result["error"] is None
    assert result["subject"] == "Your account is limited"
    assert result["x_mailer"] == "PHPMailer 6.0"
    assert (result["spf"], result["dkim"], result["dmarc"]) == ("softfail", "none", "fail")

 
    assert [h["by_host"] for h in result["hops"]] == [
        "mail.evil-sender.ru", "mx.google.com", "mail-internal.google.com"]
    assert result["hops"][0]["ip"] is None           

    assert result["origin_ip"] == "185.220.101.4"
    assert result["origin_geo"]["country"] == "RU"
    assert result["origin_rdns"] == "tor-exit.evil-sender.ru"
    assert api.lookups == ["185.220.101.4"]        

    flag_types = {f["type"] for f in result["spoofing_flags"]}
    assert flag_types == {"REPLY_TO_MISMATCH", "SPF_FAIL", "DKIM_FAIL", "DMARC_FAIL"}


def test_analyze_headers_clean_email_has_no_flags(monkeypatch):
    mock_geoip = Mock(return_value={"country": "US"})
    mock_rdns = Mock(return_value="mail-sor-f41.google.com")
    monkeypatch.setattr(f"{MODULE}._geoip", mock_geoip)
    monkeypatch.setattr(f"{MODULE}._reverse_dns", mock_rdns)

    result = eha.analyze_headers(CLEAN_HEADERS)

    assert result["spoofing_flags"] == []
    assert result["origin_ip"] == "209.85.220.41"
    assert result["hops"][0]["from_host"] == "mail-sor-f41.google.com"
    assert result["hops"][0]["date"] == "Wed, 28 Oct 2026 09:00:00 +0000"
    mock_geoip.assert_called_once_with("209.85.220.41")
    mock_rdns.assert_called_once_with("209.85.220.41")


def test_analyze_headers_reads_spf_from_received_spf_header():
    headers = ("Received-SPF: fail (domain does not designate 1.2.3.4)\n"
               "From: a@b.com\n\n")

    result = eha.analyze_headers(headers)

    assert result["spf"] == "fail"
    assert result["hops"] == [] and result["origin_ip"] is None
    assert [f["type"] for f in result["spoofing_flags"]] == ["SPF_FAIL"]


def test_analyze_headers_internal_only_email_has_no_origin(monkeypatch):
    mock_geoip = Mock()
    monkeypatch.setattr(f"{MODULE}._geoip", mock_geoip)
    headers = ("Received: from pc1 ([192.168.1.10]) by exchange.local; "
               "Wed, 28 Oct 2026 08:00:00 +0000\n"
               "From: boss@company.local\n\n")

    result = eha.analyze_headers(headers)

    assert len(result["hops"]) == 1
    assert result["origin_ip"] is None and result["origin_geo"] == {}
    assert result["spf"] is None
    mock_geoip.assert_not_called()                 


def test_analyze_headers_reports_parser_error(monkeypatch):
    def stub_broken_parser(raw):
        raise ValueError("cannot parse")

    monkeypatch.setattr(f"{MODULE}.message_from_string", stub_broken_parser)

    result = eha.analyze_headers("garbage")

    assert result["error"] == "cannot parse"
    assert result["hops"] == [] and result["spoofing_flags"] == []