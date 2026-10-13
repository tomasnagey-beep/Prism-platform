from unittest.mock import MagicMock, patch

import pytest

from modules.module_status import ERROR, OK
from modules.qr_decoder import QRDecoder


def _api_response(payload, status_code=200):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload
    return response


def test_local_decode_is_ok():
    decoder = QRDecoder()
    with patch.object(decoder, "_decode_local", return_value="https://example.com"):
        result = decoder.decode(b"img")
    assert result["status"] == OK
    assert result["error"] is None
    assert result["decoded"] == "https://example.com"
    assert result["is_url"] is True
    assert result["source"] == "local"


def test_no_qr_code_is_ok_with_reason():
    decoder = QRDecoder()
    with patch.object(decoder, "_decode_local", return_value=None), patch(
        "modules.qr_decoder.requests.post",
        return_value=_api_response([{"symbol": []}]),
    ):
        result = decoder.decode(b"img")
    assert result["status"] == OK
    assert result["status_reason"] == "No QR code detected in the image"
    assert result["error"] is None
    assert result["decoded"] is None


def test_api_http_error_is_error():
    decoder = QRDecoder()
    with patch.object(decoder, "_decode_local", return_value=None), patch(
        "modules.qr_decoder.requests.post",
        return_value=_api_response(None, status_code=500),
    ):
        result = decoder.decode(b"img")
    assert result["status"] == ERROR
    assert result["error"] == "API returned HTTP 500"


def test_api_exception_is_error():
    decoder = QRDecoder()
    with patch.object(decoder, "_decode_local", return_value=None), patch(
        "modules.qr_decoder.requests.post", side_effect=ConnectionError("network down")
    ):
        result = decoder.decode(b"img")
    assert result["status"] == ERROR
    assert result["error"] == "network down"


def test_api_decode_is_ok():
    decoder = QRDecoder()
    with patch.object(decoder, "_decode_local", return_value=None), patch(
        "modules.qr_decoder.requests.post",
        return_value=_api_response([{"symbol": [{"data": "hello", "error": None}]}]),
    ):
        result = decoder.decode(b"img")
    assert result["status"] == OK
    assert result["decoded"] == "hello"
    assert result["type"] == "Plain text"
    assert result["source"] == "api"


@pytest.mark.parametrize(
    "decoded, expected_type, expected_flag",
    [
        ("http://example.com", "URL", True),
        ("https://example.com/login", "URL", True),
        ("WIFI:T:WPA;S:HomeNet;P:secret;;", "Wi-Fi credentials", False),
        ("BEGIN:VCARD\nVERSION:3.0\nFN:Jane Doe\nEND:VCARD", "Contact (vCard)", False),
        ("MECARD:N:Doe,Jane;TEL:123456789;;", "Contact (vCard)", False),
        ("BEGIN:VEVENT\nSUMMARY:Meeting\nEND:VEVENT", "Calendar event", False),
        ("mailto:someone@example.com", "Email", False),
        ("tel:+421900123456", "Phone number", False),
        ("geo:48.1486,17.1077", "Geolocation", False),
        ("bitcoin:1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", "Crypto address", False),
        ("ethereum:0x742d35Cc6634C0532925a3b844Bc9e7595f2bD68", "Crypto address", False),
        ("just some text", "Plain text", False),
    ],
)
def test_classify(decoded, expected_type, expected_flag):
    assert QRDecoder()._classify(decoded) == (expected_type, expected_flag)
 

def test_api_non_json_response_is_error_not_exception():
    decoder = QRDecoder()
    response = _api_response(None)
    response.json.side_effect = ValueError("Expecting value: line 1 column 1 (char 0)")
    with patch.object(decoder, "_decode_local", return_value=None), patch(
        "modules.qr_decoder.requests.post", return_value=response
    ):
        result = decoder.decode(b"img")
    assert result["status"] == ERROR
    assert result["decoded"] is None
    assert result["source"] == "api"
 
 
def test_api_fallback_url_is_classified_and_flagged():
    decoder = QRDecoder()
    with patch.object(decoder, "_decode_local", return_value=None), patch(
        "modules.qr_decoder.requests.post",
        return_value=_api_response([{"symbol": [{"data": "https://evil.example/login", "error": None}]}]),
    ) as post:
        result = decoder.decode(b"img")
    post.assert_called_once()
    assert result["status"] == OK
    assert result["source"] == "api"
    assert result["type"] == "URL"
    assert result["is_url"] is True


def test_undecodable_image_returns_result_instead_of_raising():
    decoder = QRDecoder()
    with patch(
        "modules.qr_decoder.requests.post",
        return_value=_api_response([{"symbol": [{"data": None, "error": None}]}]),
    ):
        result = decoder.decode(b"definitely not an image")
    assert result["status"] == OK
    assert result["decoded"] is None
    assert result["status_reason"] == "No QR code detected in the image"