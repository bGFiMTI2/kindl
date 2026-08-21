import base64
import hashlib
import re

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from kindl.auth import (
    DEVICE_TYPE,
    DeviceCredentials,
    adp_sign,
    device_client_id,
    pkce_pair,
)
from kindl.client import (
    AmazonDeviceClient,
    _raise_amazon_error,
    delivery_filename,
    parse_library_xml,
)


def test_device_client_id_is_hex_serial_and_type():
    serial = "0123456789ABCDEF0123456789ABCDEF"
    client_id = device_client_id(serial)
    assert bytes.fromhex(client_id).decode() == f"{serial}#{DEVICE_TYPE}"
    assert client_id == client_id.lower()
    assert "4f" in client_id  # The hex encoding of the O in the device type.


def test_pkce_pair_shape():
    verifier, challenge = pkce_pair()
    assert len(verifier) == 43
    assert len(challenge) == 43
    assert "=" not in verifier + challenge


def test_parse_library_xml():
    xml = b"""<response><add_update_list><meta_data><ASIN>B012345678</ASIN>
      <title>A Book</title><authors><author>One</author><author>Two</author></authors>
      <publishers><publisher>Press</publisher></publishers><cde_contenttype>EBOK</cde_contenttype>
      <content_type>application/x-mobipocket-ebook</content_type><content_size>123</content_size>
    </meta_data></add_update_list></response>"""
    items = parse_library_xml(xml)
    assert len(items) == 1
    assert items[0].asin == "B012345678"
    assert items[0].authors == ("One", "Two")
    assert items[0].content_size == 123


def test_adp_signature_covers_query_string():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    token = "device-token"
    value = adp_sign("GET", "https://example.test/path?item_count=7", b"", token, pem)
    signature, timestamp = re.match(r"^(.+):(\d{4}-.*)$", value).groups()

    numbers = key.public_key().public_numbers()
    raw = base64.b64decode(signature)
    recovered = pow(int.from_bytes(raw, "big"), numbers.e, numbers.n).to_bytes(
        256, "big"
    )
    expected = hashlib.sha256(
        f"GET\n/path?item_count=7\n{timestamp}\n\n{token}".encode()
    ).digest()
    assert recovered.endswith(b"\x00" + expected)


def test_device_credentials_are_persistent(tmp_path):
    path = tmp_path / "credentials.json"
    expected = DeviceCredentials(
        serial="A" * 32,
        pid="B" * 8,
        device_type=DEVICE_TYPE,
        adp_token="token",
        private_key="key",
        directed_id="directed-id",
        marketplace="marketplace",
    )
    expected.save(path)
    assert DeviceCredentials.load(path) == expected


def test_amazon_error_includes_safe_json_details():
    response = httpx.Response(
        400,
        json={"error": "invalid_grant", "error_description": "Code verifier mismatch"},
    )
    with pytest.raises(RuntimeError, match="invalid_grant.*Code verifier mismatch"):
        _raise_amazon_error(response, "Amazon token exchange")


def test_legacy_token_request_matches_desktop_wire_shape():
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = request.headers
        captured["body"] = request.content
        return httpx.Response(200, json={"access_token": "token"})

    client = AmazonDeviceClient()
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        response = client._legacy_token_request(
            {
                "requested_token_type": "access_token",
                "source_token_type": "authorization_code",
            }
        )
    finally:
        client.close()

    assert response.status_code == 200
    assert captured["body"] == (
        b'{"requested_token_type": "access_token", '
        b'"source_token_type": "authorization_code"}'
    )
    headers = captured["headers"]
    assert headers["content-type"] == "application/json"
    assert headers["cache-control"] == "no-cache"
    assert headers["x-amzn-identity-auth-domain"] == "api.amazon.com"
    assert "user-agent" not in headers
    assert "accept" not in headers


def test_legacy_registration_request_matches_desktop_headers():
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = request.headers
        captured["body"] = request.content
        return httpx.Response(200, content=b"<response />")

    client = AmazonDeviceClient()
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        response = client._legacy_registration_request(b"<request />")
    finally:
        client.close()

    assert response.status_code == 200
    assert captured["body"] == b"<request />"
    headers = captured["headers"]
    assert headers["content-type"] == "text/xml"
    assert headers["accept-language"] == "en-US"
    assert headers["cache-control"] == "no-cache"
    assert "user-agent" not in headers
    assert "accept" not in headers


def test_delivery_filename_is_portable_on_windows():
    url = (
        "https://example.test/delivery/ebook-content.DTP:0001_main_CR!ABC.azw9"
        "?X-Amz-Signature=secret"
    )
    assert delivery_filename(url) == "ebook-content.DTP_0001_main_CR!ABC.azw9"
    assert delivery_filename("https://example.test/path/CON") == "_CON"


def test_device_credential_refresh_rotates_and_returns_credentials():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    credentials = DeviceCredentials(
        serial="A" * 32,
        pid="B" * 8,
        device_type=DEVICE_TYPE,
        adp_token="old-token",
        private_key=pem,
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["reason"] == "TodoItem.GET.NAMS"
        assert "x-adp-authentication-token" in request.headers
        assert "x-adp-request-digest" in request.headers
        assert "x-adp-sw" not in request.headers
        assert "x-adp-reason" not in request.headers
        return httpx.Response(
            200,
            content=(
                f"<response><device_private_key>{pem}</device_private_key>"
                "<adp_token>new-token</adp_token>"
                "<user_directed_id>directed-id</user_directed_id></response>"
            ).encode(),
        )

    client = AmazonDeviceClient(credentials)
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        refreshed = client.refresh_device_credentials()
    finally:
        client.close()

    assert refreshed is credentials
    assert refreshed.adp_token == "new-token"
    assert refreshed.directed_id == "directed-id"
