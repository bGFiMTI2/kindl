import base64
import hashlib
import json
import re

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from kindl.auth import (
    APP_NAME,
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
    recovered = pow(int.from_bytes(raw, "big"), numbers.e, numbers.n).to_bytes(256, "big")
    expected = hashlib.sha256(f"GET\n/path?item_count=7\n{timestamp}\n\n{token}".encode()).digest()
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


def test_device_credentials_round_trip_refresh_token(tmp_path):
    path = tmp_path / "credentials.json"
    expected = DeviceCredentials(
        serial="A" * 32,
        pid="B" * 8,
        device_type=DEVICE_TYPE,
        adp_token="token",
        private_key="key",
        refresh_token="synth-refresh-token",
    )
    expected.save(path)

    loaded = DeviceCredentials.load(path)

    assert loaded == expected
    assert loaded.refresh_token == "synth-refresh-token"


def test_device_credentials_load_config_without_refresh_token(tmp_path):
    path = tmp_path / "credentials.json"
    path.write_text(
        json.dumps(
            {
                "serial": "A" * 32,
                "pid": "B" * 8,
                "device_type": DEVICE_TYPE,
                "adp_token": "synth-adp",
                "private_key": "synth-key",
                "directed_id": "directed-id",
            }
        ),
        encoding="utf-8",
    )

    loaded = DeviceCredentials.load(path)

    assert loaded.refresh_token == ""
    assert loaded.adp_token == "synth-adp"


def test_register_persona_extracts_refresh_token_from_map_response():
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = request.url
        captured["authorization"] = request.headers["authorization"]
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "response": {
                    "success": {
                        "customer_id": "synth-customer",
                        "tokens": {
                            "bearer": {
                                "access_token": "synth-access",
                                "refresh_token": "synth-refresh",
                            },
                            "mac_dms": {
                                "adp_token": "synth-adp",
                                "device_private_key": "synth-key",
                            },
                        },
                        "extensions": {"customer_info": {"preferred_marketplace": "US"}},
                    }
                }
            },
        )

    client = AmazonDeviceClient()
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        credentials = client.register_persona("synth-access-token", "C" * 32, "D" * 8)
    finally:
        client.close()

    assert captured["url"] == "https://api.amazon.com/auth/register"
    assert captured["authorization"] == "Bearer synth-access-token"
    assert captured["body"]["registration_data"]["device_serial"] == "C" * 32
    assert credentials.serial == "C" * 32
    assert credentials.pid == "D" * 8
    assert credentials.adp_token == "synth-adp"
    assert credentials.private_key == "synth-key"
    assert credentials.refresh_token == "synth-refresh"
    assert credentials.marketplace == "US"


def test_register_persona_tolerates_map_response_without_bearer_tokens():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "response": {
                    "success": {
                        "tokens": {
                            "mac_dms": {
                                "adp_token": "synth-adp",
                                "device_private_key": "synth-key",
                            }
                        }
                    }
                }
            },
        )

    client = AmazonDeviceClient()
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        credentials = client.register_persona("synth-access-token", "C" * 32, "D" * 8)
    finally:
        client.close()

    assert credentials.refresh_token == ""
    assert credentials.adp_token == "synth-adp"


def test_refresh_bearer_posts_refresh_grant_and_returns_access_token():
    captured: dict[str, object] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = request.url
        captured["headers"] = request.headers
        captured["body"] = json.loads(request.content)
        return httpx.Response(200, json={"access_token": "synth-access"})

    client = AmazonDeviceClient()
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        access_token = client.refresh_bearer("synth-refresh")
    finally:
        client.close()

    assert access_token == "synth-access"
    assert captured["url"] == "https://api.amazon.com/auth/token"
    assert captured["body"] == {
        "app_name": APP_NAME,
        "client_domain": "DeviceLegacy",
        "source_token_type": "refresh_token",
        "source_token": "synth-refresh",
        "requested_token_type": "access_token",
    }
    headers = captured["headers"]
    assert headers["content-type"] == "application/json"
    assert headers["x-amzn-identity-auth-domain"] == "api.amazon.com"
    assert headers["accept"] == "application/json"


def test_refresh_bearer_reports_http_failure_code():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_grant"})

    client = AmazonDeviceClient()
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(RuntimeError, match=r"Amazon bearer refresh failed \(HTTP 400\)"):
            client.refresh_bearer("stale-refresh")
    finally:
        client.close()


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
        b'{"requested_token_type": "access_token", "source_token_type": "authorization_code"}'
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


def test_restore_account_secrets_direct_json_response():
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
        assert request.method == "POST"
        assert request.url.path == "/delivery/restoreAccountSecrets"
        assert "x-adp-authentication-token" in request.headers
        assert "x-adp-request-digest" in request.headers
        assert request.headers.get("x-adp-app-id") == "com.amazon.kindle"
        return httpx.Response(
            200,
            json={"accountSecrets": ["synth-sec-1", "synth-sec-2"]},
        )

    client = AmazonDeviceClient(credentials)
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        secrets = client.restore_account_secrets()
    finally:
        client.close()

    assert secrets == ["synth-sec-1", "synth-sec-2"]
    assert credentials.account_secrets == ["synth-sec-1", "synth-sec-2"]


def test_restore_account_secrets_via_todo_items():
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

    call_log = []

    def handler(request: httpx.Request) -> httpx.Response:
        call_log.append(request.url.path)
        if request.url.path == "/delivery/restoreAccountSecrets":
            assert request.method == "POST"
            return httpx.Response(200, json={})
        if request.url.path == "/FionaTodoListProxy/getItems":
            assert request.method == "GET"
            xml_content = b"""<response>
                <items>
                    <item type="ACSR" action="SET" priority="1">
                        <value>mock_sec_a,mock_sec_b</value>
                    </item>
                </items>
            </response>"""
            return httpx.Response(200, content=xml_content)
        return httpx.Response(404)

    client = AmazonDeviceClient(credentials)
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        secrets = client.restore_account_secrets()
    finally:
        client.close()

    assert call_log == ["/delivery/restoreAccountSecrets", "/FionaTodoListProxy/getItems"]
    assert secrets == ["mock_sec_a", "mock_sec_b"]
    assert credentials.account_secrets == ["mock_sec_a", "mock_sec_b"]


def test_restore_account_secrets_error_raises_amazon_error():
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
        return httpx.Response(403, json={"error": "WeblabGate", "error_description": "Gate active"})

    client = AmazonDeviceClient(credentials)
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        with pytest.raises(
            RuntimeError, match="Amazon restore account secrets failed \\(HTTP 403\\)"
        ):
            client.restore_account_secrets()
    finally:
        client.close()


def test_restore_account_secrets_falls_through_to_todo_items_on_http_403(monkeypatch):
    monkeypatch.delenv("KINDL_PROFILE", raising=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    ios_credentials = DeviceCredentials(
        serial="A" * 32,
        pid="B" * 8,
        device_type="AGZZ1ST63LKBW",
        adp_token="ios-token",
        private_key=pem,
        software_version="1191420432",
        account_secrets=["existing_secret_40b"],
    )

    call_log: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        call_log.append((request.url.path, request.headers.get("x-adp-app-id")))
        if request.url.path == "/delivery/restoreAccountSecrets":
            return httpx.Response(403, json={"error": "Forbidden"})
        if request.url.path == "/FionaTodoListProxy/getItems":
            xml_content = b"""<response>
                <items>
                    <item type="ACSR" action="SET" priority="1">
                        <value>new_todo_secret_40b</value>
                    </item>
                </items>
            </response>"""
            return httpx.Response(200, content=xml_content)
        return httpx.Response(404)

    client = AmazonDeviceClient(ios_credentials)
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        secrets = client.restore_account_secrets()
    finally:
        client.close()

    assert call_log == [
        ("/delivery/restoreAccountSecrets", None),
        ("/FionaTodoListProxy/getItems", None),
    ]
    assert secrets == ["existing_secret_40b", "new_todo_secret_40b"]
    assert ios_credentials.account_secrets == ["existing_secret_40b", "new_todo_secret_40b"]


def test_restore_account_secrets_non_default_persona_empty_todo_does_not_raise_403(monkeypatch):
    monkeypatch.delenv("KINDL_PROFILE", raising=False)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    win_credentials = DeviceCredentials(
        serial="A" * 32,
        pid="B" * 8,
        device_type="A1UOUY6O7B48AR",
        adp_token="win-token",
        private_key=pem,
        software_version="4351",
    )

    call_log: list[tuple[str, str | None]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        call_log.append((request.url.path, request.headers.get("x-adp-app-id")))
        if request.url.path == "/delivery/restoreAccountSecrets":
            return httpx.Response(403, json={"error": "Forbidden"})
        if request.url.path == "/FionaTodoListProxy/getItems":
            return httpx.Response(200, content=b"<response><items/></response>")
        return httpx.Response(404)

    client = AmazonDeviceClient(win_credentials)
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        secrets = client.restore_account_secrets()
    finally:
        client.close()

    assert call_log == [
        ("/delivery/restoreAccountSecrets", "KatxopoWindows"),
        ("/FionaTodoListProxy/getItems", None),
    ]
    assert secrets == []
    assert win_credentials.account_secrets == []


def test_windows_profile_automatically_selects_legacy_xml_registration(monkeypatch):
    monkeypatch.setenv("KINDL_PROFILE", "windows")
    monkeypatch.delenv("KINDL_REG", raising=False)
    captured_requests: list[tuple[str, bytes]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured_requests.append((str(request.url), request.content))
        if request.url.path == "/auth/token":
            return httpx.Response(200, json={"access_token": "synth-access"})
        if request.url.path == "/FirsProxy/registerDeviceWithToken":
            return httpx.Response(
                200,
                content=(
                    b"<response><device_private_key>synth-win-key</device_private_key>"
                    b"<adp_token>synth-win-adp</adp_token>"
                    b"<user_directed_id>synth-directed</user_directed_id>"
                    b"<preferred_marketplace>US</preferred_marketplace></response>"
                ),
            )
        return httpx.Response(500)

    client = AmazonDeviceClient()
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        creds = client.register(
            "https://www.amazon.com/?openid.oa2.authorization_code=SYNTH_CODE",
            "synth-verifier",
            "1" * 32,
            "2" * 8,
        )
    finally:
        client.close()

    assert len(captured_requests) == 2
    token_url, token_body = captured_requests[0]
    reg_url, reg_body = captured_requests[1]
    assert token_url == "https://api.amazon.com/auth/token"
    assert json.loads(token_body)["app_name"] == "KatxopoWindows"
    assert reg_url == "https://firs-ta-g7g.amazon.com/FirsProxy/registerDeviceWithToken"
    assert b"<deviceType>A1UOUY6O7B48AR</deviceType>" in reg_body
    assert b"<softwareVersion>4351</softwareVersion>" in reg_body
    assert b'name="oem_platform" value="Mazama"' in reg_body
    assert creds.device_type == "A1UOUY6O7B48AR"
    assert creds.software_version == "4351"
    assert creds.adp_token == "synth-win-adp"
    assert creds.private_key == "synth-win-key"


def test_windows_profile_respects_explicit_kindl_reg_override(monkeypatch):
    monkeypatch.setenv("KINDL_PROFILE", "windows")
    monkeypatch.setenv("KINDL_REG", "map")
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        if request.url.path == "/auth/token":
            return httpx.Response(200, json={"access_token": "synth-access"})
        if request.url.path == "/auth/register":
            return httpx.Response(
                200,
                json={
                    "response": {
                        "success": {
                            "tokens": {
                                "mac_dms": {
                                    "adp_token": "synth-map-adp",
                                    "device_private_key": "synth-map-key",
                                }
                            }
                        }
                    }
                },
            )
        return httpx.Response(500)

    client = AmazonDeviceClient()
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        creds = client.register(
            "https://www.amazon.com/?openid.oa2.authorization_code=SYNTH_CODE",
            "synth-verifier",
            "1" * 32,
            "2" * 8,
        )
    finally:
        client.close()

    assert urls == ["https://api.amazon.com/auth/token", "https://api.amazon.com/auth/register"]
    assert creds.adp_token == "synth-map-adp"
    assert creds.device_type == "A1UOUY6O7B48AR"
