"""Device personas (android / ios / ios-ipad / windows) and the identity they register.

Everything here is synthetic: the RSA key is generated in-process and every
credential value is an obvious placeholder. No network, no real account material.
"""

from __future__ import annotations

import json
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from kindl import auth
from kindl.client import VOUCHER_VERSIONS, AmazonDeviceClient, _persona_voucher_versions

ANDROID = auth.PERSONAS["android"]
IOS = auth.PERSONAS["ios"]
IOS_IPAD = auth.PERSONAS["ios-ipad"]
WINDOWS = auth.PERSONAS["windows"]


_CACHED_RSA_PEM: str | None = None


def _rsa_pem() -> str:
    global _CACHED_RSA_PEM
    if _CACHED_RSA_PEM is None:
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        _CACHED_RSA_PEM = key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        ).decode()
    return _CACHED_RSA_PEM


def _credentials(pem: str) -> auth.DeviceCredentials:
    return auth.DeviceCredentials(
        serial="A" * 32,
        pid="B" * 8,
        device_type=auth.DEVICE_TYPE,
        adp_token="synth-adp-token",
        private_key=pem,
    )


# ------------------------------------------------------------------ the persona table


def test_default_persona_is_android_and_keeps_the_module_constants():
    assert auth.DEFAULT_PROFILE == "android"
    assert auth.resolve_persona({}) == ANDROID
    # With no KINDL_PROFILE / KINDL_* override the long-standing constants are
    # byte-identical to the values this module has always exposed.
    assert auth.DEVICE_TYPE == "A3VNNDO1I14V03"
    assert auth.SOFTWARE_VERSION == "1286477811"
    assert auth.APP_NAME == "com.amazon.kindle"
    assert auth.OEM_PLATFORM == "Android"
    assert auth.ADP_APP_ID == "com.amazon.kindle"


def test_unknown_profile_raises_value_error():
    with pytest.raises(ValueError, match="Unknown KINDL_PROFILE 'windows-phone'"):
        auth.resolve_persona({"KINDL_PROFILE": "windows-phone"})


def test_windows_persona_values():
    assert auth.resolve_persona({"KINDL_PROFILE": "windows"}) == WINDOWS
    assert WINDOWS["device_type"] == "A1UOUY6O7B48AR"
    assert WINDOWS["software_version"] == "4351"
    assert WINDOWS["app_name"] == "KatxopoWindows"
    assert WINDOWS["oem_platform"] == "Mazama"
    assert WINDOWS["registration_flow"] == "legacy"


def test_ios_persona_values():
    assert auth.resolve_persona({"KINDL_PROFILE": "ios"}) == IOS
    assert IOS["device_type"] == "AGZZ1ST63LKBW"
    assert IOS["software_version"] == "1191420432"
    assert IOS["app_name"] == "Kindle"
    assert IOS["oem_platform"] == "iOS"
    assert IOS["app_version"] == "7.68.1"
    assert IOS["device_model"] == "iPhone"
    assert IOS["os_version"] == "17.7.1"
    assert IOS["adp_app_id"] == ""  # the iOS client sends no X-ADP-App-Id


def test_ios_ipad_persona_values():
    assert auth.resolve_persona({"KINDL_PROFILE": "ios-ipad"}) == IOS_IPAD
    assert IOS_IPAD["device_type"] == "A1FG5NAKX0MRJL"
    assert IOS_IPAD["device_model"] == "iPad"
    assert IOS_IPAD["app_name"] == IOS["app_name"]
    assert IOS_IPAD["device_name"] == "Kindle for iPad"


def test_explicit_env_overrides_beat_the_profile():
    resolved = auth.resolve_persona(
        {
            "KINDL_PROFILE": "ios",
            "KINDL_DEVICE_TYPE": "SYNTH-DT",
            "KINDL_APP_VERSION": "9.9.9",
            "KINDL_OS_VERSION": "18.0",
        }
    )
    assert resolved["device_type"] == "SYNTH-DT"
    assert resolved["app_version"] == "9.9.9"
    assert resolved["os_version"] == "18.0"
    assert resolved["device_model"] == "iPhone"  # the untouched profile field


def test_persona_value_reads_the_environment_at_call_time(monkeypatch):
    monkeypatch.setenv("KINDL_PROFILE", "ios")
    assert auth.persona_value("device_model") == "iPhone"
    assert auth.persona_value("adp_app_id") == ""
    assert auth.persona_value("device_name") == "Kindle for iPhone"
    monkeypatch.setenv("KINDL_DEVICE_MODEL", "iPad Pro")
    assert auth.persona_value("device_model") == "iPad Pro"
    monkeypatch.delenv("KINDL_PROFILE")
    monkeypatch.delenv("KINDL_DEVICE_MODEL")
    assert auth.persona_value("device_model") == "Pixel 7"
    assert auth.persona_value("adp_app_id") == "com.amazon.kindle"


# --------------------------------------------------------- X-ADP-App-Id delivery


def test_signed_headers_send_the_app_id_only_when_asked(monkeypatch):
    monkeypatch.delenv("KINDL_PROFILE", raising=False)
    monkeypatch.delenv("KINDL_DEVICE_MODEL", raising=False)
    pem = _rsa_pem()

    client = AmazonDeviceClient(_credentials(pem))
    try:
        # Ordinary signed requests are unchanged: no app id unless opted in.
        assert "X-ADP-App-Id" not in client._signed_headers("GET", "https://example.test/x")
        android = client._signed_headers("GET", "https://example.test/x", include_app_id=True)
        assert android["X-ADP-App-Id"] == "com.amazon.kindle"
    finally:
        client.close()

    monkeypatch.setenv("KINDL_PROFILE", "ios")
    client = AmazonDeviceClient(_credentials(pem))
    try:
        ios = client._signed_headers("GET", "https://example.test/x", include_app_id=True)
        assert "X-ADP-App-Id" not in ios
    finally:
        client.close()


def test_restore_account_secrets_omits_the_app_id_for_the_ios_persona(monkeypatch):
    monkeypatch.setenv("KINDL_PROFILE", "ios")
    captured: dict[str, str | None] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["app_id"] = request.headers.get("x-adp-app-id")
        return httpx.Response(200, json={"accountSecrets": ["synth-secret"]})

    client = AmazonDeviceClient(_credentials(_rsa_pem()))
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        secrets = client.restore_account_secrets()
    finally:
        client.close()

    assert secrets == ["synth-secret"]
    assert captured["app_id"] is None


def test_signed_headers_fall_back_to_credentials_device_type_when_profile_unset(monkeypatch):
    monkeypatch.delenv("KINDL_PROFILE", raising=False)
    pem = _rsa_pem()

    for dt in ("AGZZ1ST63LKBW", "A1FG5NAKX0MRJL"):
        creds = auth.DeviceCredentials(
            serial="A" * 32,
            pid="B" * 8,
            device_type=dt,
            adp_token="synth-adp-token",
            private_key=pem,
        )
        with AmazonDeviceClient(creds) as client:
            headers = client._signed_headers("POST", "https://example.test/x", include_app_id=True)
            assert "X-ADP-App-Id" not in headers

    win_creds = auth.DeviceCredentials(
        serial="A" * 32,
        pid="B" * 8,
        device_type="A1UOUY6O7B48AR",
        adp_token="synth-adp-token",
        private_key=pem,
    )
    with AmazonDeviceClient(win_creds) as client:
        win_headers = client._signed_headers("POST", "https://example.test/x", include_app_id=True)
        assert win_headers["X-ADP-App-Id"] == "KatxopoWindows"

    unknown_creds = auth.DeviceCredentials(
        serial="A" * 32,
        pid="B" * 8,
        device_type="SYNTH-UNKNOWN",
        adp_token="synth-adp-token",
        private_key=pem,
    )
    with AmazonDeviceClient(unknown_creds) as client:
        default_headers = client._signed_headers(
            "POST", "https://example.test/x", include_app_id=True
        )
        assert default_headers["X-ADP-App-Id"] == "com.amazon.kindle"


def test_persona_voucher_versions_falls_back_to_credentials_device_type(monkeypatch):
    monkeypatch.delenv("KINDL_PROFILE", raising=False)
    monkeypatch.delenv("KINDL_VOUCHER_VERSIONS", raising=False)

    assert (
        _persona_voucher_versions("manifest_voucher_versions", device_type="AGZZ1ST63LKBW")
        == TABLE_VOUCHER_VERSIONS
    )
    assert (
        _persona_voucher_versions("voucher_versions", device_type="A1FG5NAKX0MRJL")
        == TABLE_VOUCHER_VERSIONS
    )
    assert (
        _persona_voucher_versions("manifest_voucher_versions", device_type="A1UOUY6O7B48AR")
        == LEGACY_ANDROID_VOUCHER_VERSIONS
    )

    monkeypatch.setenv("KINDL_VOUCHER_VERSIONS", "full")
    ios_full = _persona_voucher_versions("manifest_voucher_versions", device_type="AGZZ1ST63LKBW")
    assert ios_full.endswith("V5683,V1685,V0682,V0456")


# ------------------------------------------------------------ MAP registration body


def _register_map(monkeypatch: pytest.MonkeyPatch, profile: str | None, **env: str) -> dict:
    if profile is None:
        monkeypatch.delenv("KINDL_PROFILE", raising=False)
    else:
        monkeypatch.setenv("KINDL_PROFILE", profile)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    captured: dict[str, dict] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["body"] = json.loads(request.content)
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
    assert credentials.device_type == captured["body"]["registration_data"]["device_type"]
    return captured["body"]


def test_register_map_android_persona_defaults(monkeypatch):
    body = _register_map(monkeypatch, None)
    data = body["registration_data"]
    assert data["device_type"] == "A3VNNDO1I14V03"
    assert data["device_model"] == "Pixel 7"
    assert data["os_version"] == "13"
    assert data["app_name"] == "com.amazon.kindle"
    assert data["app_version"] == "1286477811"
    assert data["software_version"] == "1286477811"
    assert data["device_name"] == (
        "%FIRST_NAME%%FIRST_NAME_POSSESSIVE_STRING%%DUPE_STRATEGY_1ST%Kindle for Android"
    )
    assert body["requested_token_type"] == [
        "bearer",
        "mac_dms",
        "website_cookies",
        "store_authentication_cookie",
    ]
    assert body["auth_data"] == {}


def test_register_map_ios_persona(monkeypatch):
    data = _register_map(monkeypatch, "ios")["registration_data"]
    assert data["device_type"] == "AGZZ1ST63LKBW"
    assert data["device_model"] == "iPhone"
    assert data["os_version"] == "17.7.1"
    assert data["app_name"] == "Kindle"
    assert data["app_version"] == "7.68.1"
    assert data["software_version"] == "1191420432"
    assert data["device_name"].endswith("Kindle for iPhone")
    assert data["device_name"].startswith(
        "%FIRST_NAME%%FIRST_NAME_POSSESSIVE_STRING%%DUPE_STRATEGY_1ST%"
    )


def test_register_map_ios_ipad_persona(monkeypatch):
    data = _register_map(monkeypatch, "ios-ipad")["registration_data"]
    assert data["device_type"] == "A1FG5NAKX0MRJL"
    assert data["device_model"] == "iPad"
    assert data["device_name"].endswith("Kindle for iPad")


def test_register_map_env_overrides_beat_the_profile(monkeypatch):
    data = _register_map(
        monkeypatch, "ios", KINDL_DEVICE_MODEL="iPad mini", KINDL_OS_VERSION="18.0"
    )["registration_data"]
    assert data["device_model"] == "iPad mini"
    assert data["os_version"] == "18.0"
    assert data["app_name"] == "Kindle"  # a profile field that was not overridden


# ------------------------------------------------- supportedVoucherVersions

#: The two lists this client has always advertised for the Android persona --
#: the voucher-query one and the (older, shorter) manifest-request one -- written
#: out literally so a refactor cannot silently move either.
LEGACY_ANDROID_VOUCHER_VERSIONS = (
    "V1,V2,V3,V4,V5,V6,V7,V8,V9,V10,V11,V12,V13,V14,V15,V16,V17,V18,V19,V20,"
    "V21,V22,V23,V24,V25,V26,V27,V28,V9708,V1031,V2069,V9041,V3646,V6052,"
    "V9479,V9888,V4648,V5683,V7384,V2746,V3332"
)
LEGACY_ANDROID_MANIFEST_VOUCHER_VERSIONS = (
    "V1,V2,V3,V4,V5,V6,V7,V8,V9,V10,V11,V12,V13,V14,V15,V16,V17,V18,V19,V20,"
    "V21,V22,V23,V24,V25,V26,V27,V28,V9708,V1031,V2069,V9041,V3646,V6052,"
    "V9479,V9888,V4648,V5683,V9753"
)


def test_android_voucher_versions_are_unchanged(monkeypatch):
    monkeypatch.delenv("KINDL_PROFILE", raising=False)
    resolved = auth.resolve_persona({})
    assert ",".join(resolved["voucher_versions"]) == LEGACY_ANDROID_VOUCHER_VERSIONS
    assert (
        ",".join(resolved["manifest_voucher_versions"]) == LEGACY_ANDROID_MANIFEST_VOUCHER_VERSIONS
    )
    assert auth.persona_value("voucher_versions") == auth.ANDROID_VOUCHER_VERSIONS
    assert VOUCHER_VERSIONS == LEGACY_ANDROID_VOUCHER_VERSIONS


def test_ios_voucher_versions_differ_in_the_last_three():
    android = auth.PERSONAS["android"]["voucher_versions"]
    assert android[-3:] == ("V7384", "V2746", "V3332")
    assert auth.PERSONAS["android"]["manifest_voucher_versions"][-2:] == (
        "V5683",
        "V9753",
    )
    for profile in ("ios", "ios-ipad"):
        resolved = auth.resolve_persona({"KINDL_PROFILE": profile})
        # The iOS build advertises one list, at both request sites.
        assert resolved["manifest_voucher_versions"] == resolved["voucher_versions"]
        ios = resolved["voucher_versions"]
        assert ios[:28] == tuple(f"V{i}" for i in range(1, 29))
        assert ios[:-3] == android[:-3]  # shares the first 38 entries
        assert ios[-3:] == ("V1685", "V0682", "V0456")
        assert not {"V7384", "V2746", "V3332"} & set(ios)


def _manifest_voucher_versions(monkeypatch: pytest.MonkeyPatch, profile: str | None) -> str:
    if profile is None:
        monkeypatch.delenv("KINDL_PROFILE", raising=False)
    else:
        monkeypatch.setenv("KINDL_PROFILE", profile)
    monkeypatch.delenv("KINDL_NO_VV", raising=False)
    captured: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["versions"] = request.url.params.get("supportedVoucherVersions", "")
        return httpx.Response(200, json={"resources": []})

    client = AmazonDeviceClient(_credentials(_rsa_pem()))
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        client.manifest("B012345678")
    finally:
        client.close()
    return captured["versions"]


def test_manifest_url_advertises_the_active_personas_voucher_versions(monkeypatch):
    # Android keeps its historical manifest capture, V9753 tail and all.
    android = _manifest_voucher_versions(monkeypatch, None)
    assert android == LEGACY_ANDROID_MANIFEST_VOUCHER_VERSIONS
    assert android.endswith("V5683,V9753")
    assert "V7384" not in android and "V2746" not in android and "V3332" not in android

    # iOS persona defaults to the 38-tag table list (offline decodable).
    ios = _manifest_voucher_versions(monkeypatch, "ios")
    assert ios == TABLE_VOUCHER_VERSIONS
    assert "V1685" not in ios and "V0682" not in ios and "V0456" not in ios

    # Explicit KINDL_VOUCHER_VERSIONS=full restores the captured iOS list.
    monkeypatch.setenv("KINDL_VOUCHER_VERSIONS", "full")
    ios_full = _manifest_voucher_versions(monkeypatch, "ios")
    assert ios_full.endswith("V5683,V1685,V0682,V0456")
    assert "V7384" not in ios_full and "V2746" not in ios_full and "V3332" not in ios_full


# ------------------------------------------------- KINDL_VOUCHER_VERSIONS (probe knob)

TABLE_VOUCHER_VERSIONS = (
    "V1,V2,V3,V4,V5,V6,V7,V8,V9,V10,V11,V12,V13,V14,V15,V16,V17,V18,V19,V20,"
    "V21,V22,V23,V24,V25,V26,V27,V28,V9708,V1031,V2069,V9041,V3646,V6052,"
    "V9479,V9888,V4648,V5683"
)


def test_probe_knob_table_narrows_both_request_sites(monkeypatch):
    monkeypatch.delenv("KINDL_PROFILE", raising=False)
    monkeypatch.delenv("KINDL_VOUCHER_VERSIONS", raising=False)
    # Default ("full") is byte-identical to the captured persona lists.
    assert _persona_voucher_versions("voucher_versions") == LEGACY_ANDROID_VOUCHER_VERSIONS
    assert (
        _persona_voucher_versions("manifest_voucher_versions")
        == LEGACY_ANDROID_MANIFEST_VOUCHER_VERSIONS
    )
    # "table" narrows both Android sites to the 38 tags the decoded law can decode.
    monkeypatch.setenv("KINDL_VOUCHER_VERSIONS", "table")
    assert _persona_voucher_versions("voucher_versions") == TABLE_VOUCHER_VERSIONS
    assert _persona_voucher_versions("manifest_voucher_versions") == TABLE_VOUCHER_VERSIONS
    assert TABLE_VOUCHER_VERSIONS.endswith("V5683")
    assert "V7384" not in TABLE_VOUCHER_VERSIONS and "V9753" not in TABLE_VOUCHER_VERSIONS
    # Explicit "full" or empty value stays "full" on the default Android persona.
    for value in ("full", "FULL", ""):
        monkeypatch.setenv("KINDL_VOUCHER_VERSIONS", value)
        assert _persona_voucher_versions("voucher_versions") == LEGACY_ANDROID_VOUCHER_VERSIONS


def test_probe_knob_table_drops_the_newest_ios_generations(monkeypatch):
    monkeypatch.setenv("KINDL_PROFILE", "ios")
    # By default, ios persona already drops newest generations (defaults to "table")
    for key in ("voucher_versions", "manifest_voucher_versions"):
        versions = _persona_voucher_versions(key)
        assert versions == TABLE_VOUCHER_VERSIONS
        assert "V1685" not in versions and "V0682" not in versions and "V0456" not in versions
    # Explicit "table" also yields the 38-tag list
    monkeypatch.setenv("KINDL_VOUCHER_VERSIONS", "table")
    for key in ("voucher_versions", "manifest_voucher_versions"):
        versions = _persona_voucher_versions(key)
        assert versions == TABLE_VOUCHER_VERSIONS
        assert "V1685" not in versions and "V0682" not in versions and "V0456" not in versions
    # Explicit "full" restores the captured iOS list
    monkeypatch.setenv("KINDL_VOUCHER_VERSIONS", "full")
    for key in ("voucher_versions", "manifest_voucher_versions"):
        versions = _persona_voucher_versions(key)
        assert versions.endswith("V5683,V1685,V0682,V0456")
        assert "V1685" in versions and "V0682" in versions and "V0456" in versions


def test_probe_knob_table_reaches_the_manifest_request(monkeypatch):
    monkeypatch.setenv("KINDL_VOUCHER_VERSIONS", "table")
    assert _manifest_voucher_versions(monkeypatch, "ios") == TABLE_VOUCHER_VERSIONS
    assert _manifest_voucher_versions(monkeypatch, None) == TABLE_VOUCHER_VERSIONS


@pytest.mark.parametrize(
    ("profile", "tail"),
    [
        (None, "V5683,V7384,V2746,V3332"),  # Android: default full
        ("ios", "V5683"),  # iOS defaults to table (38 tags, ends V5683)
        ("ios-ipad", "V5683"),  # iOS-iPad defaults to table
    ],
)
def test_voucher_resource_query_uses_the_persona_list(
    monkeypatch: pytest.MonkeyPatch, tmp_path, profile: str | None, tail: str
) -> None:
    if profile is None:
        monkeypatch.delenv("KINDL_PROFILE", raising=False)
    else:
        monkeypatch.setenv("KINDL_PROFILE", profile)
    monkeypatch.delenv("KINDL_VOUCHER_VERSIONS", raising=False)
    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(str(request.url))
        if request.url.path.startswith("/delivery/manifest/"):
            return httpx.Response(
                200,
                json={
                    "resources": [
                        {
                            "type": "DRM_VOUCHER",
                            "endpoint": {
                                "url": "https://delivery.test/voucher?X-ADP-CorrelationId=synth"
                            },
                        }
                    ]
                },
            )
        return httpx.Response(200, content=b"synth-voucher")

    client = AmazonDeviceClient(_credentials(_rsa_pem()))
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        downloaded = client.download("B012345678", tmp_path)
    finally:
        client.close()

    voucher_url = next(url for url in captured if "/voucher" in url)
    versions = parse_qs(urlsplit(voucher_url).query)["supportedVoucherVersions"][0]
    assert versions.endswith(tail)
    if profile is None:
        assert versions == VOUCHER_VERSIONS
    else:
        assert versions == TABLE_VOUCHER_VERSIONS
    assert (tmp_path / "B012345678" / "voucher").read_bytes() == b"synth-voucher"
    assert (tmp_path / "B012345678" / "manifest.json") in downloaded


def test_voucher_resource_query_env_full_override_for_ios(
    monkeypatch: pytest.MonkeyPatch, tmp_path
) -> None:
    monkeypatch.setenv("KINDL_PROFILE", "ios")
    monkeypatch.setenv("KINDL_VOUCHER_VERSIONS", "full")
    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(str(request.url))
        if request.url.path.startswith("/delivery/manifest/"):
            return httpx.Response(
                200,
                json={
                    "resources": [
                        {
                            "type": "DRM_VOUCHER",
                            "endpoint": {
                                "url": "https://delivery.test/voucher?X-ADP-CorrelationId=synth"
                            },
                        }
                    ]
                },
            )
        return httpx.Response(200, content=b"synth-voucher")

    client = AmazonDeviceClient(_credentials(_rsa_pem()))
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        downloaded = client.download("B012345678", tmp_path)
    finally:
        client.close()

    voucher_url = next(url for url in captured if "/voucher" in url)
    versions = parse_qs(urlsplit(voucher_url).query)["supportedVoucherVersions"][0]
    assert versions.endswith("V5683,V1685,V0682,V0456")
    assert (tmp_path / "B012345678" / "voucher").read_bytes() == b"synth-voucher"
    assert (tmp_path / "B012345678" / "manifest.json") in downloaded


@pytest.mark.parametrize(
    ("raw_override", "expected"),
    [
        ("V1685", "V1685"),
        ("V0456", "V0456"),
        ("V0682", "V0682"),
        ("V1", "V1"),
        ("V28", "V28"),
        ("V9708", "V9708"),
        ("V1,V28", "V1,V28"),
        (" V1 , V28 , V1685 ", "V1,V28,V1685"),
    ],
)
@pytest.mark.parametrize("profile", [None, "ios", "ios-ipad"])
def test_custom_voucher_versions_override_at_both_request_sites(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path,
    raw_override: str,
    expected: str,
    profile: str | None,
) -> None:
    if profile is None:
        monkeypatch.delenv("KINDL_PROFILE", raising=False)
    else:
        monkeypatch.setenv("KINDL_PROFILE", profile)
    monkeypatch.delenv("KINDL_NO_VV", raising=False)
    monkeypatch.setenv("KINDL_VOUCHER_VERSIONS", raw_override)

    assert _persona_voucher_versions("voucher_versions") == expected
    assert _persona_voucher_versions("manifest_voucher_versions") == expected

    captured: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        captured.append(str(request.url))
        if request.url.path.startswith("/delivery/manifest/"):
            return httpx.Response(
                200,
                json={
                    "resources": [
                        {
                            "type": "DRM_VOUCHER",
                            "endpoint": {
                                "url": "https://delivery.test/voucher?X-ADP-CorrelationId=synth"
                            },
                        }
                    ]
                },
            )
        return httpx.Response(200, content=b"synth-voucher")

    client = AmazonDeviceClient(_credentials(_rsa_pem()))
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    try:
        client.download("B012345678", tmp_path)
    finally:
        client.close()

    manifest_url = next(url for url in captured if "/delivery/manifest/" in url)
    voucher_url = next(url for url in captured if "/voucher" in url)
    assert parse_qs(urlsplit(manifest_url).query)["supportedVoucherVersions"] == [expected]
    assert parse_qs(urlsplit(voucher_url).query)["supportedVoucherVersions"] == [expected]


def test_device_client_id_and_login_url_resolve_persona_dynamically(monkeypatch):
    """device_client_id and AmazonDeviceClient.login_url resolve KINDL_PROFILE / KINDL_DEVICE_TYPE at call time."""
    monkeypatch.setenv("KINDL_PROFILE", "ios")
    monkeypatch.delenv("KINDL_DEVICE_TYPE", raising=False)
    serial = "A" * 32
    cid = auth.device_client_id(serial)
    assert bytes.fromhex(cid).decode() == f"{serial}#AGZZ1ST63LKBW"
    url = AmazonDeviceClient.login_url(serial, "challenge123")
    assert f"device%3A{cid}" in url or f"device:{cid}" in url
