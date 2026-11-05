import json
from urllib.parse import parse_qs, urlencode, urlsplit

import httpx
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import kindl.cli as cli_module
from kindl.auth import Account, AccountStore, DeviceCredentials, device_client_id, persona_value
from kindl.cli import cli
from kindl.client import AmazonDeviceClient
from kindl.regions import DEFAULT_REGION, REGIONS, get_region


@pytest.fixture(autouse=True)
def default_persona(monkeypatch):
    for variable in ("KINDL_PROFILE", "KINDL_REG", "KINDL_DEVICE_TYPE", "KINDL_SW"):
        monkeypatch.delenv(variable, raising=False)


def credentials(region: str = "us", private_key: str = "key") -> DeviceCredentials:
    return DeviceCredentials(
        serial="A" * 32,
        pid="B" * 8,
        device_type="A3VNNDO1I14V03",
        adp_token="token",
        private_key=private_key,
        directed_id="directed-A",
        region=region,
    )


def mocked_client(handler, **kwargs) -> AmazonDeviceClient:
    client = AmazonDeviceClient(**kwargs)
    client.http.close()
    client.http = httpx.Client(transport=httpx.MockTransport(handler))
    return client


def map_registration_response() -> httpx.Response:
    return httpx.Response(
        200,
        json={
            "response": {
                "success": {
                    "tokens": {
                        "mac_dms": {"adp_token": "synth-adp", "device_private_key": "synth-key"}
                    }
                }
            }
        },
    )


def test_get_region_defaults_to_us_and_rejects_unknown_codes():
    assert DEFAULT_REGION == "us"
    assert get_region() is REGIONS["us"]
    assert get_region("") is REGIONS["us"]
    assert get_region(" JP ") is REGIONS["jp"]
    with pytest.raises(ValueError, match="expected one of: jp, us"):
        get_region("uk")


def test_us_login_url_is_unchanged():
    serial, challenge = "A" * 32, "C" * 43
    legacy_params = {
        "openid.oa2.client_id": f"device:{device_client_id(serial, persona_value('device_type'))}",
        "openid.claimed_id": "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.ns.oa2": "http://www.amazon.com/ap/ext/oauth/2",
        "openid.ns": "http://specs.openid.net/auth/2.0",
        "openid.identity": "http://specs.openid.net/auth/2.0/identifier_select",
        "openid.mode": "checkid_setup",
        "openid.oa2.scope": "device_auth_access",
        "openid.oa2.response_type": "code",
        "openid.oa2.code_challenge": challenge,
        "openid.oa2.code_challenge_method": "S256",
        "openid.return_to": "https://www.amazon.com/",
        "openid.ns.pape": "http://specs.openid.net/extensions/pape/1.0",
        "openid.pape.max_auth_age": "0",
        "accountStatusPolicy": "P1",
        "pageId": "amzn_mazama_pc_aui",
        "openid.assoc_handle": "amzn_mazama_desktop_us",
        "disableLoginPrepopulate": "1",
        "language": "en_US",
    }
    expected = f"https://www.amazon.com/ap/signin?{urlencode(legacy_params)}"

    assert AmazonDeviceClient.login_url(serial, challenge) == expected
    assert AmazonDeviceClient.login_url(serial, challenge, region="us") == expected


def test_jp_login_url_changes_only_site_handle_and_return_url():
    serial, challenge = "A" * 32, "C" * 43
    us = urlsplit(AmazonDeviceClient.login_url(serial, challenge))
    jp = urlsplit(AmazonDeviceClient.login_url(serial, challenge, region="jp"))
    us_params, jp_params = parse_qs(us.query), parse_qs(jp.query)

    assert (jp.scheme, jp.netloc, jp.path) == ("https", "www.amazon.co.jp", "/ap/signin")
    assert jp_params.pop("openid.assoc_handle") == ["amzn_mazama_desktop_jp"]
    assert jp_params.pop("openid.return_to") == ["https://www.amazon.co.jp/"]
    del us_params["openid.assoc_handle"], us_params["openid.return_to"]
    # Everything else, including the OAuth namespace and page ID, is shared.
    assert jp_params == us_params
    assert jp_params["openid.ns.oa2"] == ["http://www.amazon.com/ap/ext/oauth/2"]


def test_jp_map_registration_uses_jp_identity_service():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/auth/token":
            return httpx.Response(200, json={"access_token": "synth-access"})
        if request.url.path == "/auth/register":
            return map_registration_response()
        return httpx.Response(500)

    client = mocked_client(handler, region="jp")
    try:
        creds = client.register(
            "https://www.amazon.co.jp/?openid.oa2.authorization_code=SYNTH_CODE",
            "synth-verifier",
            "1" * 32,
            "2" * 8,
        )
    finally:
        client.close()

    assert [str(request.url) for request in requests] == [
        "https://api.amazon.co.jp/auth/token",
        "https://api.amazon.co.jp/auth/register",
    ]
    assert {request.headers["x-amzn-identity-auth-domain"] for request in requests} == {
        "api.amazon.co.jp"
    }
    assert json.loads(requests[0].content)["source_token"] == "SYNTH_CODE"
    assert json.loads(requests[1].content)["cookies"]["domain"] == ".amazon.co.jp"
    assert creds.region == "jp"
    assert creds.adp_token == "synth-adp"


def test_jp_legacy_registration_uses_jp_token_and_global_firs(monkeypatch):
    monkeypatch.setenv("KINDL_REG", "legacy")
    urls: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        urls.append(str(request.url))
        if request.url.path == "/auth/token":
            return httpx.Response(200, json={"access_token": "synth-access"})
        return httpx.Response(
            200,
            content=b"<response><device_private_key>synth-key</device_private_key>"
            b"<adp_token>synth-adp</adp_token></response>",
        )

    client = mocked_client(handler, region="jp")
    try:
        creds = client.register(
            "https://www.amazon.co.jp/?openid.oa2.authorization_code=SYNTH_CODE",
            "synth-verifier",
            "1" * 32,
            "2" * 8,
        )
    finally:
        client.close()

    assert urls == [
        "https://api.amazon.co.jp/auth/token",
        "https://firs-ta-g7g.amazon.com/FirsProxy/registerDeviceWithToken",
    ]
    assert creds.region == "jp"


def test_us_registration_records_us_region():
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/auth/token":
            return httpx.Response(200, json={"access_token": "synth-access"})
        assert json.loads(request.content)["cookies"]["domain"] == ".amazon.com"
        return map_registration_response()

    client = mocked_client(handler)
    try:
        creds = client.register(
            "https://www.amazon.com/?openid.oa2.authorization_code=SYNTH_CODE",
            "synth-verifier",
            "1" * 32,
            "2" * 8,
        )
    finally:
        client.close()

    assert creds.region == "us"


def test_jp_refresh_bearer_and_register_persona_use_jp_identity_service():
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/auth/token":
            return httpx.Response(200, json={"access_token": "synth-access"})
        return map_registration_response()

    client = mocked_client(handler, region="jp")
    try:
        access_token = client.refresh_bearer("synth-refresh")
        creds = client.register_persona(access_token, "C" * 32, "D" * 8)
    finally:
        client.close()

    assert [str(request.url) for request in requests] == [
        "https://api.amazon.co.jp/auth/token",
        "https://api.amazon.co.jp/auth/register",
    ]
    assert {request.headers["x-amzn-identity-auth-domain"] for request in requests} == {
        "api.amazon.co.jp"
    }
    assert creds.region == "jp"


def test_client_region_follows_credentials_unless_overridden():
    assert AmazonDeviceClient().region.code == "us"
    assert AmazonDeviceClient(credentials("jp")).region.code == "jp"
    assert AmazonDeviceClient(credentials("jp"), region="us").region.code == "us"
    with pytest.raises(ValueError, match="Unknown region 'uk'"):
        AmazonDeviceClient(credentials("uk"))


def test_jp_accounts_use_the_shared_device_services():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()
    hosts: list[tuple[str, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        hosts.append((request.url.host, request.url.path))
        if request.url.path.endswith("/syncMetaData"):
            return httpx.Response(200, content=b"<response/>")
        if request.url.path.endswith("/getDeviceCredentials"):
            return httpx.Response(
                200,
                content=f"<response><device_private_key>{pem}</device_private_key>"
                "<adp_token>token</adp_token></response>".encode(),
            )
        return httpx.Response(200, json={"resources": []})

    client = mocked_client(handler, credentials=credentials("jp", pem))
    try:
        client.library(limit=1)
        client.refresh_device_credentials()
        client.manifest("B000000000")
    finally:
        client.close()

    assert hosts == [
        ("todo-ta-g7g.amazon.com", "/FionaTodoListProxy/syncMetaData"),
        ("firs-ta-g7g.amazon.com", "/FirsProxy/getDeviceCredentials"),
        ("kindle-digital-delivery.amazon.com", "/delivery/manifest/kindle.ebook/B000000000"),
    ]


def test_configs_without_region_load_as_us_and_region_round_trips(tmp_path):
    legacy = tmp_path / "legacy.json"
    legacy.write_text(
        json.dumps(
            {
                "version": 1,
                "accounts": [
                    {
                        "name": "old",
                        "credentials": {
                            "serial": "A" * 32,
                            "device_type": "device",
                            "adp_token": "token",
                            "private_key": "key",
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    assert AccountStore.load(legacy).get("old").credentials.region == "us"

    config = tmp_path / "config.json"
    AccountStore([Account("jp-account", credentials("jp"))]).save(config)
    saved = json.loads(config.read_text(encoding="utf-8"))
    assert saved["accounts"][0]["credentials"]["region"] == "jp"
    assert AccountStore.load(config).get("jp-account").credentials.region == "jp"


@pytest.mark.parametrize(("flag", "expected"), [("jp", "jp"), ("JP", "jp")])
def test_user_add_region_flag_reaches_sign_in_and_registration(
    monkeypatch, tmp_path, flag, expected
):
    config = tmp_path / "config.json"
    calls: dict[str, object] = {}

    class FakeClient:
        def __init__(self, *, region):
            calls["client_region"] = region

        @staticmethod
        def login_url(serial, challenge, *, language, region):
            calls["login_region"] = region
            return "https://www.amazon.co.jp/ap/signin?openid.mode=checkid_setup"

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def register(self, url, verifier, serial, pid):
            return credentials(calls["client_region"])

    monkeypatch.setattr(cli_module, "AmazonDeviceClient", FakeClient)
    result = CliRunner().invoke(
        cli,
        ["--config", str(config), "user", "add", "personal-jp", "--region", flag, "--no-browser"],
        input="https://www.amazon.co.jp/?openid.oa2.authorization_code=code\n",
    )

    assert result.exit_code == 0, result.output
    assert calls == {"login_region": expected, "client_region": expected}
    assert "copy the complete amazon.co.jp URL" in result.output
    assert AccountStore.load(config).get("personal-jp").credentials.region == "jp"


def test_user_add_rejects_unknown_region(tmp_path):
    result = CliRunner().invoke(
        cli,
        ["--config", str(tmp_path / "config.json"), "user", "add", "x", "--region", "uk"],
    )

    assert result.exit_code == 2
    assert "Invalid value for '--region'" in result.output


def test_user_clone_uses_source_account_region(monkeypatch, tmp_path):
    config = tmp_path / "config.json"
    source = credentials("jp")
    source.refresh_token = "synth-refresh"
    AccountStore([Account("personal-jp", source)]).save(config)
    regions: list[str] = []

    class FakeClient:
        def __init__(self, *, region):
            regions.append(region)

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def refresh_bearer(self, refresh_token):
            return "synth-access"

        def register_persona(self, access_token, serial, pid):
            return DeviceCredentials(
                serial=serial,
                pid=pid,
                device_type="clone-device",
                adp_token="clone-adp",
                private_key="clone-key",
                region=regions[-1],
            )

    monkeypatch.setattr(cli_module, "AmazonDeviceClient", FakeClient)
    result = CliRunner().invoke(
        cli, ["--config", str(config), "user", "clone", "personal-jp", "--name", "ipad-jp"]
    )

    assert result.exit_code == 0, result.output
    assert regions == ["jp"]
    assert AccountStore.load(config).get("ipad-jp").credentials.region == "jp"


def test_user_list_shows_each_account_region(tmp_path):
    config = tmp_path / "config.json"
    us_credentials = credentials()
    us_credentials.serial = "U" * 32
    AccountStore(
        [Account("personal", us_credentials), Account("personal-jp", credentials("jp"))]
    ).save(config)

    result = CliRunner().invoke(cli, ["--config", str(config), "--fmt", "plain", "user", "list"])

    assert result.exit_code == 0, result.output
    lines = result.output.splitlines()
    assert lines[0].split() == ["Name", "Directed", "ID", "Device", "Serial", "Region"]
    assert lines[1].split()[0::3] == ["personal", "us"]
    assert lines[2].split()[0::3] == ["personal-jp", "jp"]
