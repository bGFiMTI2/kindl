import json
import os

import click
import pytest
from click.testing import CliRunner

import kindl.cli as cli_module
from kindl.auth import Account, AccountStore, DeviceCredentials
from kindl.cli import cli, format_book_path
from kindl.models import LibraryItem


def credentials(serial: str = "A" * 32) -> DeviceCredentials:
    return DeviceCredentials(
        serial=serial,
        pid="B" * 8,
        device_type="device",
        adp_token="token",
        private_key="key",
        directed_id=f"directed-{serial[0]}",
    )


def test_account_store_migrates_legacy_credentials(tmp_path):
    path = tmp_path / "credentials.json"
    credentials().save(path)

    store = AccountStore.load(path)

    assert [account.name for account in store.accounts] == ["default"]
    store.save(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    assert value["version"] == 1
    assert value["accounts"][0]["credentials"]["adp_token"] == "token"
    assert DeviceCredentials.load(path) == credentials()


def test_cli_migrates_old_project_config_location(monkeypatch, tmp_path):
    config_env = "APPDATA" if os.name == "nt" else "XDG_CONFIG_HOME"
    monkeypatch.setenv(config_env, str(tmp_path))
    legacy = tmp_path / "amzn-device-link" / "credentials.json"
    target = tmp_path / "kindl" / "config.json"
    credentials().save(legacy)

    result = CliRunner().invoke(cli, ["user", "list"])

    assert result.exit_code == 0, result.output
    assert target.is_file()
    assert AccountStore.load(target).accounts[0].name == "default"


def test_account_store_resolves_and_removes_named_accounts(tmp_path):
    path = tmp_path / "config.json"
    store = AccountStore([Account("Personal", credentials())])
    store.save(path)

    loaded = AccountStore.load(path)

    assert loaded.get("personal").name == "Personal"
    assert loaded.get("DIRECTED-A").name == "Personal"
    assert loaded.remove("personal").name == "Personal"
    assert loaded.accounts == []


def test_account_store_loads_config_without_refresh_token(tmp_path):
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps(
            {
                "version": 1,
                "accounts": [
                    {
                        "name": "old",
                        "credentials": {
                            "serial": "A" * 32,
                            "pid": "B" * 8,
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

    store = AccountStore.load(path)

    assert store.get("old").credentials.refresh_token == ""


@pytest.mark.parametrize(
    ("args", "browser_available", "launch_browser", "show_login_url"),
    [
        pytest.param(["personal", "--no-browser"], True, False, True, id="manual"),
        pytest.param(["--no-browser"], True, False, True, id="manual-prompted-name"),
        pytest.param(["personal"], True, True, False, id="default-browser"),
        pytest.param(["personal"], False, True, True, id="browser-unavailable"),
    ],
)
def test_user_add_browser_modes(
    monkeypatch, tmp_path, args, browser_available, launch_browser, show_login_url
):
    config = tmp_path / "config.json"
    account_credentials = credentials()
    login_url = "https://www.amazon.com/ap/signin?openid.mode=checkid_setup&test=value"
    final_url = "https://www.amazon.com/?openid.oa2.authorization_code=code"
    browser_urls = []
    registrations = []

    class FakeClient:
        @staticmethod
        def login_url(serial, challenge, *, language):
            assert serial == account_credentials.serial
            assert challenge == "challenge"
            assert language == "en_US"
            return login_url

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def register(self, url, verifier, serial, pid):
            registrations.append((url, verifier, serial, pid))
            return account_credentials

    def open_browser(url):
        browser_urls.append(url)
        return browser_available

    monkeypatch.setattr(cli_module, "AmazonDeviceClient", FakeClient)
    monkeypatch.setattr(
        cli_module,
        "new_device_identity",
        lambda: (account_credentials.serial, account_credentials.pid),
    )
    monkeypatch.setattr(cli_module, "pkce_pair", lambda: ("verifier", "challenge"))
    monkeypatch.setattr(cli_module.webbrowser, "open", open_browser)
    answers = "" if "personal" in args else "personal\n"
    result = CliRunner().invoke(
        cli,
        ["--config", str(config), "user", "add", *args],
        input=f"{answers}  {final_url}  \n",
    )

    assert result.exit_code == 0, result.output
    assert browser_urls == ([login_url] if launch_browser else [])
    assert (login_url in result.output.splitlines()) == show_login_url
    assert ("Opening Amazon sign-in" in result.output) == launch_browser
    assert "Final URL: " in result.output
    assert registrations == [
        (final_url, "verifier", account_credentials.serial, account_credentials.pid)
    ]
    assert AccountStore.load(config).accounts == [Account("personal", account_credentials)]


def test_user_clone_requires_stored_refresh_token(tmp_path):
    config = tmp_path / "config.json"
    AccountStore([Account("personal", credentials())]).save(config)

    result = CliRunner().invoke(
        cli, ["--config", str(config), "user", "clone", "personal", "--name", "second"]
    )

    assert result.exit_code == 1
    assert "no stored refresh_token" in result.output
    assert AccountStore.load(config).get("second") is None


def test_user_clone_registers_persona_without_leaking_tokens(monkeypatch, tmp_path):
    config = tmp_path / "config.json"
    source_credentials = credentials()
    source_credentials.refresh_token = "synth-refresh"
    AccountStore([Account("personal", source_credentials)]).save(config)
    calls = {}

    class FakeClient:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def refresh_bearer(self, refresh_token):
            calls["refresh_token"] = refresh_token
            return "synth-access"

        def register_persona(self, access_token, serial, pid):
            calls["persona"] = (access_token, serial, pid)
            return DeviceCredentials(
                serial=serial,
                pid=pid,
                device_type="clone-device",
                adp_token="clone-adp",
                private_key="clone-key",
            )

    monkeypatch.setattr(cli_module, "AmazonDeviceClient", FakeClient)
    monkeypatch.setattr(cli_module, "new_device_identity", lambda: ("C" * 32, "D" * 8))

    result = CliRunner().invoke(
        cli, ["--config", str(config), "user", "clone", "personal", "--name", "second"]
    )

    assert result.exit_code == 0, result.output
    assert calls == {
        "refresh_token": "synth-refresh",
        "persona": ("synth-access", "C" * 32, "D" * 8),
    }
    added = AccountStore.load(config).get("second")
    assert added is not None
    assert added.credentials.adp_token == "clone-adp"
    assert "second" in result.output
    assert "clone-device" in result.output
    assert "CCCCCC" in result.output  # serial suffix only
    assert "synth-refresh" not in result.output
    assert "synth-access" not in result.output
    assert "clone-adp" not in result.output

    duplicate = CliRunner().invoke(
        cli, ["--config", str(config), "user", "clone", "personal", "--name", "second"]
    )
    assert duplicate.exit_code == 2
    assert "already exists" in duplicate.output


def test_book_get_requires_user_with_multiple_accounts(tmp_path):
    path = tmp_path / "config.json"
    AccountStore(
        [
            Account("one", credentials("A" * 32)),
            Account("two", credentials("C" * 32)),
        ]
    ).save(path)

    result = CliRunner().invoke(cli, ["--config", str(path), "book", "get", "B012345678"])

    assert result.exit_code == 2
    assert "--user is required" in result.output


def test_format_book_path_supports_subdirectories_and_sanitizes(tmp_path):
    item = LibraryItem("B012345678", "A: Title", ("An/Author",))

    path = format_book_path(tmp_path, "{Author}/{Title} {ASIN}", item)

    assert path == tmp_path / "An_Author" / "A_ Title B012345678"


def test_format_book_path_rejects_parent_traversal(tmp_path):
    item = LibraryItem("B012345678", "Title")

    with pytest.raises(click.UsageError, match="relative path"):
        format_book_path(tmp_path, "../{Title}", item)


def test_get_all_downloads_every_library_item(monkeypatch, tmp_path):
    config = tmp_path / "config.json"
    output = tmp_path / "books"
    AccountStore([Account("personal", credentials())]).save(config)
    items = [
        LibraryItem("B000000001", "First", ("Author",)),
        LibraryItem("B000000002", "Second", ("Author",)),
    ]

    class FakeClient:
        def __init__(self, account_credentials=None):
            self.credentials = account_credentials

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def library(self, *, limit):
            assert limit == 1000
            return items

        def refresh_device_credentials(self):
            self.credentials.adp_token = "refreshed"
            return self.credentials

        def download(self, asin, output_dir, *, include_optional, destination):
            assert output_dir == output
            assert include_optional
            assert destination.parent == output / asin
            assert destination.name.startswith(".kindl-")
            assert list(destination.parent.iterdir()) == [destination]
            manifest = destination / "manifest.json"
            content = destination / f"{asin}.azw9"
            voucher = destination / "book.voucher"
            manifest.write_text("{}", encoding="utf-8")
            content.write_bytes(b"content")
            voucher.write_bytes(b"voucher")
            return [manifest, content, voucher]

    monkeypatch.setattr(cli_module, "AmazonDeviceClient", FakeClient)
    result = CliRunner().invoke(
        cli,
        [
            "--config",
            str(config),
            "book",
            "get",
            "--get-all",
            "--output-dir",
            str(output),
            "--format-str",
            "{ASIN}",
        ],
    )

    assert result.exit_code == 0, result.output
    assert (output / "B000000001" / "B000000001.kfx-zip").is_file()
    assert (output / "B000000002" / "B000000002.kfx-zip").is_file()
    assert list((output / "B000000001").iterdir()) == [output / "B000000001" / "B000000001.kfx-zip"]
    assert list((output / "B000000002").iterdir()) == [output / "B000000002" / "B000000002.kfx-zip"]
    assert AccountStore.load(config).accounts[0].credentials.adp_token == "refreshed"


def test_packaged_download_removes_staging_directory_after_failure(monkeypatch, tmp_path):
    config = tmp_path / "config.json"
    output = tmp_path / "books"
    AccountStore([Account("personal", credentials())]).save(config)
    item = LibraryItem("B000000001", "First", ("Author",))

    class FailingClient:
        def __init__(self, account_credentials=None):
            self.credentials = account_credentials

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def library(self, *, limit):
            return [item]

        def refresh_device_credentials(self):
            return self.credentials

        def download(self, asin, output_dir, *, include_optional, destination):
            assert destination.name.startswith(".kindl-")
            (destination / "partial.azw9").write_bytes(b"partial")
            raise RuntimeError("download failed")

    monkeypatch.setattr(cli_module, "AmazonDeviceClient", FailingClient)
    result = CliRunner().invoke(
        cli,
        [
            "--config",
            str(config),
            "book",
            "get",
            "--output-dir",
            str(output),
            "--format-str",
            "{Author}/{ASIN}",
            item.asin,
        ],
    )

    assert result.exit_code == 1
    assert list(output.iterdir()) == []


def test_secrets_refresh_and_list_cli(monkeypatch, tmp_path):
    config = tmp_path / "config.json"
    account_credentials = credentials()
    AccountStore([Account("Personal", account_credentials)]).save(config)

    def fake_restore(self):
        self.credentials.account_secrets = ["synth_secret_alpha", "synth_secret_beta"]
        return self.credentials.account_secrets

    monkeypatch.setattr(cli_module.AmazonDeviceClient, "restore_account_secrets", fake_restore)

    runner = CliRunner()
    result_refresh = runner.invoke(cli, ["--config", str(config), "secrets", "refresh"])
    assert result_refresh.exit_code == 0
    assert "restored 2 account secret(s)" in result_refresh.output

    # Check that secrets landed in the saved config
    loaded_store = AccountStore.load(config)
    assert loaded_store.accounts[0].credentials.account_secrets == [
        "synth_secret_alpha",
        "synth_secret_beta",
    ]

    result_list = runner.invoke(cli, ["--config", str(config), "secrets", "list"])
    assert result_list.exit_code == 0
    assert "Personal" in result_list.output
    assert "2" in result_list.output


def test_secrets_refresh_continues_across_accounts_when_one_fails(monkeypatch, tmp_path):
    config = tmp_path / "config.json"
    c1 = credentials("1" * 32)
    c2 = credentials("2" * 32)
    c3 = credentials("3" * 32)
    AccountStore(
        [
            Account("acct_one", c1),
            Account("acct_two_fail", c2),
            Account("acct_three", c3),
        ]
    ).save(config)

    visited: list[str] = []

    def fake_restore(self):
        visited.append(self.credentials.serial)
        if self.credentials.serial == "2" * 32:
            raise RuntimeError("Amazon restore account secrets failed (HTTP 403)")
        self.credentials.account_secrets = [f"synth_{self.credentials.serial[:4]}"]
        return self.credentials.account_secrets

    monkeypatch.setattr(cli_module.AmazonDeviceClient, "restore_account_secrets", fake_restore)

    runner = CliRunner()
    result = runner.invoke(cli, ["--config", str(config), "secrets", "refresh"])

    assert visited == ["1" * 32, "2" * 32, "3" * 32]
    assert result.exit_code != 0
    assert "Account 'acct_one': restored 1 account secret(s)." in result.output
    assert "Account 'acct_two_fail': secrets refresh failed:" in result.output
    assert "Account 'acct_three': restored 1 account secret(s)." in result.output
    assert "1 of 3 account(s) failed secrets refresh: acct_two_fail" in result.output

    loaded_store = AccountStore.load(config)
    assert loaded_store.get("acct_one").credentials.account_secrets == ["synth_1111"]
    assert loaded_store.get("acct_two_fail").credentials.account_secrets == []
    assert loaded_store.get("acct_three").credentials.account_secrets == ["synth_3333"]


def test_book_get_auto_restores_account_secrets(monkeypatch, tmp_path):
    config = tmp_path / "config.json"
    output = tmp_path / "books"
    AccountStore([Account("personal", credentials())]).save(config)
    book_item = LibraryItem("B000000001", "Book One", ("Author",))

    class FakeClient:
        def __init__(self, account_credentials=None):
            self.credentials = account_credentials

        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def library(self, *, limit):
            return [book_item]

        def refresh_device_credentials(self):
            return self.credentials

        def restore_account_secrets(self):
            self.credentials.account_secrets = ["auto_restored_secret"]
            return self.credentials.account_secrets

        def download(
            self,
            asin,
            output_dir,
            *,
            include_optional,
            destination,
        ):
            manifest = destination / "manifest.json"
            content = destination / f"{asin}.azw9"
            voucher = destination / "book.voucher"
            manifest.write_text("{}", encoding="utf-8")
            content.write_bytes(b"content")
            voucher.write_bytes(b"voucher")
            return [manifest, content, voucher]

    monkeypatch.setattr(cli_module, "AmazonDeviceClient", FakeClient)
    result = CliRunner().invoke(
        cli,
        [
            "--config",
            str(config),
            "book",
            "get",
            "--output-dir",
            str(output),
            "--format-str",
            "{ASIN}",
            book_item.asin,
        ],
    )

    assert result.exit_code == 0, result.output
    assert AccountStore.load(config).accounts[0].credentials.account_secrets == [
        "auto_restored_secret"
    ]
