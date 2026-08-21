import json

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
    monkeypatch.setenv("APPDATA", str(tmp_path))
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
            destination.mkdir(parents=True)
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
    assert list((output / "B000000001").iterdir()) == [
        output / "B000000001" / "B000000001.kfx-zip"
    ]
    assert list((output / "B000000002").iterdir()) == [
        output / "B000000002" / "B000000002.kfx-zip"
    ]
    assert AccountStore.load(config).accounts[0].credentials.adp_token == "refreshed"
