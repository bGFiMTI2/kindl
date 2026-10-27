import base64
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from kindl import cli as cli_module
from kindl.auth import Account, AccountStore, DeviceCredentials, _load_any_private_key
from kindl.cli import cli, main
from kindl.client import AmazonDeviceClient
from kindl.models import LibraryItem

_TEST_KEY = rsa.generate_private_key(public_exponent=65537, key_size=1024)
_TEST_PEM = _TEST_KEY.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption(),
).decode("ascii")


def _synth_credentials(serial: str = "0123456789ABCDEF0123456789ABCDEF") -> DeviceCredentials:
    return DeviceCredentials(
        serial=serial,
        pid="B0000001",
        device_type="A3VNNDO1I14V03",
        adp_token="synthetic-adp-token",
        private_key=_TEST_PEM,
        directed_id=f"directed-{serial[:8]}",
        account_secrets=["synthetic-secret-1"],
    )


# -----------------------------------------------------------------------------
# 1. Main CLI Subcommands & Entrypoints
# -----------------------------------------------------------------------------


def test_cli_user_rm(tmp_path: Path):
    cfg = tmp_path / "config.json"
    store = AccountStore(
        [
            Account("alice", _synth_credentials("A" * 32)),
            Account("bob", _synth_credentials("B" * 32)),
        ]
    )
    store.save(cfg)

    runner = CliRunner()

    # Remove existing account
    res = runner.invoke(cli, ["--config", str(cfg), "user", "rm", "alice"])
    assert res.exit_code == 0, res.output
    assert "Removed alice" in res.output

    reloaded = AccountStore.load(cfg)
    assert reloaded.get("alice") is None
    assert reloaded.get("bob") is not None

    # Remove nonexistent account -> raises ClickException
    res_err = runner.invoke(cli, ["--config", str(cfg), "user", "rm", "nonexistent"])
    assert res_err.exit_code != 0
    assert "no account matches 'nonexistent'" in res_err.output


def test_cli_book_list(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg = tmp_path / "config.json"
    AccountStore([Account("tester", _synth_credentials())]).save(cfg)

    item1 = LibraryItem(
        asin="B000000001",
        title="Title Beta",
        authors=("Author One", "Author Two"),
        publishers=("Publisher X",),
        content_type="Ebook",
        cde_content_type="EBOK",
        purchase_date="2026-01-01",
        publication_date="2025-01-01",
        content_size=1024,
    )
    item2 = LibraryItem(
        asin="B000000002",
        title="Title Alpha",
        authors=("Author Three",),
        publishers=(),
    )

    # Test LibraryItem.as_dict()
    d1 = item1.as_dict()
    assert d1["asin"] == "B000000001"
    assert isinstance(d1["authors"], list)
    assert d1["authors"] == ["Author One", "Author Two"]
    assert isinstance(d1["publishers"], list)
    assert d1["content_size"] == 1024

    monkeypatch.setattr(cli_module, "_library", lambda _acc, _limit: [item1, item2])

    runner = CliRunner()

    # Default table output
    res_table = runner.invoke(cli, ["--config", str(cfg), "book", "list"])
    assert res_table.exit_code == 0, res_table.output
    assert "Title Alpha" in res_table.output
    assert "Title Beta" in res_table.output
    assert "B000000001" in res_table.output

    # JSON output
    res_json = runner.invoke(cli, ["--config", str(cfg), "book", "list", "--json"])
    assert res_json.exit_code == 0, res_json.output
    parsed_json = json.loads(res_json.output)
    assert len(parsed_json) == 2
    assert parsed_json[0]["title"] == "Title Alpha"  # Sorted alphabetically
    assert parsed_json[1]["title"] == "Title Beta"
    assert parsed_json[0]["owner"] == "tester"

    # Export library flag
    export_path = tmp_path / "export.json"
    res_exp = runner.invoke(
        cli, ["--config", str(cfg), "book", "list", "--export-library", str(export_path)]
    )
    assert res_exp.exit_code == 0, res_exp.output
    assert export_path.is_file()
    exported = json.loads(export_path.read_text(encoding="utf-8"))
    assert len(exported) == 2
    assert exported[0]["asin"] == "B000000002"


def test_cli_book_package(tmp_path: Path):
    book_dir = tmp_path / "staging_book"
    book_dir.mkdir()
    (book_dir / "manifest.json").write_text("{}", encoding="utf-8")
    (book_dir / "book.azw8").write_bytes(b"SYNTH_AZW8")
    (book_dir / "book.voucher").write_bytes(b"SYNTH_VOUCHER")

    out_zip = tmp_path / "packaged.kfx-zip"
    runner = CliRunner()
    res = runner.invoke(
        cli,
        [
            "--config",
            str(tmp_path / "config.json"),
            "book",
            "package",
            str(book_dir),
            "-o",
            str(out_zip),
        ],
    )
    assert res.exit_code == 0, res.output
    assert out_zip.is_file()


def test_cli_book_get_no_package(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    cfg = tmp_path / "config.json"
    AccountStore([Account("tester", _synth_credentials())]).save(cfg)
    out_dir = tmp_path / "downloads"

    item = LibraryItem(asin="B000000001", title="Synthetic Book")
    monkeypatch.setattr(cli_module, "_library", lambda _acc, _limit: [item])

    def fake_download(self, product_id, output_dir, **kwargs):
        dest = kwargs.get("destination", output_dir / product_id)
        dest.mkdir(parents=True, exist_ok=True)
        manifest = dest / "manifest.json"
        manifest.write_text("{}", encoding="utf-8")
        frag = dest / f"{product_id}.azw8"
        frag.write_bytes(b"SYNTH_FRAGMENT")
        return [manifest, frag]

    monkeypatch.setattr(AmazonDeviceClient, "download", fake_download)
    monkeypatch.setattr(
        AmazonDeviceClient, "refresh_device_credentials", lambda self: self.credentials
    )

    runner = CliRunner()
    res = runner.invoke(
        cli,
        [
            "--config",
            str(cfg),
            "book",
            "get",
            "--no-package",
            "B000000001",
            "-o",
            str(out_dir),
        ],
    )
    assert res.exit_code == 0, res.output
    assert "manifest.json" in res.output


def test_cli_main_and_module_entrypoint(monkeypatch: pytest.MonkeyPatch):
    # main(["--help"]) returns 0
    assert main(["--help"]) == 0

    # main(["nonexistent"]) returns click usage error code
    assert main(["nonexistent-command-xyz"]) == 2

    # main with unexpected error and without --debug
    def fake_cli_raise(*args, **kwargs):
        raise RuntimeError("Synthetic CLI Failure")

    monkeypatch.setattr(cli, "main", fake_cli_raise)
    assert main([]) == 1

    # main with unexpected error and with --debug raises
    with pytest.raises(RuntimeError, match="Synthetic CLI Failure"):
        main(["--debug"])

    # Test python -m kindl invocation
    proc = subprocess.run(
        [sys.executable, "-m", "kindl", "--help"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert proc.returncode == 0
    assert "Usage: kindl" in proc.stdout


# -----------------------------------------------------------------------------
# 2. Client & Auth Gaps
# -----------------------------------------------------------------------------


def test_client_library_and_guards(monkeypatch: pytest.MonkeyPatch):
    client = AmazonDeviceClient(_synth_credentials())

    # Limit boundary guards
    with pytest.raises(ValueError, match="limit must be between 1 and 1000"):
        client.library(limit=0)

    with pytest.raises(ValueError, match="limit must be between 1 and 1000"):
        client.library(limit=1001)

    # Valid library call
    xml_resp = (
        b"<response status='ok'><meta_data>"
        b"<asin>B000000001</asin><title>Synthetic Book</title>"
        b"<author>Synthetic Author</author>"
        b"</meta_data></response>"
    )

    mock_response = MagicMock(spec=httpx.Response)
    mock_response.status_code = 200
    mock_response.content = xml_resp
    mock_response.raise_for_status = MagicMock()

    monkeypatch.setattr(client.http, "get", lambda url, headers: mock_response)
    items = client.library(limit=100)
    assert len(items) == 1
    assert items[0].asin == "B000000001"
    assert items[0].title == "Synthetic Book"
    assert items[0].authors == ("Synthetic Author",)

    # Manifest invalid ASIN guard
    with pytest.raises(ValueError, match="Invalid ASIN"):
        client.manifest("invalid asin with whitespace!")


def test_client_kindl_no_vv_query_omission(monkeypatch: pytest.MonkeyPatch):
    client = AmazonDeviceClient(_synth_credentials())
    recorded_urls: list[str] = []

    def fake_get(url, headers):
        recorded_urls.append(url)
        resp = MagicMock(spec=httpx.Response)
        resp.status_code = 200
        resp.json.return_value = {}
        resp.raise_for_status = MagicMock()
        return resp

    monkeypatch.setattr(client.http, "get", fake_get)

    # When KINDL_NO_VV is set -> voucher versions query param omitted
    monkeypatch.setenv("KINDL_NO_VV", "1")
    client.manifest("B000000001")
    assert "?supportedVoucherVersions=" not in recorded_urls[-1]

    # When KINDL_NO_VV is unset -> voucher versions query param included
    monkeypatch.delenv("KINDL_NO_VV", raising=False)
    client.manifest("B000000001")
    assert "?supportedVoucherVersions=" in recorded_urls[-1]


def test_auth_raw_der_private_key_loading():
    # Fast 1024-bit RSA key for testing
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    der_bytes = rsa_key.private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    raw_b64 = base64.b64encode(der_bytes).decode("ascii")

    # Load raw DER base64 without PEM headers
    loaded = _load_any_private_key(raw_b64)
    assert isinstance(loaded, rsa.RSAPrivateKey)
    assert loaded.private_numbers().d == rsa_key.private_numbers().d

    # Unpadded compact string
    unpadded_b64 = raw_b64.rstrip("=")
    loaded_unpadded = _load_any_private_key(unpadded_b64)
    assert loaded_unpadded.private_numbers().d == rsa_key.private_numbers().d


def test_account_store_error_branches(tmp_path: Path):
    creds = _synth_credentials()
    store = AccountStore([Account("alpha", creds)])

    # Duplicate account error
    with pytest.raises(ValueError, match="already exists; use --replace"):
        store.add(Account("alpha", creds), replace=False)

    # Successful replacement
    new_creds = _synth_credentials("C" * 32)
    store.add(Account("alpha", new_creds), replace=True)
    assert store.get("alpha").credentials.serial == "C" * 32

    # Corrupt JSON file
    bad_json = tmp_path / "bad.json"
    bad_json.write_text("{broken json", encoding="utf-8")
    with pytest.raises(RuntimeError, match="Could not read config"):
        AccountStore.load(bad_json)

    # Non-dict config
    non_dict = tmp_path / "nondict.json"
    non_dict.write_text("12345", encoding="utf-8")
    with pytest.raises(TypeError, match="Invalid config in"):
        AccountStore.load(non_dict)

    # Invalid accounts list
    bad_list = tmp_path / "badlist.json"
    bad_list.write_text('{"accounts": "not_a_list"}', encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid accounts list in"):
        AccountStore.load(bad_list)

    # Invalid account entry
    bad_entry = tmp_path / "badentry.json"
    bad_entry.write_text('{"accounts": ["not_a_dict"]}', encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid account in"):
        AccountStore.load(bad_entry)
