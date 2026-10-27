"""Tests for client identity verification profiles, version tuples, and serial issuance in kindl.auth."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from kindl import auth


def test_version_tuple_names_and_backwards_compatible_aliases() -> None:
    assert len(auth.HISTORICAL_DESKTOP_VOUCHER_VERSIONS) == 41
    assert auth.HISTORICAL_DESKTOP_VOUCHER_VERSIONS[-3:] == ("V7384", "V2746", "V3332")
    assert auth.ANDROID_VOUCHER_VERSIONS == auth.HISTORICAL_DESKTOP_VOUCHER_VERSIONS

    assert len(auth.NATIVE_ANDROID_VOUCHER_VERSIONS) == 39
    assert auth.NATIVE_ANDROID_VOUCHER_VERSIONS[-2:] == ("V5683", "V9753")
    assert auth.LEGACY_ANDROID_MANIFEST_VOUCHER_VERSIONS == auth.NATIVE_ANDROID_VOUCHER_VERSIONS

    assert set(auth.PERSONAS) == {"android", "ios", "ios-ipad", "windows"}


def test_built_in_windows_persona_profile() -> None:
    win = auth.resolve_persona({"KINDL_PROFILE": "windows"})
    assert win == auth.PERSONAS["windows"]
    assert win["device_type"] == "A1UOUY6O7B48AR"
    assert win["software_version"] == "4351"
    assert win["app_name"] == "KatxopoWindows"
    assert win["oem_platform"] == "Mazama"
    assert win["app_version"] == "4351"
    assert win["device_model"] == "PC"
    assert win["os_version"] == "10.0"
    assert win["adp_app_id"] == "KatxopoWindows"
    assert win["device_name"] == "Kindle for Windows"
    assert win["voucher_versions"] == auth.HISTORICAL_DESKTOP_VOUCHER_VERSIONS
    assert win["manifest_voucher_versions"] == auth.HISTORICAL_DESKTOP_VOUCHER_VERSIONS
    assert win["registration_flow"] == "legacy"


def test_resolve_persona_raises_value_error_on_unknown_profile() -> None:
    for invalid in ("win", "windows-phone", "unknown-profile", "mac", "eink"):
        with pytest.raises(ValueError, match=f"Unknown KINDL_PROFILE {invalid!r}"):
            auth.resolve_persona({"KINDL_PROFILE": invalid})


def test_resolve_persona_defaults_to_android_when_unset_or_blank() -> None:
    assert auth.resolve_persona({}) == auth.PERSONAS["android"]
    assert auth.resolve_persona({"KINDL_PROFILE": ""}) == auth.PERSONAS["android"]
    assert auth.resolve_persona({"KINDL_PROFILE": "   "}) == auth.PERSONAS["android"]


def test_persona_env_overrides_apply_to_windows_and_ios(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KINDL_PROFILE", "windows")
    assert auth.persona_value("registration_flow") == "legacy"
    assert auth.persona_value("device_type") == "A1UOUY6O7B48AR"

    monkeypatch.setenv("KINDL_PROFILE", "ios")
    monkeypatch.setenv("KINDL_SW", "5000000000")
    assert auth.persona_value("device_type") == "AGZZ1ST63LKBW"
    assert auth.persona_value("software_version") == "5000000000"


def test_new_device_identity_and_client_id_for_profiles(monkeypatch: pytest.MonkeyPatch) -> None:
    serial, pid = auth.new_device_identity()
    assert len(serial) == 32
    assert serial == serial.upper()
    assert len(pid) == 8

    monkeypatch.setenv("KINDL_PROFILE", "windows")
    win_cid = auth.device_client_id(serial)
    assert bytes.fromhex(win_cid).decode("ascii") == f"{serial}#A1UOUY6O7B48AR"

    monkeypatch.setenv("KINDL_PROFILE", "ios-ipad")
    ipad_cid = auth.device_client_id(serial)
    assert bytes.fromhex(ipad_cid).decode("ascii") == f"{serial}#A1FG5NAKX0MRJL"


def test_profile_and_persona_for_device_type_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("KINDL_PROFILE", raising=False)
    assert auth.profile_for_device_type("AGZZ1ST63LKBW", {}) == "ios"
    assert auth.profile_for_device_type("A1FG5NAKX0MRJL", {}) == "ios-ipad"
    assert auth.profile_for_device_type("A1UOUY6O7B48AR", {}) == "windows"
    assert auth.profile_for_device_type("A3VNNDO1I14V03", {}) == "android"
    assert auth.profile_for_device_type("UNKNOWN-DT", {}) == "android"
    assert auth.profile_for_device_type(None, {}) == "android"

    assert auth.persona_for_device_type("AGZZ1ST63LKBW", {}) == auth.PERSONAS["ios"]
    assert auth.persona_value("adp_app_id", device_type="AGZZ1ST63LKBW", environ={}) == ""
    assert (
        auth.persona_value("adp_app_id", device_type="A1UOUY6O7B48AR", environ={})
        == "KatxopoWindows"
    )
    assert (
        auth.persona_value("adp_app_id", device_type="A3VNNDO1I14V03", environ={})
        == "com.amazon.kindle"
    )

    # Explicit KINDL_PROFILE takes precedence over stored device_type.
    assert (
        auth.persona_value(
            "adp_app_id",
            device_type="A3VNNDO1I14V03",
            environ={"KINDL_PROFILE": "ios"},
        )
        == ""
    )


def test_default_config_path_env_override(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.delenv("KINDL_CONFIG", raising=False)
    standard_path = auth.default_config_path()
    assert standard_path == auth.default_credentials_path()

    # Empty KINDL_CONFIG should also fall back to standard path
    monkeypatch.setenv("KINDL_CONFIG", "")
    assert auth.default_config_path() == standard_path

    # Custom path override
    custom_file = tmp_path / "custom_dir" / "settings.json"
    monkeypatch.setenv("KINDL_CONFIG", str(custom_file))
    assert auth.default_config_path() == custom_file

    # Tilde expansion
    monkeypatch.setenv("KINDL_CONFIG", "~/test_kindl_cfg.json")
    assert auth.default_config_path() == Path.home() / "test_kindl_cfg.json"


def test_account_secrets_legacy_key_and_csv_normalization(tmp_path: Path) -> None:
    single_path = tmp_path / "single.json"
    single_path.write_text(
        json.dumps(
            {
                "serial": "A" * 32,
                "device_type": "A3VNNDO1I14V03",
                "adp_token": "synth-adp",
                "private_key": "synth-key",
                "secrets": " sec_one , sec_two , ",
            }
        ),
        encoding="utf-8",
    )
    loaded_creds = auth.DeviceCredentials.load(single_path)
    assert loaded_creds.account_secrets == ["sec_one", "sec_two"]

    multi_path = tmp_path / "multi.json"
    multi_path.write_text(
        json.dumps(
            {
                "version": 1,
                "accounts": [
                    {
                        "name": "primary",
                        "credentials": {
                            "serial": "B" * 32,
                            "device_type": "AGZZ1ST63LKBW",
                            "adp_token": "synth-adp-2",
                            "private_key": "synth-key-2",
                            "secrets": ["sec_alpha", "", "sec_beta"],
                        },
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    store = auth.AccountStore.load(multi_path)
    acct = store.get("primary")
    assert acct is not None
    assert acct.credentials.account_secrets == ["sec_alpha", "sec_beta"]
