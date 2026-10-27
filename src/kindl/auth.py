from __future__ import annotations

import base64
import hashlib
import json
import os

# Identity is persona-driven so the client can emulate supported device profiles.
# KINDL_PROFILE selects a whole persona ("android", "ios", "ios-ipad", "windows")
# and the per-field KINDL_DEVICE_TYPE / KINDL_SW / KINDL_APP_NAME /
# KINDL_OEM_PLATFORM / KINDL_APP_VERSION / KINDL_DEVICE_MODEL / KINDL_OS_VERSION
# variables override individual fields of the selected persona. The native
# ``supportedVoucherVersions`` lists (``voucher_versions`` for the voucher
# resource query, ``manifest_voucher_versions`` for the manifest request) are
# persona state as well.
# DEFAULT = the Android (Kindle 8.154) client: the delivery service keys the
# voucher generation off the device identity. KINDL_PROFILE=ios and ios-ipad
# select the Kindle for iOS (iPhone and iPad) personas. KINDL_PROFILE=windows
# selects the legacy Windows desktop persona (automatically defaulting to the
# legacy XML registration flow when KINDL_REG is unset).
import os as _os
import secrets
import stat
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization

#: The 38 base format tags shared across modern Kindle client builds (`V1`..`V28`
#: plus the ten legacy tags `V9708`..`V5683`).
TABLE_VERSION_TAGS: tuple[str, ...] = (
    *(f"V{i}" for i in range(1, 29)),
    "V9708",
    "V1031",
    "V2069",
    "V9041",
    "V3646",
    "V6052",
    "V9479",
    "V9888",
    "V4648",
    "V5683",
)

#: The historical 41-entry desktop ``supportedVoucherVersions`` list (ending
#: ``V7384,V2746,V3332``) captured from ``KatxopoWindows`` (``A1UOUY6O7B48AR``).
#: Retained on the *voucher resource* query for the Android persona for
#: backwards compatibility (see ``kindl.client.VOUCHER_VERSIONS``) and used at
#: both request sites for the ``windows`` persona.
HISTORICAL_DESKTOP_VOUCHER_VERSIONS: tuple[str, ...] = (
    *TABLE_VERSION_TAGS,
    "V7384",
    "V2746",
    "V3332",
)
#: Backwards-compatible alias for :data:`HISTORICAL_DESKTOP_VOUCHER_VERSIONS`.
ANDROID_VOUCHER_VERSIONS: tuple[str, ...] = HISTORICAL_DESKTOP_VOUCHER_VERSIONS

#: The authentic 39-entry Android runtime list (ending ``V9753``). Sent on
#: the *manifest request* for the Android persona, while
#: :data:`HISTORICAL_DESKTOP_VOUCHER_VERSIONS` (aliased as
#: :data:`ANDROID_VOUCHER_VERSIONS`, ending ``V7384,V2746,V3332`` from the
#: historical ``KatxopoWindows`` capture) is kept on the voucher resource query
#: for backwards compatibility.
NATIVE_ANDROID_VOUCHER_VERSIONS: tuple[str, ...] = (
    *TABLE_VERSION_TAGS,
    "V9753",
)
#: Backwards-compatible alias for :data:`NATIVE_ANDROID_VOUCHER_VERSIONS`.
LEGACY_ANDROID_MANIFEST_VOUCHER_VERSIONS: tuple[str, ...] = NATIVE_ANDROID_VOUCHER_VERSIONS

#: The iOS/Mac Catalyst version list. It shares its first 38 entries with
#: Android and differs only in the final three: V1685,V0682,V0456 instead of
#: V7384,V2746,V3332. The iOS client advertises this one list at both sites.
IOS_VOUCHER_VERSIONS: tuple[str, ...] = (
    *TABLE_VERSION_TAGS,
    "V1685",
    "V0682",
    "V0456",
)

#: A persona field is either a plain identity string or, for the
#: ``voucher_versions`` / ``manifest_voucher_versions`` keys, the ordered tuple of
#: advertised voucher versions.
PersonaValue = str | tuple[str, ...]

#: The client-generation profiles. Every identity field is a plain string so a
#: persona can be diffed against another and overridden one env var at a time.
#:
#: ``software_version`` is the native build number the app reports (the Android
#: versionCode, or the iOS ``KindlePackedAppVersion``); ``app_version`` is the
#: marketing version and is left empty on Android, where the two coincide.
#: ``adp_app_id`` is the ``X-ADP-App-Id`` header value; an empty value means the
#: client sends no such header at all (the iOS client).
PERSONAS: dict[str, dict[str, PersonaValue]] = {
    "android": {
        "device_type": "A3VNNDO1I14V03",
        "software_version": "1286477811",
        "app_name": "com.amazon.kindle",
        "oem_platform": "Android",
        "app_version": "",
        "device_model": "Pixel 7",
        "os_version": "13",
        "adp_app_id": "com.amazon.kindle",
        "device_name": "Kindle for Android",
        "voucher_versions": HISTORICAL_DESKTOP_VOUCHER_VERSIONS,
        "manifest_voucher_versions": NATIVE_ANDROID_VOUCHER_VERSIONS,
    },
    "ios": {
        # iPhone build 7.68.1 (Kindle for iOS)
        "device_type": "AGZZ1ST63LKBW",
        "software_version": "1191420432",
        "app_name": "Kindle",
        "oem_platform": "iOS",
        "app_version": "7.68.1",
        "device_model": "iPhone",
        "os_version": "17.7.1",
        "adp_app_id": "",
        "device_name": "Kindle for iPhone",
        "voucher_versions": IOS_VOUCHER_VERSIONS,
        "manifest_voucher_versions": IOS_VOUCHER_VERSIONS,
    },
    "ios-ipad": {
        "device_type": "A1FG5NAKX0MRJL",
        "software_version": "1191420432",
        "app_name": "Kindle",
        "oem_platform": "iOS",
        "app_version": "7.68.1",
        "device_model": "iPad",
        "os_version": "17.7.1",
        "adp_app_id": "",
        "device_name": "Kindle for iPad",
        "voucher_versions": IOS_VOUCHER_VERSIONS,
        "manifest_voucher_versions": IOS_VOUCHER_VERSIONS,
    },
    "windows": {
        "device_type": "A1UOUY6O7B48AR",
        "software_version": "4351",
        "app_name": "KatxopoWindows",
        "oem_platform": "Mazama",
        "app_version": "4351",
        "device_model": "PC",
        "os_version": "10.0",
        "adp_app_id": "KatxopoWindows",
        "device_name": "Kindle for Windows",
        "voucher_versions": HISTORICAL_DESKTOP_VOUCHER_VERSIONS,
        "manifest_voucher_versions": HISTORICAL_DESKTOP_VOUCHER_VERSIONS,
        "registration_flow": "legacy",
    },
}
DEFAULT_PROFILE = "android"
#: Stored ``device_type`` -> canonical persona profile name used when
#: ``KINDL_PROFILE`` is not explicitly set in the environment.
DEVICE_TYPE_PROFILES: dict[str, str] = {
    str(persona["device_type"]): profile_name for profile_name, persona in PERSONAS.items()
}
#: persona field -> the env var that overrides just that field.
PERSONA_ENV_VARS: dict[str, str] = {
    "device_type": "KINDL_DEVICE_TYPE",
    "software_version": "KINDL_SW",
    "app_name": "KINDL_APP_NAME",
    "oem_platform": "KINDL_OEM_PLATFORM",
    "app_version": "KINDL_APP_VERSION",
    "device_model": "KINDL_DEVICE_MODEL",
    "os_version": "KINDL_OS_VERSION",
}


def profile_for_device_type(
    device_type: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> str:
    """Resolve the effective persona profile name.

    When ``KINDL_PROFILE`` is explicitly set, validate and return it. Otherwise
    fall back to the persona matching ``device_type`` before falling back to
    :data:`DEFAULT_PROFILE`.
    """
    env = _os.environ if environ is None else environ
    raw_profile = env.get("KINDL_PROFILE")
    profile = raw_profile.strip() if isinstance(raw_profile, str) else ""
    if not profile:
        if isinstance(device_type, str) and device_type.strip():
            return DEVICE_TYPE_PROFILES.get(device_type.strip(), DEFAULT_PROFILE)
        return DEFAULT_PROFILE
    if profile not in PERSONAS:
        valid = ", ".join(sorted(PERSONAS))
        raise ValueError(f"Unknown KINDL_PROFILE {profile!r}; expected one of: {valid}")
    return profile


def resolve_persona(
    environ: Mapping[str, str] | None = None,
    *,
    device_type: str | None = None,
) -> dict[str, PersonaValue]:
    """Resolve one persona: ``KINDL_PROFILE`` (or ``device_type`` fallback) plus overrides.

    Raises :class:`ValueError` when an unknown ``KINDL_PROFILE`` is explicitly
    requested. Passing ``environ`` keeps the resolver pure and testable.
    """
    env = _os.environ if environ is None else environ
    profile = profile_for_device_type(device_type, env)
    resolved = dict(PERSONAS[profile])
    for field_name, variable in PERSONA_ENV_VARS.items():
        value = env.get(variable)
        if value:
            resolved[field_name] = value
    return resolved


def persona_for_device_type(
    device_type: str | None,
    environ: Mapping[str, str] | None = None,
) -> dict[str, PersonaValue]:
    """Resolve the persona for ``device_type`` when ``KINDL_PROFILE`` is unset."""
    return resolve_persona(environ, device_type=device_type)


def persona_value(
    key: str,
    *,
    device_type: str | None = None,
    environ: Mapping[str, str] | None = None,
) -> PersonaValue:
    """One persona field, read from the current environment at call time.

    ``voucher_versions`` and ``manifest_voucher_versions`` resolve to the
    persona's ordered tuple of advertised ``supportedVoucherVersions`` (for the
    voucher resource query and the manifest request respectively); the identity
    fields resolve to strings. An unknown key resolves to the empty string.
    """
    return resolve_persona(environ, device_type=device_type).get(key, "")


#: The profile named when the module was imported, and the persona it resolved to.
PROFILE = _os.environ.get("KINDL_PROFILE") or DEFAULT_PROFILE
ACTIVE_PERSONA: dict[str, PersonaValue] = resolve_persona()


def _identity_text(key: str) -> str:
    """One identity field of :data:`ACTIVE_PERSONA`, which is always a string."""
    value = ACTIVE_PERSONA[key]
    if not isinstance(value, str):
        raise TypeError(f"Persona field {key!r} is not a string")
    return value


# Backwards-compatible constants: with no KINDL_PROFILE / KINDL_* override these
# are byte-identical to the Android defaults this module exposes.
DEVICE_TYPE = _identity_text("device_type")
SOFTWARE_VERSION = _identity_text("software_version")
APP_NAME = _identity_text("app_name")
OEM_PLATFORM = _identity_text("oem_platform")
APP_VERSION = _identity_text("app_version")
DEVICE_MODEL = _identity_text("device_model")
OS_VERSION = _identity_text("os_version")
#: ``X-ADP-App-Id``; empty means the client generation sends no such header.
ADP_APP_ID = _identity_text("adp_app_id")
DEVICE_NAME_SUFFIX = _identity_text("device_name")


def default_credentials_path() -> Path:
    base = os.environ.get("APPDATA") if os.name == "nt" else os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "kindl" / "config.json"


def default_config_path() -> Path:
    """Return kindl's multi-account config path."""
    override = os.environ.get("KINDL_CONFIG")
    if override:
        return Path(override).expanduser()
    return default_credentials_path()


def legacy_credentials_path() -> Path:
    base = os.environ.get("APPDATA") if os.name == "nt" else os.environ.get("XDG_CONFIG_HOME")
    root = Path(base) if base else Path.home() / ".config"
    return root / "amzn-device-link" / "credentials.json"


@dataclass(slots=True)
class DeviceCredentials:
    serial: str
    device_type: str
    adp_token: str
    private_key: str
    pid: str = ""
    directed_id: str = ""
    marketplace: str = ""
    software_version: str = ""  # per-account SW for X-ADP-SW (the delivery gate)
    account_secrets: list[str] = field(default_factory=list)
    # OAuth refresh token captured from MAP registration's `bearer` tokens. It is
    # the only browserless re-authentication route: no mac_dms -> bearer exchange
    # exists. Old configs simply load the empty default.
    refresh_token: str = ""

    @classmethod
    def load(cls, path: Path) -> DeviceCredentials:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise RuntimeError(f"Not logged in; run `kindl user add` first ({path})") from exc
        if isinstance(value, dict) and "accounts" in value:
            accounts = value.get("accounts")
            if not isinstance(accounts, list) or len(accounts) != 1:
                raise RuntimeError("Choose an account from the multi-account config")
            credentials = accounts[0].get("credentials")
            if not isinstance(credentials, dict):
                raise ValueError(f"Invalid credentials in {path}")
            value = credentials
        if not isinstance(value, dict):
            raise TypeError(f"Invalid credentials in {path}")
        creds_dict = dict(value)
        if "secrets" in creds_dict and "account_secrets" not in creds_dict:
            creds_dict["account_secrets"] = creds_dict.pop("secrets")
        if "account_secrets" in creds_dict:
            sec = creds_dict["account_secrets"]
            if isinstance(sec, str):
                creds_dict["account_secrets"] = [s.strip() for s in sec.split(",") if s.strip()]
            elif isinstance(sec, list):
                creds_dict["account_secrets"] = [str(s) for s in sec if str(s).strip()]
        return cls(**creds_dict)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_private_json(path, asdict(self))


@dataclass(slots=True)
class Account:
    name: str
    credentials: DeviceCredentials

    @classmethod
    def from_dict(cls, value: dict[str, object]) -> Account:
        name = value.get("name")
        credentials = value.get("credentials")
        if not isinstance(name, str) or not name.strip():
            raise ValueError("Account is missing a name")
        if not isinstance(credentials, dict):
            raise TypeError(f"Account {name!r} is missing credentials")
        creds_dict = dict(credentials)
        if "secrets" in creds_dict and "account_secrets" not in creds_dict:
            creds_dict["account_secrets"] = creds_dict.pop("secrets")
        if "account_secrets" in creds_dict:
            sec = creds_dict["account_secrets"]
            if isinstance(sec, str):
                creds_dict["account_secrets"] = [s.strip() for s in sec.split(",") if s.strip()]
            elif isinstance(sec, list):
                creds_dict["account_secrets"] = [str(s) for s in sec if str(s).strip()]
        return cls(name.strip(), DeviceCredentials(**creds_dict))

    def as_dict(self) -> dict[str, object]:
        return {"name": self.name, "credentials": asdict(self.credentials)}


@dataclass(slots=True)
class AccountStore:
    accounts: list[Account] = field(default_factory=list)

    @classmethod
    def load(cls, path: Path) -> AccountStore:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return cls()
        except (json.JSONDecodeError, OSError) as exc:
            raise RuntimeError(f"Could not read config {path}: {exc}") from exc
        if not isinstance(value, dict):
            raise TypeError(f"Invalid config in {path}")
        if "accounts" in value:
            accounts = value["accounts"]
            if not isinstance(accounts, list):
                raise ValueError(f"Invalid accounts list in {path}")
            if not all(isinstance(account, dict) for account in accounts):
                raise ValueError(f"Invalid account in {path}")
            return cls([Account.from_dict(account) for account in accounts])
        # Seamlessly read the original single-account credentials file. It is
        # rewritten in the multi-account format on the next mutation/refresh.
        return cls([Account("default", DeviceCredentials(**value))])

    def save(self, path: Path) -> None:
        _write_private_json(
            path,
            {"version": 1, "accounts": [account.as_dict() for account in self.accounts]},
        )

    def get(self, identifier: str) -> Account | None:
        wanted = identifier.casefold()
        for account in self.accounts:
            credentials = account.credentials
            identifiers = [account.name, credentials.directed_id, credentials.serial]
            if any(value and value.casefold() == wanted for value in identifiers):
                return account
        return None

    def add(self, account: Account, *, replace: bool = False) -> None:
        existing = self.get(account.name)
        if existing:
            if not replace:
                raise ValueError(
                    f"Account {account.name!r} already exists; use --replace to log in again"
                )
            self.accounts[self.accounts.index(existing)] = account
            return
        self.accounts.append(account)

    def remove(self, identifier: str) -> Account | None:
        account = self.get(identifier)
        if account:
            self.accounts.remove(account)
        return account


def _write_private_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    partial = path.with_name(f"{path.name}.tmp")
    try:
        partial.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        partial.replace(path)
        try:
            path.chmod(stat.S_IRUSR | stat.S_IWUSR)
        except OSError:
            pass
    except BaseException:
        partial.unlink(missing_ok=True)
        raise


def new_device_identity() -> tuple[str, str]:
    serial = secrets.token_hex(16).upper()
    # The PID is a persistent per-device DRM identifier. Registration accepts an
    # eight-character value; it must be retained with the device credentials.
    alphabet = "ABCDEFGHIJKLMNPQRSTUVWXYZ123456789"
    pid = "".join(secrets.choice(alphabet) for _ in range(8))
    return serial, pid


def pkce_pair() -> tuple[str, str]:
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(b"=").decode()
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    return verifier, challenge


def device_client_id(serial: str, device_type: str | None = None) -> str:
    # This is an opaque legacy client identifier. Match Kindle for Windows by
    # retaining Python's lowercase hex encoding.
    resolved_type = device_type if device_type is not None else persona_value("device_type")
    return f"{serial}#{resolved_type}".encode().hex()


def _load_any_private_key(pem_or_der: str):
    """Accept PEM or raw-base64 DER (android-family registrations return the
    private key without PEM framing; K4PC-family return framed PEM)."""
    import base64 as _b64

    text = pem_or_der.strip()
    if text.startswith("-----"):
        return serialization.load_pem_private_key(text.encode(), password=None)
    compact = "".join(text.split())
    for candidate in (compact, compact + "=" * (-len(compact) % 4)):
        try:
            der = _b64.b64decode(candidate)
            return serialization.load_der_private_key(der, password=None)
        except Exception:  # noqa: BLE001, S112 - any decode/parse failure means "not this one"
            continue
    framed = (
        "-----BEGIN PRIVATE KEY-----\n"
        + "\n".join(compact[i : i + 64] for i in range(0, len(compact), 64))
        + "\n-----END PRIVATE KEY-----\n"
    )
    return serialization.load_pem_private_key(framed.encode(), password=None)


def adp_sign(method: str, url: str, body: bytes, token: str, private_key_pem: str) -> str:
    """Create the legacy ADP request digest observed in the capture.

    ADP uses a non-DigestInfo PKCS#1 v1.5 block around a raw SHA-256 digest,
    so the usual RSA/SHA256 helper is intentionally not used here.
    """
    timestamp = datetime.now(UTC).astimezone().strftime("%Y-%m-%dT%H:%M:%S")
    parsed = urlsplit(url)
    target = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    canonical = b"\n".join(
        (
            method.upper().encode(),
            target.encode(),
            timestamp.encode(),
            body,
            token.encode(),
        )
    )
    digest = hashlib.sha256(canonical).digest()

    key = _load_any_private_key(private_key_pem)
    numbers = key.private_numbers()
    size = (numbers.public_numbers.n.bit_length() + 7) // 8
    padding_size = size - len(digest) - 3
    if padding_size < 8:
        raise ValueError("RSA key is too short for the ADP signature")
    encoded = b"\x00\x01" + (b"\xff" * padding_size) + b"\x00" + digest
    signature = pow(int.from_bytes(encoded, "big"), numbers.d, numbers.public_numbers.n).to_bytes(
        size, "big"
    )
    return f"{base64.b64encode(signature).decode()}:{timestamp}"
