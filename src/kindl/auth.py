from __future__ import annotations

import base64
import hashlib
import json
import os
import secrets
import stat
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.hazmat.primitives import serialization

DEVICE_TYPE = "A1UOUY6O7B48AR"
SOFTWARE_VERSION = "4351"
APP_NAME = "KatxopoWindows"


def default_credentials_path() -> Path:
    base = (
        os.environ.get("APPDATA")
        if os.name == "nt"
        else os.environ.get("XDG_CONFIG_HOME")
    )
    root = Path(base) if base else Path.home() / ".config"
    return root / "kindl" / "config.json"


def default_config_path() -> Path:
    """Return kindl's multi-account config path."""
    return default_credentials_path()


def legacy_credentials_path() -> Path:
    base = (
        os.environ.get("APPDATA")
        if os.name == "nt"
        else os.environ.get("XDG_CONFIG_HOME")
    )
    root = Path(base) if base else Path.home() / ".config"
    return root / "amzn-device-link" / "credentials.json"


@dataclass(slots=True)
class DeviceCredentials:
    serial: str
    pid: str
    device_type: str
    adp_token: str
    private_key: str
    directed_id: str = ""
    marketplace: str = ""

    @classmethod
    def load(cls, path: Path) -> DeviceCredentials:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise RuntimeError(
                f"Not logged in; run `kindl user add` first ({path})"
            ) from exc
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
        return cls(**value)

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
        return cls(name.strip(), DeviceCredentials(**credentials))

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
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
        .rstrip(b"=")
        .decode()
    )
    return verifier, challenge


def device_client_id(serial: str, device_type: str = DEVICE_TYPE) -> str:
    # This is an opaque legacy client identifier. Match Kindle for Windows by
    # retaining Python's lowercase hex encoding.
    return f"{serial}#{device_type}".encode().hex()


def adp_sign(
    method: str, url: str, body: bytes, token: str, private_key_pem: str
) -> str:
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

    key = serialization.load_pem_private_key(private_key_pem.encode(), password=None)
    numbers = key.private_numbers()
    size = (numbers.public_numbers.n.bit_length() + 7) // 8
    padding_size = size - len(digest) - 3
    if padding_size < 8:
        raise ValueError("RSA key is too short for the ADP signature")
    encoded = b"\x00\x01" + (b"\xff" * padding_size) + b"\x00" + digest
    signature = pow(
        int.from_bytes(encoded, "big"), numbers.d, numbers.public_numbers.n
    ).to_bytes(size, "big")
    return f"{base64.b64encode(signature).decode()}:{timestamp}"
