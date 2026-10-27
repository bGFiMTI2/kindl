from __future__ import annotations

import json
import os
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Self
from urllib.parse import parse_qs, unquote, urlencode, urlsplit, urlunsplit

import httpx

from .auth import (
    APP_NAME,
    DEFAULT_PROFILE,
    HISTORICAL_DESKTOP_VOUCHER_VERSIONS,
    OEM_PLATFORM,
    SOFTWARE_VERSION,
    TABLE_VERSION_TAGS,
    DeviceCredentials,
    adp_sign,
    device_client_id,
    persona_value,
    profile_for_device_type,
)
from .models import LibraryItem

AUTH_URL = "https://www.amazon.com/ap/signin"
TOKEN_URL = "https://api.amazon.com/auth/token"
REGISTER_URL = "https://firs-ta-g7g.amazon.com/FirsProxy/registerDeviceWithToken"
DEVICE_CREDENTIALS_URL = "https://firs-ta-g7g.amazon.com/FirsProxy/getDeviceCredentials"
LIBRARY_URL = "https://todo-ta-g7g.amazon.com/FionaTodoListProxy/syncMetaData"
DELIVERY_ROOT = "https://kindle-digital-delivery.amazon.com"
RESTORE_ACCOUNT_SECRETS_URL = f"{DELIVERY_ROOT}/delivery/restoreAccountSecrets"
TODO_ITEMS_URL = "https://todo-ta-g7g.amazon.com/FionaTodoListProxy/getItems"
#: The default ``supportedVoucherVersions`` list for the *voucher resource
#: query* (:data:`kindl.auth.HISTORICAL_DESKTOP_VOUCHER_VERSIONS`, aliased as
#: :data:`kindl.auth.ANDROID_VOUCHER_VERSIONS`, ending ``V7384,V2746,V3332``
#: from the historical ``KatxopoWindows`` capture), retained for backwards
#: compatibility.
VOUCHER_VERSIONS = ",".join(HISTORICAL_DESKTOP_VOUCHER_VERSIONS)
INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


def _persona_voucher_versions(key: str, *, device_type: str | None = None) -> str:
    """The comma-joined voucher-version list one persona field advertises.

    ``key`` is ``"voucher_versions"`` for the voucher resource query and
    ``"manifest_voucher_versions"`` for the manifest request.

    For the iOS personas (``ios``, ``ios-ipad``), the effective default is
    ``table``: narrowing the list to the 38 base format tags
    (:data:`kindl.auth.TABLE_VERSION_TAGS`) and omitting the newest generations
    (``V1685``, ``V0682``, ``V0456``). Other personas (such as Android and
    Windows) default to ``full`` (sending their captured list unchanged).

    ``KINDL_VOUCHER_VERSIONS`` overrides this default when set: ``table`` narrows
    the advertised list, ``full`` preserves the persona's captured list unchanged,
    and any other non-empty value is treated as an explicit comma-separated version
    tag override (stripping whitespace around each tag and preserving exact case).
    """
    versions = persona_value(key, device_type=device_type)
    if isinstance(versions, str):  # unknown persona key; never the case in practice
        return versions
    raw = os.environ.get("KINDL_VOUCHER_VERSIONS", "").strip()
    mode = raw.lower()
    if mode not in ("", "table", "full"):
        custom = tuple(tag.strip() for tag in raw.split(",") if tag.strip())
        if custom:
            return ",".join(custom)
        mode = ""
    if not mode:
        profile = profile_for_device_type(device_type)
        mode = "table" if profile in ("ios", "ios-ipad") else "full"
    if mode == "table":
        table = frozenset(TABLE_VERSION_TAGS)
        versions = tuple(version for version in versions if version in table)
    return ",".join(versions)


def _raise_amazon_error(response: httpx.Response, operation: str) -> None:
    if response.is_success:
        return
    details: list[str] = []
    try:
        payload = response.json()
    except (json.JSONDecodeError, ValueError):
        payload = None
    if isinstance(payload, dict):
        for key in ("error", "error_description", "message", "request_id"):
            value = payload.get(key)
            if isinstance(value, (str, int, float, bool)) and value:
                details.append(f"{key}={value}")
    suffix = f": {'; '.join(details)}" if details else ""
    raise RuntimeError(f"{operation} failed (HTTP {response.status_code}){suffix}")


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _text(element: ET.Element, *names: str) -> str:
    wanted = {name.lower() for name in names}
    for node in element.iter():
        if _local_name(node.tag).lower() in wanted and node.text:
            return node.text.strip()
    return ""


def _texts(element: ET.Element, name: str) -> tuple[str, ...]:
    return tuple(
        node.text.strip()
        for node in element.iter()
        if _local_name(node.tag).lower() == name.lower() and node.text and node.text.strip()
    )


def parse_library_xml(content: bytes | str) -> list[LibraryItem]:
    root = ET.fromstring(content)
    result: list[LibraryItem] = []
    for meta in (
        node for node in root.iter() if _local_name(node.tag).lower() in {"meta_data", "metadata"}
    ):
        asin = _text(meta, "ASIN", "asin", "content_id")
        title = _text(meta, "title")
        if not asin:
            asin = meta.get("key", "") or meta.get("asin", "")
        if not asin or not title:
            continue
        raw_size = _text(meta, "content_size")
        try:
            size = int(raw_size) if raw_size else None
        except ValueError:
            size = None
        result.append(
            LibraryItem(
                asin=asin,
                title=title,
                authors=_texts(meta, "author"),
                publishers=_texts(meta, "publisher"),
                content_type=_text(meta, "content_type"),
                cde_content_type=_text(meta, "cde_contenttype"),
                purchase_date=_text(meta, "purchase_date"),
                publication_date=_text(meta, "publication_date"),
                content_size=size,
            )
        )
    return result


def delivery_filename(url: str, fallback: str = "resource") -> str:
    """Return a portable filename for an Amazon delivery URL."""
    raw_name = unquote(Path(urlsplit(url).path).name)
    name = INVALID_FILENAME_CHARS.sub("_", raw_name).rstrip(" .")
    if not name:
        name = INVALID_FILENAME_CHARS.sub("_", fallback).rstrip(" .") or "resource"
    if name.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES:
        name = f"_{name}"
    return name


class AmazonDeviceClient:
    def __init__(self, credentials: DeviceCredentials | None = None, *, timeout: float = 60.0):
        self.credentials = credentials
        self.http = httpx.Client(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"},
            transport=httpx.HTTPTransport(retries=2),
        )

    def close(self) -> None:
        self.http.close()

    def _legacy_token_request(self, payload: dict[str, str]) -> httpx.Response:
        # This endpoint is older than the public LWA OAuth endpoint and is
        # sensitive to the desktop client's wire shape. Keep the JSON spacing
        # and headers aligned with the captured Kindle for Windows request.
        request = self.http.build_request(
            "POST",
            TOKEN_URL,
            content=json.dumps(payload).encode(),
            headers={
                "Accept-Encoding": "gzip, deflate",
                "Cache-Control": "no-cache",
                "Connection": "Keep-Alive",
                "Content-Type": "application/json",
                "x-amzn-identity-auth-domain": "api.amazon.com",
            },
        )
        request.headers.pop("Accept", None)
        request.headers.pop("User-Agent", None)
        return self.http.send(request)

    def _legacy_registration_request(self, body: bytes) -> httpx.Response:
        request = self.http.build_request(
            "POST",
            REGISTER_URL,
            content=body,
            headers={
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "en-US",
                "Cache-Control": "no-cache",
                "Connection": "Keep-Alive",
                "Content-Type": "text/xml",
            },
        )
        request.headers.pop("Accept", None)
        request.headers.pop("User-Agent", None)
        return self.http.send(request)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def login_url(serial: str, challenge: str, *, language: str = "en_US") -> str:
        device_type = persona_value("device_type")
        params = {
            "openid.oa2.client_id": f"device:{device_client_id(serial, device_type)}",
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
            "language": language,
        }
        return f"{AUTH_URL}?{urlencode(params)}"

    def register(self, final_url: str, verifier: str, serial: str, pid: str) -> DeviceCredentials:
        code = parse_qs(urlsplit(final_url.strip()).query).get(
            "openid.oa2.authorization_code", [""]
        )[0]
        if not code:
            raise ValueError("The pasted URL does not contain openid.oa2.authorization_code")
        device_type = persona_value("device_type")
        app_name = persona_value("app_name")
        token_response = self._legacy_token_request(
            {
                "app_name": app_name,
                "client_domain": "DeviceLegacy",
                "client_id": device_client_id(serial, device_type),
                "code_algorithm": "SHA-256",
                "code_verifier": verifier,
                "requested_token_type": "access_token",
                "source_token": code,
                "source_token_type": "authorization_code",
            }
        )
        _raise_amazon_error(token_response, "Amazon token exchange")
        access_token = token_response.json()["access_token"]

        software_version = str(persona_value("software_version") or SOFTWARE_VERSION)
        oem_platform = str(persona_value("oem_platform") or OEM_PLATFORM)
        device_name_suffix = str(persona_value("device_name") or "Kindle for Android")
        body = (
            "<request><parameters>"
            f"<deviceName>%FIRST_NAME%%FIRST_NAME_POSSESSIVE_STRING% {device_name_suffix} %DUPE_STRATEGY_2ND%</deviceName>"
            f"<deviceType>{device_type}</deviceType><deviceSerialNumber>{serial}</deviceSerialNumber>"
            f"<pid>{pid}</pid><authToken>{access_token}</authToken><authTokenType>AccessToken</authTokenType>"
            f"<softwareVersion>{software_version}</softwareVersion></parameters>"
            f'<softwareVersions><softwareVersion name="oem_platform" value="{oem_platform}" />'
            '<softwareVersion name="oem_vendor" value="Kindle" />'
            '<softwareVersion name="oem_version" value="" /></softwareVersions></request>'
        )
        import os as _os

        # The modern MAP registration is the default for non-legacy profiles:
        # legacy-XML registrations for the android device family are rejected by
        # the delivery service (see _register_map). Opt back in with
        # KINDL_REG=legacy or by selecting a persona whose default
        # registration_flow is "legacy" (such as KINDL_PROFILE=windows) when
        # KINDL_REG is unset.
        reg_flow = _os.environ.get("KINDL_REG") or str(persona_value("registration_flow") or "")
        if reg_flow != "legacy":
            return self._register_map(access_token, serial, pid)
        response = self._legacy_registration_request(body.encode())
        _raise_amazon_error(response, "Amazon device registration")
        root = ET.fromstring(response.content)
        private_key = _text(root, "device_private_key")
        adp_token = _text(root, "adp_token")
        if not private_key or not adp_token:
            raise RuntimeError("Registration succeeded but did not return ADP device credentials")
        return DeviceCredentials(
            serial=serial,
            pid=pid,
            device_type=str(device_type),
            adp_token=adp_token,
            private_key=private_key,
            directed_id=_text(root, "user_directed_id"),
            marketplace=_text(root, "preferred_marketplace"),
            software_version=software_version,
        )

    def _register_map(self, access_token: str, serial: str, pid: str) -> DeviceCredentials:
        """The modern MAP registration (POST api.amazon.com/auth/register).

        This is what the real Kindle app uses; legacy-XML registrations for
        the android device family are rejected by the delivery service.
        Key findings: auth_data stays EMPTY (the token rides only in the
        Authorization header), domain "Device", a device_name is expected,
        and four token types are requested.
        """
        # Identity comes from the active persona (KINDL_PROFILE) with the per-field
        # KINDL_* overrides read here, at call time. The K4PC software-version
        # default keeps its mapping onto the current Android versionCode.
        sw = persona_value("software_version")
        if sw == "4351":
            sw = "1286477811"
        device_type = persona_value("device_type")
        app_name = persona_value("app_name")
        # An empty persona app_version follows the build number (Android).
        app_version = persona_value("app_version") or sw
        device_model = persona_value("device_model")
        os_version = persona_value("os_version")
        device_name = (
            "%FIRST_NAME%%FIRST_NAME_POSSESSIVE_STRING%"
            f"%DUPE_STRATEGY_1ST%{persona_value('device_name')}"
        )
        body = {
            "requested_token_type": [
                "bearer",
                "mac_dms",
                "website_cookies",
                "store_authentication_cookie",
            ],
            "cookies": {"website_cookies": [], "domain": ".amazon.com"},
            "registration_data": {
                "domain": "Device",
                "device_type": device_type,
                "device_serial": serial,  # must match the OAuth client_id's serial
                "device_name": device_name,
                "app_name": app_name,
                "app_version": app_version,
                "device_model": device_model,
                "os_version": os_version,
                "software_version": sw,
            },
            "auth_data": {},  # EMPTY — token only in the Authorization header!
            "requested_extensions": ["device_info", "customer_info"],
        }
        response = self.http.post(
            "https://api.amazon.com/auth/register",
            json=body,
            headers={
                "Content-Type": "application/json",
                "x-amzn-identity-auth-domain": "api.amazon.com",
                "Authorization": f"Bearer {access_token}",
                "Accept-Language": "en-US",
                "Accept": "application/json",
            },
        )
        response.raise_for_status()
        succ = response.json()["response"]["success"]
        tokens = succ.get("tokens", {})
        mac = tokens.get("mac_dms", {})
        adp_token = mac.get("adp_token")
        private_key = mac.get("device_private_key")
        if not adp_token or not private_key:
            raise RuntimeError(
                f"MAP registration returned no mac_dms credentials: {list(tokens.keys())}"
            )
        # The registration also mints bearer tokens. Its refresh_token is the
        # only browserless route back to an access token, so persist it (never
        # log it). It may be absent on older/limited responses.
        bearer = tokens.get("bearer", {})
        refresh_token = bearer.get("refresh_token", "") if isinstance(bearer, dict) else ""
        ext = succ.get("extensions", {})
        customer_info = ext.get("customer_info", {})
        return DeviceCredentials(
            serial=serial,
            pid=pid,
            device_type=device_type,
            adp_token=adp_token,
            private_key=private_key,
            directed_id=succ.get("customer_id", ""),
            marketplace=customer_info.get("preferred_marketplace", ""),
            software_version=sw,
            refresh_token=refresh_token if isinstance(refresh_token, str) else "",
        )

    def register_persona(self, access_token: str, serial: str, pid: str) -> DeviceCredentials:
        """Register an additional device persona with an existing access token.

        Same MAP body and response parsing as the initial registration; only the
        device identity (``serial``/``pid``) has to be fresh. Obtain the access
        token through :meth:`refresh_bearer` to register without a browser.
        """
        return self._register_map(access_token, serial, pid)

    def refresh_bearer(self, refresh_token: str) -> str:
        """Exchange a stored OAuth refresh token for a fresh access token.

        There is no mac_dms -> bearer exchange (the service rejects it), so this
        refresh grant is the only browserless way to re-authorize. The caller
        owns the returned access token; it is not persisted here.
        """
        response = self.http.post(
            TOKEN_URL,
            json={
                "app_name": APP_NAME,
                "client_domain": "DeviceLegacy",
                "source_token_type": "refresh_token",
                "source_token": refresh_token,
                "requested_token_type": "access_token",
            },
            headers={
                "Content-Type": "application/json",
                "x-amzn-identity-auth-domain": "api.amazon.com",
                "Accept": "application/json",
            },
        )
        _raise_amazon_error(response, "Amazon bearer refresh")
        access_token = response.json().get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise RuntimeError("Amazon bearer refresh returned no access_token")
        return access_token

    def _signed_headers(
        self,
        method: str,
        url: str,
        body: bytes = b"",
        *,
        reason: str = "ArchivedItems",
        correlation_id: str | None = None,
        device_metadata: bool = False,
        include_app_id: bool = False,
    ) -> dict[str, str]:
        if not self.credentials:
            raise RuntimeError("Device credentials are required")
        headers = {
            "Accept-Language": "en-GB",
            "X-ADP-Authentication-Token": self.credentials.adp_token,
            "X-ADP-Request-Digest": adp_sign(
                method,
                url,
                body,
                self.credentials.adp_token,
                self.credentials.private_key,
            ),
            "X-ADP-SW": getattr(self.credentials, "software_version", "") or SOFTWARE_VERSION,
            "X-ADP-APP-SW": getattr(self.credentials, "software_version", "") or SOFTWARE_VERSION,
            "X-ADP-Reason": reason,
        }
        if include_app_id:
            # Only personas that define an app id send the header: the Android
            # family sends "com.amazon.kindle", the iOS client sends none at all
            # (absent, never empty). Non-delivery requests stay untouched.
            app_id = persona_value(
                "adp_app_id",
                device_type=getattr(self.credentials, "device_type", None),
            )
            if app_id:
                headers["X-ADP-App-Id"] = str(app_id)
        if correlation_id:
            now = datetime.now(UTC).astimezone()
            headers.update(
                {
                    "Date": now.strftime("%d %b %Y %H:%M:%S ") + f"{now.microsecond // 1000:03d}",
                    "X-ADP-AttemptCount": "1",
                    "X-ADP-CorrelationId": correlation_id,
                    "X-ADP-LTO": "120",
                    "X-ADP-Transport": "WiFi",
                }
            )
            if device_metadata:
                headers["X-ADP-Device-Metadata"] = "sniffTestFailed:False"
        return headers

    def library(self, *, limit: int = 1000) -> list[LibraryItem]:
        if not 1 <= limit <= 1000:
            raise ValueError("limit must be between 1 and 1000")
        url = f"{LIBRARY_URL}?{urlencode({'item_count': limit})}"
        response = self.http.get(
            url, headers=self._signed_headers("GET", url, reason="Registration")
        )
        response.raise_for_status()
        return parse_library_xml(response.content)

    def refresh_device_credentials(self) -> DeviceCredentials:
        if not self.credentials:
            raise RuntimeError("Device credentials are required")
        url = f"{DEVICE_CREDENTIALS_URL}?{urlencode({'reason': 'TodoItem.GET.NAMS'})}"
        headers = self._signed_headers("GET", url)
        headers.pop("X-ADP-SW", None)
        headers.pop("X-ADP-Reason", None)
        headers.update(
            {
                "Accept-Encoding": "gzip, deflate",
                "Accept-Language": "en-GB",
                "Connection": "Keep-Alive",
                "User-Agent": "Mozilla/5.0",
            }
        )
        request = self.http.build_request("GET", url, headers=headers)
        request.headers.pop("Accept", None)
        response = self.http.send(request)
        _raise_amazon_error(response, "Amazon device credential refresh")
        root = ET.fromstring(response.content)
        private_key = _text(root, "device_private_key")
        adp_token = _text(root, "adp_token")
        if not private_key or not adp_token:
            raise RuntimeError("Device credential refresh succeeded without returning credentials")
        self.credentials.private_key = private_key
        self.credentials.adp_token = adp_token
        self.credentials.directed_id = (
            _text(root, "user_directed_id") or self.credentials.directed_id
        )
        return self.credentials

    def restore_account_secrets(self) -> list[str]:
        """Restore account secrets used by empty-recipient (Purchase-class) vouchers.

        Triggers account secret restoration via POST /delivery/restoreAccountSecrets,
        then extracts secrets either from an immediate JSON response or from the
        ACSR TodoItem in /FionaTodoListProxy/getItems. Discovered secrets are cached in
        self.credentials.account_secrets and returned.
        """
        if not self.credentials:
            raise RuntimeError("Device credentials are required")
        correlation_id = str(uuid.uuid4())
        headers = self._signed_headers(
            "POST",
            RESTORE_ACCOUNT_SECRETS_URL,
            b"",
            correlation_id=correlation_id,
            device_metadata=True,
            include_app_id=True,
        )
        headers["Accept"] = "application/json"

        response = self.http.post(RESTORE_ACCOUNT_SECRETS_URL, headers=headers, content=b"")
        profile = profile_for_device_type(getattr(self.credentials, "device_type", None))
        trigger_optional = profile != DEFAULT_PROFILE or response.status_code == 403
        if not response.is_success and not trigger_optional:
            _raise_amazon_error(response, "Amazon restore account secrets")

        discovered: list[str] = []

        if response.is_success and response.content:
            try:
                payload = response.json()
                if isinstance(payload, dict):
                    for key in ("accountSecrets", "account_secrets", "secrets", "tokens"):
                        value = payload.get(key)
                        if isinstance(value, list):
                            discovered.extend(str(x) for x in value if x)
                        elif isinstance(value, str) and value.strip():
                            discovered.extend(s.strip() for s in value.split(",") if s.strip())
            except (json.JSONDecodeError, ValueError):
                pass

        if not discovered:
            todo_headers = self._signed_headers("GET", TODO_ITEMS_URL, reason="Registration")
            todo_response = self.http.get(TODO_ITEMS_URL, headers=todo_headers)
            if not response.is_success and not todo_response.is_success:
                _raise_amazon_error(response, "Amazon restore account secrets")
            if todo_response.is_success and todo_response.content:
                try:
                    root = ET.fromstring(todo_response.content)
                    for item in root.iter():
                        if _local_name(item.tag).lower() != "item":
                            continue
                        item_type = (item.attrib.get("type") or "").upper()
                        if item_type in ("ACSR", "ACCOUNT_SECRETS"):
                            val_node = item.find("value")
                            if val_node is None:
                                for child in item:
                                    if _local_name(child.tag).lower() == "value":
                                        val_node = child
                                        break
                            raw_val = (
                                val_node.text.strip()
                                if val_node is not None and val_node.text
                                else ""
                            )
                            if raw_val:
                                for part in raw_val.split(","):
                                    cleaned = part.strip()
                                    if cleaned:
                                        discovered.append(cleaned)
                except (ET.ParseError, ValueError):
                    pass

        existing = getattr(self.credentials, "account_secrets", []) or []
        seen = set()
        merged = []
        for s in (*existing, *discovered):
            if s and s not in seen:
                seen.add(s)
                merged.append(s)
        self.credentials.account_secrets = merged
        return list(self.credentials.account_secrets)

    def manifest(self, asin: str) -> tuple[dict[str, Any], str]:
        import os as _os
        import time as _time
        from urllib.parse import quote

        if not re.fullmatch(r"[A-Za-z0-9._-]+", asin):
            raise ValueError("Invalid ASIN")
        if _os.environ.get("KINDL_NO_VV"):
            url = f"{DELIVERY_ROOT}/delivery/manifest/kindle.ebook/{asin}"
        else:
            _vers = _persona_voucher_versions(
                "manifest_voucher_versions",
                device_type=getattr(self.credentials, "device_type", None),
            )
            url = f"{DELIVERY_ROOT}/delivery/manifest/kindle.ebook/{asin}?supportedVoucherVersions={quote(_vers, safe=',')}"
        correlation_id = str(uuid.uuid4())
        headers = self._signed_headers(
            "GET", url, correlation_id=correlation_id, device_metadata=True, include_app_id=True
        )
        headers.update(
            {
                "Accept": "application/json",
                "X-Amzn-Accept-Type": "application/x.amzn.digital.deliverymanifest@1.0",
            }
        )
        headers.setdefault(
            "X-Amzn-RequestId", f"{self.credentials.serial}{int(_time.time() * 1000)}"
        )
        response = self.http.get(url, headers=headers)
        response.raise_for_status()
        return response.json(), correlation_id

    def download(
        self,
        asin: str,
        output_dir: Path,
        *,
        include_optional: bool = True,
        destination: Path | None = None,
    ) -> list[Path]:
        manifest, correlation_id = self.manifest(asin)
        destination = destination or (output_dir / asin)
        destination.mkdir(parents=True, exist_ok=True)
        manifest_path = destination / "manifest.json"
        manifest_partial = manifest_path.with_name(f"{manifest_path.name}.part")
        manifest_partial.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        manifest_partial.replace(manifest_path)
        downloaded = [manifest_path]

        for resource in manifest.get("resources", []):
            if not include_optional and resource.get("requirement") not in {
                "Required",
                "Preferred",
            }:
                continue
            endpoint = resource.get("endpoint") or {}
            url = endpoint.get("url")
            if not url or resource.get("type") == "KINDLE_USER_ANOT":
                continue
            if resource.get("type") == "DRM_VOUCHER":
                parts = urlsplit(url)
                query = parse_qs(parts.query, keep_blank_values=True)
                query["supportedVoucherVersions"] = [
                    _persona_voucher_versions(
                        "voucher_versions",
                        device_type=getattr(self.credentials, "device_type", None),
                    )
                ]
                url = urlunsplit(
                    (
                        parts.scheme,
                        parts.netloc,
                        parts.path,
                        urlencode(query, doseq=True),
                        parts.fragment,
                    )
                )
            path_name = delivery_filename(url, fallback=str(resource.get("id", "resource")))
            target = destination / path_name
            partial = target.with_name(f"{target.name}.part")
            headers = self._signed_headers("GET", url, correlation_id=correlation_id)
            if resource.get("type") == "DRM_VOUCHER":
                headers["Accept"] = "application/x-com.amazon.drm.Voucher@1.0"
            try:
                with self.http.stream("GET", url, headers=headers) as response:
                    if not response.is_success:
                        response.read()
                        _raise_amazon_error(response, "Amazon resource download")
                    with partial.open("wb") as handle:
                        for chunk in response.iter_bytes():
                            handle.write(chunk)
                partial.replace(target)
            except BaseException:
                partial.unlink(missing_ok=True)
                raise
            downloaded.append(target)
        return downloaded
