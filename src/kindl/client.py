from __future__ import annotations

import json
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
    DEVICE_TYPE,
    SOFTWARE_VERSION,
    DeviceCredentials,
    adp_sign,
    device_client_id,
)
from .models import LibraryItem

AUTH_URL = "https://www.amazon.com/ap/signin"
TOKEN_URL = "https://api.amazon.com/auth/token"
REGISTER_URL = "https://firs-ta-g7g.amazon.com/FirsProxy/registerDeviceWithToken"
DEVICE_CREDENTIALS_URL = "https://firs-ta-g7g.amazon.com/FirsProxy/getDeviceCredentials"
LIBRARY_URL = "https://todo-ta-g7g.amazon.com/FionaTodoListProxy/syncMetaData"
DELIVERY_ROOT = "https://kindle-digital-delivery.amazon.com"
VOUCHER_VERSIONS = ",".join(
    [
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
        "V7384",
        "V2746",
        "V3332",
    ]
)
INVALID_FILENAME_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}


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
        if _local_name(node.tag).lower() == name.lower()
        and node.text
        and node.text.strip()
    )


def parse_library_xml(content: bytes | str) -> list[LibraryItem]:
    root = ET.fromstring(content)
    result: list[LibraryItem] = []
    for meta in (
        node
        for node in root.iter()
        if _local_name(node.tag).lower() in {"meta_data", "metadata"}
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
    def __init__(
        self, credentials: DeviceCredentials | None = None, *, timeout: float = 60.0
    ):
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
        params = {
            "openid.oa2.client_id": f"device:{device_client_id(serial)}",
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

    def register(
        self, final_url: str, verifier: str, serial: str, pid: str
    ) -> DeviceCredentials:
        code = parse_qs(urlsplit(final_url.strip()).query).get(
            "openid.oa2.authorization_code", [""]
        )[0]
        if not code:
            raise ValueError(
                "The pasted URL does not contain openid.oa2.authorization_code"
            )
        token_response = self._legacy_token_request(
            {
                "app_name": APP_NAME,
                "client_domain": "DeviceLegacy",
                "client_id": device_client_id(serial),
                "code_algorithm": "SHA-256",
                "code_verifier": verifier,
                "requested_token_type": "access_token",
                "source_token": code,
                "source_token_type": "authorization_code",
            }
        )
        _raise_amazon_error(token_response, "Amazon token exchange")
        access_token = token_response.json()["access_token"]

        body = (
            "<request><parameters>"
            "<deviceName>%FIRST_NAME%%FIRST_NAME_POSSESSIVE_STRING% Kindle for Windows %DUPE_STRATEGY_2ND%</deviceName>"
            f"<deviceType>{DEVICE_TYPE}</deviceType><deviceSerialNumber>{serial}</deviceSerialNumber>"
            f"<pid>{pid}</pid><authToken>{access_token}</authToken><authTokenType>AccessToken</authTokenType>"
            f"<softwareVersion>{SOFTWARE_VERSION}</softwareVersion></parameters>"
            '<softwareVersions><softwareVersion name="oem_platform" value="Mazama" />'
            '<softwareVersion name="oem_vendor" value="Kindle" />'
            '<softwareVersion name="oem_version" value="" /></softwareVersions></request>'
        )
        response = self._legacy_registration_request(body.encode())
        _raise_amazon_error(response, "Amazon device registration")
        root = ET.fromstring(response.content)
        private_key = _text(root, "device_private_key")
        adp_token = _text(root, "adp_token")
        if not private_key or not adp_token:
            raise RuntimeError(
                "Registration succeeded but did not return ADP device credentials"
            )
        return DeviceCredentials(
            serial=serial,
            pid=pid,
            device_type=DEVICE_TYPE,
            adp_token=adp_token,
            private_key=private_key,
            directed_id=_text(root, "user_directed_id"),
            marketplace=_text(root, "preferred_marketplace"),
        )

    def _signed_headers(
        self,
        method: str,
        url: str,
        body: bytes = b"",
        *,
        reason: str = "ArchivedItems",
        correlation_id: str | None = None,
        device_metadata: bool = False,
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
            "X-ADP-SW": SOFTWARE_VERSION,
            "X-ADP-Reason": reason,
        }
        if correlation_id:
            now = datetime.now(UTC).astimezone()
            headers.update(
                {
                    "Date": now.strftime("%d %b %Y %H:%M:%S ")
                    + f"{now.microsecond // 1000:03d}",
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
            raise RuntimeError(
                "Device credential refresh succeeded without returning credentials"
            )
        self.credentials.private_key = private_key
        self.credentials.adp_token = adp_token
        self.credentials.directed_id = (
            _text(root, "user_directed_id") or self.credentials.directed_id
        )
        return self.credentials

    def manifest(self, asin: str) -> tuple[dict[str, Any], str]:
        if not re.fullmatch(r"[A-Za-z0-9._-]+", asin):
            raise ValueError("Invalid ASIN")
        url = f"{DELIVERY_ROOT}/delivery/manifest/kindle.ebook/{asin}"
        correlation_id = str(uuid.uuid4())
        headers = self._signed_headers(
            "GET", url, correlation_id=correlation_id, device_metadata=True
        )
        headers.update(
            {
                "Accept": "application/json",
                "X-Amzn-Accept-Type": "application/x.amzn.digital.deliverymanifest@1.0",
            }
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
        manifest_partial.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
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
                query["supportedVoucherVersions"] = [VOUCHER_VERSIONS]
                url = urlunsplit(
                    (
                        parts.scheme,
                        parts.netloc,
                        parts.path,
                        urlencode(query, doseq=True),
                        parts.fragment,
                    )
                )
            path_name = delivery_filename(
                url, fallback=str(resource.get("id", "resource"))
            )
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
