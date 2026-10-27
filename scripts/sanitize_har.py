"""Sanitize a HAR while retaining non-sensitive protocol evidence.

The sanitizer is intentionally allow-structural rather than allow-content:
JSON/XML/form shapes and harmless protocol constants survive, while secrets,
account/library identifiers, personal metadata, signed URLs, browser documents,
and downloaded content are pseudonymized or omitted.
"""

from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import re
import tempfile
from collections import defaultdict
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit
from xml.etree import ElementTree as ET

POLICY_VERSION = 2
OPAQUE = "__REDACTED_OPAQUE_CONTENT__"

EMAIL_RE = re.compile(r"(?i)\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b")
PEM_RE = re.compile(r"-----BEGIN [^-]+-----.*?-----END [^-]+-----", re.DOTALL)
ASIN_RE = re.compile(r"(?i)\bB[0-9A-Z]{9}\b")
UUID_RE = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
ACCOUNT_RE = re.compile(r"(?i)\bamzn1\.account\.[A-Z0-9]+\b")
VOUCHER_RE = re.compile(r"(?i)\bamzn1\.drm-voucher\.[^/?\s]+")
RESOURCE_RE = re.compile(r"(?i)(?<=CR!)[A-Z0-9]{20,}")
CONTENT_NUMBER_RE = re.compile(r"(?i)(?<=DTP:)[0-9]{10,}")
MAC_RE = re.compile(
    r"(?i)(?<![0-9A-Fa-f:-])(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}(?![0-9A-Fa-f:-])"
)
COMPOUND_SERIAL_RE = re.compile(r"(?i)\b[0-9A-Za-z]{16,32}#[A-Za-z0-9_.-]+(?:#[A-Za-z0-9_.-]+)?\b")
HEX32_SERIAL_RE = re.compile(r"(?i)\b[0-9A-Fa-f]{32}\b")
LONG_OPAQUE_RE = re.compile(r"^[A-Za-z0-9_+=/!:$.-]{48,}$")

SECRET_HEADERS = {
    "authorization",
    "bugsnag-api-key",
    "cookie",
    "if-range",
    "set-cookie",
    "x-adp-authentication-token",
    "x-adp-correlationid",
    "x-adp-request-digest",
    "x-adp-signature",
    "x-adp-token",
    "x-amz-cf-id",
    "x-amz-ir-id",
    "x-amz-rid",
    "x-amzn-flow-closure-id",
    "x-amzn-requestid",
    "x-client-id",
    "x-request-id",
}
URL_HEADERS = {"location", "origin", "referer"}

SAFE_SEMANTIC_FIELDS = {
    "authtokentype",
    "requested_token_type",
    "source_token_type",
    "token_type",
    "supportedvoucherversions",
}
SECRET_FIELD_NAMES = {
    "anti-csrftoken-a2z",
    "appactiontoken",
    "client_id",
    "code_verifier",
    "deviceid",
    "email",
    "encryptedpasswordexpected",
    "encryptedpwd",
    "guid",
    "hardwareid",
    "id",
    "key",
    "mac",
    "macaddress",
    "metadata1",
    "password",
    "pid",
    "prevrid",
    "radioid",
    "serial",
    "serialnumber",
    "source_token",
    "wifimac",
    "workflowstate",
}
SECRET_FIELD_PARTS = {
    "account",
    "annotationid",
    "apikey",
    "authorizationcode",
    "authorizationmetadata",
    "clientid",
    "codechallenge",
    "cookie",
    "correlationid",
    "credential",
    "customer",
    "deviceid",
    "directedid",
    "email",
    "hardwareid",
    "mac",
    "macaddress",
    "nonce",
    "password",
    "privatekey",
    "radioid",
    "requestid",
    "secureSessionToken".casefold(),
    "sessionid",
    "signature",
    "sig",
    "token",
    "userid",
    "userkey",
    "wifimac",
}
PRIVATE_XML_FIELDS = {
    "alias",
    "asin",
    "author",
    "content_size",
    "device_private_key",
    "deviceid",
    "deviceSerialNumber".casefold(),
    "given_name",
    "guid",
    "hardwareid",
    "id",
    "kindle_email_address",
    "mac",
    "macaddress",
    "name",
    "pid",
    "publication_date",
    "publisher",
    "purchase_date",
    "radioid",
    "store_authentication_cookie",
    "title",
    "user_device_name",
    "user_directed_id",
    "value",
    "wifimac",
}
SENSITIVE_QUERY_FIELDS = {
    "anti-csrftoken-a2z",
    "deviceid",
    "directed-id",
    "guid",
    "hardwareid",
    "key",
    "mac",
    "macaddress",
    "openid.claimed_id",
    "openid.identity",
    "openid.oa2.authorization_code",
    "openid.oa2.client_id",
    "openid.oa2.code_challenge",
    "openid.pape.auth_time",
    "openid.response_nonce",
    "openid.sig",
    "radioid",
    "serial",
    "session-id",
    "wifimac",
    "x-adp-correlationid",
    "x-amz-credential",
    "x-amz-date",
    "x-amz-signature",
}


class Sanitizer:
    def __init__(self) -> None:
        self._values: dict[str, dict[str, str]] = defaultdict(dict)

    def marker(self, category: str, value: str = "") -> str:
        category = re.sub(r"[^A-Z0-9]+", "_", category.upper()).strip("_")
        if not value:
            return f"__REDACTED_{category}__"
        known = self._values[category]
        if value not in known:
            known[value] = f"__REDACTED_{category}_{len(known) + 1}__"
        return known[value]

    def sanitize_string(self, value: str, *, field: str = "value") -> str:
        if value.startswith(("http://", "https://")):
            return self.sanitize_url(value)
        value = PEM_RE.sub(lambda match: self.marker("PRIVATE_KEY", match.group()), value)
        value = EMAIL_RE.sub(lambda match: self.marker("EMAIL", match.group()), value)
        value = ACCOUNT_RE.sub(lambda match: self.marker("ACCOUNT", match.group()), value)
        value = VOUCHER_RE.sub(lambda match: self.marker("VOUCHER", match.group()), value)
        value = ASIN_RE.sub(lambda match: self.marker("ASIN", match.group()), value)
        value = UUID_RE.sub(lambda match: self.marker("UUID", match.group()), value)
        value = RESOURCE_RE.sub(lambda match: self.marker("RESOURCE", match.group()), value)
        value = CONTENT_NUMBER_RE.sub(lambda match: self.marker("CONTENT_ID", match.group()), value)
        value = MAC_RE.sub(lambda match: self.marker("MAC", match.group()), value)

        def _replace_compound(match: re.Match[str]) -> str:
            val = match.group()
            serial_part = val.split("#")[0]
            self.marker("SERIAL", serial_part)
            return self.marker("SERIAL", val)

        value = COMPOUND_SERIAL_RE.sub(_replace_compound, value)
        value = HEX32_SERIAL_RE.sub(lambda match: self.marker("SERIAL", match.group()), value)
        if LONG_OPAQUE_RE.fullmatch(value):
            return self.marker(field, value)
        return value

    def field_is_sensitive(self, name: str) -> bool:
        folded = name.casefold().replace("-", "").replace("_", "").replace(".", "")
        if name.casefold() in SAFE_SEMANTIC_FIELDS or folded in SAFE_SEMANTIC_FIELDS:
            return False
        if name.casefold() in SECRET_FIELD_NAMES or folded in SECRET_FIELD_NAMES:
            return True
        return any(part in folded for part in SECRET_FIELD_PARTS)

    def sanitize_value(self, value: Any, *, field: str = "value") -> Any:
        if self.field_is_sensitive(field):
            return self.marker(field, str(value))
        if isinstance(value, dict):
            return {key: self.sanitize_value(item, field=key) for key, item in value.items()}
        if isinstance(value, list):
            return [self.sanitize_value(item, field=field) for item in value]
        if isinstance(value, str):
            return self.sanitize_string(value, field=field)
        return value

    def sanitize_url(self, value: str) -> str:
        try:
            parsed = urlsplit(value)
        except ValueError:
            return self.marker("URL", value)
        if not parsed.scheme or not parsed.netloc:
            return self.marker("URL", value)
        path = self.sanitize_string(parsed.path, field="path")
        # Browser telemetry encodes account/session IDs throughout a single path
        # segment and is not part of the client protocol being documented.
        if parsed.netloc.startswith(("fls-", "unagi")):
            path = "/__REDACTED_TELEMETRY_PATH__"
        query_items = []
        for key, item in parse_qsl(parsed.query, keep_blank_values=True):
            if key.casefold() in SENSITIVE_QUERY_FIELDS or self.field_is_sensitive(key):
                item = self.marker(key, item)
            else:
                item = self.sanitize_string(item, field=key)
            query_items.append((key, item))
        return urlunsplit(
            (parsed.scheme, parsed.netloc, path, urlencode(query_items, doseq=True), "")
        )

    def sanitize_headers(self, headers: list[dict[str, Any]]) -> None:
        for header in headers:
            name = str(header.get("name", ""))
            value = str(header.get("value", ""))
            folded = name.casefold()
            if folded in SECRET_HEADERS or self.field_is_sensitive(name):
                header["value"] = self.marker(name, value)
            elif folded in URL_HEADERS:
                header["value"] = self.sanitize_url(value)
            else:
                header["value"] = self.sanitize_string(value, field=name)

    def sanitize_parameters(self, parameters: list[dict[str, Any]]) -> None:
        for parameter in parameters:
            name = str(parameter.get("name", ""))
            value = str(parameter.get("value", ""))
            if name.casefold() in SENSITIVE_QUERY_FIELDS or self.field_is_sensitive(name):
                parameter["value"] = self.marker(name, value)
            else:
                parameter["value"] = self.sanitize_string(value, field=name)

    def sanitize_xml(self, text: str) -> str:
        root = ET.fromstring(text)
        for node in root.iter():
            tag = node.tag.rsplit("}", 1)[-1]
            if node.text and node.text.strip():
                if tag.casefold() in PRIVATE_XML_FIELDS or self.field_is_sensitive(tag):
                    node.text = self.marker(tag, node.text.strip())
                else:
                    node.text = self.sanitize_string(node.text, field=tag)
            for key, item in node.attrib.items():
                if self.field_is_sensitive(key):
                    node.attrib[key] = self.marker(key, item)
                else:
                    node.attrib[key] = self.sanitize_string(item, field=key)
        return ET.tostring(root, encoding="unicode")

    def sanitize_form(self, text: str) -> str:
        values = []
        for key, value in parse_qsl(text, keep_blank_values=True):
            if key.casefold() in SENSITIVE_QUERY_FIELDS or self.field_is_sensitive(key):
                value = self.marker(key, value)
            else:
                value = self.sanitize_string(value, field=key)
            values.append((key, value))
        return urlencode(values)

    def sanitize_post_data(self, post_data: dict[str, Any]) -> None:
        self.sanitize_parameters(post_data.get("params", []))
        text = post_data.get("text")
        if not isinstance(text, str):
            return
        mime = str(post_data.get("mimeType", "")).casefold()
        try:
            if "json" in mime:
                post_data["text"] = json.dumps(
                    self.sanitize_value(json.loads(text)), separators=(",", ":")
                )
            elif "xml" in mime:
                post_data["text"] = self.sanitize_xml(text)
            elif "form" in mime:
                post_data["text"] = self.sanitize_form(text)
            elif text.strip() in {"", "{}", "[]"}:
                post_data["text"] = text
            else:
                post_data["text"] = OPAQUE
                post_data["_sanitization"] = "opaque request body omitted"
        except (ET.ParseError, json.JSONDecodeError, UnicodeError, ValueError):
            post_data["text"] = OPAQUE
            post_data["_sanitization"] = "unparseable request body omitted"

    def sanitize_content(self, content: dict[str, Any]) -> None:
        text = content.get("text")
        if not isinstance(text, str):
            return
        was_base64 = content.get("encoding") == "base64"
        if was_base64:
            try:
                text = base64.b64decode(text).decode("utf-8")
            except (UnicodeDecodeError, ValueError):
                text = ""
        mime = str(content.get("mimeType", "")).casefold()
        try:
            if "json" in mime:
                sanitized = json.dumps(self.sanitize_value(json.loads(text)), separators=(",", ":"))
            elif "xml" in mime:
                sanitized = self.sanitize_xml(text)
            elif mime.startswith("text/plain") and text.strip() in {"", "{}", "[]"}:
                sanitized = text
            else:
                sanitized = OPAQUE
                content["_sanitization"] = "browser, binary, or protected body omitted"
        except (ET.ParseError, json.JSONDecodeError, UnicodeError, ValueError):
            sanitized = OPAQUE
            content["_sanitization"] = "unparseable response body omitted"
        content["text"] = sanitized
        content.pop("encoding", None)

    def redact_known_values(self, value: Any) -> Any:
        """Remove secrets repeated later in otherwise harmless fields."""
        if isinstance(value, dict):
            return {key: self.redact_known_values(item) for key, item in value.items()}
        if isinstance(value, list):
            return [self.redact_known_values(item) for item in value]
        if not isinstance(value, str):
            return value
        all_known = [
            (orig, marker)
            for known in self._values.values()
            for orig, marker in known.items()
            if len(orig) >= 8
        ]
        all_known.sort(key=lambda pair: len(pair[0]), reverse=True)
        for original, marker in all_known:
            if original in value:
                value = value.replace(original, marker)
        return value

    def sanitize(self, document: dict[str, Any]) -> dict[str, Any]:
        result = copy.deepcopy(document)
        log = result.setdefault("log", {})
        log["_sanitization"] = {
            "policy": "kindl-har-sanitizer",
            "version": POLICY_VERSION,
            "principle": "retain protocol structure; remove secrets and personal/content data",
        }
        for page in log.get("pages", []):
            if "title" in page:
                page["title"] = self.sanitize_string(str(page["title"]), field="page")

        for entry in log.get("entries", []):
            request = entry.get("request", {})
            if "url" in request:
                request["url"] = self.sanitize_url(str(request["url"]))
            self.sanitize_headers(request.get("headers", []))
            self.sanitize_parameters(request.get("queryString", []))
            for cookie in request.get("cookies", []):
                cookie["value"] = self.marker("COOKIE", str(cookie.get("value", "")))
            post_data = request.get("postData")
            if isinstance(post_data, dict):
                self.sanitize_post_data(post_data)

            response = entry.get("response", {})
            self.sanitize_headers(response.get("headers", []))
            for cookie in response.get("cookies", []):
                cookie["value"] = self.marker("COOKIE", str(cookie.get("value", "")))
            content = response.get("content")
            if isinstance(content, dict):
                self.sanitize_content(content)
            if response.get("redirectURL"):
                response["redirectURL"] = self.sanitize_url(str(response["redirectURL"]))

            if "_initiator" in entry:
                entry["_initiator"] = self.sanitize_value(entry["_initiator"], field="initiator")
            for message in entry.get("_webSocketMessages", []):
                if "data" in message:
                    message["data"] = OPAQUE
        return self.redact_known_values(result)


def sanitize_har(document: dict[str, Any]) -> dict[str, Any]:
    return Sanitizer().sanitize(document)


def write_atomic(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(document, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
        temporary.replace(path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path, nargs="?")
    args = parser.parse_args()
    document = json.loads(args.source.read_text(encoding="utf-8"))
    write_atomic(args.output or args.source, sanitize_har(document))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
