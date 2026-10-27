import base64
import json
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.sanitize_har import OPAQUE, Sanitizer, main, sanitize_har, write_atomic


def test_sanitizer_retains_protocol_values_and_redacts_secrets():
    document = {
        "log": {
            "entries": [
                {
                    "request": {
                        "method": "POST",
                        "url": "https://api.example.test/items?limit=100&session-id=secret",
                        "headers": [
                            {"name": "Content-Type", "value": "application/json"},
                            {"name": "Authorization", "value": "Bearer secret"},
                        ],
                        "cookies": [],
                        "queryString": [
                            {"name": "limit", "value": "100"},
                            {"name": "session-id", "value": "secret"},
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps(
                                {"requested_token_type": "access_token", "password": "secret"}
                            ),
                        },
                    },
                    "response": {
                        "headers": [{"name": "Content-Type", "value": "application/json"}],
                        "cookies": [],
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps({"token_type": "bearer", "access_token": "secret"}),
                        },
                    },
                }
            ]
        }
    }

    clean = sanitize_har(document)
    entry = clean["log"]["entries"][0]

    assert "limit=100" in entry["request"]["url"]
    assert entry["request"]["headers"][0]["value"] == "application/json"
    assert "REDACTED" in entry["request"]["headers"][1]["value"]
    request_body = json.loads(entry["request"]["postData"]["text"])
    assert request_body["requested_token_type"] == "access_token"
    assert "REDACTED" in request_body["password"]
    response_body = json.loads(entry["response"]["content"]["text"])
    assert response_body["token_type"] == "bearer"
    assert "REDACTED" in response_body["access_token"]


def test_sanitizer_omits_browser_and_binary_bodies():
    document = {
        "log": {
            "entries": [
                {
                    "request": {"url": "https://example.test/", "headers": [], "cookies": []},
                    "response": {
                        "headers": [],
                        "cookies": [],
                        "content": {"mimeType": "text/html", "text": "<p>account page</p>"},
                    },
                }
            ]
        }
    }

    clean = sanitize_har(document)

    assert clean["log"]["entries"][0]["response"]["content"]["text"] == OPAQUE


def test_sanitize_xml():
    sanitizer = Sanitizer()
    xml_input = (
        "<response status='ok'>"
        "<asin>B000000001</asin>"
        "<deviceSerialNumber>0123456789ABCDEF0123456789ABCDEF</deviceSerialNumber>"
        "<title>Synthetic Title</title>"
        "<radioId>R12345678</radioId>"
        "<macAddress>00:1A:2B:3C:4D:5E</macAddress>"
        "<info token='secret_token_val'>Contact tester@example.com for help</info>"
        "</response>"
    )
    sanitized = sanitizer.sanitize_xml(xml_input)

    assert "B000000001" not in sanitized
    assert "0123456789ABCDEF0123456789ABCDEF" not in sanitized
    assert "Synthetic Title" not in sanitized
    assert "R12345678" not in sanitized
    assert "00:1A:2B:3C:4D:5E" not in sanitized
    assert "secret_token_val" not in sanitized
    assert "tester@example.com" not in sanitized
    assert "__REDACTED_ASIN_" in sanitized
    assert "__REDACTED_DEVICESERIALNUMBER_" in sanitized
    assert "__REDACTED_TITLE_" in sanitized
    assert "__REDACTED_RADIOID_" in sanitized
    assert "__REDACTED_MACADDRESS_" in sanitized
    assert "__REDACTED_TOKEN_" in sanitized
    assert "__REDACTED_EMAIL_" in sanitized

    # In HAR entry postData and content
    document = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://firs.example.test/device",
                        "headers": [],
                        "cookies": [],
                        "postData": {
                            "mimeType": "text/xml",
                            "text": "<request><device_private_key>secret_key</device_private_key></request>",
                        },
                    },
                    "response": {
                        "headers": [],
                        "cookies": [],
                        "content": {
                            "mimeType": "application/xml",
                            "text": "<result><guid>12345678-1234-1234-1234-123456789012</guid></result>",
                        },
                    },
                }
            ]
        }
    }
    clean = sanitize_har(document)
    req_xml = clean["log"]["entries"][0]["request"]["postData"]["text"]
    resp_xml = clean["log"]["entries"][0]["response"]["content"]["text"]
    assert "secret_key" not in req_xml
    assert "__REDACTED_DEVICE_PRIVATE_KEY_" in req_xml
    assert "12345678-1234-1234-1234-123456789012" not in resp_xml
    assert "__REDACTED_GUID_" in resp_xml


def test_sanitize_form():
    sanitizer = Sanitizer()
    form_input = (
        "action=sign_in&password=my_secret_pass&code_verifier=verifier123"
        "&email=tester%40example.com&deviceid=D0123456789"
        "&note=serial+0123456789ABCDEF0123456789ABCDEF+registered"
    )
    sanitized = sanitizer.sanitize_form(form_input)

    assert "my_secret_pass" not in sanitized
    assert "verifier123" not in sanitized
    assert "tester%40example.com" not in sanitized
    assert "D0123456789" not in sanitized
    assert "0123456789ABCDEF0123456789ABCDEF" not in sanitized
    assert "__REDACTED_PASSWORD_" in sanitized
    assert "__REDACTED_CODE_VERIFIER_" in sanitized
    assert "__REDACTED_DEVICEID_" in sanitized

    # In HAR entry
    document = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://api.example.test/auth",
                        "headers": [],
                        "cookies": [],
                        "postData": {
                            "mimeType": "application/x-www-form-urlencoded",
                            "params": [{"name": "radioid", "value": "radio_secret"}],
                            "text": "radioid=radio_secret&client_id=client_123",
                        },
                    },
                    "response": {"headers": [], "cookies": [], "content": {}},
                }
            ]
        }
    }
    clean = sanitize_har(document)
    entry = clean["log"]["entries"][0]
    assert entry["request"]["postData"]["params"][0]["value"] != "radio_secret"
    assert "radio_secret" not in entry["request"]["postData"]["text"]
    assert "client_123" not in entry["request"]["postData"]["text"]


def test_cookie_websocket_redirect_and_telemetry_redaction():
    document = {
        "log": {
            "pages": [{"title": "Sign In for tester@example.com"}],
            "entries": [
                {
                    "request": {
                        "url": "https://fls-na.amazon.com/1/batch/1/OE/?account=amzn1.account.TEST1&mac=00:11:22:33:44:55",
                        "headers": [
                            {"name": "Cookie", "value": "session-id=secret_cookie_val"},
                            {"name": "Referer", "value": "https://example.test/auth?code=abc12345"},
                            {"name": "Origin", "value": "https://example.test:8443"},
                            {
                                "name": "Location",
                                "value": "https://example.test/redirect?key=topsecret",
                            },
                            {
                                "name": "User-Agent",
                                "value": "SyntheticClient/1.0 (tester@example.com)",
                            },
                        ],
                        "cookies": [{"name": "session-token", "value": "cookie_secret_val_1"}],
                    },
                    "response": {
                        "headers": [{"name": "Set-Cookie", "value": "at-main=cookie_secret_val_2"}],
                        "cookies": [{"name": "x-main", "value": "cookie_secret_val_3"}],
                        "redirectURL": "https://api.example.test/callback?openid.oa2.authorization_code=supersecret&serial=0123456789ABCDEF0123456789ABCDEF",
                        "content": {"mimeType": "text/plain", "text": "OK"},
                    },
                    "_initiator": {
                        "url": "https://example.test/script.js?token=secret_initiator_token"
                    },
                    "_webSocketMessages": [
                        {"type": "send", "data": "sensitive_websocket_payload_data"},
                        {"type": "receive"},
                    ],
                }
            ],
        }
    }

    clean = sanitize_har(document)
    page = clean["log"]["pages"][0]
    entry = clean["log"]["entries"][0]

    assert "tester@example.com" not in page["title"]
    assert "__REDACTED_EMAIL_" in page["title"]

    assert "/__REDACTED_TELEMETRY_PATH__" in entry["request"]["url"]
    assert "00:11:22:33:44:55" not in entry["request"]["url"]
    assert "TEST1" not in entry["request"]["url"]

    # Cookies
    assert entry["request"]["cookies"][0]["value"] != "cookie_secret_val_1"
    assert "__REDACTED_COOKIE_" in entry["request"]["cookies"][0]["value"]
    assert entry["response"]["cookies"][0]["value"] != "cookie_secret_val_3"
    assert "__REDACTED_COOKIE_" in entry["response"]["cookies"][0]["value"]

    # WebSocket messages
    assert entry["_webSocketMessages"][0]["data"] == OPAQUE

    # Redirect URL
    assert "supersecret" not in entry["response"]["redirectURL"]
    assert "0123456789ABCDEF0123456789ABCDEF" not in entry["response"]["redirectURL"]

    # Initiator
    assert "secret_initiator_token" not in str(entry["_initiator"])


def test_base64_json_response_redaction():
    payload = {"account": "amzn1.account.TESTACCOUNT", "password": "nested_secret_pass"}
    encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")

    document = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://api.example.test/token",
                        "headers": [],
                        "cookies": [],
                    },
                    "response": {
                        "headers": [],
                        "cookies": [],
                        "content": {
                            "mimeType": "application/json",
                            "encoding": "base64",
                            "text": encoded,
                        },
                    },
                }
            ]
        }
    }

    clean = sanitize_har(document)
    content = clean["log"]["entries"][0]["response"]["content"]
    assert "encoding" not in content
    sanitized_body = json.loads(content["text"])
    assert "TESTACCOUNT" not in sanitized_body["account"]
    assert "nested_secret_pass" not in sanitized_body["password"]
    assert "__REDACTED_ACCOUNT_" in sanitized_body["account"]
    assert "__REDACTED_PASSWORD_" in sanitized_body["password"]

    # Invalid base64 fallback
    bad_doc = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://api.example.test/token",
                        "headers": [],
                        "cookies": [],
                    },
                    "response": {
                        "headers": [],
                        "cookies": [],
                        "content": {
                            "mimeType": "application/json",
                            "encoding": "base64",
                            "text": "not-valid-base64-content!@#$%",
                        },
                    },
                }
            ]
        }
    }
    clean_bad = sanitize_har(bad_doc)
    assert clean_bad["log"]["entries"][0]["response"]["content"]["text"] == OPAQUE


def test_mac_radioid_and_hex32_serial_redaction():
    document = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://api.example.test/register",
                        "headers": [
                            {"name": "X-Hardware-Id", "value": "HW-998877"},
                            {"name": "X-Wifi-Mac", "value": "00:1A:2B:3C:4D:5E"},
                        ],
                        "cookies": [],
                        "queryString": [
                            {"name": "radioid", "value": "RADIO_SECRET_VAL"},
                            {"name": "mac", "value": "AA-BB-CC-DD-EE-FF"},
                        ],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps(
                                {
                                    "deviceid": "DEV-00112233",
                                    "hardwareid": "HW-AABBCCDD",
                                    "wifimac": "00:11:22:33:44:55",
                                    "macaddress": "12-34-56-78-9A-BC",
                                    "unusual_key": "0123456789ABCDEF0123456789ABCDEF",
                                    "compound_id": "0123456789ABCDEF0123456789ABCDEF#A3VNNDO1I14V03",
                                    "compound_slot": "0123456789ABCDEF0123456789ABCDEF#A1B2C3D4#0",
                                }
                            ),
                        },
                    },
                    "response": {
                        "headers": [],
                        "cookies": [],
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps(
                                {
                                    "notes": "Device with MAC AA:BB:CC:DD:EE:FF and serial 0123456789ABCDEF0123456789ABCDEF registered."
                                }
                            ),
                        },
                    },
                }
            ]
        }
    }

    clean = sanitize_har(document)
    entry = clean["log"]["entries"][0]

    # Headers
    assert "HW-998877" not in entry["request"]["headers"][0]["value"]
    assert "00:1A:2B:3C:4D:5E" not in entry["request"]["headers"][1]["value"]

    # Query params
    assert entry["request"]["queryString"][0]["value"] != "RADIO_SECRET_VAL"
    assert entry["request"]["queryString"][1]["value"] != "AA-BB-CC-DD-EE-FF"

    # JSON Body
    body = json.loads(entry["request"]["postData"]["text"])
    assert body["deviceid"] != "DEV-00112233"
    assert body["hardwareid"] != "HW-AABBCCDD"
    assert body["wifimac"] != "00:11:22:33:44:55"
    assert body["macaddress"] != "12-34-56-78-9A-BC"
    assert body["unusual_key"] != "0123456789ABCDEF0123456789ABCDEF"
    assert "__REDACTED_SERIAL_" in body["unusual_key"]
    assert body["compound_id"] != "0123456789ABCDEF0123456789ABCDEF#A3VNNDO1I14V03"
    assert "__REDACTED_SERIAL_" in body["compound_id"]
    assert body["compound_slot"] != "0123456789ABCDEF0123456789ABCDEF#A1B2C3D4#0"
    assert "__REDACTED_SERIAL_" in body["compound_slot"]

    # Response body
    resp_body = json.loads(entry["response"]["content"]["text"])
    assert "AA:BB:CC:DD:EE:FF" not in resp_body["notes"]
    assert "0123456789ABCDEF0123456789ABCDEF" not in resp_body["notes"]


def test_cascading_redact_known_values():
    secret_serial = "0123456789ABCDEF0123456789ABCDEF"
    secret_password = "very_secret_customer_password_123"

    document = {
        "log": {
            "entries": [
                {
                    "request": {
                        "url": "https://api.example.test/login",
                        "headers": [],
                        "cookies": [],
                        "postData": {
                            "mimeType": "application/json",
                            "text": json.dumps(
                                {
                                    "serial": secret_serial,
                                    "password": secret_password,
                                }
                            ),
                        },
                    },
                    "response": {
                        "headers": [],
                        "cookies": [],
                        "content": {
                            "mimeType": "application/json",
                            "text": json.dumps(
                                {
                                    "description": f"Audited registration of {secret_serial} with credentials {secret_password}.",
                                    "items": [f"ref:{secret_serial}", f"token:{secret_password}"],
                                }
                            ),
                        },
                    },
                }
            ]
        }
    }

    clean = sanitize_har(document)
    resp_body = json.loads(clean["log"]["entries"][0]["response"]["content"]["text"])

    assert secret_serial not in resp_body["description"]
    assert secret_password not in resp_body["description"]
    assert "__REDACTED_SERIAL_" in resp_body["description"]
    assert "__REDACTED_PASSWORD_" in resp_body["description"]
    assert secret_serial not in resp_body["items"][0]
    assert secret_password not in resp_body["items"][1]


def test_write_atomic_and_cli_main(tmp_path: Path):
    doc = {"log": {"entries": [], "pages": []}}
    out_file = tmp_path / "sub" / "output.har"

    # Test write_atomic
    write_atomic(out_file, doc)
    assert out_file.is_file()
    loaded = json.loads(out_file.read_text(encoding="utf-8"))
    assert loaded == doc

    # Test write_atomic failure cleanup
    class Unserializable:
        pass

    with pytest.raises(TypeError):
        write_atomic(out_file, {"bad": Unserializable()})  # type: ignore[dict-item]

    # Test CLI main with source and output arguments
    src_file = tmp_path / "source.har"
    src_file.write_text(json.dumps(doc), encoding="utf-8")
    cli_out = tmp_path / "cli_out.har"

    with patch.object(sys, "argv", ["sanitize_har.py", str(src_file), str(cli_out)]):
        assert main() == 0

    assert cli_out.is_file()
    cli_loaded = json.loads(cli_out.read_text(encoding="utf-8"))
    assert "_sanitization" in cli_loaded["log"]

    # Test CLI main in-place
    with patch.object(sys, "argv", ["sanitize_har.py", str(src_file)]):
        assert main() == 0

    in_place_loaded = json.loads(src_file.read_text(encoding="utf-8"))
    assert "_sanitization" in in_place_loaded["log"]

    # Test CLI invocation via subprocess (__name__ == '__main__')
    sub_file = tmp_path / "sub_source.har"
    sub_file.write_text(json.dumps(doc), encoding="utf-8")
    proc = subprocess.run(
        [sys.executable, "scripts/sanitize_har.py", str(sub_file)],
        capture_output=True,
        text=True,
        check=True,
    )
    assert proc.returncode == 0
    assert "_sanitization" in json.loads(sub_file.read_text(encoding="utf-8"))["log"]


def test_sanitizer_edge_cases_and_error_handling():
    sanitizer = Sanitizer()

    # Empty marker category
    assert sanitizer.marker("URL") == "__REDACTED_URL__"

    # URL splitting error or invalid scheme/netloc
    assert "__REDACTED_URL_" in sanitizer.sanitize_url("http://[invalid-ipv6-host")
    assert "__REDACTED_URL_" in sanitizer.sanitize_url("/relative/path/only")

    # sanitize_string with HTTP URL
    assert "https://" in sanitizer.sanitize_string("https://example.test/path?foo=bar")

    # Long opaque value
    long_opaque = "A" * 50
    assert sanitizer.sanitize_string(long_opaque, field="mytoken") == "__REDACTED_MYTOKEN_1__"

    # Non-string/dict/list in sanitize_value
    assert sanitizer.sanitize_value(12345, field="number") == 12345
    assert sanitizer.sanitize_value(True, field="flag") is True
    assert sanitizer.sanitize_value(None, field="none") is None

    # List in sanitize_value
    assert sanitizer.sanitize_value(["test@example.com"], field="items") == ["__REDACTED_EMAIL_1__"]

    # PEM key and voucher prefix regexes
    pem_text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEfake\n-----END RSA PRIVATE KEY-----"
    assert "__REDACTED_PRIVATE_KEY_" in sanitizer.sanitize_string(pem_text)
    voucher_text = "amzn1.drm-voucher.v1.01234567-89ab-cdef-0123-456789abcdef"
    assert "__REDACTED_VOUCHER_" in sanitizer.sanitize_string(voucher_text)
    resource_text = "Delivery CR!ABCDEF1234567890ABCDEF component"
    assert "__REDACTED_RESOURCE_" in sanitizer.sanitize_string(resource_text)
    content_id_text = "Document DTP:123456789012 item"
    assert "__REDACTED_CONTENT_ID_" in sanitizer.sanitize_string(content_id_text)

    # PostData with non-string text
    post_data = {"mimeType": "application/json", "text": None}
    sanitizer.sanitize_post_data(post_data)
    assert post_data["text"] is None

    # PostData with empty/whitespace body
    empty_post = {"mimeType": "text/plain", "text": "   "}
    sanitizer.sanitize_post_data(empty_post)
    assert empty_post["text"] == "   "

    # PostData with unparseable JSON
    bad_json_post = {"mimeType": "application/json", "text": "{invalid json"}
    sanitizer.sanitize_post_data(bad_json_post)
    assert bad_json_post["text"] == OPAQUE
    assert "unparseable" in bad_json_post["_sanitization"]

    # PostData with unparseable XML
    bad_xml_post = {"mimeType": "application/xml", "text": "<unclosed tag"}
    sanitizer.sanitize_post_data(bad_xml_post)
    assert bad_xml_post["text"] == OPAQUE

    # PostData with unknown non-empty mime type
    unknown_post = {"mimeType": "application/octet-stream", "text": "binary bytes"}
    sanitizer.sanitize_post_data(unknown_post)
    assert unknown_post["text"] == OPAQUE

    # Content with non-string text
    content_none = {"mimeType": "application/json", "text": None}
    sanitizer.sanitize_content(content_none)
    assert content_none["text"] is None

    # Content with text/plain empty/curly braces
    content_plain = {"mimeType": "text/plain", "text": "{}"}
    sanitizer.sanitize_content(content_plain)
    assert content_plain["text"] == "{}"

    # Content with unparseable XML
    bad_xml_content = {"mimeType": "application/xml", "text": "<broken"}
    sanitizer.sanitize_content(bad_xml_content)
    assert bad_xml_content["text"] == OPAQUE
    assert "unparseable" in bad_xml_content["_sanitization"]
