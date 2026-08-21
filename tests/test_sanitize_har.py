import json

from scripts.sanitize_har import OPAQUE, sanitize_har


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
