# HAR sanitization policy

Raw HTTP Archives are secrets. They can contain passwords or encrypted password
submissions, OAuth codes, access tokens, cookies, private keys, signed download
URLs, account identifiers, purchase history, book metadata, DRM vouchers, and
downloaded content. Both raw and sanitized `*.har` files are ignored by Git.

## Rebuild the cleaned capture

Keep the private source capture at `capture.har`, then run:

```powershell
uv run python scripts\sanitize_har.py capture.har sanitized.har
```

The sanitizer always reads the source and writes a newly derived document. It
does not incrementally edit a previously sanitized file. This makes the current
private `sanitized.har` the authoritative cleaned representation of the source
capture for local protocol analysis.

## Retained

- all HAR entries and ordering;
- methods, status codes, timing data, hostnames, and endpoint shapes;
- safe HTTP header values such as media types, encodings, language, cache
  behavior, client hints, software versions, and protocol-reason constants;
- safe query/form values such as limits, modes, scopes, and version lists;
- JSON, XML, and form field structure;
- non-sensitive enum values, types, requirements, and response shapes; and
- deterministic markers that preserve equality relationships between repeated
  redacted identifiers.

## Removed or pseudonymized

- passwords, encrypted password fields, cookies, CSRF values, OAuth codes,
  PKCE material, access/refresh/ADP tokens, request signatures, and private keys;
- device serials, PIDs, account/directed/session IDs, emails, names, and other
  account metadata;
- ASINs, titles, authors, publishers, purchase history, annotations, resource
  IDs, and signed delivery credentials;
- browser telemetry path identifiers; and
- response/request bodies that are HTML, JavaScript, opaque logs, images, KFX,
  vouchers, or other binary/protected content.

Omitted bodies retain their HAR metadata and an `_sanitization` explanation.
The log root records the sanitizer policy and version.

## Validation

The test suite verifies that protocol constants survive while representative
secrets do not. The actual cleaned capture was additionally scanned against
captured sensitive header, cookie, query, JSON, form, and private XML values,
and against email, PEM private-key, account-ID, ASIN, and bearer-token patterns.

Sanitization reduces risk; it does not prove that arbitrary future captures are
safe. Endpoint schemas change and unrecognized personal data may appear. Review
the resulting diff and scan it independently before sharing any derivative.
