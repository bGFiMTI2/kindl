# Kindle device and delivery protocol

Status: observed, unofficial, and subject to change.

This document describes the end-to-end flow implemented by `kindl`. It was
reconstructed from a cleaned HTTP Archive and then checked against the client
implementation. It is descriptive, not Amazon documentation. Fields marked
"observed" appeared in the capture; behavior marked "implementation" records a
choice made by `kindl`.

For machine use, see [openapi.yaml](openapi.yaml) for operations and schemas and
[workflows.arazzo.yaml](workflows.arazzo.yaml) for call ordering. OpenAPI was
selected because it provides a standard machine-readable HTTP API description;
Arazzo complements it with sequences and dependencies between calls.

## Security boundary

The browser owns password entry, MFA, CAPTCHA, and account challenges. `kindl`
only creates the authorization URL and receives the final redirected URL pasted
by the user. The client persists a generated device identity, ADP token, and RSA
private key. It never persists the one-time authorization code or PKCE verifier.

The config file is sensitive. So are raw HAR files, manifests, signed resource
URLs, vouchers, and downloaded components. None belongs in a public issue or
repository.

## Actors and stored state

| Actor | Responsibility |
| --- | --- |
| Browser | Amazon sign-in and user-facing challenges |
| `api.amazon.com` | Exchanges an authorization code for a short-lived access token |
| FIRS | Registers the emulated desktop device and refreshes ADP credentials |
| Todo metadata service | Returns Kindle library metadata |
| Digital delivery service | Returns a manifest, voucher, and KFX components |
| `kindl` config | Stores named accounts and persistent per-device credentials |

Each account stores:

- local account name;
- 32-byte hexadecimal device serial;
- eight-character persistent PID;
- device type;
- ADP authentication token;
- RSA private key returned during device registration;
- directed ID and marketplace when supplied by the service.

## 1. Create the device identity and PKCE values

Implementation:

1. Generate a 16-byte random device serial represented as 32 uppercase hex characters.
2. Generate an eight-character PID from the desktop client's accepted alphabet.
3. Generate a 32-byte random PKCE verifier using unpadded base64url.
4. Calculate `BASE64URL(SHA256(verifier))` as the S256 challenge.

The serial and PID must remain stable after registration because they identify
the registered delivery device and participate in later DRM-bound delivery.

## 2. Authorize in the browser

Open `GET https://www.amazon.com/ap/signin` with OpenID 2.0 and OAuth-extension
parameters. Important observed constants include:

- association handle `amzn_mazama_desktop_us`;
- page ID `amzn_mazama_pc_aui`;
- OAuth scope `device_auth_access`;
- response type `code`;
- code-challenge method `S256`;
- return URL `https://www.amazon.com/`;
- client ID `device:` followed by the lowercase hex encoding of
  `<serial>#<device-type>`.

After successful sign-in, Amazon redirects to the return URL. The query includes
`openid.oa2.authorization_code`. Other signed OpenID response fields establish
the browser response but are not sent to the token endpoint by `kindl`.

## 3. Exchange the authorization code

Send `POST https://api.amazon.com/auth/token` as JSON. The legacy desktop
endpoint proved sensitive to request shape, so the implementation intentionally
uses a minimal header set and conventional JSON spacing.

```json
{
  "app_name": "KatxopoWindows",
  "client_domain": "DeviceLegacy",
  "client_id": "<hex(serial#device-type)>",
  "code_algorithm": "SHA-256",
  "code_verifier": "<PKCE verifier>",
  "requested_token_type": "access_token",
  "source_token": "<authorization code>",
  "source_token_type": "authorization_code"
}
```

The returned access token is short-lived input to device registration. It is
not the persistent ADP token.

## 4. Register the desktop-compatible device

Send an XML `POST` to
`https://firs-ta-g7g.amazon.com/FirsProxy/registerDeviceWithToken`. The request
contains the device name template, device type, serial, PID, access token,
software version, and desktop platform metadata.

The response supplies the persistent ADP authentication token and device RSA
private key, plus account/marketplace metadata. `kindl` saves these immediately
in its private config. A browser login is therefore not normally required on
later runs.

## 5. Sign ADP requests

Authenticated service requests use these headers:

- `X-ADP-Authentication-Token`;
- `X-ADP-Request-Digest`;
- `X-ADP-SW` and `X-ADP-Reason` where required;
- correlation, timestamp, attempt, transport, and device metadata headers for
  delivery operations.

The digest input is the byte concatenation:

```text
UPPERCASE_METHOD + "\n" +
PATH_AND_QUERY + "\n" +
LOCAL_TIMESTAMP + "\n" +
RAW_REQUEST_BODY + "\n" +
ADP_TOKEN
```

`kindl` hashes that input with SHA-256 and applies the observed legacy raw-digest
PKCS#1 v1.5 RSA operation. The resulting base64 signature and timestamp are
joined with `:`. This differs from a normal RSA/SHA-256 DigestInfo signature and
is deliberately implemented only for request authentication.

## 6. List library metadata

Send a signed `GET` to
`https://todo-ta-g7g.amazon.com/FionaTodoListProxy/syncMetaData` with
`item_count` from 1 through 1000. The XML response contains an
`add_update_list` of `meta_data` elements and optional removal/series lists.

`kindl` normalizes these observed fields:

- ASIN;
- title;
- authors and publishers;
- content and CDE content types;
- purchase/publication dates;
- content size.

Library metadata is personal data and is removed from the cleaned HAR even
though the surrounding XML schema is retained.

## 7. Refresh device credentials before delivery

Before a download batch, send a signed `GET` to
`https://firs-ta-g7g.amazon.com/FirsProxy/getDeviceCredentials` with reason
`TodoItem.GET.NAMS`. This operation may rotate the ADP token or private key.
`kindl` atomically saves the returned values before downloading resources.

Refreshing once per batch avoids repeating browser login while ensuring the
delivery requests use current device credentials.

## 8. Request the delivery manifest

Send a signed `GET` to:

```text
https://kindle-digital-delivery.amazon.com/delivery/manifest/kindle.ebook/{asin}
```

Use a fresh UUID correlation ID, `Accept: application/json`, and:

```text
X-Amzn-Accept-Type: application/x.amzn.digital.deliverymanifest@1.0
```

The JSON response identifies the content and lists resources. Each resource can
include its ID, type, requirement (`Required`, `Preferred`, or deferred), size,
and endpoint URL. Typical observed resource types include the main KFX payload,
metadata, attachable resources, a DRM voucher, and user-annotation data.

User-annotation resources are not downloaded. `--required-only` excludes
resources that are neither required nor preferred.

## 9. Download the voucher and KFX components

All resource requests retain the manifest's correlation ID and receive fresh
ADP signatures because the complete path and query are signed.

For the DRM voucher, append `supportedVoucherVersions` using the version list
implemented by the compatible desktop client and send:

```text
Accept: application/x-com.amazon.drm.Voucher@1.0
```

Other resource endpoints return KFX component media, observed as
`application/x-kfx-ebook`. URLs can contain expiring AWS query credentials and
must never be logged or shared.

Each response is streamed to a `.part` file and atomically renamed after a
successful transfer. The manifest and account config use the same atomic-write
principle. Interrupted partial files are removed.

## 10. Package KFX-ZIP without changing content

KFX delivery commonly consists of multiple files. Following the KFX-ZIP
convention introduced by John Howell's KFX Input calibre plugin, `kindl` creates
a flat, uncompressed ZIP archive with a `.kfx-zip` extension. It includes the
AZW8/AZW9 components and voucher, renaming a suffixless voucher entry to end in
`.voucher` for compatibility.

Packaging is not decryption. File bytes are copied unchanged, and DRM remains.

## Captured but nonessential traffic

The source capture also contained normal browser assets, sign-in forms,
telemetry, crash reporting, collection synchronization, todo-item polling,
sidecar annotations, and device logs. The cleaned HAR retains request metadata
and safe schemas where reliable sanitization is possible. Browser HTML,
JavaScript, binary assets, downloaded KFX content, vouchers, and opaque device
logs are omitted because they may contain secrets, personal state, copyrighted
content, or unstable embedded identifiers. None is required by the implemented
login/library/download path.

## Known limitations

- These are private endpoints, not a supported public API.
- The flow is based on one observed desktop-client family and may be regional or
  version dependent.
- The library request is capped at 1000 items because that is the observed and
  implemented range; no additional pagination contract has been established.
- A successful download does not imply that third-party software can open the
  encrypted files.
- HTTP success and schema compatibility can change without a `kindl` release.
