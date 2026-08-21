# kindl

`kindl` is an independent educational client for studying Amazon's Kindle
device-registration and digital-delivery protocol. It signs in through the
normal Amazon browser flow, emulates the device identity and request shapes
observed from Kindle for Windows, lists books available to the signed-in
account, and downloads the original encrypted delivery resources that Amazon
returns for an authorized title. It is not an official Kindle client or an
Amazon-certified Supported Device. Amazon accepting a request or registering
the emulated device does not represent compatibility approval or permission.

> [!IMPORTANT]
> `kindl` does not decrypt, crack, strip, defeat, or bypass DRM. It does not
> contain DRM keys, DRM-removal code, or a protected-content parser. Downloaded
> resources and generated KFX-ZIP archives retain Amazon's original DRM. DRM
> circumvention is not a project goal, and contributions adding it are out of
> scope. Do not share credentials, device keys, vouchers, signed URLs, library
> exports, downloaded resources, or generated archives.

This is unofficial software, is not affiliated with or endorsed by Amazon, and
is intended for protocol education and interoperability research. Use it only
with your own account and content you are authorized to access. You are
responsible for applicable law, contracts, and service terms. See
[Legal and responsible-use notice](LEGAL.md) before use.

## Install

Requires Python 3.11 or newer.

```powershell
uv sync
uv run kindl --help
```

## Accounts

The command layout follows KoboDL's approachable `user`/`book` organization.
Give each Amazon account a local label:

```powershell
uv run kindl user add personal
uv run kindl user add family
uv run kindl user list
uv run kindl user rm family
```

`user add` opens Amazon in your browser. After sign-in, copy the complete final
`amazon.com/?openid...` URL from the address bar into the prompt. `kindl` never
receives or stores your Amazon password. Device credentials are persistent, so
normal later runs do not require another browser login.

The default config is `%APPDATA%\kindl\config.json` on Windows and
`$XDG_CONFIG_HOME/kindl/config.json` (or `~/.config/kindl/config.json`) elsewhere.

The old `amzn-device-link` executable name remains as a compatibility alias for
existing virtual environments and scripts. New usage should call `kindl`.

## Books

```powershell
# Combine libraries from all configured accounts
uv run kindl book list

# Select one account or use machine-readable output
uv run kindl book list --user personal
uv run kindl book list --json
uv run kindl book list --export-library library.json

# Download one or more owned titles
$asin = "YOUR_BOOK_ASIN"
uv run kindl book get --user personal $asin

# Download the complete library
uv run kindl book get --user personal --get-all
```

`--user` is optional with one account and required for downloads when several
accounts exist. Bulk downloads skip completed books, continue after individual
failures, and return a nonzero exit status with a failure summary. Add `--force`
to download completed titles again.

Downloads default to `kindl_downloads` and use
`{Author} - {Title} {ASIN}`. The fields `{Author}`, `{Title}`, and `{ASIN}` are
available; `/` creates subdirectories:

```powershell
uv run kindl book get --get-all --format-str "{Author}/{Title} {ASIN}"
```

Each directory contains the delivery manifest, KFX component resources, and
the Amazon DRM voucher. By default, `kindl` also places those files unchanged
into a flat, uncompressed `.kfx-zip` archive. Use `--required-only` to omit
deferred resources or `--no-package` to skip that archive.

```powershell
uv run kindl book package "kindl_downloads\EXISTING_BOOK_DIRECTORY"
```

## Documentation

- [Human-readable protocol flow](docs/protocol.md)
- [OpenAPI 3.1 endpoint description](docs/openapi.yaml)
- [Arazzo 1.0 workflow description](docs/workflows.arazzo.yaml)
- [HAR sanitization policy and reproduction](docs/har-sanitization.md)
- [Legal and responsible-use notice](LEGAL.md)
- [Rights-holder notice process](RIGHTS-HOLDERS.md)
- [Credits and prior art](CREDITS.md)

The Markdown guide explains intent and behavior for people. OpenAPI describes
the observed HTTP operations for tools, while Arazzo describes their ordering
and dependencies. This split follows the OpenAPI Initiative's formats for API
descriptions and multi-call workflows.

## Development

```powershell
uv run pytest
uv run ruff check scripts src tests
```

HAR files, account configs, downloads, and credentials are ignored by Git. Do
not attach raw captures or debug logs to public issues or discussions; they can contain tokens,
cookies, personal metadata, and protected content.

## License

MIT. See [LICENSE](LICENSE). The license covers this project's code and
documentation, not Amazon services, trademarks, downloaded content, or
third-party projects named in [CREDITS.md](CREDITS.md).
