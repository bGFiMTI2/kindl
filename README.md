# kindl

`kindl` is an independent educational client for studying Amazon's Kindle
device-registration and digital-delivery protocol. It signs in through the
normal Amazon browser flow, emulates the device identity and request shapes,
lists books available to the signed-in account, and downloads the original
encrypted delivery resources that Amazon returns for an authorized title.
It is not an official Kindle client or an Amazon-certified Supported Device.
Amazon accepting a request or registering the emulated device does not
represent compatibility approval or permission.

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
uv run kindl secrets refresh --user personal
uv run kindl secrets list
```

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

By default, `kindl` downloads the KFX components and Amazon DRM voucher into a
unique hidden staging directory, packages them unchanged into a flat,
uncompressed `.kfx-zip`, and removes the staging directory. The bundle is
published atomically, so each completed book directory contains only its
`.kfx-zip`; failed downloads do not leave temporary files or empty directories.
Use `--required-only` to omit deferred resources or `--no-package` to retain the
delivery manifest, component resources, and voucher without creating an archive.

```powershell
uv run kindl book package "kindl_downloads\EXISTING_BOOK_DIRECTORY"
```

## Device identity

`user add` opens Amazon in your browser. After sign-in, copy the complete final
`amazon.com/?openid...` URL from the address bar into the prompt. `kindl` never
receives or stores your Amazon password. Device credentials are persistent, so
normal later runs do not require another browser login.

To use another browser without opening the default browser automatically:

```powershell
uv run kindl user add personal --no-browser
```

Copy the printed sign-in URL into your preferred browser, finish signing in,
then paste the complete final URL from the address bar into the `Final URL` prompt.

The default config is `%APPDATA%\kindl\config.json` on Windows and
`$XDG_CONFIG_HOME/kindl/config.json` (or `~/.config/kindl/config.json`) elsewhere,
overridable via `KINDL_CONFIG`.

### Personas (`KINDL_PROFILE`)

`kindl` registers and downloads as the Android (Kindle 8.154) client by default.
`KINDL_PROFILE` selects a whole client persona:
- `android` (default): Kindle for Android 8.154 (`A3VNNDO1I14V03`, Pixel 7, Android 13).
- `ios`: Kindle for iPhone, build 7.68.1 (`AGZZ1ST63LKBW`, iPhone, iOS 17.7.1).
- `ios-ipad`: Kindle for iPad, build 7.68.1 (`A1FG5NAKX0MRJL`, iPad, iOS 17.7.1).
- `windows`: Kindle for PC (`A1UOUY6O7B48AR`, KatxopoWindows, Mazama; automatically configures legacy XML registration flow).

```bash
# Kindle iOS (iPhone) persona
KINDL_PROFILE=ios uv run kindl user add personal-ios

# Register another persona from stored refresh token without opening a browser
KINDL_PROFILE=ios-ipad uv run kindl user clone personal --name personal-ipad

# Kindle for Windows persona
KINDL_PROFILE=windows uv run kindl user add personal-pc
```

Registration returns an OAuth `refresh_token`, which `kindl` stores alongside
device credentials. `kindl user clone` spends it on a fresh access token and
registers another device persona for the same account without opening a browser.
Set `KINDL_PROFILE` for each clone; the source account keeps its own identity.

- See [`docs/protocol.md`](docs/protocol.md) for persona field values, `KINDL_*` environment overrides, and registration/delivery protocol details.

The old `amzn-device-link` executable name remains as a compatibility alias for
existing virtual environments and scripts. New usage should call `kindl`.

## Documentation

- [Protocol and persona specification](docs/protocol.md)
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
