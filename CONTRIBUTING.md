# Contributing

Contributions that improve protocol documentation, portability, reliability,
testing, privacy, and access to content already authorized for the contributor's
own account are welcome.

The following are out of scope:

- DRM decryption, key derivation/extraction, or DRM removal;
- conversion or export intended to make DRM-protected content readable in
  otherwise unauthorized software;
- bypassing authentication, authorization, regional restrictions, rate limits,
  account controls, or payment;
- acquiring or redistributing another person's content or credentials; and
- committing captures, tokens, private keys, signed URLs, vouchers, manifests,
  library exports, or downloaded book data.

Do not submit examples or test fixtures obtained from another person's account.
Do not ask maintainers or users to exchange credentials or downloaded content,
even privately.

Run before submitting changes:

```powershell
uv run pytest
uv run ruff check scripts src tests
```

Protocol changes should distinguish captured evidence from inference, update
both `docs/openapi.yaml` and `docs/workflows.arazzo.yaml` when applicable, and
include synthetic tests that contain no account or book data.
