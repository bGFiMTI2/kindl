"""Amazon marketplace regions.

Amazon keeps separate customer accounts per regional site, so the browser
sign-in and the identity service (token exchange and MAP registration) must use
the region the account belongs to. The Kindle device services (FIRS, the todo
metadata service, and digital delivery) have no regional host names and are
shared by every region; see ``docs/protocol.md``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Region:
    """The region-specific values of the sign-in and identity requests."""

    #: Short code stored with each account and accepted by ``--region``.
    code: str
    #: Retail site shown to the user, e.g. in the final-URL prompt.
    site: str
    #: Amazon-hosted OpenID sign-in page.
    signin_url: str
    #: ``openid.return_to``: the page the browser lands on after sign-in. It
    #: must be on the same site as ``signin_url``.
    return_to: str
    #: ``openid.assoc_handle``. Amazon answers 404 ("not a functioning page")
    #: when the handle does not belong to the sign-in site.
    assoc_handle: str
    #: Host of the identity service, also sent as ``x-amzn-identity-auth-domain``.
    identity_host: str
    #: Cookie domain requested during MAP registration.
    cookie_domain: str

    @property
    def token_url(self) -> str:
        return f"https://{self.identity_host}/auth/token"

    @property
    def register_url(self) -> str:
        return f"https://{self.identity_host}/auth/register"


REGIONS: dict[str, Region] = {
    "us": Region(
        code="us",
        site="amazon.com",
        signin_url="https://www.amazon.com/ap/signin",
        return_to="https://www.amazon.com/",
        assoc_handle="amzn_mazama_desktop_us",
        identity_host="api.amazon.com",
        cookie_domain=".amazon.com",
    ),
    "jp": Region(
        code="jp",
        site="amazon.co.jp",
        signin_url="https://www.amazon.co.jp/ap/signin",
        return_to="https://www.amazon.co.jp/",
        assoc_handle="amzn_mazama_desktop_jp",
        identity_host="api.amazon.co.jp",
        cookie_domain=".amazon.co.jp",
    ),
}
#: Accounts saved before regions existed were all registered on amazon.com.
DEFAULT_REGION = "us"


def get_region(code: str | None = None) -> Region:
    """Return the region for ``code``; empty or ``None`` means :data:`DEFAULT_REGION`."""
    key = (code or "").strip().lower() or DEFAULT_REGION
    try:
        return REGIONS[key]
    except KeyError:
        valid = ", ".join(sorted(REGIONS))
        raise ValueError(f"Unknown region {code!r}; expected one of: {valid}") from None
