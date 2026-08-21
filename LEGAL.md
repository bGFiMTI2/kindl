# Legal and responsible-use notice

This notice explains the project's intended technical scope. It is not legal
advice and cannot guarantee that a particular use is lawful or permitted by a
service agreement. Laws and contracts differ by jurisdiction and can change;
consult a qualified lawyer if you need advice about your circumstances.

## Project scope

`kindl` is published for education, protocol study, preservation of technical
knowledge, and development of interoperable software. It is designed to:

- authenticate an account through Amazon's own browser-hosted sign-in flow;
- register and retain a device identity;
- request library metadata and delivery resources made available to that
  authenticated account; and
- preserve the encrypted files returned by the service.

It is not designed to acquire content from another person's account, evade
access controls, automate password entry, defeat rate limits, conceal identity,
or redistribute content.

## No DRM circumvention

`kindl` does not decrypt, crack, strip, remove, disable, or bypass DRM. It does
not derive or extract content keys and does not make DRM-protected books
readable outside software that is independently authorized to read them. The
KFX-ZIP operation is byte-preserving packaging: it stores the original KFX
components and voucher in an uncompressed ZIP container. Encryption and DRM
remain intact.

DRM circumvention is not a project objective. Issues, documentation, or code
whose purpose is to add DRM removal are outside the project's contribution
scope.

## User responsibilities

Use `kindl` only with accounts you control and content you lawfully acquired or
are otherwise authorized to access. Do not share credentials, vouchers,
download URLs, captures, or downloaded content. You are solely responsible for
evaluating and complying with:

- copyright and anti-circumvention law in your jurisdiction;
- Amazon's current agreements, policies, and technical restrictions;
- publisher or rightsholder terms; and
- privacy, computer-access, export, and other applicable law.

The existence of this software is not a representation that any particular use
is authorized. Educational intent is not, by itself, a legal defense.

## Independent project and trademarks

This project is independent and unofficial. It is not affiliated with,
sponsored by, approved by, or endorsed by Amazon.com, Inc. or its affiliates.
Amazon, Kindle, and related names and marks belong to their respective owners.
They are used only to identify the service and formats with which the software
interoperates. The project name `kindl` is not an Amazon product.

## Service and account risk

The observed interfaces are private, undocumented, and may change or stop
working without notice. Using unofficial clients may carry contractual or
account risk. The maintainers make no promise that Amazon permits this client,
that access will remain available, or that an account will not be restricted.

## Privacy and publication

Raw HAR captures, debug logs, configuration files, device credentials,
manifests, vouchers, and downloaded resources can contain secrets, personal
data, purchase history, or copyrighted material. They must not be committed or
posted publicly. The repository ignores these artifacts by default. The
sanitizer is a risk-reduction tool, not a guarantee; review any output before
sharing it.

## Warranty and liability

The software is provided "as is", without warranty. The complete warranty and
liability disclaimer is in [LICENSE](LICENSE). You assume the risk of using the
software, including data loss, account action, service interruption, legal
claims, and unexpected downloads or charges.

## Background reading

The wording and boundaries above were informed by disclaimers used by other
independent interoperability projects and by the Electronic Frontier
Foundation's [Coders' Rights Project](https://www.eff.org/issues/coders). Those
materials are informational and are not incorporated as legal advice.
