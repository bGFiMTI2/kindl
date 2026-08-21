# Legal and responsible-use notice

This notice explains the project's intended technical scope. It is not legal
advice and cannot guarantee that a particular use is lawful or permitted by a
service agreement. Laws and contracts differ by jurisdiction and can change;
consult a qualified lawyer if you need advice about your circumstances.

## Project scope

`kindl` is published for education, protocol study, preservation of technical
knowledge, and development of interoperable software. It is designed to:

- authenticate an account through Amazon's own browser-hosted sign-in flow;
- generate and register an emulated desktop device identity using identifiers,
  metadata, and request shapes observed from Kindle for Windows;
- request library metadata and delivery resources made available to that
  authenticated account; and
- preserve the encrypted files returned by the service.

This emulation is descriptive interoperability behavior, not a claim that
`kindl` is Kindle for Windows, official Kindle Software, an Amazon-certified
Supported Device, or approved by Amazon. A successful authentication,
registration, or download response does not establish Amazon's approval or a
legal entitlement to use the interface.

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
scope and will not be accepted. The project will not add content-key derivation
or extraction, DRM removal, decryption, or conversion/export functionality
whose purpose is to make protected content readable by otherwise unauthorized
software.

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

## Rights-holder notices

The maintainers intend to respect valid intellectual-property rights and to
address substantiated legal concerns in good faith. A rights holder or its
authorized representative may use the process in
[RIGHTS-HOLDERS.md](RIGHTS-HOLDERS.md) to identify specific repository material
and explain the rights and legal basis involved. The maintainers will review a
complete notice promptly and may correct, restrict, or remove material where
appropriate.

This statement is not an admission that the project or any identified material
is unlawful. It does not waive defenses, exceptions, or other rights, and it
does not promise automatic action in response to an incomplete, mistaken, or
unverified demand.

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
