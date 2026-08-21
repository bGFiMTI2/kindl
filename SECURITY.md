# Security and privacy

Do not report vulnerabilities by attaching raw HAR captures, debug logs,
configuration files, browser callback URLs, manifests, vouchers, or downloaded
book resources to a public issue. These can expose account access, personal
data, purchase history, signed URLs, or protected content.

Before sharing a reproduction:

1. remove credentials and downloaded files;
2. reproduce with synthetic identifiers where possible;
3. run the HAR sanitizer if a capture is essential;
4. manually review the sanitized result; and
5. describe the smallest relevant request shape in text instead of attaching a
   capture whenever possible.

The sanitizer is defense in depth, not a guarantee that an arbitrary future
response contains no newly introduced personal field.

Reports requesting DRM keys, DRM removal, decryption, access to another user's
account, or bypass of Amazon access controls are outside project scope.
