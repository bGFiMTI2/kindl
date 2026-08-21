# Credits and prior art

`kindl` is an independent implementation, but its user experience and packaging
conventions benefit from prior open-source work.

## KFX-ZIP

The KFX-ZIP convention originated in John Howell's **KFX Input** plugin for
calibre. KFX books commonly consist of several component files; the plugin's
file-type component gathers those files into an uncompressed ZIP archive with a
`.kfx-zip` extension. `kindl` follows that container convention but does not
copy the plugin's conversion or DRM-processing code.

- Canonical KFX Input discussion and releases:
  https://www.mobileread.com/forums/showthread.php?t=291290
- GitHub mirror of the KFX Input plugin:
  https://github.com/kluyg/calibre-kfx-input

KFX Input is a separate project with its own author, copyright, and GPL-3.0
license. It is neither bundled with nor required by `kindl`.

## Kobo downloader lineage

The friendly `user add/list/rm` and `book list/get` command organization,
multi-account selection, bulk-download behavior, and output-format concepts
were inspired by:

- **KoboDL**, the actively maintained fork by Brandon Davis (`subdavis`):
  https://github.com/subdavis/kobo-book-downloader
- **kobo-book-downloader**, the original project by `TnS-hun`:
  https://github.com/TnS-hun/kobo-book-downloader

Those projects target Kobo rather than Amazon and use different protocols and
content formats. They are credited as design and CLI inspiration; their names
do not imply endorsement of `kindl`.
