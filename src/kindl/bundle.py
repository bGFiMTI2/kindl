from __future__ import annotations

import zipfile
from pathlib import Path


def package_kfx_zip(book_dir: Path, output: Path | None = None) -> Path:
    """Package unchanged components, then remove the loose downloaded files."""
    if not book_dir.is_dir():
        raise ValueError(f"Downloaded book directory does not exist: {book_dir}")
    destination = output or (book_dir / f"{book_dir.name}.kfx-zip")
    candidates = sorted(
        (
            path
            for path in book_dir.iterdir()
            if path.is_file()
            and (
                path.suffix.lower() in {".azw8", ".azw9", ".md", ".res", ".voucher"}
                or path.name.startswith("amzn1.drm-voucher.")
            )
        ),
        key=lambda path: path.name,
    )
    content = [path for path in candidates if path.suffix.lower() in {".azw8", ".azw9"}]
    vouchers = [
        path
        for path in candidates
        if "drm-voucher" in path.name or path.suffix.lower() == ".voucher"
    ]
    if not content:
        raise ValueError(f"No AZW8/AZW9 KFX components found in {book_dir}")
    if not vouchers:
        raise ValueError(f"No DRM voucher found in {book_dir}")

    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = destination.with_name(f"{destination.name}.part")
    try:
        with zipfile.ZipFile(partial, "w", compression=zipfile.ZIP_STORED) as archive:
            for path in candidates:
                archive_name = path.name
                if (
                    path.name.startswith("amzn1.drm-voucher.")
                    and path.suffix.lower() != ".voucher"
                ):
                    archive_name = f"{path.name}.voucher"
                archive.write(path, archive_name)
        partial.replace(destination)
    except BaseException:
        partial.unlink(missing_ok=True)
        raise

    for path in book_dir.iterdir():
        if path != destination and (path.is_file() or path.is_symlink()):
            path.unlink()
    return destination
