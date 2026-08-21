import zipfile

import pytest

from kindl.bundle import package_kfx_zip


def test_package_kfx_zip_is_flat_stored_and_renames_voucher(tmp_path):
    book = tmp_path / "B012345678"
    book.mkdir()
    (book / "main.azw8").write_bytes(b"main")
    (book / "metadata.azw9").write_bytes(b"metadata")
    (book / "amzn1.drm-voucher.v1.1234").write_bytes(b"voucher")
    (book / "manifest.json").write_text("{}")

    output = package_kfx_zip(book)

    with zipfile.ZipFile(output) as archive:
        assert archive.namelist() == [
            "amzn1.drm-voucher.v1.1234.voucher",
            "main.azw8",
            "metadata.azw9",
        ]
        assert all(
            info.compress_type == zipfile.ZIP_STORED for info in archive.infolist()
        )
        assert archive.read("main.azw8") == b"main"


def test_package_kfx_zip_requires_content_and_voucher(tmp_path):
    book = tmp_path / "B012345678"
    book.mkdir()
    with pytest.raises(ValueError, match="No AZW8/AZW9"):
        package_kfx_zip(book)
