import zipfile

import pytest

from kindl.bundle import package_kfx_zip


def test_package_kfx_zip_is_flat_stored_renames_voucher_and_removes_loose_files(
    tmp_path,
):
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
    assert list(book.iterdir()) == [output]


def test_package_kfx_zip_requires_content_and_voucher(tmp_path):
    book = tmp_path / "B012345678"
    book.mkdir()
    with pytest.raises(ValueError, match="No AZW8/AZW9"):
        package_kfx_zip(book)


def test_package_kfx_zip_keeps_loose_files_when_archive_creation_fails(
    monkeypatch, tmp_path
):
    book = tmp_path / "B012345678"
    book.mkdir()
    content = book / "main.azw8"
    voucher = book / "book.voucher"
    content.write_bytes(b"main")
    voucher.write_bytes(b"voucher")

    def fail_replace(self, target):
        raise OSError("replace failed")

    monkeypatch.setattr("kindl.bundle.Path.replace", fail_replace)

    with pytest.raises(OSError, match="replace failed"):
        package_kfx_zip(book)
    assert content.is_file()
    assert voucher.is_file()
    assert not (book / "B012345678.kfx-zip.part").exists()
