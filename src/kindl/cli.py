from __future__ import annotations

import json
import re
import sys
import webbrowser
from dataclasses import dataclass
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path, PurePosixPath

import click
import httpx
from tabulate import tabulate

from .auth import (
    Account,
    AccountStore,
    default_config_path,
    legacy_credentials_path,
    new_device_identity,
    pkce_pair,
)
from .bundle import package_kfx_zip
from .client import WINDOWS_RESERVED_NAMES, AmazonDeviceClient
from .models import LibraryItem

DEFAULT_FORMAT = "{Author} - {Title} {ASIN}"
INVALID_PATH_CHARS = re.compile(r'[<>:"/\\|?*\x00-\x1f]')


@dataclass(slots=True)
class Runtime:
    config: Path
    store: AccountStore
    table_format: str
    debug: bool


def _package_version() -> str:
    try:
        return version("kindl")
    except PackageNotFoundError:
        return "0.1.0"


@click.group()
@click.option(
    "--fmt", default="simple", show_default=True, help="python-tabulate table format"
)
@click.option(
    "--config",
    type=click.Path(path_type=Path, dir_okay=False),
    default=default_config_path,
    show_default=True,
    help="path to the account config file",
)
@click.option("--debug", is_flag=True, help="show complete exceptions")
@click.version_option(version=_package_version())
@click.pass_context
def cli(ctx: click.Context, fmt: str, config: Path, debug: bool) -> None:
    """Log in to Amazon and download owned Kindle books."""
    store = AccountStore.load(config)
    legacy = legacy_credentials_path()
    if config == default_config_path() and not store.accounts and legacy.is_file():
        store = AccountStore.load(legacy)
        store.save(config)
    ctx.obj = Runtime(config, store, fmt, debug)


@cli.group(name="user", short_help="show and manage Amazon accounts")
def user_group() -> None:
    pass


@user_group.command(name="list", help="list all accounts")
@click.pass_obj
def user_list(runtime: Runtime) -> None:
    rows = sorted(
        (
            account.name,
            account.credentials.directed_id or "-",
            account.credentials.serial,
        )
        for account in runtime.store.accounts
    )
    click.echo(tabulate(rows, headers=["Name", "Directed ID", "Device Serial"], tablefmt=runtime.table_format))


@user_group.command(name="add", help="log in and add an Amazon account")
@click.argument("name", required=False)
@click.option("--language", default="en_US", show_default=True)
@click.option("--replace", is_flag=True, help="replace an existing account with this name")
@click.pass_obj
def user_add(runtime: Runtime, name: str | None, language: str, replace: bool) -> None:
    name = (name or click.prompt("Account name")).strip()
    if not name:
        raise click.UsageError("account name cannot be empty")
    if runtime.store.get(name) and not replace:
        raise click.UsageError(
            f"account {name!r} already exists; use --replace to log in again"
        )

    serial, pid = new_device_identity()
    verifier, challenge = pkce_pair()
    url = AmazonDeviceClient.login_url(serial, challenge, language=language)
    click.echo("Opening Amazon sign-in in your browser.")
    click.echo(
        "After sign-in finishes, copy the complete amazon.com URL from the address bar and paste it here."
    )
    if not webbrowser.open(url):
        click.echo(f"Open this URL manually:\n{url}")
    final_url = click.prompt("Final URL", prompt_suffix=": ").strip()
    with AmazonDeviceClient() as client:
        credentials = client.register(final_url, verifier, serial, pid)
    runtime.store.add(Account(name, credentials), replace=replace)
    runtime.store.save(runtime.config)
    click.echo(f"Login complete. Account {name!r} saved to {runtime.config}")


@user_group.command(name="rm", help="remove an account by name, directed ID, or serial")
@click.argument("identifier")
@click.pass_obj
def user_remove(runtime: Runtime, identifier: str) -> None:
    removed = runtime.store.remove(identifier)
    if not removed:
        raise click.ClickException(f"no account matches {identifier!r}")
    runtime.store.save(runtime.config)
    click.echo(f"Removed {removed.name}")


@cli.group(name="book", short_help="list and download Kindle books")
def book_group() -> None:
    pass


def _selected_accounts(runtime: Runtime, identifier: str | None, *, one: bool) -> list[Account]:
    accounts = runtime.store.accounts
    if not accounts:
        raise click.ClickException("no accounts found; run `kindl user add`")
    if identifier:
        account = runtime.store.get(identifier)
        if not account:
            raise click.ClickException(f"no account matches {identifier!r}")
        return [account]
    if one and len(accounts) > 1:
        raise click.UsageError("--user is required when more than one account exists")
    return accounts[:1] if one else accounts


def _library(account: Account, limit: int) -> list[LibraryItem]:
    with AmazonDeviceClient(account.credentials) as client:
        return client.library(limit=limit)


@book_group.command(name="list", help="list books")
@click.option("-u", "--user", help="limit results to an account name, directed ID, or serial")
@click.option("--limit", type=click.IntRange(1, 1000), default=1000, show_default=True)
@click.option("--json", "as_json", is_flag=True, help="write JSON instead of a table")
@click.option(
    "--export-library",
    type=click.File(mode="w", encoding="utf-8"),
    help="write the raw normalized library JSON to a file",
)
@click.pass_obj
def book_list(
    runtime: Runtime,
    user: str | None,
    limit: int,
    as_json: bool,
    export_library: object | None,
) -> None:
    records: list[dict[str, object]] = []
    for account in _selected_accounts(runtime, user, one=False):
        for item in _library(account, limit):
            records.append({**item.as_dict(), "owner": account.name})
    records.sort(key=lambda item: (str(item["title"]).casefold(), str(item["owner"])))
    if export_library:
        json.dump(records, export_library, indent=2)
        export_library.write("\n")
    if as_json:
        click.echo(json.dumps(records, indent=2))
        return
    rows = [
        (item["title"], ", ".join(item["authors"]), item["asin"], item["owner"])
        for item in records
    ]
    click.echo(tabulate(rows, headers=["Title", "Author", "ASIN", "Owner"], tablefmt=runtime.table_format))


def _safe_component(value: str) -> str:
    value = INVALID_PATH_CHARS.sub("_", value).strip(" .")[:100]
    if not value:
        value = "Untitled"
    if value.split(".", 1)[0].upper() in WINDOWS_RESERVED_NAMES:
        value = f"_{value}"
    return value


def format_book_path(output_dir: Path, format_str: str, item: LibraryItem) -> Path:
    try:
        rendered = format_str.format_map(
            {
                "ASIN": _safe_component(item.asin),
                "Title": _safe_component(item.title),
                "Author": _safe_component(" & ".join(item.authors)),
            }
        )
    except KeyError as exc:
        raise click.UsageError(f"unknown --format-str field: {exc.args[0]}") from exc
    pure = PurePosixPath(rendered.replace("\\", "/"))
    if pure.is_absolute() or any(part in {"", ".", ".."} for part in pure.parts):
        raise click.UsageError("--format-str must be a relative path without . or ..")
    return output_dir.joinpath(*(_safe_component(part) for part in pure.parts))


def _download_complete(book_dir: Path, *, package: bool) -> bool:
    if package:
        return (book_dir / f"{book_dir.name}.kfx-zip").is_file()
    if not (book_dir / "manifest.json").is_file():
        return False
    names = [path.name.lower() for path in book_dir.iterdir() if path.is_file()]
    return any(name.endswith((".azw8", ".azw9")) for name in names) and any(
        "drm-voucher" in name or name.endswith(".voucher") for name in names
    )


@book_group.command(name="get", short_help="download one, several, or all books")
@click.option("-u", "--user", help="account name, directed ID, or serial")
@click.option(
    "-o",
    "--output-dir",
    type=click.Path(path_type=Path, file_okay=False),
    default=Path("kindl_downloads"),
    show_default=True,
)
@click.option("-a", "--get-all", is_flag=True, help="download every library book")
@click.option("--limit", type=click.IntRange(1, 1000), default=1000, show_default=True)
@click.option("--required-only", is_flag=True, help="skip deferred optional resources")
@click.option("--no-package", is_flag=True, help="do not create a KFX-ZIP bundle")
@click.option("--force", is_flag=True, help="redownload books that already exist")
@click.option(
    "-f",
    "--format-str",
    default=DEFAULT_FORMAT,
    show_default=True,
    help="output path using {Author}, {Title}, and {ASIN}; / creates directories",
)
@click.argument("asin", nargs=-1)
@click.pass_obj
def book_get(
    runtime: Runtime,
    user: str | None,
    output_dir: Path,
    get_all: bool,
    limit: int,
    required_only: bool,
    no_package: bool,
    force: bool,
    format_str: str,
    asin: tuple[str, ...],
) -> None:
    if get_all and asin:
        raise click.UsageError("cannot pass ASINs together with --get-all")
    if not get_all and not asin:
        raise click.UsageError("pass at least one ASIN, or use --get-all")
    account = _selected_accounts(runtime, user, one=True)[0]
    items = _library(account, limit)
    by_asin = {item.asin.casefold(): item for item in items}
    requested = list(dict.fromkeys(item.asin for item in items)) if get_all else list(dict.fromkeys(asin))

    output_dir.mkdir(parents=True, exist_ok=True)
    failures: list[tuple[str, str]] = []
    with AmazonDeviceClient(account.credentials) as client:
        client.refresh_device_credentials()
        runtime.store.save(runtime.config)
        for product_id in requested:
            item = by_asin.get(product_id.casefold()) or LibraryItem(product_id, product_id)
            book_dir = format_book_path(output_dir, format_str, item)
            if get_all and not force and _download_complete(book_dir, package=not no_package):
                click.echo(f"Skipping already downloaded book {book_dir}")
                continue
            try:
                click.echo(f"Downloading {product_id} to {book_dir}", err=True)
                paths = client.download(
                    product_id,
                    output_dir,
                    include_optional=not required_only,
                    destination=book_dir,
                )
                for path in paths:
                    click.echo(path)
                if not no_package:
                    click.echo(package_kfx_zip(book_dir))
            except (ValueError, RuntimeError, OSError, httpx.HTTPError) as exc:
                if not get_all:
                    raise
                failures.append((product_id, str(exc)))
                click.echo(f"Skipping failed download for {product_id}: {exc}", err=True)
    if failures:
        raise click.ClickException(
            f"{len(failures)} of {len(requested)} downloads failed: "
            + ", ".join(product_id for product_id, _ in failures)
        )


@book_group.command(name="package", help="package a downloaded component directory as KFX-ZIP")
@click.argument("book-dir", type=click.Path(path_type=Path, file_okay=False, exists=True))
@click.option("-o", "--output", type=click.Path(path_type=Path, dir_okay=False))
def book_package(book_dir: Path, output: Path | None) -> None:
    click.echo(package_kfx_zip(book_dir, output))


def main(argv: list[str] | None = None) -> int:
    try:
        cli.main(args=argv, prog_name="kindl", standalone_mode=False)
        return 0
    except click.ClickException as exc:
        exc.show()
        return exc.exit_code
    except (TypeError, ValueError, RuntimeError, OSError, httpx.HTTPError) as exc:
        if "--debug" in (argv if argv is not None else sys.argv[1:]):
            raise
        click.echo(f"error: {exc}", err=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
