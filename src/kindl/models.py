from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True, slots=True)
class LibraryItem:
    asin: str
    title: str
    authors: tuple[str, ...] = ()
    publishers: tuple[str, ...] = ()
    content_type: str = ""
    cde_content_type: str = ""
    purchase_date: str = ""
    publication_date: str = ""
    content_size: int | None = None

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["authors"] = list(self.authors)
        result["publishers"] = list(self.publishers)
        return result
