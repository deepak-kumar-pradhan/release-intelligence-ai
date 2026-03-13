from typing import Iterable, List, Optional


class ReleaseNotesAgent:
    def __init__(self, data: Optional[Iterable[str]] = None):
        self.data: List[str] = list(data or [])

    def generate_release_notes(self, items: Optional[Iterable[str]] = None) -> str:
        if items is not None:
            self.data = list(items)

        release_notes = "Release Notes:\n"
        for item in self.data:
            release_notes += f"- {item}\n"
        return release_notes

    def save_release_notes(self, file_path: str) -> None:
        with open(file_path, "w", encoding="utf-8") as file:
            file.write(self.generate_release_notes())