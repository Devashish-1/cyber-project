import hashlib
import tempfile
import unittest
from pathlib import Path

from app.runner import verify_source_content


def content_digest(content_root: Path) -> str:
    entries = []
    for path in content_root.rglob("*"):
        if path.is_file():
            data = path.read_bytes()
            entries.append((path.relative_to(content_root).as_posix(), len(data), hashlib.sha256(data).hexdigest()))
    digest = hashlib.sha256()
    for relative_path, size, file_digest in sorted(entries):
        digest.update(f"{relative_path}\0{size}\0{file_digest}\n".encode("utf-8"))
    return digest.hexdigest()


class RunnerSourceIntegrityTests(unittest.TestCase):
    def test_matching_content_is_accepted(self):
        with tempfile.TemporaryDirectory() as temporary_root:
            content = Path(temporary_root) / "content"
            content.mkdir()
            (content / "app.py").write_text("print('ok')\n", encoding="utf-8")
            self.assertIsNone(verify_source_content(content, content_digest(content)))

    def test_changed_content_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_root:
            content = Path(temporary_root) / "content"
            content.mkdir()
            source = content / "app.py"
            source.write_text("approved\n", encoding="utf-8")
            expected = content_digest(content)
            source.write_text("changed\n", encoding="utf-8")
            self.assertIn("integrity verification", verify_source_content(content, expected))

    def test_missing_baseline_is_rejected(self):
        with tempfile.TemporaryDirectory() as temporary_root:
            content = Path(temporary_root) / "content"
            content.mkdir()
            self.assertIn("re-upload", verify_source_content(content, None))


if __name__ == "__main__":
    unittest.main()
