import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from uuid import uuid4

from fastapi import HTTPException

from app import main


class SourceArtifactStorageTests(unittest.TestCase):
    def test_existing_content_directory_is_accepted(self):
        artifact_id = uuid4()
        with tempfile.TemporaryDirectory() as temporary_root:
            content = Path(temporary_root) / str(artifact_id) / "content"
            content.mkdir(parents=True)
            (content / "app.py").write_text("print('ok')\n", encoding="utf-8")
            with patch.object(main, "SOURCE_ROOT", Path(temporary_root)):
                main.require_source_artifact_storage(artifact_id)

    def test_missing_content_directory_fails_closed(self):
        with tempfile.TemporaryDirectory() as temporary_root:
            with patch.object(main, "SOURCE_ROOT", Path(temporary_root)):
                with self.assertRaises(HTTPException) as raised:
                    main.require_source_artifact_storage(uuid4())

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("missing from storage", raised.exception.detail)

    def test_symbolic_link_inside_content_is_rejected(self):
        artifact_id = uuid4()
        with tempfile.TemporaryDirectory() as temporary_root:
            root = Path(temporary_root)
            content = root / str(artifact_id) / "content"
            content.mkdir(parents=True)
            target = root / "outside.txt"
            target.write_text("outside\n", encoding="utf-8")
            try:
                (content / "linked.txt").symlink_to(target)
            except OSError:
                self.skipTest("Symbolic links are unavailable in this test environment")
            with patch.object(main, "SOURCE_ROOT", root):
                with self.assertRaises(HTTPException) as raised:
                    main.require_source_artifact_storage(artifact_id)

        self.assertEqual(raised.exception.status_code, 409)
        self.assertIn("unsafe symbolic link", raised.exception.detail)


if __name__ == "__main__":
    unittest.main()
