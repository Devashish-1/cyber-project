import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "verify_artifact_backup", Path("/app/ops/verify_artifact_backup.py")
)
module = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = module
spec.loader.exec_module(module)


class ArtifactBackupVerifierTests(unittest.TestCase):
    def build_archive(self, root: Path, *, tamper=False):
        run_id = "11111111-1111-1111-1111-111111111111"
        artifact_id = "22222222-2222-2222-2222-222222222222"
        event = b'{"event":"succeeded"}\n'
        event_digest = hashlib.sha256(event).hexdigest()
        manifest = {
            "version": 1,
            "algorithm": "sha256",
            "run_id": run_id,
            "files": [{"name": "events.jsonl", "size": len(event), "sha256": event_digest}],
        }
        manifest_bytes = json.dumps(manifest).encode()
        source = b"print('ok')\n"
        source_digest = hashlib.sha256()
        source_digest.update(
            f"app.py\0{len(source)}\0{hashlib.sha256(source).hexdigest()}\n".encode()
        )
        archive_path = root / "artifacts.tar.gz"
        with tarfile.open(archive_path, "w:gz") as archive:
            files = {
                f"evidence/runs/{run_id}/integrity.json": manifest_bytes,
                f"evidence/runs/{run_id}/events.jsonl": event + (b"tampered" if tamper else b""),
                f"data/sources/{artifact_id}/content/app.py": source,
            }
            for name, content in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(content)
                archive.addfile(info, io.BytesIO(content))
        return archive_path, run_id, hashlib.sha256(manifest_bytes).hexdigest(), artifact_id, source_digest.hexdigest()

    def test_verifies_database_bound_evidence_and_source_content(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, run_id, seal, artifact_id, source_hash = self.build_archive(Path(directory))
            result = module.verify_archive(archive, {run_id: seal}, {artifact_id: source_hash})
            self.assertEqual(result["sealed_runs_verified"], 1)
            self.assertEqual(result["source_artifacts_verified"], 1)

    def test_rejects_changed_sealed_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, run_id, seal, artifact_id, source_hash = self.build_archive(Path(directory), tamper=True)
            with self.assertRaisesRegex(ValueError, "missing or changed"):
                module.verify_archive(archive, {run_id: seal}, {artifact_id: source_hash})


if __name__ == "__main__":
    unittest.main()
