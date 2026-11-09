"""Unit tests for safe in-memory extraction and path traversal prevention."""

import io
import tarfile
import unittest

from bumpguard.extract.safe_extractor import SafeExtractor, safe_path


class TestSafeExtractor(unittest.TestCase):
    def test_safe_path_rejections(self):
        # Traversal attempts
        self.assertIsNone(safe_path("../evil.js"))
        self.assertIsNone(safe_path("foo/../../bar.js"))
        self.assertIsNone(safe_path("/etc/passwd"))
        self.assertIsNone(safe_path("\\Windows\\System32\\cmd.exe"))
        self.assertIsNone(safe_path("C:\\autoexec.bat"))
        self.assertIsNone(safe_path("D:/evil.sh"))
        self.assertIsNone(safe_path("con.js"))
        self.assertIsNone(safe_path("NUL"))
        self.assertIsNone(safe_path(""))
        self.assertIsNone(safe_path("foo/\0/bar.js"))

        # Valid relative paths
        self.assertEqual(safe_path("package/index.js"), "package/index.js")
        self.assertEqual(safe_path("./package/lib/utils.js"), "package/lib/utils.js")
        self.assertEqual(safe_path("sub/folder/file.json"), "sub/folder/file.json")

    def _create_tarball(self, files_dict) -> bytes:
        bio = io.BytesIO()
        with tarfile.open(fileobj=bio, mode="w:gz") as tar:
            for name, content in files_dict.items():
                data = content.encode("utf-8") if isinstance(content, str) else content
                ti = tarfile.TarInfo(name=name)
                ti.size = len(data)
                tar.addfile(ti, io.BytesIO(data))
        return bio.getvalue()

    def test_safe_tarball_extraction(self):
        raw_tar = self._create_tarball({
            "package/package.json": '{"name": "test-pkg", "version": "1.0.0"}',
            "package/index.js": 'console.log("hello world");',
        })

        extractor = SafeExtractor()
        archive = extractor.extract_tarball(raw_tar)

        self.assertEqual(archive.file_count, 2)
        self.assertIn("package.json", archive.files)
        self.assertIn("index.js", archive.files)
        self.assertEqual(archive.files["index.js"].text, 'console.log("hello world");')
        self.assertFalse(archive.files["index.js"].is_truncated)

    def test_tarball_drops_traversal_entry(self):
        # Mix a good file with a malicious traversal path
        raw_tar = self._create_tarball({
            "package/index.js": 'console.log("valid");',
            "../../etc/cron.d/backdoor": "malicious script",
        })

        extractor = SafeExtractor()
        archive = extractor.extract_tarball(raw_tar)

        # The traversal file should be dropped
        self.assertIn("index.js", archive.files)
        self.assertNotIn("../../etc/cron.d/backdoor", archive.files)
        self.assertNotIn("etc/cron.d/backdoor", archive.files)

    def test_tarball_size_limit(self):
        raw_tar = self._create_tarball({
            "package/large.bin": b"A" * 1024,
        })
        # Set max_compressed_bytes to strictly less than the archive size
        strict_extractor = SafeExtractor(max_compressed_bytes=len(raw_tar) - 1)
        with self.assertRaises(ValueError):
            strict_extractor.extract_tarball(raw_tar)


if __name__ == "__main__":
    unittest.main()
