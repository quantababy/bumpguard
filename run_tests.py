"""Convenience test runner from project root."""

import os
import sys
import unittest

if __name__ == "__main__":
    root_dir = os.path.dirname(os.path.abspath(__file__))
    backend_dir = os.path.join(root_dir, "backend")
    tests_dir = os.path.join(backend_dir, "tests")

    if backend_dir not in sys.path:
        sys.path.insert(0, backend_dir)

    loader = unittest.TestLoader()
    suite = loader.discover(start_dir=tests_dir, top_level_dir=backend_dir)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
