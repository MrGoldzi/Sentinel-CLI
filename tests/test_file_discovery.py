"""Unit tests for the file discovery module.

Tests .gitignore-aware file traversal, binary detection, and include/exclude patterns.
"""

from __future__ import annotations

import os
import tempfile
import unittest

from sentinel.scanner.file_discovery import (
    discover_files,
    is_binary_file,
    should_skip_by_name,
    count_files,
    TEXT_EXTS,
    ALWAYS_EXCLUDE_DIRS,
    BINARY_EXTS,
)


class TestAlwaysExcludeDirs(unittest.TestCase):
    """Tests that ALWAYS_EXCLUDE_DIRS contains standard dirs."""

    def test_git_excluded(self):
        self.assertIn(".git", ALWAYS_EXCLUDE_DIRS)

    def test_node_modules_excluded(self):
        self.assertIn("node_modules", ALWAYS_EXCLUDE_DIRS)

    def test_pycache_excluded(self):
        self.assertIn("__pycache__", ALWAYS_EXCLUDE_DIRS)

    def test_venv_excluded(self):
        self.assertIn(".venv", ALWAYS_EXCLUDE_DIRS)


class TestShouldSkipByName(unittest.TestCase):
    """Tests for file name/extension filtering."""

    def test_skip_pyc(self):
        self.assertTrue(should_skip_by_name("module.pyc"))

    def test_skip_jpg(self):
        self.assertTrue(should_skip_by_name("image.jpg"))

    def test_skip_git_dir(self):
        self.assertTrue(should_skip_by_name(".git"))

    def test_skip_png(self):
        self.assertTrue(should_skip_by_name("image.png"))

    def test_skip_pdf(self):
        self.assertTrue(should_skip_by_name("doc.pdf"))

    def test_not_skip_py(self):
        self.assertFalse(should_skip_by_name("module.py"))

    def test_not_skip_txt(self):
        self.assertFalse(should_skip_by_name("readme.txt"))

    def test_not_skip_js(self):
        self.assertFalse(should_skip_by_name("app.js"))

    def test_not_skip_yaml(self):
        self.assertFalse(should_skip_by_name("config.yaml"))

    def test_not_skip_env(self):
        self.assertFalse(should_skip_by_name(".env"))


class TestIsBinaryFile(unittest.TestCase):
    """Tests for binary file detection."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_text_file_not_binary(self):
        path = os.path.join(self.temp_dir, "test.txt")
        with open(path, "w") as f:
            f.write("Hello, world!\n")
        self.assertFalse(is_binary_file(path))

    def test_python_file_not_binary(self):
        path = os.path.join(self.temp_dir, "test.py")
        with open(path, "w") as f:
            f.write('print("hello")\n')
        self.assertFalse(is_binary_file(path))

    def test_binary_file_detected(self):
        path = os.path.join(self.temp_dir, "test.bin")
        with open(path, "wb") as f:
            f.write(b"\x00\x01\x02\x03")
        self.assertTrue(is_binary_file(path))

    def test_empty_file_binary_check(self):
        path = os.path.join(self.temp_dir, "empty.txt")
        with open(path, "w") as f:
            pass
        self.assertTrue(is_binary_file(path))

    def test_nonexistent_file(self):
        self.assertTrue(is_binary_file("/nonexistent/file"))


class TestDiscoverFiles(unittest.TestCase):
    """Tests for file discovery."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        # Create a simple file structure
        os.makedirs(os.path.join(self.temp_dir, "src"))
        os.makedirs(os.path.join(self.temp_dir, "docs"))

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_file(self, *path_parts: str, content: str = ""):
        full_path = os.path.join(self.temp_dir, *path_parts)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w") as f:
            f.write(content)
        return full_path

    def test_empty_directory(self):
        files = discover_files(self.temp_dir)
        self.assertEqual(files, [])

    def test_discover_python_files(self):
        self._create_file("src", "main.py", content='print("hello")\n')
        self._create_file("src", "utils.py", content='def foo(): pass\n')
        files = discover_files(self.temp_dir)
        self.assertEqual(len(files), 2)

    def test_discover_mixed_extensions(self):
        self._create_file("src", "main.py")
        self._create_file("README.md", content="# Readme")
        self._create_file("config.yaml", content="key: value")
        files = discover_files(self.temp_dir)
        self.assertEqual(len(files), 3)

    def test_gitignore_respected(self):
        # Create a .gitignore that ignores .md files
        # Note: the .gitignore file itself is also discovered, so total_files = 2
        with open(os.path.join(self.temp_dir, ".gitignore"), "w") as f:
            f.write("*.md\n")
        self._create_file("README.md")
        self._create_file("src", "main.py")
        files = discover_files(self.temp_dir, include_gitignored=False)
        # .gitignore itself + main.py = 2 (README.md is gitignored)
        self.assertEqual(len(files), 2)
        self.assertFalse(any(f.endswith(".md") for f in files))

    def test_gitignore_optional_by_default(self):
        """By default, include_gitignored=True so .gitignored files are included."""
        with open(os.path.join(self.temp_dir, ".gitignore"), "w") as f:
            f.write("*.md\n")
        self._create_file("README.md")
        self._create_file("src", "main.py")
        files = discover_files(self.temp_dir)
        # .gitignore + README.md + src/main.py = 3
        self.assertEqual(len(files), 3)

    def test_exclude_patterns(self):
        self._create_file("main.py")
        self._create_file("test_main.py")
        self._create_file("utils.py")
        files = discover_files(self.temp_dir, exclude_patterns=["test_*"])
        self.assertEqual(len(files), 2)
        self.assertFalse(any("test_main" in f for f in files))

    def test_include_patterns(self):
        self._create_file("main.py")
        self._create_file("config.yaml")
        self._create_file("README.md")
        files = discover_files(self.temp_dir, include_patterns=["*.py"])
        self.assertEqual(len(files), 1)
        self.assertTrue(all(f.endswith(".py") for f in files))

    def test_skip_git_directory(self):
        os.makedirs(os.path.join(self.temp_dir, ".git"))
        self._create_file(".git", "config")
        self._create_file("src", "main.py")
        files = discover_files(self.temp_dir)
        # .git directory should be skipped
        self.assertEqual(len(files), 1)

    def test_skip_node_modules(self):
        os.makedirs(os.path.join(self.temp_dir, "node_modules"))
        self._create_file("node_modules", "package.json")
        self._create_file("src", "main.py")
        files = discover_files(self.temp_dir)
        self.assertEqual(len(files), 1)

    def test_scan_all_includes_everything(self):
        os.makedirs(os.path.join(self.temp_dir, ".git"))
        self._create_file(".git", "config")
        self._create_file("node_modules", "package.json")
        self._create_file("image.jpg")
        files = discover_files(self.temp_dir, scan_all=True)
        # scan_all includes everything, including binary files
        self.assertGreaterEqual(len(files), 3)

    def test_binary_file_skipped_by_default(self):
        path = os.path.join(self.temp_dir, "image.png")
        with open(path, "wb") as f:
            f.write(b"\x89PNG\r\n\x1a\n")
        self._create_file("main.py")
        files = discover_files(self.temp_dir)
        # PNG should be excluded by extension
        self.assertEqual(len(files), 1)

    def test_subdirectory_discovery(self):
        self._create_file("src", "main.py")
        self._create_file("src", "utils", "helpers.py")
        self._create_file("docs", "guide.md")
        files = discover_files(self.temp_dir)
        self.assertEqual(len(files), 3)
        self.assertTrue(any("helpers.py" in f for f in files))

    def test_discover_relative_paths(self):
        self._create_file("src", "main.py")
        files = discover_files(self.temp_dir)
        self.assertTrue(all(not os.path.isabs(f) for f in files))


class TestCountFiles(unittest.TestCase):
    """Tests for count_files function."""

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def _create_file(self, *path_parts: str):
        full_path = os.path.join(self.temp_dir, *path_parts)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, "w") as f:
            f.write("content\n")

    def test_count_files(self):
        self._create_file("a.py")
        self._create_file("b.py")
        self._create_file("c.py")
        count = count_files(self.temp_dir)
        self.assertEqual(count, 3)


class TestTextExts(unittest.TestCase):
    """Tests that TEXT_EXTS contains expected extensions."""

    def test_common_extensions_present(self):
        for ext in [".py", ".js", ".ts", ".md", ".txt", ".yaml", ".json", ".env"]:
            self.assertIn(ext, TEXT_EXTS, f"{ext} should be in TEXT_EXTS")

    def test_binary_extensions_not_present(self):
        for ext in [".pyc", ".jpg", ".png", ".zip", ".pdf"]:
            self.assertNotIn(ext, TEXT_EXTS, f"{ext} should not be in TEXT_EXTS")


if __name__ == "__main__":
    unittest.main()
