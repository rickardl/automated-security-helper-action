#!/usr/bin/env python3
"""
Unit tests for SARIF enhancement with scanned files list
"""

import json
import sys
import tempfile
import unittest
from pathlib import Path

# Add the src directory to the path
sys.path.insert(0, str(Path(__file__).parent.parent.parent / 'src'))

from utils.sarif_enhancer import (  # noqa: E402
    enhance_sarif_with_file_coverage,
    load_scanned_files_from_ash_list
)


class TestSARIFEnhancement(unittest.TestCase):
    """Test cases for SARIF enhancement functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.minimal_sarif = {
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "test-tool",
                            "version": "1.0.0"
                        }
                    },
                    "results": []
                }
            ]
        }

        self.sample_files_list = """
/workspace/README.md
/workspace/action.yml
/workspace/src/core/config_parser.py
/workspace/src/github/sarif_pr_commenter.py
/workspace/tests/unit/test_severity_filter.py
"""

    def test_load_scanned_files_from_ash_list(self):
        """Test loading scanned files from ASH's files list."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create test files list
            files_list_path = temp_path / "scanned_files.txt"
            with open(files_list_path, 'w', encoding='utf-8') as f:
                f.write(self.sample_files_list.strip())

            # Create test source directory and files
            source_dir = temp_path / "source"
            source_dir.mkdir()

            # Create the files that are in the list
            (source_dir / "README.md").write_text("# Test", encoding='utf-8')
            (source_dir / "action.yml").write_text("name: test", encoding='utf-8')

            src_dir = source_dir / "src"
            src_dir.mkdir()
            core_dir = src_dir / "core"
            core_dir.mkdir()
            github_dir = src_dir / "github"
            github_dir.mkdir()
            tests_dir = source_dir / "tests"
            tests_dir.mkdir()
            unit_dir = tests_dir / "unit"
            unit_dir.mkdir()

            (core_dir / "config_parser.py").write_text("# config", encoding='utf-8')
            (github_dir / "sarif_pr_commenter.py").write_text("# sarif", encoding='utf-8')
            (unit_dir / "test_severity_filter.py").write_text("# test", encoding='utf-8')

            # Test loading
            scanned_files = load_scanned_files_from_ash_list(str(files_list_path), str(source_dir))

            # Verify results
            self.assertEqual(len(scanned_files), 5)

            # Check that all expected files are loaded
            file_names = [f.name for f in scanned_files]
            self.assertIn("README.md", file_names)
            self.assertIn("action.yml", file_names)
            self.assertIn("config_parser.py", file_names)
            self.assertIn("sarif_pr_commenter.py", file_names)
            self.assertIn("test_severity_filter.py", file_names)

    def test_enhance_sarif_with_scanned_files_list(self):
        """Test SARIF enhancement using a scanned files list."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create test SARIF file
            sarif_path = temp_path / "test.sarif"
            with open(sarif_path, 'w', encoding='utf-8') as f:
                json.dump(self.minimal_sarif, f)

            # Create test files list
            files_list_path = temp_path / "scanned_files.txt"
            with open(files_list_path, 'w', encoding='utf-8') as f:
                f.write(self.sample_files_list.strip())

            # Create test source directory and files
            source_dir = temp_path / "source"
            source_dir.mkdir()
            (source_dir / "README.md").write_text("# Test", encoding='utf-8')
            (source_dir / "action.yml").write_text("name: test", encoding='utf-8')

            # Test enhancement
            output_path = temp_path / "enhanced.sarif"
            files_count = enhance_sarif_with_file_coverage(
                str(sarif_path),
                str(source_dir),
                str(output_path),
                str(files_list_path)
            )

            # Verify enhancement
            self.assertEqual(files_count, 2)  # Only 2 files actually exist

            # Load and verify enhanced SARIF
            with open(output_path, 'r', encoding='utf-8') as f:
                enhanced_sarif = json.load(f)

            run = enhanced_sarif['runs'][0]

            # Check artifacts
            artifacts = run.get('artifacts', [])
            self.assertEqual(len(artifacts), 2)

            # Check invocations
            invocations = run.get('invocations', [])
            self.assertEqual(len(invocations), 1)
            self.assertEqual(invocations[0]['properties']['filesScanned'], 2)

            # Check originalUriBaseIds
            self.assertIn('originalUriBaseIds', run)
            self.assertIn('SRCROOT', run['originalUriBaseIds'])

    def test_enhance_sarif_fallback_to_heuristic(self):
        """Test SARIF enhancement falls back to heuristic discovery when no files list is provided."""
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)

            # Create test SARIF file
            sarif_path = temp_path / "test.sarif"
            with open(sarif_path, 'w', encoding='utf-8') as f:
                json.dump(self.minimal_sarif, f)

            # Create source directory with some Python files
            source_dir = temp_path / "source"
            source_dir.mkdir()
            (source_dir / "main.py").write_text("print('hello')", encoding='utf-8')
            (source_dir / "README.md").write_text("# Test", encoding='utf-8')

            # Test enhancement without files list
            output_path = temp_path / "enhanced.sarif"
            files_count = enhance_sarif_with_file_coverage(
                str(sarif_path),
                str(source_dir),
                str(output_path),
                None  # No scanned files list
            )

            # Verify enhancement used heuristic discovery
            self.assertGreater(files_count, 0)

            # Load and verify enhanced SARIF
            with open(output_path, 'r', encoding='utf-8') as f:
                enhanced_sarif = json.load(f)

            run = enhanced_sarif['runs'][0]
            artifacts = run.get('artifacts', [])
            self.assertGreater(len(artifacts), 0)


if __name__ == '__main__':
    unittest.main()
