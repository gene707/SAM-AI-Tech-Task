import unittest
import os
import sys
import shutil
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from integrity_checker import HashCalculator, HashComparator, BaselineManager

class TestFileIntegrityChecker(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.file1 = os.path.join(self.test_dir, "sample1.txt")
        self.file2 = os.path.join(self.test_dir, "sample2.txt")
        with open(self.file1, "w") as f:
            f.write("Hello Antigravity Integrity World!")
        with open(self.file2, "w") as f:
            f.write("Hello Antigravity Integrity World!")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_hash_calculation(self):
        h_sha256 = HashCalculator.calculate_hash(self.file1, "sha256")
        h_md5 = HashCalculator.calculate_hash(self.file1, "md5")
        self.assertEqual(len(h_sha256), 64)
        self.assertEqual(len(h_md5), 32)

    def test_compare_files(self):
        match, h1, h2 = HashComparator.compare_two_files(self.file1, self.file2, "sha256")
        self.assertTrue(match)
        self.assertEqual(h1, h2)

    def test_compare_hash(self):
        actual_h = HashCalculator.calculate_hash(self.file1, "sha256")
        match, _, _ = HashComparator.compare_file_with_hash(self.file1, actual_h, "sha256")
        self.assertTrue(match)

    def test_baseline_and_modification(self):
        manifest = os.path.join(tempfile.gettempdir(), "test_baseline_manifest.json")
        mgr = BaselineManager(self.test_dir, "sha256")
        mgr.generate_baseline(manifest)
        
        # Verify baseline initial state
        res = mgr.verify_baseline(manifest)
        self.assertEqual(res["summary"]["modified"], 0)
        self.assertEqual(res["summary"]["deleted"], 0)
        self.assertEqual(res["summary"]["added"], 0)
        
        # Modify file1
        with open(self.file1, "a") as f:
            f.write(" Added extra line.")

        # Add file3
        file3 = os.path.join(self.test_dir, "sample3.txt")
        with open(file3, "w") as f:
            f.write("New file content")

        # Delete file2
        os.remove(self.file2)

        res2 = mgr.verify_baseline(manifest)
        self.assertEqual(res2["summary"]["modified"], 1)
        self.assertEqual(res2["summary"]["deleted"], 1)
        self.assertEqual(res2["summary"]["added"], 1)

if __name__ == "__main__":
    unittest.main()
