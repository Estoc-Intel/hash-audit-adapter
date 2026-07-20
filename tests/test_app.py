import io
import pathlib
import tempfile
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

import app


class AdapterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=pathlib.Path(__file__).parent)
        self.root = pathlib.Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def write(self, name, content, binary=False):
        path = self.root / name
        if binary:
            path.write_bytes(content)
        else:
            path.write_text(content, encoding="ascii")
        return path

    def test_allows_only_reviewed_modes_and_exact_hash_shapes(self):
        synthetic_digest = "a" * 32
        hashes = self.write("hashes.txt", f"{synthetic_digest}\n")
        self.assertEqual(app.validate_hashes(hashes, "0"), 1)
        with self.assertRaisesRegex(app.AuditInputError, "not approved") as error:
            app.validate_hashes(hashes, "22000")
        self.assertEqual(error.exception.code, "hash_mode_rejected")
        bad = self.write("bad.txt", "not-a-hash\n")
        with self.assertRaisesRegex(app.AuditInputError, "not valid MD5"):
            app.validate_hashes(bad, "0")

    def test_rejects_duplicate_hashes(self):
        value = "a" * 32
        hashes = self.write("hashes.txt", f"{value}\n{value.upper()}\n")
        with self.assertRaisesRegex(app.AuditInputError, "duplicates"):
            app.validate_hashes(hashes, "0")

    def test_rejects_paths_outside_approved_mount(self):
        approved = self.root / "approved"
        approved.mkdir()
        inside = approved / "hashes.txt"
        inside.write_text("value", encoding="ascii")
        outside = self.root / "outside.txt"
        outside.write_text("value", encoding="ascii")
        self.assertEqual(app.validate_mounted_file(str(inside), "Hash file", 100, approved), inside.resolve())
        with self.assertRaisesRegex(app.AuditInputError, "approved input mount"):
            app.validate_mounted_file(str(outside), "Hash file", 100, approved)

    def test_validates_wordlist_bounds(self):
        wordlist = self.write("words.txt", b"alpha\nbeta\n", binary=True)
        self.assertEqual(app.validate_wordlist(wordlist), 2)
        bad = self.write("bad-words.txt", b"a\x00b\n", binary=True)
        with self.assertRaisesRegex(app.AuditInputError, "NUL"):
            app.validate_wordlist(bad)

    def test_command_has_no_user_controlled_options(self):
        command = app.build_command("1400", pathlib.Path("/workspace/inputs/hashes"), pathlib.Path("/workspace/inputs/words"), pathlib.Path("/tmp/out"))
        self.assertEqual(command[1:5], ["--attack-mode", "0", "--hash-type", "1400"])
        self.assertIn("--potfile-disable", command)
        self.assertIn("--restore-disable", command)
        self.assertIn("--logfile-disable", command)
        self.assertNotIn("--rules-file", command)
        self.assertEqual(
            [pathlib.PurePath(value).parts[-3:] for value in command[-2:]],
            [("workspace", "inputs", "hashes"), ("workspace", "inputs", "words")],
        )

    def test_parses_hex_plaintext_without_separator_ambiguity(self):
        synthetic_digest = "a" * 32
        synthetic_plaintext = b"fixture:value"
        plaintext_hex = synthetic_plaintext.hex()
        outfile = self.write("recovered.txt", f"{synthetic_digest}:{plaintext_hex}\n")
        self.assertEqual(app.parse_results(outfile), [{
            "hash": synthetic_digest,
            "password_utf8": synthetic_plaintext.decode("ascii"),
            "password_hex": plaintext_hex,
        }])

    def test_classifies_gpu_failures_without_returning_diagnostics(self):
        diagnostic = b"Failed to initialize NVIDIA RTC library. secret-never-returned"
        self.assertEqual(app.classify_hashcat_failure(255, diagnostic), "gpu_toolkit_unavailable")
        self.assertNotIn("secret", app.classify_hashcat_failure(255, diagnostic))
        self.assertEqual(
            app.classify_hashcat_failure(255, b"No OpenCL, HIP or CUDA compatible platform found"),
            "gpu_runtime_unavailable",
        )
        self.assertEqual(app.classify_hashcat_failure(2, b"aborted"), "hashcat_interrupted")
        self.assertEqual(app.classify_hashcat_failure(255, b"unknown"), "hashcat_execution_failed")

    def test_main_emits_only_a_fixed_safe_error_code(self):
        stderr = io.StringIO()
        with patch.object(app, "run", side_effect=app.AuditExecutionError("gpu_toolkit_unavailable")):
            with redirect_stderr(stderr):
                self.assertEqual(app.main(["app.py", "1400", "hashes", "wordlist"]), 2)
        self.assertEqual(stderr.getvalue(), "ESTOC_SAFE_ERROR:gpu_toolkit_unavailable\n")

    def test_dockerfile_includes_toolkit_without_using_inherited_nvidia_apt_source(self):
        dockerfile = (pathlib.Path(__file__).parents[1] / "Dockerfile").read_text(encoding="utf-8")
        self.assertTrue(dockerfile.startswith("FROM nvidia/cuda:12.8.1-devel-ubuntu24.04\n"))
        remove_source = "rm -f /etc/apt/sources.list.d/cuda*.list /etc/apt/sources.list.d/cuda*.sources"
        self.assertIn(remove_source, dockerfile)
        self.assertLess(dockerfile.index(remove_source), dockerfile.index("apt-get update"))


if __name__ == "__main__":
    unittest.main()
