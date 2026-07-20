import pathlib
import tempfile
import unittest

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
        with self.assertRaisesRegex(app.AuditInputError, "not approved"):
            app.validate_hashes(hashes, "22000")
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


if __name__ == "__main__":
    unittest.main()
