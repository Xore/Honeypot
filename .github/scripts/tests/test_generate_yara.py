from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "generate_yara.py"
SPEC = importlib.util.spec_from_file_location("generate_yara", SCRIPT)
assert SPEC and SPEC.loader
generate_yara = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(generate_yara)


def string_rule(count: int = 5) -> str:
    strings = "\n".join(
        f'        $s{i} = "indicator-{i}" ascii nocase'
        for i in range(1, count + 1)
    )
    return (
        "rule AutoGen_Test\n"
        "{\n"
        "    meta:\n"
        "        auto_generated = true\n\n"
        "    strings:\n"
        f"{strings}\n\n"
        "    condition:\n"
        f"        {generate_yara.required_string_matches(count)} of ($s*)\n"
        "}\n"
    )


class GeneratorValidationTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("yara"), "yara CLI is not installed")
    def test_real_compiler_accepts_generated_rule_and_rejects_orphan(self) -> None:
        valid_rule = generate_yara.build_rule(
            "fixture",
            "fixture",
            ["indicator-one", "indicator-two", "indicator-three"],
            ["a" * 64],
            {"fixture"},
            [],
            [],
        )
        valid, error = generate_yara.validate_rule(valid_rule)
        self.assertTrue(valid, error)

        invalid, error = generate_yara.validate_rule(
            'rule Broken { strings: $orphan = "unused" condition: true }'
        )
        self.assertFalse(invalid)
        self.assertIn("unreferenced string", error)

    def test_validation_fails_closed_without_yara(self) -> None:
        with mock.patch.object(generate_yara.shutil, "which", return_value=None):
            valid, error = generate_yara.validate_rule(string_rule())

        self.assertFalse(valid)
        self.assertIn("not found", error)

    def test_append_rescales_threshold_and_validates_before_write(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.yar"
            path.write_text(string_rule(5))
            additions = [f"new-indicator-{i}" for i in range(1, 6)]

            with mock.patch.object(
                generate_yara, "validate_rule", return_value=(True, "")
            ) as validate:
                changed, error, candidate = generate_yara.append_new_strings_to_rule(
                    path, additions
                )

            self.assertTrue(changed)
            self.assertEqual("", error)
            self.assertIsNotNone(candidate)
            self.assertIn("4 of ($s*)", path.read_text())
            validate.assert_called_once_with(path.read_text())

    def test_invalid_update_does_not_replace_active_rule(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "test.yar"
            original = string_rule(5)
            path.write_text(original)

            with mock.patch.object(
                generate_yara, "validate_rule", return_value=(False, "compile error")
            ):
                changed, error, candidate = generate_yara.append_new_strings_to_rule(
                    path, ["new-indicator"]
                )

            self.assertFalse(changed)
            self.assertEqual("compile error", error)
            self.assertIsNotNone(candidate)
            self.assertEqual(original, path.read_text())

    def test_hash_only_rule_is_promoted_when_strings_become_available(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            reports = root / "reports"
            samples = root / "samples"
            output = root / "rules"
            reports.mkdir()
            samples.mkdir()
            output.mkdir()
            (reports / "sample.json").write_text("{}")
            (output / "testfamily.yar").write_text(
                generate_yara.build_hash_only_rule(
                    "testfamily", ["a" * 64], {"PE"}, []
                )
            )
            profile = {
                "sha256": "b" * 64,
                "filename": "sample.exe",
                "file_type": "PE",
                "family_names": ["testfamily"],
                "binary_strings": [
                    "https://malware.example/payload",
                    "Global\\MalwareMutex",
                    "C:\\Malware\\payload.exe",
                ],
                "references": [],
                "tags": [],
            }

            with (
                mock.patch.object(generate_yara, "parse_report", return_value=profile),
                mock.patch.object(generate_yara, "validate_rule", return_value=(True, "")),
            ):
                self.assertEqual(0, generate_yara.run(reports, samples, output))

            promoted = (output / "testfamily.yar").read_text()
            self.assertNotIn("hash_only   = true", promoted)
            self.assertIn("strings:", promoted)
            self.assertIn("3 of ($s*)", promoted)


class ArchivedSampleExtractionTests(unittest.TestCase):
    """Committed samples are password-protected archives (analyze_samples.py's
    publish convention), not raw binaries. extract_strings_from_sample must
    unpack before running `strings`, or every generated rule is built from
    the archive container's own compressed bytes instead of the payload.
    """

    DISTINCTIVE = "this-string-only-exists-inside-the-payload-4f8c2e"

    def _zip_containing(self, dest: Path, password: str | None) -> Path:
        import pyzipper

        # analyze_samples.is_scannable() (reused via expand_file) filters
        # extracted archive *members* by magic bytes -- a plain-text member
        # is treated as bundled noise (READMEs etc.) and dropped, the same
        # heuristic the scanner-submission path already relies on. A real
        # sample is a PE/ELF/etc. binary, not bare text, so lead with a PE
        # magic to fixture the common case realistically. Known, pre-existing
        # limitation this inherits rather than fixes: a genuinely plain-text
        # dropper (samples/Scripts/) extracted from an archive would also be
        # filtered here -- out of scope for this change, since that heuristic
        # is analyze_samples.py's own and changing it could affect what gets
        # submitted to external scanners, not just YARA generation.
        payload = dest / "payload.bin"
        payload.write_bytes(
            b"MZ" + (self.DISTINCTIVE + "\n").encode() * 4  # long enough for `strings -n 8`
        )
        archive = dest / "sample.zip"
        with pyzipper.AESZipFile(
            archive, "w",
            compression=pyzipper.ZIP_LZMA,
            encryption=pyzipper.WZ_AES if password else None,
        ) as zf:
            if password:
                zf.setpassword(password.encode())
                zf.setencryption(pyzipper.WZ_AES, nbits=256)
            zf.write(payload, arcname="payload.bin")
        payload.unlink()
        return archive

    @unittest.skipUnless(shutil.which("strings"), "strings (binutils) is not installed")
    def test_unpacks_before_extracting_strings(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self._zip_containing(root, password="infected")

            # The bug this covers: scanning the archive directly finds
            # nothing, because `strings` on a real (LZMA/deflate-compressed)
            # zip essentially never recovers the payload's own text.
            raw_scan = generate_yara.extract_strings_from_binary(archive)
            self.assertNotIn(
                self.DISTINCTIVE, raw_scan,
                "fixture assumption broken: the payload string is directly "
                "recoverable from the compressed archive without unpacking, "
                "so this test cannot distinguish unpacked from not"
            )

            unpacked = generate_yara.extract_strings_from_sample(
                archive, passwords=["infected"], tmpdir=root / "extract"
            )
            self.assertIn(self.DISTINCTIVE, unpacked)

    @unittest.skipUnless(shutil.which("strings"), "strings (binutils) is not installed")
    def test_tries_each_configured_password_in_order(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self._zip_containing(root, password="malware")

            unpacked = generate_yara.extract_strings_from_sample(
                archive, passwords=["infected", "malware", "virus"],
                tmpdir=root / "extract",
            )
            self.assertIn(self.DISTINCTIVE, unpacked)

    @unittest.skipUnless(shutil.which("strings"), "strings (binutils) is not installed")
    def test_falls_back_to_the_archive_itself_when_no_password_matches(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            archive = self._zip_containing(root, password="not-in-the-configured-list")

            # Must not raise and must not silently return nothing without a
            # reason -- falls back to scanning the archive container, same
            # as if it had never been unpacked at all.
            result = generate_yara.extract_strings_from_sample(
                archive, passwords=["infected", "malware"], tmpdir=root / "extract"
            )
            self.assertIsInstance(result, list)

    @unittest.skipUnless(shutil.which("strings"), "strings (binutils) is not installed")
    def test_non_archive_extension_is_scanned_directly(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            binary = root / "payload.exe"
            binary.write_bytes((self.DISTINCTIVE + "\n").encode() * 4)

            result = generate_yara.extract_strings_from_sample(
                binary, passwords=["infected"], tmpdir=root / "extract"
            )
            self.assertIn(self.DISTINCTIVE, result)

    @unittest.skipUnless(shutil.which("strings"), "strings (binutils) is not installed")
    def test_parse_report_uses_unpacked_strings_when_tmpdir_given(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            samples = root / "samples"
            samples.mkdir()
            archive = self._zip_containing(samples, password="infected")

            report = root / "report.json"
            report.write_text(json.dumps({
                "sha256": "c" * 64,
                "filename": archive.name,
                "size": archive.stat().st_size,
                "results": {},
            }))

            profile = generate_yara.parse_report(
                report, samples, passwords=["infected"], tmpdir=root / "extract"
            )
            self.assertIsNotNone(profile)
            self.assertIn(self.DISTINCTIVE, profile["binary_strings"])


if __name__ == "__main__":
    unittest.main()
