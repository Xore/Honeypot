from __future__ import annotations

import importlib.util
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


if __name__ == "__main__":
    unittest.main()
