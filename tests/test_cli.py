"""Tests for the CLI layer."""

import io
import json
import unittest
from contextlib import redirect_stdout
from tempfile import TemporaryDirectory
from pathlib import Path

from phishscope.cli import build_parser, main, render_report
from phishscope.analyzer import analyze


class CliTests(unittest.TestCase):
    def test_exit_code_clean(self):
        self.assertEqual(main(["https://www.paypal.com/signin"]), 0)

    def test_exit_code_suspicious(self):
        self.assertEqual(main(["https://paypal.com.evil.tk/login"]), 1)

    def test_quiet_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["-q", "https://paypa1.com"])
        out = buf.getvalue()
        self.assertIn("HIGH", out)
        self.assertIn("paypa1.com", out)

    def test_json_output(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["--json", "https://paypa1.com"])
        data = json.loads(buf.getvalue())
        self.assertEqual(data[0]["verdict"], "HIGH")
        self.assertTrue(any(f["name"] == "homoglyph-impersonation" for f in data[0]["flags"]))

    def test_explain_renders_reasons(self):
        report = analyze("https://paypal.com.evil.tk/login")
        text = render_report(report, explain=True, color=False)
        self.assertIn("real brands never sit", text)

    def test_file_input(self):
        with TemporaryDirectory() as tmp:
            urls_file = Path(tmp) / "urls.txt"
            urls_file.write_text(
                "https://www.paypal.com/signin\nhttps://paypa1.com\n", encoding="utf-8"
            )
            buf = io.StringIO()
            with redirect_stdout(buf):
                code = main(["-q", "--file", str(urls_file)])
            self.assertEqual(code, 1)
            self.assertEqual(buf.getvalue().count("\n"), 2)

    def test_main_rejects_empty(self):
        self.assertEqual(main([]), 2)

    def test_quiet_output_clean_url(self):
        buf = io.StringIO()
        with redirect_stdout(buf):
            main(["-q", "https://www.paypal.com/signin"])
        self.assertIn("CLEAN", buf.getvalue())


if __name__ == "__main__":
    unittest.main()
