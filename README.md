# PhishScope

Offline phishing-URL risk scoring with the reasoning included. You give it a
URL, it returns a 0–100 score built from named, weighted heuristics — and each
heuristic explains itself. No API keys, no network calls, no dependencies
beyond the Python standard library.

I built this while studying URL-based phishing: the tricks are mostly simple
(hostname padding, lookalike characters, brands parked in subdomains, `@`
abuse), so a transparent rule-based scorer is both useful and a good way to
understand the techniques. Verdicts are heuristics, not ground truth —read the flags, don't just trust the number.

## Quick start

The repo ships a single-file build, `phishscope.py`, so on any Linux box:

```bash
curl -LO https://raw.githubusercontent.com/MANYMITE/PhishScope/main/phishscope.py
python3 phishscope.py paypa1.com
```

Works on anything with Python 3.8+ — servers, Raspberry Pi, air-gapped
machines. CI runs the standalone file in Debian, Ubuntu, Fedora, Arch,
Rocky Linux and openSUSE containers to keep that honest.

From a checkout (or on Windows):

```bash
git clone https://github.com/MANYMITE/PhishScope.git
cd PhishScope
python -m phishscope --explain paypa1.com            # single URL
python -m phishscope --file examples/sample_urls.txt # batch, one URL per line
python -m phishscope --json paypa1.com               # machine-readable
pip install .                                        # installs the `phishscope` command
```

Exit code is `1` when any URL scores MEDIUM or above, so you can drop it into
a CI job or a shell script that gates on the result.



## Project layout

```
phishscope/            the package: analyzer.py, data.py, cli.py
phishscope.py          generated single-file build (what curl-and-run users get)
tools/build_standalone.py   regenerates phishscope.py from the package
tests/                 unit tests
examples/              sample URL set (all synthetic, nothing live)
```

If you change anything under `phishscope/`, regenerate the single-file build
so it stays in sync:

```bash
python tools/build_standalone.py
```

## Tests

```bash
python -m unittest discover -s tests
```

## Roadmap

- Levenshtein typosquatting (`paypall.com`, `paypa1.net`)
- Full Public Suffix List instead of the small built-in table
- Optional VirusTotal enrichment, still offline by default
- MISP/STIX export for SOC pipelines

## License

MIT — see [LICENSE](LICENSE).
