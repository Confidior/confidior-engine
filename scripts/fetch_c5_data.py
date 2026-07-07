"""Download and extract C5:2026 machine-readable control catalog from BSI.

Usage:
    uv run --no-project python scripts/fetch_c5_data.py

Downloads the official C5:2026 YAML data from BSI and extracts it to
data/c5/v2026-04-bsi/. Requires no dependencies beyond stdlib.

Terms: BSI publishes C5 under CC BY-ND 4.0 for non-commercial use.
Commercial use requires a separate agreement with BSI.
See https://www.bsi.bund.de for details.
"""
from __future__ import annotations

import re
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path
from tempfile import NamedTemporaryFile, TemporaryDirectory

_C5_URL = (
    "https://www.bsi.bund.de/SharedDocs/Downloads/EN/BSI/CloudComputing/"
    "ComplianceControlsCatalogue/2026/C5_machine_readable.zip"
    "?__blob=publicationFile&v=4"
)
_ATTR_NOTICE = (
    "C5:2026 criteria catalogue (c) Bundesamt fuer Sicherheit in der "
    "Informationstechnik (BSI), CC BY-ND 4.0. Non-commercial use only. "
    "Commercial use requires separate agreement with BSI."
)


def main():
    data_dir = Path(__file__).resolve().parent.parent / "data"
    extract_dir = data_dir / "c5" / "v2026-04-bsi"

    if extract_dir.is_dir():
        print(f"C5 data already exists at {extract_dir}")
        return

    print(f"Downloading C5:2026 control data from BSI...")
    with NamedTemporaryFile(suffix=".zip") as tmp:
        urllib.request.urlretrieve(_C5_URL, tmp.name)
        with TemporaryDirectory() as tmpdir:
            with zipfile.ZipFile(tmp.name) as zf:
                zf.extractall(tmpdir)
            extracted = Path(tmpdir)
            yml_dirs = [d for d in extracted.iterdir() if d.is_dir() and list(d.glob("*.yml"))]
            src = yml_dirs[0] if yml_dirs else extracted
            extract_dir.mkdir(parents=True, exist_ok=True)
            for f in src.glob("*.yml"):
                if re.match(r"^[A-Z]{2,3}\.yml$", f.name):
                    shutil.copy2(f, extract_dir / f.name)

    notice_path = extract_dir / "NOTICE.txt"
    notice_path.write_text(_ATTR_NOTICE)

    print(f"Extracted to {extract_dir}")
    print(f"Attribution: {_ATTR_NOTICE}")


if __name__ == "__main__":
    main()
