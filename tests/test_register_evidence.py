"""Final register pass as a test (all risks): a status needs evidence that exists.

A row marked Implemented or Verified must have every file named in its Evidence cell present
in the repository, except items marked "(to add)" or "(pending)", which are the evidence the
row does not yet rely on. Statuses in the xlsx must match the markdown export.
"""

from __future__ import annotations

import glob
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HEADER = ["ID", "Register", "Asset", "Threat / technique", "ATT&CK / ATLAS", "Vulnerability", "L", "I", "Inherent",
          "Control", "rL", "rI", "Residual", "Evidence", "Owner", "Status"]
DONE = {"Implemented", "Verified"}
ALLOWED = {"Open", "In progress", "Implemented", "Verified"}


def rows() -> list[dict[str, str]]:
    out = []
    for line in (ROOT / "RISK-REGISTER.md").read_text().splitlines():
        if re.match(r"\| R-\d+ ", line):
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            out.append(dict(zip(HEADER, cells)))
    return out


def evidence_paths(cell: str) -> list[str]:
    found = []
    for item in cell.split(";"):
        if "(to add)" in item or "(pending)" in item:
            continue
        item = re.sub(r"\([^)]*\)", "", item)
        for token in re.split(r",| and ", item):
            token = token.strip()
            if not re.fullmatch(r"[\w./*-]+", token) or not ("." in token or "/" in token):
                continue
            found.append(f"docs/evidence/{token}" if "/" not in token and re.match(r"s\d-", token) else token)
    return found


def test_register_has_ten_rows_with_known_statuses() -> None:
    data = rows()
    assert [r["ID"] for r in data] == [f"R-{i:02d}" for i in range(1, 11)]
    assert {r["Status"] for r in data} <= ALLOWED


@pytest.mark.parametrize("row", [r for r in rows() if r["Status"] in DONE], ids=lambda r: r["ID"])
def test_done_rows_have_existing_evidence(row: dict[str, str]) -> None:
    paths = evidence_paths(row["Evidence"])
    assert paths, "no evidence listed"
    assert any(p.startswith("docs/evidence/") for p in paths), "no file under docs/evidence"
    missing = [p for p in paths if not glob.glob(str(ROOT / p))]
    assert not missing, f"{row['ID']} is {row['Status']} but these do not exist: {missing}"


def test_xlsx_statuses_match_the_markdown() -> None:
    openpyxl = pytest.importorskip("openpyxl")
    ws = openpyxl.load_workbook(ROOT / "RISK-REGISTER.xlsx", data_only=True)["Risk Register"]
    status = {}
    for row in ws.iter_rows(values_only=True):
        if row and isinstance(row[0], str) and re.fullmatch(r"R-\d+", row[0]):
            status[row[0]] = str(row[-1]).strip()
    assert status == {r["ID"]: r["Status"] for r in rows()}
