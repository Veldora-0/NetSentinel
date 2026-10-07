"""Phase 14 End-to-End Validation: Harness Execution Test.

Verifies:
1. `ValidationHarness.run_all()` completes with zero scenario failures.
2. Machine-readable JSON and Markdown validation reports are written to disk.
3. Every scenario status is explicitly 'PASS'.
"""

import json
import os
import tempfile
import pytest

from validation_harness import ValidationHarness


def test_validation_harness_execution():
    """Verify that running the validation harness executes all scenarios and generates reports."""
    with tempfile.TemporaryDirectory() as tmpdir:
        harness = ValidationHarness(reports_dir=tmpdir)
        summary = harness.run_all()

        assert summary["summary"]["total_scenarios"] == 13
        assert summary["summary"]["passed"] == 13
        assert summary["summary"]["failed"] == 0
        assert summary["summary"]["success_rate_percent"] == 100.0

        # Verify reports written
        json_path = os.path.join(tmpdir, "validation_report.json")
        md_path = os.path.join(tmpdir, "validation_report.md")

        assert os.path.exists(json_path)
        assert os.path.exists(md_path)

        with open(json_path, "r") as fh:
            data = json.load(fh)
            assert len(data["scenarios"]) == 13
            for scn in data["scenarios"]:
                assert scn["status"] == "PASS"
