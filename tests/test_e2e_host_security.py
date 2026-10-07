"""Phase 14 End-to-End Validation: Host Security & FIM.

Verifies File Integrity Monitoring (FIM):
1. Initial baseline establishment without spurious alerts.
2. Unchanged filesystem verification.
3. Accurate detection of FILE_MODIFIED when contents change.
4. Operator rebaseline updating the stored fingerprint.
5. Accurate detection of FILE_DELETED when file is removed.
6. Persistence boundary: restoring baseline from database preserves the 'exists' flag
   and does NOT emit false-positive alerts on server reboot/restart.
"""

import os
import shutil
import tempfile
import time
import pytest

from app import create_app
from database import db, get_all_fim_baseline_records, save_fim_baseline_record
from host.file_integrity import FileIntegrityMonitor, FILE_MODIFIED, FILE_DELETED, STATUS_BASELINE


@pytest.fixture
def fim_env():
    """Setup temporary test directory and isolated Flask app context."""
    temp_dir = tempfile.mkdtemp(prefix="netsentinel_e2e_fim_")
    test_file = os.path.join(temp_dir, "critical_config.json")
    with open(test_file, "w") as fh:
        fh.write('{"mode": "secure", "allow_root": false}\n')

    cfg = {
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "FIM_SETTINGS": {
            "fim_enabled": True,
            "fim_paths": [test_file],
            "fim_critical_paths": [test_file],
            "fim_interval_sec": 1.0,
        },
    }

    app, _ = create_app(config_class=cfg, start_capture=False)

    with app.app_context():
        db.create_all()

        def _loader():
            with app.app_context():
                return get_all_fim_baseline_records()

        def _saver(path, meta):
            with app.app_context():
                return save_fim_baseline_record(meta)

        fim = FileIntegrityMonitor(
            config=app.config.get("FIM_SETTINGS"),
            baseline_loader=_loader,
            baseline_saver=_saver,
        )
        fim.initialize()

        yield {
            "app": app,
            "fim": fim,
            "test_file": test_file,
            "temp_dir": temp_dir,
            "loader": _loader,
            "saver": _saver,
        }

        db.session.remove()
        db.drop_all()

    shutil.rmtree(temp_dir, ignore_errors=True)


def test_e2e_fim_lifecycle_and_rebaseline(fim_env):
    """Verify FIM correctly identifies modifications, rebaselines, and deletions."""
    fim = fim_env["fim"]
    test_file = fim_env["test_file"]

    # 1. Verification of unchanged state produces no alerts
    events_unchanged = fim.verify_integrity()
    assert len(events_unchanged) == 0

    # 2. Modify file content
    with open(test_file, "w") as fh:
        fh.write('{"mode": "compromised", "allow_root": true}\n')

    events_mod = fim.verify_integrity()
    assert len(events_mod) == 1
    assert events_mod[0].detection_type == FILE_MODIFIED
    assert events_mod[0].severity == "HIGH"  # Configured as critical path

    # 3. Rebaseline to accept the new state
    rebaseline_res = fim.rebuild_baseline([test_file])
    assert rebaseline_res["success"] is True
    assert rebaseline_res["updated_count"] == 1

    # Following verification should now be clean
    assert len(fim.verify_integrity()) == 0

    # 4. Delete file
    os.remove(test_file)
    events_del = fim.verify_integrity()
    assert len(events_del) == 1
    assert events_del[0].detection_type == FILE_DELETED


def test_e2e_fim_persistence_reload_boundary(fim_env):
    """Verify restarting/reloading FIM from SQLite database preserves 'exists' attribute and emits no false alerts."""
    app = fim_env["app"]
    loader = fim_env["loader"]
    saver = fim_env["saver"]
    test_file = fim_env["test_file"]

    with app.app_context():
        # Verify the record exists in SQLite
        persisted = loader()
        assert test_file in persisted
        rec = persisted[test_file]
        assert rec["exists"] is True
        assert rec["status"] == STATUS_BASELINE

        # Simulate fresh server boot: instantiate brand-new FileIntegrityMonitor instance
        reloaded_fim = FileIntegrityMonitor(
            config=app.config.get("FIM_SETTINGS"),
            baseline_loader=loader,
            baseline_saver=saver,
        )
        reloaded_fim.initialize()

        # Crucial invariant: verified state on unchanged file must emit ZERO alerts
        events_after_reload = reloaded_fim.verify_integrity()
        assert len(events_after_reload) == 0, (
            "Reloading baseline from database must not trigger spurious FILE_CREATED/MODIFIED alerts."
        )
