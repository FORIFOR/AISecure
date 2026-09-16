"""Required quality job: an optional-security skip is a failure in this job."""
from pathlib import Path
import argparse
import json
import sys
import time
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
p=argparse.ArgumentParser();p.add_argument('--report',type=Path,default=Path('/tmp/aisecure-tests.json'))
a=p.parse_args();started=time.monotonic()
suite=unittest.defaultTestLoader.discover('tests')
r=unittest.TextTestRunner(verbosity=2).run(suite)
report={'tests_run':r.testsRun,'failures':len(r.failures),'errors':len(r.errors),'skipped':len(r.skipped),'duration_seconds':round(time.monotonic()-started,2),'scope':'automated_synthetic_tests_not_live_enterprise_validation'}
a.report.parent.mkdir(parents=True,exist_ok=True);a.report.write_text(json.dumps(report,indent=2))
raise SystemExit(0 if r.wasSuccessful() and not r.skipped else 1)
