"""Reproduce the 20-dataset synthetic evaluation; no external service calls."""
from pathlib import Path
import json
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from aisecure.baseline import scenario
from aisecure.evaluate import evaluate

if __name__ == '__main__':
    output = Path(sys.argv[1])
    if output.exists():
        raise SystemExit('Use a new output file; do not replace evidence.')
    cases = [scenario(f'controlled-{seed}-{attack}', seed=seed, days=7, users=10, attack=attack)
             for seed in range(1, 11) for attack in (False, True)]
    report = evaluate(cases)
    report['scope'] = '20 synthetic seven-day datasets: 10 seeds × normal/one injected attack chain; not 20 distinct attack types, not enterprise logs'
    report['source_commit'] = subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()
    report['source_dirty'] = bool(subprocess.check_output(['git', 'status', '--porcelain'], text=True))
    output.write_text(json.dumps(report, ensure_ascii=False, indent=2))
    print(json.dumps(report['totals'], ensure_ascii=False))
