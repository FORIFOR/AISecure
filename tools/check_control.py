#!/usr/bin/env python3
"""Run reproducible local checks; passing does not certify deployment readiness."""
import argparse,json,subprocess,sys
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);args=p.parse_args()
    root=Path(__file__).resolve().parents[1]
    commands=[[sys.executable,'-m','unittest','discover','-s','tests/control','-t','.','-v'],
              ['node','--test','browser/aisecure/protocol.test.js']]
    results=[]
    for command in commands:
        try:
            run=subprocess.run(command,cwd=root,capture_output=True,text=True,timeout=240)
            results.append({'command':command,'returncode':run.returncode,'output':run.stdout+run.stderr})
        except Exception:results.append({'command':command,'returncode':None,'output':'Execution could not be completed.'})
    result={'local_checks':results,'local_checks_passed':all(r['returncode']==0 for r in results),
            'production_certified':False,'real_browser_enforcement_tested':False,'vpn_containment_tested':False}
    args.output.write_text(json.dumps(result,ensure_ascii=False,indent=2))
    return 0 if result['local_checks_passed'] else 1
if __name__=='__main__':raise SystemExit(main())
