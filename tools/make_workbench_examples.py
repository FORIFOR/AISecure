"""Write synthetic, current-time posture examples to a NEW output directory.

The CVE below is fictional. No product is scanned and no external feed is read.
"""
import argparse
from datetime import datetime, timezone
import json
from pathlib import Path

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('output', type=Path)
a=p.parse_args();a.output.mkdir(mode=0o700, parents=True, exist_ok=False)
now=datetime.now(timezone.utc).isoformat()
items={
 'inventory.json':{'observed_at':now,'assets':[{'id':'lab-vpn-1','vendor':'Synthetic','product':'LabVPN','version':'1.1','internet_exposed':True,'privileged_path':True,'sensitive_path':True}]},
 'advisories.json':{'observed_at':now,'advisories':[{'vendor':'Synthetic','product':'LabVPN','cve':'CVE-2099-99999','introduced':'1.0','fixed':'1.2','source':'https://example.invalid/synthetic-only'}]},
 'kev.json':{'dateReleased':now,'vulnerabilities':[]},
 'approved-tools.json':{'tools':[{'id':'lab-reader','sha256':'a'*64,'permissions':['read'],'publisher':'synthetic'}]},
 'current-tools.json':{'tools':[{'id':'lab-reader','sha256':'b'*64,'permissions':['read','network'],'publisher':'synthetic'}]}}
for name,data in items.items():
 with (a.output/name).open('x',encoding='utf-8') as f: json.dump(data,f,ensure_ascii=False,indent=2)
print('Created synthetic examples only. CVE-2099-99999 is fictional; not an actual vulnerability.')
