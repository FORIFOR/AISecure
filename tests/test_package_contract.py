"""Installed resources and current release documentation stay coherent."""
from pathlib import Path
import json
import subprocess
import sys
import tempfile
import unittest
from aisecure.posture import assess, audit_tools
from aisecure.gateway import GatewayError
ROOT=Path(__file__).resolve().parents[1]

class PackageContractTests(unittest.TestCase):
 def test_legacy_web_matches_repository(self):
  for name in ('index.html','style.css','quiet-cinema.css','app.js','i18n.js'):
   self.assertEqual((ROOT/'web'/name).read_bytes(),(ROOT/'aisecure/legacy_web'/name).read_bytes())
 def test_task_matrix_covers_every_requested_id(self):
  text=(ROOT/'docs/operations/TASK_MATRIX.md').read_text()
  for group,count in [('A',8),('B',5),('C',5),('D',7),('E',7)]:
   for n in range(1,count+1):self.assertIn(f'| {group}{n} |',text)
 def test_published_quickstart_matches_the_recorded_app(self):
  # The homepage recording shows aisecure.control, so the published command must
  # start that app, not the older workbench.
  for name in ['docs/index.html','docs/index.ja.html','README.md','README.ja.md']:
   text=(ROOT/name).read_text();self.assertIn('python -m aisecure.control --demo',text)
  for name in ['docs/index.html','docs/index.ja.html']:
   self.assertNotIn('aisecure.workbench --demo',(ROOT/name).read_text())
 def test_synthetic_examples_are_runnable_and_not_actual_cve(self):
  with tempfile.TemporaryDirectory() as temp:
   out=Path(temp)/'synthetic'
   r=subprocess.run([sys.executable,str(ROOT/'tools/make_workbench_examples.py'),str(out)],capture_output=True,text=True)
   self.assertEqual(r.returncode,0,r.stderr)
   load=lambda name:json.loads((out/name).read_text())
   result=assess(load('inventory.json'),load('advisories.json'),load('kev.json'))
   self.assertEqual(result['findings'][0]['status'],'affected')
   self.assertFalse(result['live_device_verified'])
   self.assertIn('fictional',r.stdout)
 def test_malformed_tool_permission_refused(self):
  with self.assertRaises(GatewayError):
   audit_tools({'tools':[{'id':'x','sha256':'a'*64,'publisher':'x','permissions':[[]]}]},{'tools':[]})
