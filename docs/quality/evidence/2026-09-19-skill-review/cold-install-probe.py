import base64,json,os,subprocess,sys,tempfile,time
from pathlib import Path
from aisecure.control.example_document import sample_file
out=Path('docs/quality/evidence/2026-09-19-skill-review').resolve()
wheel=Path('/tmp/aisecure-skill-wheels/ai_secure_local_prototype-0.4.0a3.dev0-py3-none-any.whl')
commands=[];logs=[];started=time.monotonic()
with tempfile.TemporaryDirectory(prefix='aisecure-clean-') as directory:
 env=Path(directory)/'venv'
 def run(cmd,expected=0):
  result=subprocess.run(cmd,cwd=directory,env={k:v for k,v in os.environ.items() if k not in ['PYTHONPATH','PYTHONHOME']},stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True,timeout=180)
  logs.append(result.stdout);commands.append({'command':cmd,'exit_code':result.returncode,'expected_exit_code':expected})
  if result.returncode!=expected: raise RuntimeError('cold installation step failed; see log')
  return result.stdout
 run([sys.executable,'-m','venv',str(env)])
 python=str(env/'bin/python')
 run([python,'-m','pip','--isolated','--disable-pip-version-check','install','--index-url','https://pypi.org/simple',str(wheel)+'[control]'])
 file=Path(directory)/'sample.xlsx';file.write_bytes(base64.b64decode(sample_file('社外秘：cold install sample')['base64']))
 report=json.loads(run([str(env/'bin/aisecure-inspect'),str(file)],3));assert report['verdict']=='review' and report['release_authorized'] is False
 run([str(env/'bin/aisecure-control'),'--help'])
 run([python,'-c',"from aisecure.control.inspection import report_schema; assert report_schema()['properties']['report_schema']['const']=='aisecure.document-report.v1'"])
 packages=run([python,'-m','pip','--disable-pip-version-check','list','--format=json'])
(out/'cold-install.log').write_text('\n'.join(logs))
(out/'cold-install.json').write_text(json.dumps({'status':'PASS','command':'PYTHONPATH=. .venv/bin/python /tmp/aisecure-cold-install.py','exit_code':0,'elapsed_seconds':round(time.monotonic()-started,2),'includes':'fresh venv, dependency acquisition from PyPI/cache, actual CLI report, control entry point, schema','commands':commands,'packages':json.loads(packages),'report':report},indent=2)+'\n')
print('PASS fresh venv installation and real CLI report')
