"""Offline wheel smoke: python -m tools.check_control_package WHEEL."""
import tempfile,subprocess,sys,os,json,base64
from pathlib import Path
from aisecure.control.example_document import sample_file
with tempfile.TemporaryDirectory() as directory:
    target=Path(directory)/'installed'
    install=subprocess.run([sys.executable,'-m','pip','install','--no-index','--no-deps','--target',str(target),str(Path(sys.argv[1]).resolve())],capture_output=True,text=True)
    assert install.returncode==0,install.stderr
    source=Path(directory)/'sample.xlsx';source.write_bytes(base64.b64decode(sample_file('社外秘：wheel smoke')['base64']))
    command=[str(target/'bin'/'aisecure-inspect'),str(source)]
    run=subprocess.run(command,cwd=directory,env={**os.environ,'PYTHONPATH':str(target)},capture_output=True,text=True)
    assert run.returncode==3,run.stderr
    result=json.loads(run.stdout);assert result['verdict']=='review';assert result['release_authorized'] is False
    print('PASS: installed wheel console script inspects real bytes outside repo, exit 3 and valid JSON')
    check=subprocess.run([sys.executable,'-c',"from aisecure.control.inspection import report_schema; assert report_schema()['$schema'].endswith('2020-12/schema'); assert report_schema('bundle')['properties']['report_schema']['const']=='aisecure.bundle-report.v1'"],cwd=directory,env={**os.environ,'PYTHONPATH':str(target)},capture_output=True,text=True)
    assert check.returncode==0,check.stderr
    print('PASS: installed wheel exposes both bundled JSON schemas without network access')
