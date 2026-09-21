import json,tempfile,stat,copy
from pathlib import Path
from unittest.mock import patch
from jsonschema import Draft202012Validator
from aisecure.control.inspection import report_schema,inspect_document
from aisecure.control.inspect_file import save_report
out=Path(__file__).parent
for name in ('pass-a-result.json','pass-c-result.json'):
    r=json.loads((out/name).read_text()); v=Draft202012Validator(report_schema('bundle')); v.validate(r)
    for key,value in [('report_schema','unknown'),('release_authorized',True)]:
        assert list(v.iter_errors({**r,key:value})),key
r=inspect_document(b'fictional broken pdf','pdf'); Draft202012Validator(report_schema()).validate(r)
with tempfile.TemporaryDirectory() as d:
    p=Path(d)/'report.json'; body=json.dumps(r)
    # Publication must observe a fully flushed complete file before final path exists.
    import os
    link=os.link
    def observe(src,dst):
        assert not Path(dst).exists(); assert json.loads(Path(src).read_text())==r
        assert stat.S_IMODE(Path(src).stat().st_mode)==0o600
        return link(src,dst)
    with patch('aisecure.control.inspect_file.os.link',side_effect=observe): save_report(p,body)
    assert json.loads(p.read_text())==r
    q=Path(d)/'dangling'; q.symlink_to(Path(d)/'missing')
    try: save_report(q,body)
    except FileExistsError: pass
    else: raise AssertionError('dangling symlink replaced')
    assert q.is_symlink() and not q.exists()
    fail=Path(d)/'fail'
    with patch('aisecure.control.inspect_file.os.fsync',side_effect=OSError('injected')):
        try: save_report(fail,body)
        except OSError: pass
        else: raise AssertionError('injection ignored')
    assert not fail.exists() and not list(Path(d).glob('.aisecure-report-*'))
print('PASS independent prior/current bundle validation, unsafe flags, malformed SDK output, complete private pre-publication file, dangling symlink no-clobber, failure cleanup')
