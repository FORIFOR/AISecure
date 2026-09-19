import io,json,unittest,zipfile
from unittest.mock import patch
from aisecure.control.documents import inspect,inspect_bytes,Scanner,MAX_FILE
from aisecure.control.common import ControlError,decode
from .helpers import office,pdf

class DocumentTests(unittest.TestCase):
    def test_all_office_parts_including_hidden(self):
        r=inspect(office(text='api_key=synthetic-password-123',hidden=True),'xlsx')
        self.assertEqual(r.verdict,'block');self.assertIn('DOC-HIDDEN-CONTENT',[f['rule'] for f in r.findings])
    def test_ppt_notes(self):
        r=inspect(office('pptx',extra={'ppt/notesSlides/notesSlide1.xml':'<notes><t>api_key=synthetic-note-key</t></notes>'}),'pptx')
        self.assertEqual(r.verdict,'block')
    def test_clean_is_not_release_permission(self):
        r=inspect(office(),'xlsx');self.assertEqual(r.verdict,'no_findings');self.assertFalse(r.report()['release_authorized'])
    def test_pii_not_in_report(self):
        r=inspect(office(text='sensitive-person@example.invalid'),'xlsx')
        self.assertEqual(r.verdict,'review');self.assertNotIn('sensitive-person',json.dumps(r.report()))
    def test_embedded_image_partial(self):
        r=inspect(office(extra={'xl/media/image1.png':b'not-real-image'}),'xlsx');self.assertEqual(r.coverage,'partial')
    def test_macro_blocked(self):
        r=inspect(office(extra={'xl/vbaProject.bin':b'synthetic'}),'xlsx');self.assertEqual(r.verdict,'block')
    def test_embedded_ole_blocked(self):
        r=inspect(office(extra={'xl/embeddings/object.bin':b'synthetic'}),'xlsx');self.assertEqual(r.verdict,'block')
    def test_external_relationship_review(self):
        r=inspect(office(extra={'xl/_rels/book.xml.rels':'<Relationships><Relationship TargetMode="External" Target="https://example.invalid/"/></Relationships>'}),'xlsx')
        self.assertEqual(r.verdict,'review')
    def test_xml_entities_rejected(self):
        r=inspect(office(extra={'xl/test.xml':'<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><x>&a;</x>'}),'xlsx')
        self.assertEqual(r.coverage,'unreadable');self.assertNotIn('root:',r.text)
    def test_traversal_rejected(self):
        r=inspect(office(extra={'../test.xml':'<x/>'}),'xlsx');self.assertEqual(r.coverage,'unreadable')
    def test_duplicate_names_rejected(self):
        r=inspect(office(extra={'XL/WORKBOOK.XML':'<x/>'}),'xlsx');self.assertEqual(r.coverage,'unreadable')
    def test_zip_bomb_budget(self):
        r=inspect(office(extra={'xl/huge.xml':' '*(9*1024*1024)}),'xlsx');self.assertEqual(r.coverage,'unreadable')
    def test_extension_mismatch(self):self.assertEqual(inspect(office(),'pdf').verdict,'block')
    def test_old_office_unknown(self):self.assertEqual(inspect(b'fake','xls').coverage,'unreadable')
    def test_split_xml_run_secret(self):
        r=inspect(office(extra={'xl/test.xml':'<x><t>api_</t><t>key=synthetic-secret-value</t></x>'}),'xlsx')
        self.assertEqual(r.verdict,'block')
    def test_pdf_text(self):
        r=inspect(pdf('Public report'),'pdf');self.assertIn('Public report',r.text)
    def test_pdf_secret(self):self.assertEqual(inspect(pdf('api_key=synthetic-pdf-value'),'pdf').verdict,'block')
    def test_pdf_encrypted_unknown(self):self.assertEqual(inspect(pdf(encrypted=True),'pdf').coverage,'unreadable')
    def test_pdf_blank_unknown(self):self.assertEqual(inspect(pdf(blank=True),'pdf').coverage,'partial')
    def test_pdf_image_unknown(self):self.assertEqual(inspect(pdf(image=True),'pdf').coverage,'partial')
    def test_pdf_javascript_blocked(self):self.assertEqual(inspect(pdf(js=True),'pdf').verdict,'block')
    def test_timeout_failclosed(self):
        import subprocess
        with patch('aisecure.control.documents._run_bounded',side_effect=subprocess.TimeoutExpired('worker',1)):
            self.assertEqual(inspect(office(),'xlsx').coverage,'unreadable')
    def test_podman_requires_digest(self):
        with self.assertRaises(ControlError):Scanner('podman','image:latest')
    def test_no_secrets_in_worker_environment(self):
        import os,subprocess
        from aisecure.control.documents import _run_bounded
        real=_run_bounded;seen={}
        def run(*a,**kw):seen.update(kw['env']);return real(*a,**kw)
        with patch.dict(os.environ,{'OPENAI_API_KEY':'SENTINEL'}),patch('aisecure.control.documents._run_bounded',side_effect=run):
            inspect(office(),'xlsx')
        self.assertNotIn('OPENAI_API_KEY',seen)
    def test_json_duplicates_nan_rejected(self):
        for data in (b'{"a":1,"a":2}',b'{"a":NaN}'):
            with self.assertRaises(ControlError):decode(data)

    def test_worker_stdout_bound_enforced_while_reading(self):
        import sys,os
        from aisecure.control.documents import _run_bounded
        with self.assertRaises(ControlError):
            _run_bounded([sys.executable,'-c','import sys;sys.stdout.write("x"*100000)'],input=b'',timeout=2,env={'PATH':os.environ['PATH']},max_output=1024)

    def test_pdf_old_revision_not_silently_ignored(self):
        from pypdf import PdfWriter
        writer=PdfWriter(io.BytesIO(pdf()),incremental=True)
        writer.add_metadata({'/Subject':'synthetic-update'})
        output=io.BytesIO();writer.write(output)
        self.assertEqual(inspect(output.getvalue(),'pdf').coverage,'partial')
    def test_pdf_trailing_data_not_silently_ignored(self):
        self.assertEqual(inspect(pdf()+b'UNINSPECTED_TRAILING_CONTENT','pdf').coverage,'partial')
    def test_fake_office_main_without_content_types_denied(self):
        b=io.BytesIO()
        with zipfile.ZipFile(b,'w') as z:
            z.writestr('[Content_Types].xml','<Types/>');z.writestr('xl/workbook.xml','<workbook/>')
            z.writestr('xl/worksheets/sheet1.xml','<worksheet/>')
        self.assertEqual(inspect(b.getvalue(),'xlsx').verdict,'block')
