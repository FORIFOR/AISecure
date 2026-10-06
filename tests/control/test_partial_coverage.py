"""Real declared-parser regressions using generated files and capture transports.

No customer documents, external endpoints, or live provider credentials are used.
"""
import base64
import io
import json
import secrets
import struct
import unittest
import zipfile

from aisecure.control.bundles import BundleGateway, sign_bundle
from aisecure.control.documents import inspect
from aisecure.control.inspection import inspect_document
from .helpers import Store, keypair, office, pdf

SENTINEL = b'api_key=synthetic-uninspected-content'


def repack(raw, *, archive_comment=b'', member_comment=b'', extra=b'', compression=zipfile.ZIP_STORED):
    output = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(raw)) as source, zipfile.ZipFile(output, 'w') as target:
        for index, item in enumerate(source.infolist()):
            content = source.read(item)
            item.compress_type = compression
            if index == 0:
                item.comment, item.extra = member_comment, extra
            target.writestr(item, content)
        target.comment = archive_comment
    return output.getvalue()


def insert_before_directory(raw, gap):
    end = raw.rfind(b'PK\x05\x06')
    central = struct.unpack_from('<I', raw, end + 16)[0]
    output = bytearray(raw[:central] + gap + raw[central:])
    struct.pack_into('<I', output, end + len(gap) + 16, central + len(gap))
    return bytes(output)


def insert_in_first_member(raw, payload, *, local_extra=False):
    end = raw.rfind(b'PK\x05\x06')
    central = struct.unpack_from('<I', raw, end + 16)[0]
    name_size, extra_size = struct.unpack_from('<HH', raw, 26)
    body_start = 30 + name_size + extra_size
    old_compressed = struct.unpack_from('<I', raw, 18)[0]
    addition = struct.pack('<HH', 0xCAFE, len(payload)) + payload if local_extra else payload
    insertion = body_start if local_extra else body_start + old_compressed
    output = bytearray(raw[:insertion] + addition + raw[insertion:])
    if local_extra:
        struct.pack_into('<H', output, 28, extra_size + len(addition))
    else:
        struct.pack_into('<I', output, 18, old_compressed + len(addition))
    cursor = central + len(addition)
    first = True
    while output[cursor:cursor + 4] == b'PK\x01\x02':
        offset = struct.unpack_from('<I', output, cursor + 42)[0]
        if offset >= insertion:
            struct.pack_into('<I', output, cursor + 42, offset + len(addition))
        if first and not local_extra:
            struct.pack_into('<I', output, cursor + 20, old_compressed + len(addition))
        first = False
        n, e, c = struct.unpack_from('<HHH', output, cursor + 28)
        cursor += 46 + n + e + c
    struct.pack_into('<I', output, end + len(addition) + 16, central + len(addition))
    return bytes(output)


def envelope_cases(fmt):
    clean = office(fmt)
    prior = io.BytesIO()
    with zipfile.ZipFile(prior, 'w') as archive:
        archive.writestr('prior.txt', SENTINEL)
    first_archive = prior.getvalue()
    end = first_archive.rfind(b'PK\x05\x06')
    local_part_end = struct.unpack_from('<I', first_archive, end + 16)[0]
    commented = repack(clean, archive_comment=SENTINEL)
    return {
        'trailer': clean + SENTINEL,
        'archive-comment': commented,
        'truncated-comment': commented[:-5],
        'member-comment': repack(clean, member_comment=SENTINEL),
        'extra-field': repack(clean, extra=struct.pack('<HH', 0xCAFE, len(SENTINEL)) + SENTINEL),
        'local-only-extra': insert_in_first_member(clean, SENTINEL, local_extra=True),
        'concatenated-archive': first_archive + clean,
        'unreferenced-gap': insert_before_directory(clean, SENTINEL),
        'unindexed-member': insert_before_directory(clean, first_archive[:local_part_end]),
        'deflate-tail': insert_in_first_member(repack(clean, compression=zipfile.ZIP_DEFLATED), SENTINEL),
        'directory-data': office(fmt, extra={'custom/cache/': SENTINEL}),
    }


def pdf_stream(key='/Metadata'):
    from pypdf import PdfReader, PdfWriter
    from pypdf.generic import DecodedStreamObject, NameObject
    writer = PdfWriter()
    writer.append_pages_from_reader(PdfReader(io.BytesIO(pdf())))
    stream = DecodedStreamObject()
    stream.set_data(SENTINEL)
    if key == '/Metadata':
        stream.update({NameObject('/Type'): NameObject('/Metadata'), NameObject('/Subtype'): NameObject('/XML')})
    writer._root_object[NameObject(key)] = writer._add_object(stream)
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def pdf_content_comment():
    from pypdf import PdfReader, PdfWriter
    writer = PdfWriter()
    writer.append_pages_from_reader(PdfReader(io.BytesIO(pdf())))
    content = writer.pages[0]['/Contents']
    content.set_data(content.get_data() + b'\n% ' + SENTINEL + b'\n')
    output = io.BytesIO()
    writer.write(output)
    return output.getvalue()


def descriptor_office():
    class Unseekable(io.BytesIO):
        def seekable(self): return False
        def seek(self, *args): raise OSError('synthetic unseekable output')
    output = Unseekable()
    with zipfile.ZipFile(io.BytesIO(office())) as source, zipfile.ZipFile(output, 'w', zipfile.ZIP_DEFLATED) as target:
        for item in source.infolist(): target.writestr(item.filename, source.read(item))
    return output.getvalue()


class PartialCoverageTests(unittest.TestCase):
    def assert_review(self, raw, fmt, rule=None):
        result = inspect(raw, fmt)
        self.assertNotEqual(result.coverage, 'supported_text_complete')
        self.assertNotEqual(result.verdict, 'no_findings')
        if rule:
            self.assertIn(rule, {finding['rule'] for finding in result.findings})
        self.assertNotIn(SENTINEL.decode(), json.dumps(result.report()))
        self.assertFalse(result.report()['release_authorized'])

    def test_office_envelope_omissions_are_not_complete(self):
        for fmt in ('xlsx', 'pptx'):
            for name, raw in envelope_cases(fmt).items():
                with self.subTest(format=fmt, case=name):
                    self.assert_review(raw, fmt)

    def test_xml_comments_and_processing_instructions_require_review(self):
        for fmt in ('xlsx', 'pptx'):
            for encoding in ('utf-8', 'utf-16'):
                for omitted in (f'<!--{SENTINEL.decode()}-->', f'<?uninspected {SENTINEL.decode()}?>'):
                    for xml in (f'{omitted}<data>Public text</data>', f'<data>{omitted}Public text</data>'):
                        raw_xml = (f'<?xml version="1.0" encoding="{encoding}"?>' + xml).encode(encoding)
                        with self.subTest(format=fmt, encoding=encoding, omitted=omitted[:4], outside=xml.startswith('<!')):
                            self.assert_review(office(fmt, extra={'custom/metadata.xml': raw_xml}), fmt)

    def test_doctype_without_entities_is_unreadable_not_clean(self):
        self.assert_review(office(extra={'custom/types.xml': '<!DOCTYPE data><data>Public</data>'}), 'xlsx')

    def test_xml_declarations_and_literal_comment_text_still_supported(self):
        for encoding in ('utf-8', 'utf-16'):
            xml = (f'<?xml version="1.0" encoding="{encoding}"?><data><![CDATA[<!-- public example -->]]></data>').encode(encoding)
            result = inspect(office(extra={'custom/text.xml': xml}), 'xlsx')
            self.assertEqual(result.coverage, 'supported_text_complete')
            self.assertEqual(result.verdict, 'no_findings')

    def test_public_stored_and_deflated_packages_still_complete(self):
        for fmt in ('xlsx', 'pptx'):
            for compression in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                result = inspect(repack(office(fmt), compression=compression), fmt)
                self.assertEqual(result.coverage, 'supported_text_complete')
                self.assertEqual(result.verdict, 'no_findings')

    def test_ordinary_data_descriptor_package_still_supported(self):
        result = inspect(descriptor_office(), 'xlsx')
        self.assertEqual(result.verdict, 'no_findings')

    def test_descriptor_header_payload_cannot_hide_in_ignored_placeholders(self):
        raw = bytearray(descriptor_office())
        raw[14:26] = b'a@b.invalid!'
        self.assert_review(bytes(raw), 'xlsx', 'DOC-ARCHIVE-UNINSPECTED')

    def test_pdf_metadata_and_other_uninspected_streams_require_review(self):
        for key in ('/Metadata', '/UninspectedPayload'):
            with self.subTest(key=key):
                self.assert_review(pdf_stream(key), 'pdf', 'DOC-PDF-STREAM-UNINSPECTED')

    def test_clean_pdf_content_stream_still_complete(self):
        result = inspect(pdf(), 'pdf')
        self.assertEqual(result.coverage, 'supported_text_complete')
        self.assertEqual(result.verdict, 'no_findings')

    def test_pdf_content_comments_and_ambiguous_percent_require_review(self):
        self.assert_review(pdf_content_comment(), 'pdf', 'DOC-PDF-LEXICAL-UNINSPECTED')
        # This intentional conservative case does not claim the percent is malicious.
        self.assert_review(pdf('Public discount 50%'), 'pdf', 'DOC-PDF-LEXICAL-UNINSPECTED')

    def test_encrypted_truncated_unsupported_and_parse_failed_stay_unreadable(self):
        for raw, fmt in ((pdf(encrypted=True), 'pdf'), (office()[:-25], 'xlsx'),
                         (b'not-supported', 'xls'), (b'%PDF-broken', 'pdf')):
            with self.subTest(format=fmt): self.assert_review(raw, fmt)

    def test_public_report_keeps_partial_coverage(self):
        report = inspect_document(office() + SENTINEL, 'xlsx')
        self.assertEqual(report['coverage'], 'partial')
        self.assertEqual(report['verdict'], 'review')
        self.assertFalse(report['release_authorized'])
        self.assertNotIn(SENTINEL.decode(), json.dumps(report))

    def test_public_signature_cannot_override_uninspected_raw_content(self):
        class Capture:
            def __init__(self): self.calls = []
            def send(self, body): self.calls.append(body); return 'synthetic-only'
        with Store() as store:
            private, public = keypair()
            capture = Capture()
            gateway = BundleGateway(store.audit, public, 'demo-model', capture, 'synthetic-org')
            cases = [(fmt, raw) for fmt in ('xlsx', 'pptx') for raw in envelope_cases(fmt).values()]
            cases += [('pdf', pdf_stream()), ('pdf', pdf_content_comment()),
                      ('xlsx', office(extra={'custom/metadata.xml': '<data><!--uninspected--></data>'}))]
            descriptor = bytearray(descriptor_office()); descriptor[14:26] = b'a@b.invalid!'
            cases.append(('xlsx', bytes(descriptor)))
            for fmt, raw in cases:
                request_id = secrets.token_hex(16)
                files = [{'format': fmt, 'base64': base64.b64encode(raw).decode()}]
                proof = sign_bundle(private, 'Summarize public data.', files, 'demo-model', request_id, 'synthetic-org')
                result = gateway.send('Summarize public data.', files, request_id, proof, consent=True)
                self.assertEqual(result['execution_state'], 'prevented_in_gateway')
            self.assertEqual(capture.calls, [])
            self.assertNotIn(SENTINEL.decode(), store.audit.export(100).decode())


if __name__ == '__main__':
    unittest.main()
