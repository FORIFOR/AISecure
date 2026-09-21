"""Experimental 0.4 document-report API. No upload, authorization or audit side effects."""
import hashlib
import json
from importlib.resources import files
from .common import ControlError
from .documents import MAX_FILE, Scanner

REPORT_SCHEMA = 'aisecure.document-report.v1'


def inspect_document(data: bytes, format: str, *, scanner=None) -> dict:
    """Inspect bounded bytes through the shared worker and return metadata only.

    Raises ControlError for invalid API input. Parser/worker failures return an
    unreadable review report. Never interpret no_findings as permission to send.
    """
    if type(data) is not bytes or not 0 < len(data) <= MAX_FILE:
        raise ControlError('資料は空でないbytes、16MiB以下で指定してください。')
    if format not in ('xlsx', 'pptx', 'pdf'):
        raise ControlError('形式はxlsx・pptx・pdfです。')
    return {'report_schema': REPORT_SCHEMA, 'input_sha256': hashlib.sha256(data).hexdigest(),
            **(scanner or Scanner()).inspect(data, format).report()}


def report_schema(kind: str = 'document') -> dict:
    """Load a bundled Draft 2020-12 schema; no network or validator dependency."""
    if kind not in ('document', 'bundle'):
        raise ControlError('schema kind must be document or bundle')
    return json.loads(files('aisecure.control').joinpath('schemas', kind + '-report-v1.json').read_text(encoding='utf-8'))
