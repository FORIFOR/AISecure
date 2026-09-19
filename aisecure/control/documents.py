"""Bounded document inspection. Not antivirus, OCR, or an information classifier.

Scans ALL XML parts, including hidden sheets, notes, cached values and metadata.
No Office application, formulas, macros or external relationships are executed.
Extracted text is volatile and must NEVER be passed to the audit logger.
A no-findings result is not a release authorization. Unsupported content remains
partial. PDF extraction runs in a resource-limited subprocess (see worker.py).
"""
from __future__ import annotations
import base64
from dataclasses import dataclass, field
import io
import os
from pathlib import PurePosixPath
import re
import subprocess
import sys
import unicodedata
import zipfile
from defusedxml import ElementTree as ET
from .common import ControlError, canonical, decode
from ..preflight import SECRET, PERSONAL

MAX_FILE = 16 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_PART = 8 * 1024 * 1024
MAX_PARTS = 2048
MAX_TEXT = 2 * 1024 * 1024
MAX_PAGES = 200
SCANNER_VERSION = 'documents-1'
CONFIDENTIAL = re.compile(r'社外秘|極秘|持出禁止|持ち出し禁止|(?i:\bconfidential\b|\brestricted\b)')
INJECTION = re.compile(r'(?is:ignore.{0,60}(?:previous|system).{0,30}instructions|'
                       r'システム.{0,30}指示.{0,20}無視|これまでの指示を無視)')
ACTIVE = re.compile(r'(?i:vbaproject|activex|macrosheets|embeddings/)')

@dataclass(frozen=True)
class Inspection:
    format: str
    coverage: str
    findings: tuple[dict, ...]
    units: int
    bytes_scanned: int
    text: str = field(repr=False, default='')
    network_isolation: bool = False

    @property
    def verdict(self):
        if any(f['level'] == 'block' for f in self.findings): return 'block'
        if self.coverage != 'supported_text_complete' or self.findings: return 'review'
        return 'no_findings'

    def report(self):
        return {'format': self.format, 'coverage': self.coverage, 'verdict': self.verdict,
                'findings': list(self.findings), 'units': self.units,
                'bytes_scanned': self.bytes_scanned, 'scanner': SCANNER_VERSION,
                'ocr_performed': False, 'malware_scan_performed': False,
                'network_isolation_verified': self.network_isolation,
                'release_authorized': False}

class Builder:
    def __init__(self, fmt, size):
        self.fmt, self.size, self.units = fmt, size, 0
        self.texts, self.findings, self.used = [], {}, 0
        self.partial = False

    def add(self, rule, level, location):
        key = (rule, level)
        item = self.findings.setdefault(key, {'rule': rule, 'level': level, 'count': 0, 'locations': []})
        item['count'] += 1
        if len(item['locations']) < 5: item['locations'].append(location)

    def put(self, text, location):
        if not isinstance(text, str): return
        text = unicodedata.normalize('NFKC', text)
        size = len(text.encode())
        if self.used + size > MAX_TEXT: raise ControlError('文字抽出の上限を超えています。')
        self.used += size
        self.texts.append(text)
        for rule, level, pattern in [('DOC-SECRET','block',SECRET), ('DOC-PII','review',PERSONAL),
                                     ('DOC-CLASS','review',CONFIDENTIAL), ('DOC-INJECTION','review',INJECTION)]:
            for _ in pattern.finditer(text): self.add(rule, level, location)

    def cross_text(self, text, location):
        text=unicodedata.normalize('NFKC',text)
        if len(text.encode())>MAX_TEXT:raise ControlError('文字抽出の上限です。')
        for rule, level, pattern in [('DOC-SECRET','block',SECRET), ('DOC-PII','review',PERSONAL),
                                     ('DOC-CLASS','review',CONFIDENTIAL), ('DOC-INJECTION','review',INJECTION)]:
            if (rule,level) not in self.findings and pattern.search(text):
                self.add(rule,level,location)

    def finish(self):
        # Also inspect text across XML run boundaries without whitespace: a token
        # split into styled runs must not evade the checks. Do not return values.
        joined = ''.join(self.texts)
        for rule, level, pattern in [('DOC-SECRET','block',SECRET), ('DOC-PII','review',PERSONAL),
                                     ('DOC-CLASS','review',CONFIDENTIAL), ('DOC-INJECTION','review',INJECTION)]:
            if (rule, level) not in self.findings and pattern.search(joined):
                self.add(rule, level, 'cross_part_text')
        return Inspection(self.fmt, 'partial' if self.partial else 'supported_text_complete',
                          tuple(self.findings.values()), self.units, self.size,
                          '\n'.join(self.texts))

def failure(fmt, size, rule, level='review'):
    return Inspection(fmt, 'unreadable', ({'rule': rule, 'level': level, 'count': 1,
                                          'locations': []},), 0, size)

def _office(data: bytes, fmt: str) -> Inspection:
    b = Builder(fmt, len(data))
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        items = z.infolist()
        if not items or len(items) > MAX_PARTS: raise ControlError('展開項目の上限です。')
        names, total = set(), 0
        for item in items:
            name = item.filename
            path = PurePosixPath(name)
            if ('\\' in name or '\x00' in name or name.startswith('/') or
                    '..' in path.parts or ':' in name or any(ord(c)<32 for c in name) or
                    unicodedata.normalize('NFKC', name).casefold() in names or
                    (item.external_attr >> 16) & 0o170000 == 0o120000):
                raise ControlError('アーカイブの項目が不正です。')
            names.add(unicodedata.normalize('NFKC', name).casefold())
            total += item.file_size
            if (item.flag_bits & 1 or item.file_size > MAX_PART or total > MAX_EXPANDED or
                    item.file_size > max(1, item.compress_size) * 1000 or
                    item.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED)):
                raise ControlError('展開サイズまたは圧縮形式が許可範囲外です。')
        required = 'xl/workbook.xml' if fmt == 'xlsx' else 'ppt/presentation.xml'
        if required not in z.namelist() or '[Content_Types].xml' not in z.namelist() or '_rels/.rels' not in z.namelist():
            return failure(fmt, len(data), 'DOC-FORMAT-MISMATCH', 'block')
        types=ET.fromstring(z.read('[Content_Types].xml'))
        if types.tag!='{http://schemas.openxmlformats.org/package/2006/content-types}Types':
            return failure(fmt,len(data),'DOC-FORMAT-MISMATCH','block')
        expected_type=('application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml'
                       if fmt=='xlsx' else 'application/vnd.openxmlformats-officedocument.presentationml.presentation.main+xml')
        overrides=[n.attrib.get('ContentType') for n in types if n.attrib.get('PartName')=='/'+required]
        if overrides!=[expected_type]:return failure(fmt,len(data),'DOC-FORMAT-MISMATCH','block')
        rels=ET.fromstring(z.read('_rels/.rels'))
        office_refs=[n for n in rels if n.attrib.get('Type','').endswith('/officeDocument')]
        if (len(office_refs)!=1 or office_refs[0].attrib.get('Target','').lstrip('/')!=required or
                office_refs[0].attrib.get('TargetMode','Internal')!='Internal'):
            return failure(fmt,len(data),'DOC-FORMAT-MISMATCH','block')
        for idx, item in enumerate(items):
            if item.is_dir(): continue
            name = item.filename.lower()
            location = f'part:{idx+1}'  # no original path / sheet title in audit
            if ACTIVE.search(name): b.add('DOC-ACTIVE-CONTENT', 'block', location); b.partial=True
            if '/media/' in name:
                b.add('DOC-IMAGE-UNINSPECTED', 'review', location); b.partial=True
            if name.endswith(('.xml','.rels')):
                with z.open(item) as f: raw = f.read(MAX_PART + 1)
                if len(raw) > MAX_PART: raise ControlError('展開上限です。')
                root = ET.fromstring(raw)
                nodes = list(root.iter())
                if len(nodes) > 100000: raise ControlError('XML要素の上限です。')
                b.cross_text(''.join(root.itertext()),location)
                for node in nodes:
                    tag = node.tag.rsplit('}',1)[-1]
                    if tag in {'si','is','p','c','comment'}:
                        b.cross_text(''.join(node.itertext()),location)
                    b.put(node.text, location)
                    b.put(node.tail, location)
                    # Include custom properties, hyperlinks, definitions and labels.
                    for value in node.attrib.values():
                        b.put(value, location)
                        if tag=='Override' and re.search(r'(?i:macroEnabled|vbaProject|activeX)',value):
                            b.add('DOC-ACTIVE-CONTENT','block',location);b.partial=True
                    if tag == 'Relationship' and node.attrib.get('TargetMode') == 'External':
                        b.add('DOC-EXTERNAL-REFERENCE','review',location)
                    if tag in {'sheet','row','col'} and (node.attrib.get('state') in {'hidden','veryHidden'} or node.attrib.get('hidden') in {'1','true'}):
                        b.add('DOC-HIDDEN-CONTENT','review',location)
                    if tag == 'sld' and node.attrib.get('show') in {'0','false'}:
                        b.add('DOC-HIDDEN-CONTENT','review',location)
                if re.fullmatch(r'xl/worksheets/sheet\d+\.xml',name) or re.fullmatch(r'ppt/slides/slide\d+\.xml',name):
                    b.units += 1
            elif '/media/' not in name:
                b.add('DOC-BINARY-UNINSPECTED','review',location); b.partial=True
        if not b.units:
            b.add('DOC-NO-CONTENT','review','package'); b.partial=True
    return b.finish()

def _pdf(data: bytes) -> Inspection:
    # Import here so malformed Office files never invoke PDF parsing.
    from pypdf import PdfReader
    from pypdf.generic import (DictionaryObject, ArrayObject, IndirectObject,
                               TextStringObject, StreamObject)
    b = Builder('pdf', len(data))
    if data.count(b'%%EOF')>1 or data.count(b'startxref')>1:
        b.add('DOC-PDF-REVISION-HISTORY','review','pdf:structure');b.partial=True
    if b'%%EOF' in data and data.rsplit(b'%%EOF',1)[1].strip():
        b.add('DOC-PDF-TRAILING-CONTENT','review','pdf:structure');b.partial=True
    reader = PdfReader(io.BytesIO(data), strict=True)
    if reader.is_encrypted: return failure('pdf', len(data), 'DOC-ENCRYPTED')
    if not 0 < len(reader.pages) <= MAX_PAGES:
        return failure('pdf',len(data),'DOC-PAGE-LIMIT')
    seen, walked = set(), 0
    def walk(obj, depth=0):
        nonlocal walked
        walked += 1
        if depth > 64 or walked > 50000: raise ControlError('PDF構造の上限です。')
        if isinstance(obj, IndirectObject):
            identity=(obj.idnum, obj.generation)
            if identity in seen: return
            seen.add(identity); obj = obj.get_object()
        if isinstance(obj, TextStringObject): b.put(str(obj),'pdf:metadata'); return
        if isinstance(obj, DictionaryObject):
            for key, value in obj.items():
                if str(key) in {'/JS','/JavaScript','/Launch','/OpenAction','/AA','/EmbeddedFiles','/XFA','/RichMedia'}:
                    b.add('DOC-ACTIVE-CONTENT','block','pdf:structure'); b.partial=True
                if str(key) in {'/URI','/GoToR'}:
                    b.add('DOC-EXTERNAL-REFERENCE','review','pdf:structure')
                if str(key) in {'/OCProperties','/PieceInfo'}:
                    b.add('DOC-OPTIONAL-CONTENT','review','pdf:structure'); b.partial=True
                if str(key) == '/Subtype' and str(value) == '/Image':
                    b.add('DOC-IMAGE-UNINSPECTED','review','pdf:structure'); b.partial=True
                walk(value,depth+1)
        elif isinstance(obj, ArrayObject):
            for value in obj: walk(value, depth+1)
    walk(reader.trailer)
    # Raw uploads include stale/unreachable objects, not just the rendered pages.
    known={(objid,generation) for generation,entries in reader.xref.items() for objid in entries if objid>0 and generation!=65535}
    known.update((objid,0) for objid in getattr(reader,'xref_objStm',{}))
    if known-seen:
        b.add('DOC-PDF-UNREFERENCED-OBJECT','review','pdf:structure');b.partial=True
    for number, page in enumerate(reader.pages,1):
        b.units += 1
        content=page.get_contents()
        if content is not None and len(content.get_data()) > MAX_PART:
            raise ControlError('PDF内容ストリームの上限です。')
        text=page.extract_text() or ''
        b.put(text, f'page:{number}')
        if not text.strip():
            b.add('DOC-PAGE-UNINSPECTED','review',f'page:{number}');b.partial=True
        # Vector illustrations / inline images can carry meaning not covered by text.
        if content is not None and any(op in {b'm',b'l',b'c',b'v',b'y',b're',b'S',b's',b'f',b'F',b'f*',b'B',b'B*',b'b',b'b*',b'sh',b'BI',b'Do'} for _,op in content.operations):
            b.add('DOC-VISUAL-UNINSPECTED','review',f'page:{number}');b.partial=True
    return b.finish()

def inspect_bytes(data: bytes, extension: str) -> Inspection:
    """Internal worker entry; caller must provide process/resource isolation."""
    if type(data) is not bytes or not data or len(data) > MAX_FILE:
        return failure('unknown', len(data) if isinstance(data,bytes) else 0, 'DOC-SIZE', 'block')
    fmt = extension.lower().removeprefix('.') if isinstance(extension,str) else 'unknown'
    if fmt not in {'xlsx','pptx','pdf'}: return failure('unknown',len(data),'DOC-UNSUPPORTED')
    try:
        if fmt == 'pdf':
            if not data.startswith(b'%PDF-'): return failure(fmt,len(data),'DOC-FORMAT-MISMATCH','block')
            return _pdf(data)
        if not data.startswith(b'PK\x03\x04'): return failure(fmt,len(data),'DOC-FORMAT-MISMATCH','block')
        return _office(data,fmt)
    except (Exception, RecursionError):
        return failure(fmt,len(data),'DOC-PARSE-FAILED')

def _run_bounded(command, *, input, timeout, env, cwd=None, max_output=MAX_TEXT*8):
    """Bound stdout while reading, rather than after communicate has allocated it."""
    import threading
    import signal
    process=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,env=env,cwd=cwd,start_new_session=os.name!='nt')
    expired=threading.Event()
    def kill():
        """Never raises: a failed kill must not mask the bound/timeout error."""
        try:
            if os.name!='nt':os.killpg(process.pid,signal.SIGKILL)
            else:process.kill()
            return
        except ProcessLookupError:return
        except OSError:pass  # Darwin can refuse killpg; still stop the direct child.
        try:process.kill()
        except OSError:pass
    def expire():expired.set();kill()
    def write():
        try:process.stdin.write(input);process.stdin.close()
        except (OSError,ValueError):pass
    writer=threading.Thread(target=write,daemon=True);timer=threading.Timer(timeout,expire)
    writer.start();timer.start();out=bytearray()
    try:
        while True:
            chunk=process.stdout.read1(65536)
            if not chunk:break
            if len(out)+len(chunk)>max_output:
                kill();raise ControlError('解析応答の上限です。')
            out.extend(chunk)
        process.wait(timeout=3)
        if expired.is_set():raise subprocess.TimeoutExpired(command,timeout)
        return subprocess.CompletedProcess(command,process.returncode,bytes(out))
    finally:
        timer.cancel()
        if process.poll() is None:kill()
        process.wait(timeout=3);writer.join(timeout=1)
        process.stdout.close()
        if not process.stdin.closed:process.stdin.close()


def inspect(data: bytes, extension: str, *, timeout=12) -> Inspection:
    """Subprocess timeout/resource guard, NOT an OS network sandbox guarantee.

    For hostile documents run the whole worker service using deploy/control's
    network-disabled container profile. No provider keys are inherited.
    """
    if type(data) is not bytes or len(data)>MAX_FILE:
        return failure('unknown',0,'DOC-SIZE','block')
    if type(extension) is not str or extension.lower().removeprefix('.') not in {'xlsx','pptx','pdf'}:
        return failure('unknown',len(data),'DOC-UNSUPPORTED')
    env = {k:v for k,v in os.environ.items() if k in {'PATH','SYSTEMROOT','WINDIR','LANG','LC_ALL'}}
    # Explicit trusted source root, not the caller's PYTHONPATH.
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    env['PYTHONPATH'] = root
    try:
        result = _run_bounded([sys.executable,'-m','aisecure.control.worker',extension],
                                input=data,timeout=timeout,env=env,cwd=root)
        if result.returncode or len(result.stdout)>MAX_TEXT*8:
            return failure(extension,len(data),'DOC-WORKER-FAILED')
        obj=decode(result.stdout,MAX_TEXT*8)
        return Inspection(obj['format'],obj['coverage'],tuple(obj['findings']),obj['units'],
                          obj['bytes_scanned'],obj['text'],False)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        return failure(extension,len(data),'DOC-WORKER-TIMEOUT')

@dataclass(frozen=True)
class Scanner:
    """Admin-selected worker backend. Podman image MUST be pinned by digest.

    No host mounts, provider keys or network access are granted to the container.
    The image itself must be reviewed and built before live operation. Rootless
    Podman/system limits are installation requirements, not installed by this code.
    """
    backend: str='process'
    image: str=''

    def __post_init__(self):
        if self.backend not in {'process','podman'}: raise ControlError('解析基盤が不正です。')
        if self.backend=='podman' and not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9._:/-]{0,200}@sha256:[a-f0-9]{64}',self.image):
            raise ControlError('解析イメージの固定ダイジェストが必要です。')

    @property
    def enforces_network_isolation(self):return self.backend=='podman'

    def inspect(self,data,extension):
        if self.backend=='process':return inspect(data,extension)
        if type(data) is not bytes or not 0<len(data)<=MAX_FILE or extension not in {'xlsx','pptx','pdf'}:
            return failure('unknown',0,'DOC-SIZE','block')
        # Never interpolate shell strings or mount caller paths.
        import secrets
        name='aisecure-scan-'+secrets.token_hex(12)
        cmd=['podman','run','--name',name,'--rm','--pull=never','--network=none','--read-only',
             '--cap-drop=ALL','--security-opt=no-new-privileges','--memory=768m',
             '--cpus=1','--pids-limit=32','--user=65532:65532','-i',self.image,
             'python','-m','aisecure.control.worker',extension]
        env={k:v for k,v in os.environ.items() if k in {'PATH','HOME','XDG_RUNTIME_DIR'}}
        try:
            result=_run_bounded(cmd,input=data,timeout=20,env=env)
            if result.returncode:return failure(extension,len(data),'DOC-WORKER-FAILED')
            obj=decode(result.stdout,MAX_TEXT*8)
            return Inspection(obj['format'],obj['coverage'],tuple(obj['findings']),obj['units'],
                              obj['bytes_scanned'],obj['text'],True)
        except Exception:return failure(extension,len(data),'DOC-WORKER-FAILED')
        finally:
            # Kill a container even if the runner timed out or disconnected. The
            # generated name is never derived from an untrusted file or request.
            try:subprocess.run(['podman','rm','-f',name],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=5,env=env,check=False)
            except Exception:pass
