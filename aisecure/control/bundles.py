"""A fixed-destination file bundle gate: inspect BEFORE any external upload.

The approved bytes are exactly the serialized bytes sent by the adapter. No URL,
file_id, hidden conversation memory, caller tools or arbitrary headers are accepted.
Signatures classify a request; they cannot override a scanner block or partial read.
"""
from __future__ import annotations
import base64
import hashlib
import re
import time
from .common import ControlError, canonical
from .documents import inspect, Scanner, MAX_FILE, SCANNER_VERSION
from ..gateway import ENDPOINT, valid_text, b64, unb64
from ..preflight import evaluate, Request, Policy, Grant, SECRET, PERSONAL
from ..safety import EmergencyStop

POLICY='managed-bundle-1'
MIME={'pdf':'application/pdf','xlsx':'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      'pptx':'application/vnd.openxmlformats-officedocument.presentationml.presentation'}


def decode_files(files):
    if type(files) is not list or not 1<=len(files)<=4:raise ControlError('添付は1〜4件です。')
    total=0;out=[]
    for file in files:
        if type(file) is not dict or set(file)!={'format','base64'} or file['format'] not in MIME:
            raise ControlError('添付形式が不正です。')
        data=file['base64']
        if type(data) is not str or len(data)>MAX_FILE*4//3+8:raise ControlError('添付の上限です。')
        try:raw=base64.b64decode(data,validate=True)
        except Exception:raise ControlError('添付の符号化が不正です。') from None
        total+=len(raw)
        if not raw or total>MAX_FILE:raise ControlError('添付の合計上限は16MiBです。')
        out.append((file['format'],raw))
    return out


def wire(question,files,model):
    if type(model) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}',model):
        raise ControlError('管理者がモデルを設定してください。')
    content=[{'type':'input_text','text':question}]
    for i,(fmt,raw) in enumerate(decode_files(files),1):
        content.append({'type':'input_file','filename':f'document-{i}.{fmt}',
                        'file_data':'data:'+MIME[fmt]+';base64,'+base64.b64encode(raw).decode()})
    return canonical({'model':model,'input':[{'role':'user','content':content}],
                      'tools':[],'store':False,'stream':False,'max_output_tokens':2048})


def claim_for(question,files,model,request_id,organization,issued_at):
    valid_text(question,request_id)
    return {'request_id':request_id,'sha256':hashlib.sha256(wire(question,files,model)).hexdigest(),
            'organization':organization,'model':model,'endpoint':ENDPOINT,'policy':POLICY,
            'scanner':SCANNER_VERSION,'data_class':'public','issued_at':issued_at,'expires_at':issued_at+300}


def sign_bundle(private_key,question,files,model,request_id,organization,*,now=None):
    """Offline admin confirms the final bundle is public. No UI signing endpoint."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    now=int(time.time()) if now is None else now
    claim=claim_for(question,files,model,request_id,organization,now)
    return {'claim':claim,'signature':b64(Ed25519PrivateKey.from_private_bytes(private_key).sign(canonical(claim)))}


def verify_bundle(proof,public_key,question,files,model,request_id,organization,*,now=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    now=int(time.time()) if now is None else now
    if proof is None:return 'unknown'
    try:
        if type(proof) is not dict or set(proof)!={'claim','signature'}:raise ValueError
        claim=proof['claim'];issued=claim['issued_at']
        if type(issued) is not int or not now-300<=issued<=now+15:raise ValueError
        expected=claim_for(question,files,model,request_id,organization,issued)
        if claim!=expected or now>=claim['expires_at']:raise ValueError
        Ed25519PublicKey.from_public_bytes(public_key).verify(unb64(proof['signature'],64),canonical(claim))
    except Exception:raise ControlError('添付・質問・送信先に対応する分類証明を確認できません。') from None
    return 'public'

class BundleGateway:
    def __init__(self,audit,public_key,model,transport,organization,*,live=False,stop_file=None,scanner=None,delivery_enabled=True):
        if type(public_key) is not bytes or len(public_key)!=32:raise ControlError('分類公開鍵が必要です。')
        self.audit,self.public_key,self.model,self.transport=audit,public_key,model,transport
        self.organization,self.live,self.stop=organization,live is True,EmergencyStop(stop_file)
        self.scanner=scanner or Scanner()
        self.delivery_enabled=delivery_enabled is True
        if self.live and not self.scanner.enforces_network_isolation:
            raise ControlError('実送信にはネットワーク分離された解析基盤が必要です。')
    def check(self,question,files,request_id,label=None,*,record=True,now=None):
        valid_text(question,request_id)
        data_class=verify_bundle(label,self.public_key,question,files,self.model,request_id,self.organization,now=now)
        decoded=decode_files(files)
        docs=[self.scanner.inspect(data,fmt) for fmt,data in decoded]
        req=Request('EV-1','ai.prompt',ENDPOINT,question,data_class)
        policy=Policy((Grant('ai.prompt',ENDPOINT,('public',)),))
        result=evaluate(req,policy);decision=result.decision
        rules=list(result.rule_ids)
        for doc in docs:
            rules.extend(f['rule'] for f in doc.findings)
            if doc.verdict=='block':decision='block'
            elif doc.verdict=='review' and decision!='block':decision='review'
        coverage='supported_text_complete' if all(d.coverage=='supported_text_complete' for d in docs) else 'partial'
        entry=self.audit.entry(kind='document_inspection',request_id=request_id,decision=decision,
            target=self.organization+':'+self.model, rules=list(dict.fromkeys(rules))[:24],coverage=coverage,
            counts={'files':len(docs),'units':sum(d.units for d in docs),'bytes':sum(d.bytes_scanned for d in docs),
                    'findings':sum(sum(f['count'] for f in d.findings) for d in docs)})
        if record:self.audit.evidence.append(entry)
        return {**entry,'report_schema':'aisecure.bundle-report.v1','documents':[{**d.report(), 'input_sha256':hashlib.sha256(raw).hexdigest()} for d,(_,raw) in zip(docs,decoded)],
                'coverage_note':'登録ポリシーと対応する文字範囲の検査。完全な安全性・マルウェア不在の保証ではありません。',
                'classification':data_class,'release_authorized':decision=='allow',
                'whole_device_protected':False,'delivery_enabled':self.delivery_enabled,
                'provider': 'openai' if self.live else 'demo' if self.delivery_enabled else 'disabled'}
    def send(self,question,files,request_id,label=None,*,consent=False,now=None):
        if consent is not True:raise ControlError('送信の明示確認が必要です。')
        checked=self.check(question,files,request_id,label,record=False,now=now)
        if not self.delivery_enabled:
            checked['decision']='review' if checked['decision']=='allow' else checked['decision']
            checked['rules']=list(dict.fromkeys(checked['rules']+['BUNDLE-DELIVERY-DISABLED']))
        body=wire(question,files,self.model)
        fingerprint=self.audit.evidence.digest(body+b'\0'+checked['classification'].encode()+b'\0'+self.organization.encode())
        entry={k:v for k,v in checked.items() if k in {'schema','request_id','decision','actor','target','rules','counts','coverage'}}
        initial={**entry,'kind':'bundle_request','execution_state':'dispatch_pending' if checked['decision']=='allow' else 'prevented_in_gateway'}
        self.stop.assert_clear()
        previous=self.audit.evidence.reserve(request_id,fingerprint,initial)
        if previous is not None:return previous
        if checked['decision']!='allow':return initial
        output=None
        try:
            self.stop.assert_clear()
            output=self.transport.send(body)
            state='provider_completed' if self.live else 'demo_received'
        except Exception:state='delivery_unknown'
        final={**initial,'execution_state':state}
        self.audit.evidence.finish(request_id,final)
        return {**final,**({'output':output} if output is not None else {}),'automatic_retry':False}


def redacted_text_preview(files,*,scanner=None):
    """Explicit LOCAL lossy preview only. Not a sanitized Office/PDF file.

    No class downgrade, no original changes, no automatic external send. Review
    information loss (formulas, layout, images) and reclassify the final text.
    """
    reports=[];parts=[];withheld=False
    for fmt,raw in decode_files(files):
        doc=(scanner or Scanner()).inspect(raw,fmt);reports.append(doc.report())
        if any(f['rule'] in {'DOC-SECRET','DOC-PII'} for f in doc.findings):
            # Detection crosses styled XML runs; a regex over extracted lines cannot
            # reliably redact those bytes. Withhold the whole document instead.
            parts.append('[本文非表示: 機密・個人情報の完全な伏せ字を保証できません]')
            withheld=True
            continue
        text=SECRET.sub('[REDACTED_SECRET]',doc.text)
        text=PERSONAL.sub('[REDACTED_PERSONAL]',text)
        parts.append(text)
    return {'text':'\n\n'.join(parts),'documents':reports,'representation':'lossy_text_only',
            'preview_withheld':withheld,'original_modified':False,'release_authorized':False,'requires_reclassification':True}
