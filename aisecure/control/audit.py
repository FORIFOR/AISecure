"""Bounded, encrypted metadata audit using the existing checkpointable journal.

No raw filenames, document text, explanations or provider credentials are allowed
by this interface. JSONL export is a deliberate plaintext disclosure operation.
"""
from __future__ import annotations
import re
from .common import ControlError, canonical, ident, integer, opaque

STATES = frozenset({'not_executed', 'prevented_in_gateway', 'dispatch_pending',
                    'delivery_unknown', 'provider_completed', 'demo_received',
                    'observed_only', 'verified', 'precondition_failed'})
DECISIONS = frozenset({'allow','block','review','no_findings','not_applicable'})
KINDS = frozenset({'document_inspection','bundle_request','security_event',
                   'response_request','vpn_assessment','case_review'})
COVERAGE = frozenset({'supported_text_complete','partial','unreadable','metadata_only','not_connected'})
RULE = re.compile(r'[A-Z][A-Z0-9-]{1,47}\Z')
MAX_RECORD = 2048

class Audit:
    def __init__(self, evidence, key: bytes):
        self.evidence, self.key = evidence, key
        opaque(key,'check',b'')

    def identifier(self, category, raw):
        if type(raw) is not str or len(raw.encode()) > 1024:
            raise ControlError('識別情報が上限を超えています。')
        return opaque(self.key, category, raw)

    def entry(self, *, kind, request_id, decision='not_applicable', state='not_executed',
              actor='', target='', rules=(), counts=None, coverage='metadata_only'):
        if kind not in KINDS or state not in STATES or decision not in DECISIONS or coverage not in COVERAGE:
            raise ControlError('監査項目が不正です。')
        ident(request_id)
        if not isinstance(rules,(list,tuple)) or len(rules)>24 or any(type(r) is not str or not RULE.fullmatch(r) for r in rules):
            raise ControlError('監査ルールが不正です。')
        counts = {} if counts is None else counts
        if type(counts) is not dict or not set(counts) <= {'files','units','findings','bytes','uninspected','events'}:
            raise ControlError('監査件数が不正です。')
        for value in counts.values(): integer(value,0,2**53-1)
        value = {'schema':1,'kind':kind,'request_id':request_id,'decision':decision,
                 'execution_state':state, 'actor':self.identifier('actor',actor),
                 'target':self.identifier('target',target), 'rules':list(dict.fromkeys(rules)),
                 'counts':counts,'coverage':coverage}
        if len(canonical(value))>MAX_RECORD: raise ControlError('監査記録の上限です。')
        return value

    def record(self, **kwargs):
        value=self.entry(**kwargs)
        self.evidence.append(value)
        return value

    def export(self, limit=1000):
        """Caller must authenticate. Never export opaque provider receipt bodies."""
        integer(limit,1,10000)
        with self.evidence.lock:
            self.evidence.verify()
            rows=self.evidence.db.execute('SELECT * FROM journal ORDER BY seq DESC LIMIT ?', (limit,)).fetchall()
            import json
            allowed=[]
            for row in reversed(rows):
                value=json.loads(self.evidence.cipher.decrypt(row['payload'], f"event:{row['seq']}"))
                if value.get('kind') not in KINDS: continue
                # Explicit export allowlist; future fields must not accidentally leak.
                item={k:value[k] for k in ('schema','kind','request_id','decision','execution_state',
                                           'actor','target','rules','counts','coverage') if k in value}
                item.update(seq=row['seq'], at=row['at'])
                allowed.append(canonical(item))
            return b'\n'.join(allowed)+(b'\n' if allowed else b'')
