"""Bounded, encrypted collector event repository sharing the journal transaction."""
from __future__ import annotations
from .common import ControlError,canonical,decode,integer
from .audit import MAX_RECORD
from .analytics import normalize

class EventStore:
    def __init__(self,audit,limit=10000):
        self.audit,self.db,self.limit=audit,audit.evidence.db,limit
        integer(limit,1,10000)
        with audit.evidence.lock:
            self.db.execute('CREATE TABLE IF NOT EXISTS control_events(id TEXT PRIMARY KEY,at INTEGER,payload TEXT NOT NULL)')
    def ingest(self,raw,*,organization,source,now=None):
        event=normalize(raw,key=self.audit.key,organization=organization,source=source,now=now)
        eid=event['id'];payload=canonical(event)
        with self.audit.evidence.lock:
            self.audit.evidence.verify()
            self.db.execute('BEGIN IMMEDIATE')
            try:
                old=self.db.execute('SELECT payload FROM control_events WHERE id=?',(eid,)).fetchone()
                if old:
                    decoded=self.audit.evidence.cipher.decrypt(old[0],'control_event:'+eid)
                    if decoded.encode()!=payload:raise ControlError('同じ観測IDの内容が一致しません。')
                    self.db.execute('COMMIT');return {'accepted':True,'duplicate':True,'id':eid}
                for prior in self.read():
                    if prior['id']==eid:
                        if canonical(prior)!=payload:raise ControlError('監査上の観測IDと一致しません。')
                        self.db.execute('COMMIT');return {'accepted':True,'duplicate':True,'id':eid}
                if self.db.execute('SELECT count(*) FROM control_events').fetchone()[0]>=self.limit:
                    raise ControlError('観測記録の保持上限です。保持手順の実施が必要です。')
                self.db.execute('INSERT INTO control_events VALUES(?,?,?)',
                    (eid,event['at'],self.audit.evidence.cipher.encrypt(payload.decode(),'control_event:'+eid)))
                entry=self.audit.entry(kind='security_event',request_id=eid[:32],actor=raw['actor'],
                    target=source,state='observed_only',counts={'events':1,'bytes':event['bytes']})
                entry['event']=event
                if len(canonical(entry))>MAX_RECORD:raise ControlError('観測監査の上限です。')
                self.audit.evidence._append(entry)
                self.db.execute('COMMIT')
            except Exception:
                self.db.execute('ROLLBACK');raise
        return {'accepted':True,'duplicate':False,'id':eid}
    def read(self):
        # The index table is only a deduplication aid. The authenticated journal
        # is authoritative, so deleting cache rows cannot hide observed events.
        with self.audit.evidence.lock:
            self.audit.evidence.verify()
            events=[]
            for r in self.db.execute('SELECT seq,payload FROM journal ORDER BY seq'):
                entry=decode(self.audit.evidence.cipher.decrypt(r['payload'],f"event:{r['seq']}").encode())
                if entry.get('kind')=='security_event' and 'event' in entry:
                    events.append(entry['event'])
            if len(events)>self.limit:raise ControlError('観測範囲の上限です。')
            return sorted(events,key=lambda e:(e['at'],e['id']))
    def prune(self, before:int, *, checkpoint):
        """OFFLINE: back up and externally retain checkpoint before calling.

        Prunes the shared audit prefix, not just analytics. Tail integrity still
        requires an independently retained anchor. Run only during maintenance.
        """
        import time
        integer(before,0,int(time.time())-86400)
        with self.audit.evidence.lock:
            if checkpoint!=self.audit.evidence.verify():raise ControlError('現在のチェックポイントが必要です。')
            result=self.audit.evidence.prune(before)
            retained={e['id'] for e in self.read()}
            rows=self.db.execute('SELECT id FROM control_events').fetchall()
            expired=[(r['id'],) for r in rows if r['id'] not in retained]
            self.db.executemany('DELETE FROM control_events WHERE id=?',expired)
            return {'deleted_event_index_entries':len(expired),'audit':result,
                    'independent_checkpoint_retention_not_verified':True}
