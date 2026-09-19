"""Exact-action dual approval, durable no-retry receipt, state verification.

The service has PUBLIC keys only. The offline signing helper is not exposed on
HTTP. A config-confirmed result never claims traffic containment or patching.
"""
from __future__ import annotations
import base64
import hashlib
import re
import time
from .common import ControlError, canonical, ident, integer
from ..safety import EmergencyStop

OPERATIONS=frozenset({'disable_registered_rule','restore_registered_rule'})
PLAN_FIELDS=frozenset({'id','target','operation','state_hash','expires_at','policy','rollback_requires_new_approval'})

def plan(adapter,operation,*,now=None):
    now=int(time.time()) if now is None else now
    if operation not in OPERATIONS:raise ControlError('操作が許可範囲外です。')
    current=adapter.read_state()
    desired=adapter.expected(operation)
    if current['status']==desired:raise ControlError('対象は既に要求された状態です。')
    import secrets
    return {'id':secrets.token_hex(16),'target':adapter.target_id,'operation':operation,
            'state_hash':current['state_hash'],'expires_at':now+300,'policy':'response-1',
            'rollback_requires_new_approval':True}

def sign(private_key,proposal,approver,role,*,now=None):
    """Offline administrator helper. Never import private keys into the service."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    now=int(time.time()) if now is None else now
    if role not in {'primary','secondary'}:raise ControlError('承認者の役割が不正です。')
    claim={'proposal_sha256':hashlib.sha256(canonical(proposal)).hexdigest(),'approver':ident(approver),
           'role':role,'issued_at':now,'expires_at':min(proposal['expires_at'],now+300),'decision':'approve'}
    sig=Ed25519PrivateKey.from_private_bytes(private_key).sign(canonical(claim))
    return {'claim':claim,'signature':base64.b64encode(sig).decode()}

def verify_pair(proposal,proofs,keys,*,now=None):
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    now=int(time.time()) if now is None else now
    if type(proposal) is not dict or set(proposal)!=PLAN_FIELDS:raise ControlError('対応計画が不正です。')
    ident(proposal['id']);ident(proposal['target'])
    if proposal['operation'] not in OPERATIONS or proposal['policy']!='response-1' or proposal['rollback_requires_new_approval'] is not True:
        raise ControlError('対応計画の操作が不正です。')
    if type(proposal['state_hash']) is not str or not re.fullmatch('[a-f0-9]{64}',proposal['state_hash']):raise ControlError('状態証明が不正です。')
    integer(proposal['expires_at'],now+1,now+300)
    if type(proofs) is not list or len(proofs)!=2:raise ControlError('独立した2名の署名付き承認が必要です。')
    people,publics,roles=set(),set(),set()
    try:
        for proof in proofs:
            if set(proof)!={'claim','signature'}:raise ValueError
            claim=proof['claim']
            if set(claim)!={'proposal_sha256','approver','role','issued_at','expires_at','decision'}:raise ValueError
            if claim['proposal_sha256']!=hashlib.sha256(canonical(proposal)).hexdigest() or claim['decision']!='approve':raise ValueError
            integer(claim['issued_at'],now-300,now+15)
            integer(claim['expires_at'],now+1,min(claim['issued_at']+300,proposal['expires_at']))
            if claim['role'] not in {'primary','secondary'}:raise ValueError
            approver=ident(claim['approver']);key=keys[approver]
            if type(key) is not bytes or len(key)!=32:raise ValueError
            signature=base64.b64decode(proof['signature'],validate=True)
            Ed25519PublicKey.from_public_bytes(key).verify(signature,canonical(claim))
            people.add(approver);publics.add(key);roles.add(claim['role'])
        if len(people)!=2 or len(publics)!=2 or len(roles)!=2:raise ValueError
    except Exception:raise ControlError('対応計画・対象・独立した二者承認を確認できません。') from None
    return sorted(people)

class ResponseController:
    def __init__(self,audit,adapters,public_keys,stop_file):
        self.audit,self.adapters,self.keys=audit,dict(adapters),dict(public_keys)
        self.stop=EmergencyStop(stop_file)
    def execute(self,proposal,proofs,*,consent=False,now=None):
        if consent is not True:raise ControlError('実操作の確認が必要です。')
        approvers=verify_pair(proposal,proofs,self.keys,now=now)
        adapter=self.adapters.get(proposal['target'])
        if adapter is None or not adapter.deployment_verified:raise ControlError('検証済みの実行先がありません。')
        self.stop.assert_clear()
        eid=hashlib.sha256(('response:'+proposal['id']).encode()).hexdigest()[:32]
        initial=self.audit.entry(kind='response_request',request_id=eid,actor=':'.join(approvers),
            target=proposal['target'],decision='allow',state='dispatch_pending',rules=['RESPONSE-APPROVED'])
        fingerprint=self.audit.evidence.digest(canonical(proposal))
        prior=self.audit.evidence.reserve(eid,fingerprint,initial)
        if prior is not None:return {**prior,'containment_verified':False}
        # Reservation is deliberately before ALL provider calls. Failures never
        # trigger automatic retries. The operator must investigate unknown state.
        state='delivery_unknown';rule='RESPONSE-UNKNOWN'
        try:
            self.stop.assert_clear()
            current=adapter.read_state()
            if current['state_hash']!=proposal['state_hash']:
                state='precondition_failed';rule='RESPONSE-STATE-CHANGED'
            else:
                self.stop.assert_clear();adapter.apply(proposal['operation'])
                after=adapter.read_state()
                if after['status']==adapter.expected(proposal['operation']):
                    state='verified';rule='RESPONSE-CONFIG-VERIFIED'
        except Exception:pass
        final={**initial,'execution_state':state,'rules':[rule]}
        self.audit.evidence.finish(eid,final)
        return {**final,'configuration_verified':state=='verified','containment_verified':False,
                'automatic_retry':False,'rollback_requires_new_approval':True}
