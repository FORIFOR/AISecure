"""Native Messaging companion: explicit preflight checks, NOT traffic interception.

Only the installer-registered extension origin may connect. No arbitrary file
paths, classification authority, network URLs, commands or provider calls exist.
"""
from __future__ import annotations
import argparse
import base64
import os
from pathlib import Path
import re
import struct
import sys
from .common import ControlError,canonical,decode
from .bundles import decode_files
from .documents import Scanner
from .audit import Audit
from ..gateway import Evidence
from ..preflight import SECRET,PERSONAL
from ..workbench import key_from_env

MAX_MESSAGE=24*1024*1024

def read_exact(stream,n):
    parts=[];left=n
    while left:
        chunk=stream.read(left)
        if not chunk:raise ControlError('メッセージが途中で終了しました。')
        parts.append(chunk);left-=len(chunk)
    return b''.join(parts)

def read_message(stream):
    header=stream.read(4)
    if not header:return None
    if len(header)<4:header+=read_exact(stream,4-len(header))
    size=struct.unpack('<I',header)[0]
    if not 0<size<=MAX_MESSAGE:raise ControlError('メッセージ上限です。')
    return decode(read_exact(stream,size),MAX_MESSAGE)

def write_message(stream,value):
    raw=canonical(value)
    if len(raw)>1024*1024:raise ControlError('応答上限です。')
    stream.write(struct.pack('<I',len(raw)));stream.write(raw);stream.flush()

def handle(value,audit,scanner=None):
    if type(value) is not dict or not set(value)<={'action','files','text','request_id'}:
        raise ControlError('検査項目が不正です。')
    if value.get('action')=='inspect_files' and set(value)=={'action','files','request_id'}:
        reports=[(scanner or Scanner()).inspect(raw,fmt).report() for fmt,raw in decode_files(value['files'])]
        decision='block' if any(r['verdict']=='block' for r in reports) else 'review' if any(r['verdict']=='review' for r in reports) else 'no_findings'
        rules=list(dict.fromkeys(f['rule'] for r in reports for f in r['findings']))[:24]
        entry=audit.record(kind='document_inspection',request_id=value['request_id'],decision=decision,
            coverage='partial' if any(r['coverage']!='supported_text_complete' for r in reports) else 'supported_text_complete',
            rules=rules,counts={'files':len(reports),'bytes':sum(r['bytes_scanned'] for r in reports)})
        return {**entry,'documents':reports,'release_authorized':False,'browser_enforcement':False,
                'message':'送信前の確認結果です。AIサイトの通信を停止・許可する機能ではありません。'}
    if value.get('action')=='inspect_text' and set(value)=={'action','text','request_id'}:
        import unicodedata
        text=value['text']
        if type(text) is not str or len(text.encode())>262144:raise ControlError('文字数の上限です。')
        text=unicodedata.normalize('NFKC',text);rules=[]
        if SECRET.search(text):rules.append('DOC-SECRET')
        if PERSONAL.search(text):rules.append('DOC-PII')
        result=audit.record(kind='document_inspection',request_id=value['request_id'],
                 decision='block' if 'DOC-SECRET' in rules else 'review' if rules else 'no_findings',rules=rules,
                 counts={'bytes':len(text.encode())})
        return {**result,'release_authorized':False,'browser_enforcement':False}
    raise ControlError('対応する検査操作ではありません。')

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--extension-id',required=True);p.add_argument('--state-dir',type=Path,required=True)
    p.add_argument('origin');p.add_argument('extra',nargs='*');args=p.parse_args(argv)
    if not re.fullmatch('[a-p]{32}',args.extension_id) or args.origin!=f'chrome-extension://{args.extension_id}/':
        return 2
    try:
        key=key_from_env('AISECURE_GATEWAY_KEY');audit=Audit(Evidence(args.state_dir,key),key)
        # One message per invocation bounds work; Chrome sendNativeMessage uses this mode.
        value=read_message(sys.stdin.buffer)
        if value is not None:write_message(sys.stdout.buffer,handle(value,audit))
    except Exception:
        write_message(sys.stdout.buffer,{'error':'検査サービスを確認できません。','release_authorized':False,'browser_enforcement':False})
        return 1
    return 0

if __name__=='__main__':raise SystemExit(main())
