#!/usr/bin/env python3
"""Generate a POSIX Native Messaging launcher/manifest (never installs silently)."""
import argparse,json,os,re,shlex,sys
from pathlib import Path

def main():
    p=argparse.ArgumentParser();p.add_argument('--extension-id',required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--state-dir',type=Path,required=True);a=p.parse_args()
    if os.name=='nt':p.error('Windowsの登録・鍵管理は別のインストーラーが必要です。')
    if not re.fullmatch('[a-p]{32}',a.extension_id):p.error('拡張機能IDを確認してください。')
    if a.output.exists():p.error('新しい出力ディレクトリを指定してください。')
    a.output.mkdir(mode=0o700,parents=True)
    launcher=a.output.resolve()/'aisecure-native'
    command=[sys.executable,'-m','aisecure.control.native','--extension-id',a.extension_id,'--state-dir',str(a.state_dir.resolve())]
    launcher.write_text('#!/bin/sh\nexec '+shlex.join(command)+' "$@"\n');launcher.chmod(0o700)
    manifest={'name':'com.reachmade.aisecure','description':'AISecure explicit preflight, not upload enforcement',
              'path':str(launcher),'type':'stdio','allowed_origins':[f'chrome-extension://{a.extension_id}/']}
    path=a.output/'com.reachmade.aisecure.json';path.write_text(json.dumps(manifest,indent=2));path.chmod(0o600)
    print('マニフェストと起動ファイルを作成しました。OS別のNativeMessagingHostsへの登録と外部鍵供給が必要です。')
if __name__=='__main__':main()
