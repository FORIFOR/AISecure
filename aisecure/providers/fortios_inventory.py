"""Read-only FortiOS status collector. No patching, isolation or configuration writes.

Fixed API path documented by Fortinet. Verify in an authorized test device first.
TLS verification is mandatory; hostname/serial/raw response are never persisted.
"""
from __future__ import annotations
import argparse
from datetime import datetime,timezone
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import ssl
import tempfile
from ..gateway import GatewayError
from ..schema import read_json

STATUS_PATH='/api/v2/monitor/system/status?global=1'


def parse_status(value: dict, asset_id: str) -> dict:
    if type(asset_id) is not str or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,79}',asset_id):
        raise GatewayError('仮名の資産IDを指定してください。')
    if type(value) is not dict or value.get('status')!='success' or value.get('http_method')!='GET':
        raise GatewayError('機器状態の取得に成功していません。')
    version=value.get('version')
    if type(version) is not str or not re.fullmatch(r'v?\d{1,4}(?:\.\d{1,4}){1,4}',version):
        version='unknown'
    else:version=version.removeprefix('v')
    return {'observed_at':datetime.now(timezone.utc).isoformat(), 'assets':[{
        'id':asset_id,'vendor':'Fortinet','product':'FortiOS','version':version,
        'internet_exposed':None,'privileged_path':None,'sensitive_path':None}]}


class DeviceHTTPS(http.client.HTTPSConnection):
    def connect(self):
        addrs=socket.getaddrinfo(self.host,self.port,type=socket.SOCK_STREAM)
        # RFC1918 is intended for an explicitly selected managed device; never metadata/link-local.
        for addr in addrs:
            ip=ipaddress.ip_address(addr[4][0])
            if ip.is_link_local or ip.is_loopback or ip.is_multicast or ip.is_unspecified:
                raise GatewayError('接続対象外のアドレスです。')
        if not addrs:raise GatewayError('機器を解決できません。')
        a=addrs[0];sock=socket.socket(a[0],a[1],a[2]);sock.settimeout(self.timeout)
        try:
            sock.connect(a[4]);self.sock=self._context.wrap_socket(sock,server_hostname=self.host)
        except Exception:sock.close();raise


def collect(host: str, token: str, asset_id: str, *, port=443, ca_file: str | None=None):
    if type(host) is not str or len(host)>253 or not re.fullmatch(r'[A-Za-z0-9.-]+',host):
        raise GatewayError('管理対象機器のホスト名またはIPv4を指定してください。')
    if type(port) is not int or not 1<=port<=65535:
        raise GatewayError('機器ポートが不正です。')
    if type(token) is not str or len(token)<16 or not token.isascii() or any(c.isspace() for c in token):
        raise GatewayError('読み取り専用の専用APIトークンが必要です。')
    conn=DeviceHTTPS(host,port=port,timeout=15,context=ssl.create_default_context(cafile=ca_file))
    try:
        conn.request('GET',STATUS_PATH,headers={'Authorization':'Bearer '+token,'Accept':'application/json'})
        response=conn.getresponse();raw=response.read(2*1024*1024+1)
        if response.status!=200 or len(raw)>2*1024*1024:raise GatewayError('機器状態を取得できません。')
        return parse_status(read_json(raw,2*1024*1024),asset_id)
    except Exception:raise GatewayError('機器のTLS・権限・対応版を確認してください。実機の設定は変更していません。') from None
    finally:conn.close()


def main(argv=None):
    p=argparse.ArgumentParser(description='明示指定したFortiOS機器の状態を読み取り専用で取得。')
    p.add_argument('--host',required=True);p.add_argument('--port',type=int,default=443)
    p.add_argument('--asset-id',required=True);p.add_argument('--ca-file');p.add_argument('--output',type=Path,required=True)
    args=p.parse_args(argv)
    try:
        result=collect(args.host,os.environ.get('AISECURE_FORTIOS_READ_TOKEN',''),args.asset_id,port=args.port,ca_file=args.ca_file)
        # Do not silently overwrite a prior evidence snapshot.
        fd=os.open(args.output,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
        with os.fdopen(fd,'w',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
        print('読み取り専用の状態を保存しました。公開面と到達性は未確認です。')
    except (OSError,ValueError):p.exit(2,'取得・保存を完了できませんでした。秘密情報は出力しません。\n')


if __name__=='__main__':main()
