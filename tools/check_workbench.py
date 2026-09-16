"""HTTP browser acceptance: real engine -> persistent metadata -> explanation.
No external model, inquiry, API key or real user data is used.
"""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from playwright.sync_api import sync_playwright


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--browser',choices=['chromium','webkit'],default='chromium')
    parser.add_argument('--executable')
    parser.add_argument('--out',type=Path,default=Path('/tmp/aisecure-workbench-qa'))
    args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=True)
    proc=subprocess.Popen([sys.executable,'-m','aisecure.workbench','--demo','--port','8877'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
    try:
        url=None
        for _ in range(10):
            line=proc.stdout.readline()
            if line.startswith('Open: '):url=line.strip()[6:];break
            if proc.poll() is not None:raise RuntimeError('workbench startup failed')
        assert url
        time.sleep(.6)
        with sync_playwright() as p:
            browser=getattr(p,args.browser).launch(**({'executable_path':args.executable} if args.executable else {}))
            reports=[]
            for width in [390,1440]:
                page=browser.new_page(viewport={'width':width,'height':1000})
                errors=[];external=[]
                page.on('pageerror',lambda e:errors.append(str(e)))
                page.on('request',lambda r:external.append(r.url) if not r.url.startswith('http://127.0.0.1:8877/') else None)
                page.goto(url,wait_until='networkidle')
                page.get_by_text('デモモード —',exact=False).wait_for()
                page.locator('#check').click();page.get_by_text('このままでは送信しません。',exact=True).wait_for()
                assert page.locator('#send').is_disabled()
                page.locator('#sample').select_option('public')
                page.locator('#check').click();page.get_by_text('送信前の確認ができました。',exact=True).wait_for()
                page.locator('#consent').check();page.locator('#send').click()
                page.get_by_text('デモ受信器が検査済みの本文を受け取りました。',exact=False).wait_for()
                page.locator('#history button').first.click()
                page.get_by_text('ルールに基づく説明です。生成AIは使用していません。',exact=False).wait_for()
                assert not page.evaluate('document.documentElement.scrollWidth > innerWidth')
                assert not page.evaluate('location.hash')
                assert not errors and not external,(errors,external)
                page.screenshot(path=str(args.out/f'{args.browser}-{width}.png'),full_page=True)
                reports.append({'width':width,'engine_check':True,'demo_delivery':True,'history':True,'explanation':True,'js_errors':errors,'external_requests':external})
                page.close()
            browser.close()
        (args.out/f'{args.browser}.json').write_text(json.dumps({'browser':args.browser,'mode':'local-http-demo','results':reports},indent=2))
        print('PASS: browser checks; external AI was not used')
    finally:
        proc.terminate()
        try:proc.wait(timeout=10)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()


if __name__=='__main__':main()
