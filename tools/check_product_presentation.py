"""Render the two homepages at five widths and test product media.

Needs Playwright + Chromium/WebKit. No real inquiry is sent. --offline renders
already-local resources when navigation is unavailable; it is not a live-site
check. Default tests the local HTTP server, not GitHub Pages.
"""
from pathlib import Path
import argparse, base64, functools, http.server, json, threading
from playwright.sync_api import sync_playwright

parser=argparse.ArgumentParser();parser.add_argument('--offline',action='store_true')
parser.add_argument('--browser', choices=['chromium','webkit'], default='chromium')
parser.add_argument('--public', action='store_true')
parser.add_argument('--out',type=Path,default=Path('/tmp/aisecure-presentation-check'))
args=parser.parse_args();args.out.mkdir(parents=True,exist_ok=True)
root=Path(__file__).resolve().parents[1]/'docs'
server=http.server.ThreadingHTTPServer(('127.0.0.1',0),functools.partial(http.server.SimpleHTTPRequestHandler,directory=str(root)))
threading.Thread(target=server.serve_forever,daemon=True).start()
base='https://forifor.github.io/AISecure/' if args.public else f'http://127.0.0.1:{server.server_port}/';results=[]
try:
 with sync_playwright() as p:
  browser=getattr(p,args.browser).launch(headless=True,**({'executable_path':'/usr/bin/chromium'} if args.offline else {}))
  for lang,name in [('ja','index.ja.html'),('en','index.html')]:
   for width in [320,390,768,1024,1440]:
    page=browser.new_page(viewport={'width':width,'height':1000},reduced_motion='reduce')
    errors=[];posts=[];bad=[]
    page.on('pageerror',lambda e:errors.append(str(e)))
    page.on('request',lambda r:posts.append(r.url) if r.method=='POST' else None)
    page.on('response',lambda r:bad.append([r.status,r.url]) if r.status>=400 else None)
    # Never send a real lead or analytics request during a visual test.
    page.route('**/*',lambda route:route.continue_() if route.request.url.startswith(base) else route.abort())
    if args.offline:
     from bs4 import BeautifulSoup
     source=BeautifulSoup((root/name).read_text(encoding='utf-8'),'html.parser')
     for tag in source.find_all(['link','script','source','track','video','img']):
      for attr in ['src','href','poster']:
       path=tag.get(attr,'').split('?')[0]
       if path and (root/path).is_file():
        mime={'.css':'text/css','.js':'text/javascript','.mp4':'video/mp4','.jpg':'image/jpeg','.png':'image/png','.vtt':'text/vtt'}.get(Path(path).suffix)
        if mime:tag[attr]='data:'+mime+';base64,'+base64.b64encode((root/path).read_bytes()).decode()
     page.set_content(str(source),wait_until='load')
    else:page.goto(base+name,wait_until='networkidle')
    if not args.offline:
     page.wait_for_function("() => document.querySelectorAll('img.product-actual').length >= 4")
     product_images=page.locator('img.product-actual')
     assert product_images.count()>=4,(lang,width,'missing product images')
     for i in range(product_images.count()):
      image=product_images.nth(i).evaluate("img => ({w:img.naturalWidth,h:img.naturalHeight,src:img.currentSrc})")
      assert image['w']>=1200 and image['h']>=1800,(lang,width,image)
      assert 'workbench-actual.png' in image['src'],(lang,width,image)
    page.screenshot(path=str(args.out/f'{lang}-{width}.png'),full_page=True)
    if width==1440:page.screenshot(path=str(args.out/f'{lang}-hero.png'))
    assert not page.evaluate('document.documentElement.scrollWidth>innerWidth'),(lang,width,'overflow')
    if lang=='ja':
     broken=page.locator('.jp-phrase').evaluate_all("""els => els.filter(el => {
       const r=el.getBoundingClientRect();
       const vw=document.documentElement.clientWidth;
       const nowrap=getComputedStyle(el).whiteSpace==='nowrap';
       return !nowrap || r.left < -0.5 || r.right > vw + 0.5 || el.scrollWidth > el.clientWidth + 1;
     }).map(el=>el.textContent.trim())""")
     assert not broken,(lang,width,'jp-phrase-overflow',broken)
    for i in range(4):
     page.locator('[data-sample-tab]').nth(i).click()
     assert page.locator('[data-sample-panel]:visible').count()==1
    page.locator('[data-sample-tab]').first.focus();page.keyboard.press('End')
    assert page.locator('[data-sample-tab]').nth(3).get_attribute('aria-selected')=='true'
    page.locator('[data-play-film]').first.click();page.wait_for_timeout(1200)
    dimensions=page.locator('video').evaluate('(v)=>({w:v.videoWidth,h:v.videoHeight,t:v.currentTime,duration:v.duration})')
    assert dimensions['w']==1920 and dimensions['h']==1080 and dimensions['t']>0 and dimensions['duration']==18,dimensions
    assert page.locator('.film-splash').is_hidden()
    page.locator('video').evaluate('(v)=>v.pause()')
    assert not errors,errors;assert not posts,posts;assert not bad,bad
    results.append({'lang':lang,'width':width,'product_images_decoded':not args.offline,'jp_phrases_safe':lang!='ja' or True,'overflow':False,'js_errors':errors,'unsolicited_posts':posts,'http_errors':bad,'video':dimensions})
    page.close()
  browser.close()
finally:server.shutdown()
report={'mode':'public-github-pages' if args.public else 'offline-local-resources' if args.offline else 'local-http','browser':args.browser,'results':results}
(args.out/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
print(json.dumps(report,ensure_ascii=False))
