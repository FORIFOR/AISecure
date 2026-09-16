"""Render original, silent product-concept films. No real data or live UI.

Needs Pillow, ffmpeg and system-installed Noto Sans CJK. Fonts are not copied.
Run: python tools/render_product_film.py --out docs/media
"""
from __future__ import annotations
import argparse
from functools import lru_cache
from pathlib import Path
import subprocess
from PIL import Image, ImageDraw, ImageFont

W, H, FPS, DURATION = 1920, 1080, 30, 18
BG, PANEL, LINE = '#0c1424', '#152138', '#2a3a50'
WHITE, MUTED, MINT, RED = '#f6f8fc', '#afbdd0', '#8ce7d0', '#ffb4ab'
ROOT = Path('/usr/share/fonts/opentype/noto')
TEXT = {
 'ja': {
  'concept': '製品イメージ / 合成例・実機の動作映像ではありません',
  'titles': ['AIに渡す、その前に。', '機密情報は、送らない。', '止めた理由まで、わかる。', 'AIを使う。その前に。'],
  'sub': ['送信する情報と、送信先を確かめる。', '機密として分類された情報の、判定例。', '根拠と未確認のことを、分けて表示。', '送信前の確認から、過去のログ調査まで。'],
  'doc': '顧客情報の要約', 'docsub': 'AIに送信するテキスト / 架空の例',
  'classification': '分類：機密', 'classification_note': '管理された情報分類を使用',
  'destination': '送信先', 'approved': '許可済みのAIエンドポイント',
  'guard': '送信前のチェック', 'checking': '情報分類 × 送信先 × 操作',
  'decision': 'この送信は拒否', 'not_sent': '検査のみ / 送信は未実行',
  'reason': '機密情報の外部送信は許可されていません。',
  'evidence': '判断の根拠', 'fact': '確認したこと',
  'fact_body': '入力に機密ラベルが設定されています。',
  'unknown': '確認していないこと', 'unknown_body': '実際の外部送信・漏えいの有無。',
  'next': '次に確認すること', 'next_body': '情報分類と、社内の利用ルール。',
  'dev': 'ローカル検証用の開発版 / 実際の防御には組み込みが必要',
  'steps': ['入力', '判定', '根拠', 'AISecure'],
 },
 'en': {
  'concept': 'PRODUCT CONCEPT / SYNTHETIC EXAMPLE, NOT A LIVE DEMO',
  'titles': ['Before it reaches AI.', 'Keep confidential data in.', 'Understand the decision.', 'Use AI. Check first.'],
  'sub': ['Review the content and where it is going.', 'An example using trusted confidential classification.', 'Separate evidence from what remains unknown.', 'Preflight checks. Evidence-led investigation.'],
  'doc': 'Summarize customer data', 'docsub': 'Text prepared for AI / synthetic example',
  'classification': 'CONFIDENTIAL', 'classification_note': 'Classification from a trusted adapter',
  'destination': 'DESTINATION', 'approved': 'An approved AI endpoint',
  'guard': 'Preflight check', 'checking': 'Classification × destination × action',
  'decision': 'Request denied', 'not_sent': 'Evaluation only / not executed',
  'reason': 'This route does not permit confidential information.',
  'evidence': 'Decision evidence', 'fact': 'OBSERVED',
  'fact_body': 'The input carries a confidential label.',
  'unknown': 'NOT ESTABLISHED', 'unknown_body': 'Actual delivery or a data leak.',
  'next': 'CHECK NEXT', 'next_body': 'The classification and your usage policy.',
  'dev': 'LOCAL EVALUATION BUILD / INTEGRATION REQUIRED FOR ENFORCEMENT',
  'steps': ['INPUT', 'DECISION', 'EVIDENCE', 'AISecure'],
 }
}

@lru_cache(maxsize=100)
def font(size: int, bold: bool = False):
    path = ROOT / ('NotoSansCJK-Bold.ttc' if bold else 'NotoSansCJK-Regular.ttc')
    return ImageFont.truetype(str(path), size, index=0)

def text(im, xy, value, size=30, color=WHITE, bold=False):
    ImageDraw.Draw(im).text(xy, value, font=font(size, bold), fill=color, anchor='lt')

def box(im, rect, fill=PANEL, border=LINE, radius=24):
    ImageDraw.Draw(im).rounded_rectangle(rect, radius, fill=fill, outline=border, width=2)

def pill(im, x, y, value, color=MINT, fill='#20394a', size=22):
    width = int(ImageDraw.Draw(im).textlength(value, font=font(size, True))) + 40
    box(im, (x, y, x+width, y+52), fill, fill, 10)
    text(im, (x+20, y+13), value, size, color, True)

def mark(im, x, y, scale=1.0, color=MINT):
    d=ImageDraw.Draw(im)
    d.rounded_rectangle((x,y,x+52*scale,y+58*scale),radius=14*scale,outline=color,width=max(2,int(3*scale)))
    d.line([(x+14*scale,y+29*scale),(x+24*scale,y+39*scale),(x+40*scale,y+19*scale)],fill=color,width=max(3,int(4*scale)))

def background(lang):
    im=Image.new('RGB',(W,H),BG)
    d=ImageDraw.Draw(im)
    # A restrained, low-contrast light field; not a stock animated background.
    for y in range(H):
        a=1-y/H
        d.line((0,y,W,y), fill=(12+int(3*a),20+int(4*a),36+int(6*a)))
    mark(im,104,72,.65)
    text(im,(153,77),'AISecure',32,WHITE,True)
    label=TEXT[lang]['concept']
    tw=d.textlength(label,font=font(19))
    text(im,(W-104-tw,84),label,19,MUTED)
    d.line((104,145,1816,145),fill=LINE,width=2)
    return im

def scene(lang, index):
    t=TEXT[lang]; im=background(lang)
    text(im,(112,201),f'0{index+1} / '+['BEFORE THE SEND','THE DECISION','THE EVIDENCE','A BETTER CHECKPOINT'][index],22,MINT,True)
    text(im,(106,253),t['titles'][index],68,WHITE,True)
    text(im,(112,353),t['sub'][index],30,MUTED)
    d=ImageDraw.Draw(im)
    if index==0:
        box(im,(112,444,830,856))
        text(im,(154,486),t['doc'],35,WHITE,True)
        text(im,(154,545),t['docsub'],23,MUTED)
        for k,length in enumerate([574,448,512]):
            d.rounded_rectangle((154,604+k*27,154+length,614+k*27),5,fill='#344159')
        pill(im,154,735,t['classification'])
        box(im,(1056,444,1808,856),fill='#182b37',border='#4b776f')
        mark(im,1100,493,1.0)
        text(im,(1180,505),t['guard'],34,WHITE,True)
        text(im,(1100,603),t['checking'],26,MUTED)
        d.line((1100,665,1764,665),fill='#35534e',width=2)
        text(im,(1100,704),t['destination'],20,MINT,True)
        text(im,(1100,753),t['approved'],27,WHITE)
        d.line((855,643,1034,643),fill='#517467',width=3)
        d.line((1018,629,1034,643,1018,657),fill=MINT,width=3)
    elif index==1:
        box(im,(112,444,670,856))
        text(im,(154,488),'ai.prompt',30,MUTED)
        text(im,(154,558),t['doc'],28,WHITE,True)
        pill(im,154,647,t['classification'])
        text(im,(154,752),t['classification_note'],22,MUTED)
        d.line((696,643,826,643),fill=RED,width=3)
        d.line((808,623,808,663),fill=RED,width=5)
        box(im,(848,444,1808,856),fill='#211f30',border='#59414b')
        pill(im,894,482,'BLOCK',RED,'#452d38')
        text(im,(894,570),t['decision'],52,WHITE,True)
        text(im,(894,658),t['reason'],26,MUTED)
        d.line((894,727,1762,727),fill='#483746',width=2)
        text(im,(894,764),'PG-002',25,RED,True)
        text(im,(1115,765),t['not_sent'],24,MUTED)
    elif index==2:
        box(im,(112,444,1808,856))
        pill(im,154,485,'PG-002',MINT,'#203c43')
        text(im,(154,572),t['evidence'],38,WHITE,True)
        text(im,(154,650),'EV-101',27,MUTED)
        d.line((692,488,692,810),fill=LINE,width=2)
        for j,(title,body) in enumerate([(t['fact'],t['fact_body']),(t['unknown'],t['unknown_body']),(t['next'],t['next_body'])]):
            y=480+j*109
            text(im,(742,y),title,22,MINT if j!=1 else '#e8c595',True)
            text(im,(742,y+44),body,28,WHITE)
    else:
        mark(im,744,460,1.2)
        text(im,(835,460),'AISecure',65,WHITE,True)
        text(im,(552 if lang=='ja' else 588,607),'EVIDENCE BEFORE ACTION',30,MINT,True)
        dw=d.textlength(t['dev'],font=font(24))
        text(im,((W-dw)/2,727),t['dev'],24,MUTED)
    return im

def ease(v):
    v=max(0.0,min(1.0,v)); return 1-(1-v)**3

def frame(scenes, t, lang):
    spans=[0,4.5,9,14,18]
    index=min(3,int(t//4.5)) if t<9 else 2 if t<14 else 3
    local=t-spans[index]
    im=background(lang)
    src=scenes[index]
    def reveal(rect, delay=0.0, rise=24):
        progress=ease((local-delay)/.7)
        if progress<=0: return
        layer=src.crop(rect).convert('RGBA')
        layer.putalpha(round(255*progress))
        im.paste(layer,(rect[0],rect[1]+round(rise*(1-progress))),layer)
    reveal((100,185,1818,408),0,15)
    if index==0:
        reveal((110,442,832,858),.15,28)
        reveal((1054,442,1810,858),.45,28)
        reveal((852,620,1038,669),.72,0)
        if local>1.25:
            d=ImageDraw.Draw(im)
            q=min(1,(local-1.25)/1.2)
            x=858+int(q*171)
            d.ellipse((x-7,636,x+7,650),fill=MINT)
    elif index==1:
        reveal((110,442,672,858),.05)
        reveal((846,442,1810,858),.25,32)
        reveal((693,620,830,667),.55,0)
    elif index==2:
        reveal((110,442,1810,858),.2,30)
    else:
        reveal((100,432,1820,792),.22,22)
    if local<.24 and index:
        im=Image.blend(scenes[index-1],im,ease(local/.24))
    d=ImageDraw.Draw(im)
    # The playhead is the only continuous motion; content stays readable.
    for k in range(4):
        x=112+k*430
        d.rounded_rectangle((x,942,x+397,946),2,fill=LINE)
        q=max(0,min(1,(t-spans[k])/(spans[k+1]-spans[k])))
        if q: d.rounded_rectangle((x,942,x+max(2,int(397*q)),946),2,fill=MINT)
        text(im,(x,975),f'0{k+1}  '+TEXT[lang]['steps'][k],20,MINT if k==index else MUTED)
    return im

def render(out: Path, lang: str):
    out.mkdir(parents=True,exist_ok=True)
    scenes=[scene(lang,i) for i in range(4)]
    frame(scenes,7,lang).save(out/f'product-film-{lang}-poster.jpg',quality=94,subsampling=0)
    movie=out/f'product-film-{lang}.mp4'
    command=['ffmpeg','-hide_banner','-loglevel','error','-y','-f','rawvideo','-pix_fmt','rgb24','-s',f'{W}x{H}',
             '-r',str(FPS),'-i','-','-an','-c:v','libx264','-preset','medium','-crf','19','-pix_fmt','yuv420p','-movflags','+faststart',str(movie)]
    with subprocess.Popen(command,stdin=subprocess.PIPE) as p:
        try:
            for i in range(FPS*DURATION): p.stdin.write(frame(scenes,i/FPS,lang).tobytes())
            p.stdin.close()
            if p.wait(): raise RuntimeError('Film encoding failed')
        except Exception:
            p.kill();raise
    cues=[]
    for n,(start,end) in enumerate([(0,4.5),(4.5,9),(9,14),(14,18)]):
        stamp=lambda v:f'00:00:{int(v):02d}.{int((v%1)*1000):03d}'
        cues.append(f'{n+1}\n{stamp(start)} --> {stamp(end)}\n{TEXT[lang]["titles"][n]} {TEXT[lang]["sub"][n]}')
    (out/f'product-film-{lang}.vtt').write_text('WEBVTT\n\n'+'\n\n'.join(cues)+'\n',encoding='utf-8')
    print(f'{lang}: {movie.stat().st_size} bytes / {DURATION}s / {W}x{H} / {FPS}fps',flush=True)

if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--out',type=Path,default=Path('docs/media'))
    parser.add_argument('--lang',choices=['ja','en','both'],default='both');args=parser.parse_args()
    for language in (['ja','en'] if args.lang=='both' else [args.lang]): render(args.out,language)
