"""Public presentation contracts. These are not tests of security enforcement."""
from html.parser import HTMLParser
from pathlib import Path
import unittest

DOCS=Path(__file__).resolve().parents[1]/'docs'
class Tags(HTMLParser):
    def __init__(self,text):
        super().__init__();self.tags=[];self.feed(text)
    def handle_starttag(self,name,attrs):self.tags.append((name,dict(attrs)))

class ProductPresentationTests(unittest.TestCase):
    def setUp(self):
        self.pages=[(lang,(DOCS/name).read_text(encoding='utf-8')) for lang,name in [('ja','index.ja.html'),('en','index.html')]]
    def test_both_languages_use_the_real_recording(self):
        # The homepage video is a screen recording of the shipped app, produced by
        # tools/record_demo.cjs. Captions are burned in, so one cut serves both pages.
        for lang,html in self.pages:
            tags=Tags(html).tags
            videos=[a for t,a in tags if t=='video'];self.assertEqual(len(videos),1)
            self.assertEqual(videos[0]['id'],'product-film');self.assertIn('controls',videos[0])
            self.assertNotIn('autoplay',videos[0]);self.assertEqual(videos[0]['preload'],'none')
            self.assertEqual(videos[0]['poster'],'media/demo-poster.jpg')
            self.assertTrue(any(t=='source' and a['src']=='media/demo-desktop.mp4' for t,a in tags))
            self.assertNotIn('product-film-en.mp4',html);self.assertNotIn('product-film-ja.mp4',html)
    def test_old_recordings_are_not_on_homepage(self):
        for lang,html in self.pages:
            for old in ('screendemo.mp4','intro.mp4','intro-ja.mp4','screendemo-poster.png'):
                self.assertNotIn(old,html)
    def test_local_movies_and_posters_exist(self):
        movie=(DOCS/'media/demo-desktop.mp4').read_bytes()
        self.assertEqual(movie[4:8],b'ftyp');self.assertIn(b'moov',movie)
        self.assertGreater(len(movie),100000);self.assertLess(len(movie),5*1024*1024)
        self.assertEqual((DOCS/'media/demo-poster.jpg').read_bytes()[:2],b'\xff\xd8')
        # The vertical cut ships for social, from the same recording.
        vertical=(DOCS/'media/demo-vertical.mp4').read_bytes()
        self.assertEqual(vertical[4:8],b'ftyp');self.assertLess(len(vertical),5*1024*1024)
        self.assertTrue((DOCS/'media/demo-raw/raw.webm').exists(),'原録画を残すこと')
    def test_recording_has_a_text_alternative(self):
        # Burned-in captions are not reachable by a screen reader, so the same
        # content must exist as text next to the video.
        for lang,html in self.pages:
            self.assertEqual([a for t,a in Tags(html).tags if t=='track'],[])
            self.assertIn('class="transcript"',html)
            for line in (['社外秘の資料を、AIに貼ろうとしている','判定はJSONで手元に残る'] if lang=='ja'
                         else ['A confidential draft is about to be pasted into an AI',
                               'The verdict is kept as JSON on the device']):
                self.assertIn(line,html)
    def test_recording_is_labelled_for_what_it_is(self):
        # It is a real recording, so it must not be labelled a concept film — and
        # it must still say the data is synthetic and nothing was sped up.
        for lang,html in self.pages:
            self.assertIn('film-disclosure',html)
            for phrase in (['実アプリの画面収録','合成サンプル','早送りなし'] if lang=='ja'
                           else ['Screen recording of the real app','synthetic sample','no speed-up']):
                self.assertIn(phrase,html)
            self.assertNotIn('製品イメージ' if lang=='ja' else 'PRODUCT CONCEPT',html)
    def test_play_cover_is_progressively_enhanced(self):
        for lang,html in self.pages:
            buttons=[a for t,a in Tags(html).tags if t=='button' and 'film-splash' in a.get('class','')]
            self.assertEqual(len(buttons),1);self.assertTrue(buttons[0].get('aria-label'))
        script=(DOCS/'home.js').read_text(encoding='utf-8')
        self.assertIn("video.addEventListener('play'",script);self.assertNotIn('fetch(',script)
    def test_original_samples_and_evaluation_boundaries_remain(self):
        for lang,html in self.pages:
            panels=[a for t,a in Tags(html).tags if 'data-sample-panel' in a]
            self.assertEqual([a['data-decision'] for a in panels],['block','review','allow','review'])
            self.assertIn('not_executed',html);self.assertIn('PREVENTION_BOUNDARY.ja.md',html)
    def test_no_third_party_video_embed(self):
        for lang,html in self.pages:
            self.assertFalse(any(t=='iframe' for t,a in Tags(html).tags))
            self.assertIn('data-analytics="off"',html)

if __name__=='__main__':unittest.main()
