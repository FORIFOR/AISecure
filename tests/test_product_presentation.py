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
    def test_both_languages_use_new_film(self):
        for lang,html in self.pages:
            tags=Tags(html).tags
            videos=[a for t,a in tags if t=='video'];self.assertEqual(len(videos),1)
            self.assertEqual(videos[0]['id'],'product-film');self.assertIn('controls',videos[0])
            self.assertNotIn('autoplay',videos[0]);self.assertEqual(videos[0]['preload'],'none')
            self.assertEqual(videos[0]['poster'],f'media/product-film-{lang}-poster.jpg')
            self.assertTrue(any(t=='source' and a['src']==f'media/product-film-{lang}.mp4' for t,a in tags))
    def test_old_recordings_are_not_on_homepage(self):
        for lang,html in self.pages:
            for old in ('screendemo.mp4','intro.mp4','intro-ja.mp4','screendemo-poster.png'):
                self.assertNotIn(old,html)
    def test_local_movies_and_posters_exist(self):
        for lang,html in self.pages:
            movie=(DOCS/f'media/product-film-{lang}.mp4').read_bytes()
            self.assertEqual(movie[4:8],b'ftyp');self.assertIn(b'moov',movie)
            self.assertGreater(len(movie),100000);self.assertLess(len(movie),5*1024*1024)
            self.assertEqual((DOCS/f'media/product-film-{lang}-poster.jpg').read_bytes()[:2],b'\xff\xd8')
    def test_caption_tracks_are_language_matched(self):
        for lang,html in self.pages:
            tracks=[a for t,a in Tags(html).tags if t=='track'];self.assertEqual(len(tracks),1)
            self.assertEqual(tracks[0]['srclang'],lang);self.assertEqual(tracks[0]['kind'],'captions')
            captions=(DOCS/tracks[0]['src']).read_text(encoding='utf-8')
            self.assertTrue(captions.startswith('WEBVTT'));self.assertEqual(captions.count('-->'),4)
            self.assertIn('00:00:18.000',captions)
    def test_concept_disclosure_and_text_alternative(self):
        for lang,html in self.pages:
            self.assertIn('film-disclosure',html);self.assertIn('class="transcript"',html)
            self.assertIn('製品イメージ' if lang=='ja' else 'PRODUCT CONCEPT',html)
            self.assertIn('実機の操作・防御実績ではありません' if lang=='ja' else 'Not a live UI recording',html)
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
