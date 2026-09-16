"""Homepage contracts; no browser, network, real logs or credentials required."""
from html.parser import HTMLParser
import json
from pathlib import Path
import unittest
from urllib.parse import unquote, urlsplit
from aisecure.preflight import evaluate, parse_policy, parse_request

ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / 'docs'


class Tags(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.tags = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def select(self, tag):
        return [attrs for name, attrs in self.tags if name == tag]


class HomepageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pages = [(name, (DOCS / name).read_text(encoding='utf-8'))
                     for name in ('index.html', 'index.ja.html')]
        cls.fixture = json.loads((DOCS / 'preflight-preview.json').read_text(encoding='utf-8'))

    def test_preview_results_match_python_guard(self):
        policy = parse_policy(self.fixture['policy'])
        self.assertEqual(len(self.fixture['samples']), 4)
        for sample in self.fixture['samples']:
            self.assertEqual(evaluate(parse_request(sample['request']), policy).report(), sample['result'])

    def test_panels_match_real_sample_decisions(self):
        for name, text in self.pages:
            with self.subTest(page=name):
                panels = [a for t, a in Tags(text).tags if 'data-sample-panel' in a]
                self.assertEqual(len(panels), 4)
                for panel, sample in zip(panels, self.fixture['samples']):
                    self.assertEqual(panel['data-decision'], sample['result']['decision'])
                    self.assertEqual(panel['data-rule'], ', '.join(sample['result']['rule_ids']) or '—')

    def test_accessible_tabs_have_unique_targets(self):
        for name, text in self.pages:
            with self.subTest(page=name):
                tags = Tags(text)
                ids = [a['id'] for t, a in tags.tags if 'id' in a]
                self.assertEqual(len(ids), len(set(ids)))
                tabs = [a for t, a in tags.tags if a.get('role') == 'tab']
                self.assertEqual(len(tabs), 4)
                self.assertEqual(sum(t['aria-selected'] == 'true' for t in tabs), 1)
                for tab in tabs:
                    self.assertIn(tab['aria-controls'], ids)
                self.assertTrue(any(a.get('href') == '#main' for a in tags.select('a')))

    def test_local_assets_and_anchor_links_exist(self):
        for name, text in self.pages:
            with self.subTest(page=name):
                tags = Tags(text)
                ids = {a['id'] for t, a in tags.tags if 'id' in a}
                for tag, attrs in tags.tags:
                    for key in ('src', 'href', 'poster'):
                        value = attrs.get(key)
                        if not value:
                            continue
                        if value.startswith('#'):
                            self.assertIn(value[1:], ids)
                        else:
                            url = urlsplit(value)
                            if not url.scheme and not url.netloc and url.path:
                                path = (DOCS / unquote(url.path)).resolve()
                                self.assertTrue(path.is_relative_to(DOCS.resolve()))
                                self.assertTrue(path.is_file(), f'{name}: {value}')

    def test_language_and_search_metadata(self):
        for name, text in self.pages:
            with self.subTest(page=name):
                tags = Tags(text)
                self.assertEqual(tags.select('html')[0]['lang'], 'ja' if '.ja.' in name else 'en')
                self.assertEqual(len(tags.select('h1')), 1)
                links = tags.select('link')
                self.assertEqual(sum(a.get('rel') == 'canonical' for a in links), 1)
                self.assertEqual({a.get('hreflang') for a in links if a.get('rel') == 'alternate'}, {'ja', 'en', 'x-default'})
                metas = tags.select('meta')
                self.assertTrue(any(a.get('name') == 'description' for a in metas))
                self.assertTrue(any(a.get('name') == 'referrer' and a.get('content') == 'no-referrer' for a in metas))

    def test_no_external_script_or_stylesheet(self):
        for name, text in self.pages:
            with self.subTest(page=name):
                tags = Tags(text)
                for attrs in tags.select('script'):
                    self.assertFalse(urlsplit(attrs['src']).scheme)
                    self.assertIn('defer', attrs)
                for attrs in tags.select('link'):
                    if attrs.get('rel') == 'stylesheet':
                        self.assertFalse(urlsplit(attrs['href']).scheme)

    def test_homepage_explicitly_disables_shared_analytics(self):
        for name, text in self.pages:
            scripts = Tags(text).select('script')
            shared = next(a for a in scripts if a.get('src') == 'portfolio.js')
            self.assertEqual(shared.get('data-analytics'), 'off')
        script = (DOCS / 'portfolio.js').read_text(encoding='utf-8')
        self.assertIn("if(script.dataset.analytics==='off')return;", script)
        self.assertNotIn('fetch(', (DOCS / 'home.js').read_text(encoding='utf-8'))

    def test_contact_requires_javascript_and_consent(self):
        for name, text in self.pages:
            tags = Tags(text)
            form = next(a for a in tags.select('form') if a.get('id') == 'portfolio-form')
            self.assertEqual(form.get('method'), 'post')
            submit = next(a for a in tags.select('button') if a.get('type') == 'submit')
            self.assertIn('disabled', submit)
            consent = next(a for a in tags.select('input') if a.get('name') == 'consent')
            self.assertIn('required', consent)
            self.assertEqual(consent['type'], 'checkbox')
        script = (DOCS / 'portfolio.js').read_text(encoding='utf-8')
        self.assertIn('submitButton.disabled=false', script)

    def test_video_is_user_initiated_and_retains_poster(self):
        for name, text in self.pages:
            videos = Tags(text).select('video')
            self.assertEqual(len(videos), 1)
            self.assertIn('controls', videos[0])
            self.assertNotIn('autoplay', videos[0])
            self.assertEqual(videos[0]['preload'], 'none')
            self.assertTrue((DOCS / videos[0]['poster']).is_file())

    def test_unverified_old_headline_metrics_removed(self):
        for name, text in self.pages:
            self.assertNotIn('テスト216件', text)
            self.assertNotIn('F1 1.00', text)
            self.assertNotIn('依存ゼロ', text)
            self.assertIn('not_executed', text)
            self.assertIn('PREVENTION_BOUNDARY.ja.md', text)

    def test_reduced_motion_and_keyboard_navigation_exist(self):
        self.assertIn('prefers-reduced-motion', (DOCS / 'home.css').read_text(encoding='utf-8'))
        script = (DOCS / 'home.js').read_text(encoding='utf-8')
        for key in ('ArrowRight', 'ArrowLeft', 'Home', 'End'):
            self.assertIn(key, script)
        self.assertIn('aria-selected', script)

    def test_synthetic_fixture_never_claims_live_execution(self):
        for sample in self.fixture['samples']:
            self.assertEqual(urlsplit(sample['request']['destination']).hostname, 'approved.example')
            self.assertEqual(sample['result']['execution_state'], 'not_executed')
            self.assertFalse(sample['result']['llm_used'])


if __name__ == '__main__':
    unittest.main()
