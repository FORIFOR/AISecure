import struct
import unittest
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
DOCS=ROOT/'docs'


class HomepageProductImageTests(unittest.TestCase):
    def test_actual_workbench_capture_is_a_real_png(self):
        data=(DOCS/'media'/'workbench-actual.png').read_bytes()
        self.assertGreater(len(data),100_000,'workbench capture is suspiciously small')
        self.assertEqual(data[:8],b'\x89PNG\r\n\x1a\n')
        self.assertEqual(data[12:16],b'IHDR')
        width,height=struct.unpack('>II',data[16:24])
        self.assertGreaterEqual(width,1200)
        self.assertGreaterEqual(height,1800)

    def test_homepage_swaps_to_the_verified_capture(self):
        js=(DOCS/'home.js').read_text(encoding='utf-8')
        css=(DOCS/'home-refine.css').read_text(encoding='utf-8')
        self.assertIn('media/workbench-actual.png',js)
        self.assertIn("product-actual",js)
        self.assertIn('.hero-shot .product-actual',css)
        self.assertIn('.crop-history .product-actual',css)
        self.assertIn('object-fit:cover',css)


if __name__=='__main__':
    unittest.main()
