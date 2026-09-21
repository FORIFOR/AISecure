import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from concurrent.futures import ThreadPoolExecutor
from aisecure.control.inspect_file import save_report


class SaveReportTests(unittest.TestCase):
    def test_private_complete_and_existing_target_preserved(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'result.json'
            save_report(output, '{"complete":true}\n')
            self.assertEqual(output.read_text(), '{"complete":true}\n')
            if os.name == 'posix': self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): save_report(output,'replacement')
            self.assertEqual(output.read_text(), '{"complete":true}\n')
            self.assertEqual(list(Path(directory).glob('.aisecure-report-*')), [])

    def test_write_or_publish_failure_leaves_no_output(self):
        for target in ['os.fsync','os.link']:
            with self.subTest(target=target), tempfile.TemporaryDirectory() as directory:
                output=Path(directory)/'result.json'
                with patch('aisecure.control.inspect_file.'+target, side_effect=OSError('synthetic disk failure')):
                    with self.assertRaises(OSError): save_report(output,'{"complete":true}')
                self.assertFalse(output.exists())
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_partial_write_failure_never_publishes(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/'result.json'
            original=os.fdopen
            class PartialWrite:
                def __init__(self, descriptor, *args, **kwargs):
                    self.stream=original(descriptor,*args,**kwargs)
                def __enter__(self): return self
                def __exit__(self,*args): self.stream.close()
                def write(self, body):
                    self.stream.write(body[:5]); self.stream.flush()
                    raise OSError('synthetic short disk write')
            with patch('aisecure.control.inspect_file.os.fdopen',side_effect=PartialWrite):
                with self.assertRaises(OSError): save_report(output,'{"complete":true}')
            self.assertFalse(output.exists())
            self.assertEqual(list(Path(directory).iterdir()),[])

    def test_symlink_and_concurrent_publish_do_not_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            original=Path(directory)/'original'; original.write_text('preserve')
            output=Path(directory)/'link'; output.symlink_to(original)
            with self.assertRaises(FileExistsError): save_report(output,'replacement')
            self.assertEqual(original.read_text(),'preserve')
            output=Path(directory)/'race.json'
            def attempt(value):
                try: save_report(output,value); return True
                except FileExistsError: return False
            with ThreadPoolExecutor(max_workers=2) as pool:
                results=list(pool.map(attempt,['{"a":1}','{"b":2}']))
            self.assertEqual(sum(results),1)
            self.assertIn(output.read_text(),['{"a":1}','{"b":2}'])
            self.assertEqual(list(Path(directory).glob('.aisecure-report-*')), [])
