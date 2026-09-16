"""One-time, hash-bound source transfer. Removed before integration."""
import base64
import hashlib
import json
import lzma
from pathlib import Path
import subprocess

ROOT = Path.cwd().resolve()
raw64 = ''.join((ROOT / f'.workbench-transfer/{i}.b64').read_text().strip() for i in range(6))
assert len(raw64) == 59896, 'Encoded length mismatch'
compressed = base64.b64decode(raw64, validate=True)
decoder = lzma.LZMADecompressor(memlimit=128 * 1024 * 1024)
raw = decoder.decompress(compressed, max_length=1_000_000)
assert decoder.eof and not decoder.unused_data, 'Incomplete or trailing archive'
assert len(raw) == 159590, 'Decoded length mismatch'
assert hashlib.sha256(raw).hexdigest() == '9e354d1b2779d47fc7f460e244d710eb3667b0069c58a09f532b266437e208c3', 'Transfer checksum mismatch'
bundle = json.loads(raw)
assert bundle['base'] == '9826f9f01c51ea8cd47ebd904d11dd86e14d5951'
subprocess.run(['git', 'merge-base', '--is-ancestor', bundle['base'], 'HEAD'], check=True)
assert len(bundle['files']) == 40
prefixes = ('aisecure/', 'deployment/', 'docs/', 'tests/', 'tools/', '.github/workflows/')
root_files = {'.dockerignore', '.gitignore', 'CHANGELOG.md', 'README.md', 'README.ja.md', 'pyproject.toml'}
outputs = {}
for item in bundle['files']:
    name = item['path']
    path = Path(name)
    assert not path.is_absolute() and '..' not in path.parts and name not in outputs
    assert name in root_files or name.startswith(prefixes)
    target = ROOT / path
    assert target.resolve().is_relative_to(ROOT)
    assert not target.is_symlink()
    if 'text' in item:
        assert not target.exists(), f'New path already exists: {name}'
        text = item['text']
    elif 'copy' in item:
        assert not target.exists()
        assert item['copy'] in {'web/app.js', 'web/i18n.js', 'web/index.html', 'web/style.css'}
        text = (ROOT / item['copy']).read_text(encoding='utf-8')
    else:
        original = target.read_bytes()
        assert hashlib.sha256(original).hexdigest() == item['old_sha256'], f'Base changed: {name}'
        text = original.decode('utf-8')
        previous = len(text)
        for begin, end, insertion in reversed(item['edits']):
            assert 0 <= begin <= end <= previous
            text = text[:begin] + insertion + text[end:]
            previous = begin
    content = text.encode('utf-8')
    assert hashlib.sha256(content).hexdigest() == item['sha256'], f'Output mismatch: {name}'
    outputs[name] = content
for name, content in outputs.items():
    target = ROOT / name
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(content)
quality = Path('/tmp/workbench-quality')
quality.mkdir(exist_ok=True)
(quality / 'applied-sources.json').write_text(json.dumps({name: hashlib.sha256(content).hexdigest() for name, content in outputs.items()}, indent=2))
print(f'Validated and applied {len(outputs)} sources. No production connections were activated.')
