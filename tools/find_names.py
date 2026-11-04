import os
import sys

sys.stdout.reconfigure(encoding='utf-8')

files = [
    'README.en.md', 'README.ja.md', 'README.md',
    'docs/index.en.html', 'docs/index.html', 'docs/index.ja.html',
    'docs/en/index.html', 'docs/ja/index.html',
    'src/AuditorProgram.cs'
]

for f in files:
    print(f'=== {f} ===')
    with open(f, 'r', encoding='utf-8', errors='ignore') as fp:
        lines = fp.readlines()
    for i, line in enumerate(lines):
        if 'naseeba' in line.lower() or 'kanu' in line.lower():
            print(f'{i+1}: {line.strip()[:110]}')
