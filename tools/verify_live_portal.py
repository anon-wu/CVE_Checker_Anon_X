import urllib.request
import re
import sys

sys.stdout.reconfigure(encoding='utf-8')

urls = [
    ('Korean', 'https://anon-wu.github.io/CVE_Checker_Anon_X/index.html'),
    ('English', 'https://anon-wu.github.io/CVE_Checker_Anon_X/index.en.html'),
    ('Japanese', 'https://anon-wu.github.io/CVE_Checker_Anon_X/index.ja.html'),
]

for label, url in urls:
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as resp:
            html = resp.read().decode('utf-8')
        card_count = html.count('class="stat-card"')
        matches = re.findall(r'class="stat-number">([^<]+)</div>\s*<div class="stat-label">([^<]+)</div>', html)
        print(f'[{label}] Stat cards: {card_count}')
        for num, lab in matches:
            print(f'    - {num.strip()} : {lab.strip()}')
    except Exception as e:
        print(f'[{label}] Error: {e}')
