import sys
import re

sys.stdout.reconfigure(encoding='utf-8')

with open(r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\src\CveCatalogGenerator.cs', 'r', encoding='utf-8') as f:
    text = f.read()

comps = set(re.findall(r'ComponentOrPort\s*=\s*"([^"]+)"', text))
print('Total unique components in Internal DB:', len(comps))
for c in sorted(comps)[:35]:
    print(' -', c)

with open(r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\src\ExternalScannerProgram.cs', 'r', encoding='utf-8') as f:
    ext_text = f.read()

ext_comps = set(re.findall(r'ComponentOrPort\s*=\s*"([^"]+)"', ext_text))
print('Total unique components in External DB:', len(ext_comps))
for c in sorted(ext_comps)[:35]:
    print(' -', c)
