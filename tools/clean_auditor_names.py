# -*- coding: utf-8 -*-
import sys

sys.stdout.reconfigure(encoding='utf-8')

aud_path = r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\src\AuditorProgram.cs'

with open(aud_path, 'r', encoding='utf-8') as f:
    text = f.read()

import re
text = re.sub(r'Device Zero-Touch Auditor v11\.5 \(Naseeba Kanu [^)]+\)',
              lambda m: 'Device Zero-Touch Auditor v11.5 (독립 감사자 전용 무변형 에디션)' if '감사' in m.group(0) or '엔터' in m.group(0) else ('Device Zero-Touch Auditor v11.5 (独立監査者専用・無変形エディション)' if '企業' in m.group(0) or 'モデル' in m.group(0) else 'Device Zero-Touch Auditor v11.5 (Independent Zero-Touch Auditor Edition)'),
              text)

# Also ensure any stray 'Naseeba Kanu' is replaced
text = text.replace('Naseeba Kanu', 'Zero-Touch')

with open(aud_path, 'w', encoding='utf-8') as f:
    f.write(text)

print('Cleaned any remaining occurrences of Naseeba Kanu in AuditorProgram.cs')
