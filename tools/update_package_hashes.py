import json
import re

# 1. Scoop
scoop_path = r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\packages\scoop\cve-security-suite.json'
with open(scoop_path, 'r', encoding='utf-8') as f:
    data = json.load(f)
data['hash'] = 'sha256:E296850AB4D2F9DE878928C7710374B2CD9931B97F3188C849AFE6CA6318225E'
with open(scoop_path, 'w', encoding='utf-8') as f:
    json.dump(data, f, indent=2, ensure_ascii=False)
print('Updated scoop json successfully')

# 2. Winget
winget_path = r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\packages\winget\CVE.SecurityOperationsSuite.yaml'
with open(winget_path, 'r', encoding='utf-8') as f:
    text = f.read()
text = re.sub(r'InstallerSha256:\s+[A-Fa-f0-9]{64}', 'InstallerSha256: E296850AB4D2F9DE878928C7710374B2CD9931B97F3188C849AFE6CA6318225E', text)
with open(winget_path, 'w', encoding='utf-8') as f:
    f.write(text)
print('Updated winget yaml successfully')
