import sys

sys.stdout.reconfigure(encoding='utf-8')

# 1. README.md
p_ko = r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\README.md'
with open(p_ko, 'r', encoding='utf-8') as f:
    t = f.read()
t = t.replace(
    '> — **Naseeba Kanu** (Co-founder at TFalke | Windows device management)',
    '> — **엔터프라이즈 SecOps & 디바이스 관리 핵심 원칙 (Enterprise SecOps Principle)**'
)
with open(p_ko, 'w', encoding='utf-8') as f:
    f.write(t)

# 2. README.en.md
p_en = r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\README.en.md'
with open(p_en, 'r', encoding='utf-8') as f:
    t = f.read()
t = t.replace(
    '> — **Naseeba Kanu** (Co-founder at TFalke | Windows device management)',
    '> — **Enterprise SecOps & Device Management Principle**'
)
with open(p_en, 'w', encoding='utf-8') as f:
    f.write(t)

# 3. README.ja.md
p_ja = r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\README.ja.md'
with open(p_ja, 'r', encoding='utf-8') as f:
    t = f.read()
t = t.replace(
    '> — **Naseeba Kanu 氏** (TFalke 共同創設者 | Windows デバイス管理)',
    '> — **エンタープライズ SecOps & デバイス管理の基本原則**'
)
with open(p_ja, 'w', encoding='utf-8') as f:
    f.write(t)

# 4. docs/index.html
for path in [
    r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\docs\index.html'
]:
    with open(path, 'r', encoding='utf-8') as f:
        t = f.read()
    t = t.replace('FREE & OPEN AUDITOR • NASEEBA KANU ENTERPRISE SPEC', 'FREE & OPEN AUDITOR • ZERO-TOUCH ENTERPRISE SPEC')
    t = t.replace(
        'TFalke 공동창업자 <b>Naseeba Kanu</b>의 핵심 조언을 수용하여 설계된 초경량 제로-터치 감사 도구입니다. <b>"EDR과 싸우거나 롤백 계획이 필요한 감사는 보안팀이 도입하지 못합니다. 엔드포인트 상태를 확인하는 가벼운 읽기 전용 방식이 보안팀에게 훨씬 매력적인 대안입니다."</b>',
        '글로벌 엔터프라이즈 SecOps 표준 원칙을 수용하여 설계된 초경량 제로-터치 감사 도구입니다. <b>"EDR과 충돌하거나 롤백 계획이 필요한 감사는 보안팀이 도입하지 못합니다. 엔드포인트 상태를 확인하는 가벼운 읽기 전용 방식이 보안팀에게 가장 안전하고 실용적인 대안입니다."</b>'
    )
    with open(path, 'w', encoding='utf-8') as f:
        f.write(t)

# 5. docs/index.en.html and docs/en/index.html
for path in [
    r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\docs\index.en.html',
    r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\docs\en\index.html'
]:
    with open(path, 'r', encoding='utf-8') as f:
        t = f.read()
    t = t.replace('FREE & OPEN AUDITOR • NASEEBA KANU ENTERPRISE SPEC', 'FREE & OPEN AUDITOR • ZERO-TOUCH ENTERPRISE SPEC')
    t = t.replace(
        'Engineered based on enterprise SecOps feedback from <b>Naseeba Kanu</b> (Co-founder at TFalke): <b>"An audit that fights the EDR or needs a rollback plan just does not get run. A lightweight, read-only way to check endpoint state is a much easier sell to the security team."</b>',
        'Engineered based on enterprise SecOps principles: <b>"An audit that fights the EDR or needs a rollback plan just does not get run. A lightweight, read-only way to check endpoint state is the optimal path for security teams."</b>'
    )
    with open(path, 'w', encoding='utf-8') as f:
        f.write(t)

# 6. docs/index.ja.html and docs/ja/index.html
for path in [
    r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\docs\index.ja.html',
    r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\docs\ja\index.html'
]:
    with open(path, 'r', encoding='utf-8') as f:
        t = f.read()
    t = t.replace('FREE & OPEN AUDITOR • NASEEBA KANU ENTERPRISE SPEC', 'FREE & OPEN AUDITOR • ZERO-TOUCH ENTERPRISE SPEC')
    t = t.replace(
        'TFalke 共同創設者 <b>Naseeba Kanu</b> 氏の洞察に基づき設計された超軽量ゼロタッチ監査ツールです。<b>「EDR と競合したりロールバック計画が必要な監査は導入されません。軽量で読み取り専用のエンドポイント状態確認こそが、セキュリティチームに受け入れられる最善の方法です」</b>',
        'エンタープライズ SecOps 原則に基づき設計された超軽量ゼロタッチ監査ツールです。<b>「EDR と競合したりロールバック計画が必要な監査は導入されません。軽量で読み取り専用のエンドポイント状態確認こそが、セキュリティチームに受け入れられる最善の方法です」</b>'
    )
    with open(path, 'w', encoding='utf-8') as f:
        f.write(t)

print('Cleaned personal names from docs and READMEs successfully')
