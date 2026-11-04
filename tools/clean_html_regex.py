import re
import sys

sys.stdout.reconfigure(encoding='utf-8')

# KO
with open(r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\docs\index.html', 'r', encoding='utf-8') as f:
    text = f.read()
text = re.sub(r'TFalke[^\n<]*<b>Naseeba Kanu</b>[^\n<]*<b>"[^"\n]*"</b>',
              '글로벌 엔터프라이즈 SecOps 표준 원칙을 수용하여 설계된 초경량 제로-터치 감사 도구입니다. <b>"EDR과 충돌하거나 롤백 계획이 필요한 감사는 보안팀이 도입하지 못합니다. 엔드포인트 상태를 확인하는 가벼운 읽기 전용 방식이 보안팀에게 가장 안전하고 실용적인 대안입니다."</b>', text)
with open(r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\docs\index.html', 'w', encoding='utf-8') as f:
    f.write(text)

# JA
for p in [
    r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\docs\index.ja.html',
    r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\docs\ja\index.html'
]:
    with open(p, 'r', encoding='utf-8') as f:
        text = f.read()
    text = re.sub(r'TFalke[^\n<]*<b>Naseeba Kanu</b>[^\n<]*<b>「[^」\n]*」</b>',
                  'エンタープライズ SecOps 原則に基づき設計された超軽量ゼロタッチ監査ツールです。<b>「EDR と競合したりロールバック計画が必要な監査は導入されません。軽量で読み取り専用のエンドポイント状態確認こそが、セキュリティチームに受け入れられる最善の方法です」</b>', text)
    with open(p, 'w', encoding='utf-8') as f:
        f.write(text)

print('Updated html files via regex successfully')
