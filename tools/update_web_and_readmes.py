# -*- coding: utf-8 -*-
"""
Web Portals & Multilingual README Updater for DeviceAuditor.exe
Updates all 5 HTML pages and 3 README documents with authentic DeviceAuditor documentation.
"""

import os
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS_DIR = os.path.join(BASE_DIR, "docs")

AUDITOR_HTML_KO = """
    <!-- Dedicated Zero-Touch Auditor Section -->
    <section id="auditor" style="margin-top: 3rem; margin-bottom: 3.5rem;">
      <div style="background: linear-gradient(135deg, rgba(22, 27, 34, 0.95) 0%, rgba(13, 17, 23, 0.95) 100%); border: 1px solid rgba(88, 166, 255, 0.35); border-radius: 16px; padding: 2.2rem; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 15px; margin-bottom: 1.2rem;">
          <div>
            <span style="background: rgba(46, 160, 67, 0.15); color: #3fb950; border: 1px solid rgba(46, 160, 67, 0.3); padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 700; letter-spacing: 0.5px;">
              FREE & OPEN AUDITOR • NASEEBA KANU ENTERPRISE SPEC
            </span>
            <h2 style="font-size: 1.85rem; font-weight: 800; color: #fff; margin-top: 0.8rem; margin-bottom: 0.4rem;">
              🛡️ DeviceAuditor.exe — 100% 무변형 읽기 전용 엔터프라이즈 감사기
            </h2>
            <p style="color: #8b949e; font-size: 1rem; max-width: 820px; line-height: 1.6;">
              TFalke 공동창업자 <b>Naseeba Kanu</b>의 핵심 조언을 수용하여 설계된 초경량 제로-터치 감사 도구입니다. <b>"EDR과 싸우거나 롤백 계획이 필요한 감사는 보안팀이 도입하지 못합니다. 가볍고 읽기 전용인 상태 확인 방식이 보안팀에게 훨씬 매력적입니다."</b>
            </p>
          </div>
          <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <a href="https://raw.githubusercontent.com/anon-wu/CVE_Checker_Anon_X/main/releases/CVE_Security_Operations_Suite_Portable.zip" class="btn-primary" style="padding: 10px 20px; font-size: 0.9rem;">
              ⬇️ DeviceAuditor.exe 무료 다운로드
            </a>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.2rem; margin-top: 1.5rem;">
          <div style="background: rgba(13, 17, 23, 0.8); border: 1px solid #30363d; border-radius: 10px; padding: 1.2rem;">
            <div style="font-size: 1.1rem; font-weight: 700; color: #58a6ff; margin-bottom: 0.5rem;">🔒 100% 무변형 읽기 전용 (0 Byte Mutation)</div>
            <p style="font-size: 0.88rem; color: #c9d1d9; line-height: 1.5; margin: 0;">
              레지스트리 쓰기 0건, 서비스 중단 0건, 파일 수정 0건을 코드 레벨에서 보장합니다. 시스템을 전혀 변경하지 않으므로 변경 관리 위원회(CAB) 승인이나 <b>롤백 계획(Rollback Plan)이 전혀 불필요</b>합니다.
            </p>
          </div>

          <div style="background: rgba(13, 17, 23, 0.8); border: 1px solid #30363d; border-radius: 10px; padding: 1.2rem;">
            <div style="font-size: 1.1rem; font-weight: 700; color: #3fb950; margin-bottom: 0.5rem;">⚡ EDR 무간섭 & 초고속 진단</div>
            <p style="font-size: 0.88rem; color: #c9d1d9; line-height: 1.5; margin: 0;">
              CrowdStrike, SentinelOne, Defender for Endpoint 등 어떤 EDR 솔루션과도 충돌이나 오탐 경고를 유발하지 않으며, 표준 Windows API 읽기만으로 수초 내에 감사를 완료합니다.
            </p>
          </div>

          <div style="background: rgba(13, 17, 23, 0.8); border: 1px solid #30363d; border-radius: 10px; padding: 1.2rem;">
            <div style="font-size: 1.1rem; font-weight: 700; color: #d2a8ff; margin-bottom: 0.5rem;">📊 JSON & OASIS SARIF v2.1.0 완벽 지원</div>
            <p style="font-size: 0.88rem; color: #c9d1d9; line-height: 1.5; margin: 0;">
              GUI에서 1클릭 복사/저장뿐만 아니라, CLI(<code>--json</code>, <code>--sarif</code>, <code>--lang=ko|en|ja</code>)를 통해 <b>TFalke, Microsoft Intune, SIEM, GitHub Code Scanning</b>에 즉시 연동됩니다.
            </p>
          </div>
        </div>

        <div style="margin-top: 1.5rem; background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 0.9rem 1.2rem; font-family: Consolas, monospace; font-size: 0.85rem; color: #79c0ff; overflow-x: auto;">
          <span style="color: #8b949e;"># TFalke / Intune 파이프라인 자동화 CLI 실행 예시</span><br/>
          <span>.\\DeviceAuditor.exe --json --lang=ko --out="audit_report.json"</span><br/>
          <span>.\\DeviceAuditor.exe --sarif --out="cve_audit.sarif"</span>
        </div>
      </div>
    </section>
"""

AUDITOR_HTML_EN = """
    <!-- Dedicated Zero-Touch Auditor Section -->
    <section id="auditor" style="margin-top: 3rem; margin-bottom: 3.5rem;">
      <div style="background: linear-gradient(135deg, rgba(22, 27, 34, 0.95) 0%, rgba(13, 17, 23, 0.95) 100%); border: 1px solid rgba(88, 166, 255, 0.35); border-radius: 16px; padding: 2.2rem; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 15px; margin-bottom: 1.2rem;">
          <div>
            <span style="background: rgba(46, 160, 67, 0.15); color: #3fb950; border: 1px solid rgba(46, 160, 67, 0.3); padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 700; letter-spacing: 0.5px;">
              FREE & OPEN AUDITOR • NASEEBA KANU ENTERPRISE SPEC
            </span>
            <h2 style="font-size: 1.85rem; font-weight: 800; color: #fff; margin-top: 0.8rem; margin-bottom: 0.4rem;">
              🛡️ DeviceAuditor.exe — 100% Read-Only Zero-Touch Enterprise Auditor
            </h2>
            <p style="color: #8b949e; font-size: 1rem; max-width: 820px; line-height: 1.6;">
              Engineered based on enterprise SecOps feedback from <b>Naseeba Kanu</b> (Co-founder at TFalke): <b>"An audit that fights the EDR or needs a rollback plan just does not get run. A lightweight, read-only way to check endpoint state is a much easier sell to the security team."</b>
            </p>
          </div>
          <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <a href="https://raw.githubusercontent.com/anon-wu/CVE_Checker_Anon_X/main/releases/CVE_Security_Operations_Suite_Portable.zip" class="btn-primary" style="padding: 10px 20px; font-size: 0.9rem;">
              ⬇️ Free Download DeviceAuditor.exe
            </a>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.2rem; margin-top: 1.5rem;">
          <div style="background: rgba(13, 17, 23, 0.8); border: 1px solid #30363d; border-radius: 10px; padding: 1.2rem;">
            <div style="font-size: 1.1rem; font-weight: 700; color: #58a6ff; margin-bottom: 0.5rem;">🔒 100% Read-Only (0 Bytes Mutated)</div>
            <p style="font-size: 0.88rem; color: #c9d1d9; line-height: 1.5; margin: 0;">
              Guaranteed 0 registry writes, 0 stopped services, and 0 bytes modified. Because no state changes occur on the endpoint, <b>no rollback plan or change tickets are needed</b>.
            </p>
          </div>

          <div style="background: rgba(13, 17, 23, 0.8); border: 1px solid #30363d; border-radius: 10px; padding: 1.2rem;">
            <div style="font-size: 1.1rem; font-weight: 700; color: #3fb950; margin-bottom: 0.5rem;">⚡ Zero EDR Friction & High Performance</div>
            <p style="font-size: 0.88rem; color: #c9d1d9; line-height: 1.5; margin: 0;">
              Zero interference with CrowdStrike, SentinelOne, Defender, or Carbon Black. Audits endpoint state strictly using native Windows read APIs in seconds.
            </p>
          </div>

          <div style="background: rgba(13, 17, 23, 0.8); border: 1px solid #30363d; border-radius: 10px; padding: 1.2rem;">
            <div style="font-size: 1.1rem; font-weight: 700; color: #d2a8ff; margin-bottom: 0.5rem;">📊 JSON & OASIS SARIF v2.1.0 Ready</div>
            <p style="font-size: 0.88rem; color: #c9d1d9; line-height: 1.5; margin: 0;">
              One-click clipboard/file export in GUI, plus native CLI automation (<code>--json</code>, <code>--sarif</code>, <code>--lang=en|ko|ja</code>) for direct ingestion into <b>TFalke, Microsoft Intune, SIEM, and GitHub Advanced Security</b>.
            </p>
          </div>
        </div>

        <div style="margin-top: 1.5rem; background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 0.9rem 1.2rem; font-family: Consolas, monospace; font-size: 0.85rem; color: #79c0ff; overflow-x: auto;">
          <span style="color: #8b949e;"># TFalke & Intune automated endpoint state audit example</span><br/>
          <span>.\\DeviceAuditor.exe --json --lang=en --out="audit_report.json"</span><br/>
          <span>.\\DeviceAuditor.exe --sarif --out="cve_audit.sarif"</span>
        </div>
      </div>
    </section>
"""

AUDITOR_HTML_JA = """
    <!-- Dedicated Zero-Touch Auditor Section -->
    <section id="auditor" style="margin-top: 3rem; margin-bottom: 3.5rem;">
      <div style="background: linear-gradient(135deg, rgba(22, 27, 34, 0.95) 0%, rgba(13, 17, 23, 0.95) 100%); border: 1px solid rgba(88, 166, 255, 0.35); border-radius: 16px; padding: 2.2rem; box-shadow: 0 10px 30px rgba(0,0,0,0.5);">
        <div style="display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 15px; margin-bottom: 1.2rem;">
          <div>
            <span style="background: rgba(46, 160, 67, 0.15); color: #3fb950; border: 1px solid rgba(46, 160, 67, 0.3); padding: 4px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 700; letter-spacing: 0.5px;">
              FREE & OPEN AUDITOR • NASEEBA KANU ENTERPRISE SPEC
            </span>
            <h2 style="font-size: 1.85rem; font-weight: 800; color: #fff; margin-top: 0.8rem; margin-bottom: 0.4rem;">
              🛡️ DeviceAuditor.exe — 100% 読み取り専用ゼロタッチ企業監査ツール
            </h2>
            <p style="color: #8b949e; font-size: 1rem; max-width: 820px; line-height: 1.6;">
              TFalke 共同創設者 <b>Naseeba Kanu</b> 氏の洞察に基づき設計された超軽量ゼロタッチ監査ツールです。<b>「EDR と競合したりロールバック計画が必要な監査は導入されません。軽量で読み取り専用のエンドポイント状態点検こそがセキュリティチームにとって最も受け入れやすいアプローチです。」</b>
            </p>
          </div>
          <div style="display: flex; gap: 10px; flex-wrap: wrap;">
            <a href="https://raw.githubusercontent.com/anon-wu/CVE_Checker_Anon_X/main/releases/CVE_Security_Operations_Suite_Portable.zip" class="btn-primary" style="padding: 10px 20px; font-size: 0.9rem;">
              ⬇️ DeviceAuditor.exe 無料ダウンロード
            </a>
          </div>
        </div>

        <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(260px, 1fr)); gap: 1.2rem; margin-top: 1.5rem;">
          <div style="background: rgba(13, 17, 23, 0.8); border: 1px solid #30363d; border-radius: 10px; padding: 1.2rem;">
            <div style="font-size: 1.1rem; font-weight: 700; color: #58a6ff; margin-bottom: 0.5rem;">🔒 100% 読み取り専用（0バイト変更保証）</div>
            <p style="font-size: 0.88rem; color: #c9d1d9; line-height: 1.5; margin: 0;">
              レジストリ書き込み0件、サービス停止0件、ファイル改変0件をコードレベルで保証。システム状態を一切変更しないため、<b>ロールバック計画や変更管理申請が不要</b>です。
            </p>
          </div>

          <div style="background: rgba(13, 17, 23, 0.8); border: 1px solid #30363d; border-radius: 10px; padding: 1.2rem;">
            <div style="font-size: 1.1rem; font-weight: 700; color: #3fb950; margin-bottom: 0.5rem;">⚡ EDR 無干渉 & 超高速診断</div>
            <p style="font-size: 0.88rem; color: #c9d1d9; line-height: 1.5; margin: 0;">
              CrowdStrike、Defender などの EDR と一切競合せず、標準 Windows API の読み取りのみで数秒以内にエンドポイントの健全性を評価します。
            </p>
          </div>

          <div style="background: rgba(13, 17, 23, 0.8); border: 1px solid #30363d; border-radius: 10px; padding: 1.2rem;">
            <div style="font-size: 1.1rem; font-weight: 700; color: #d2a8ff; margin-bottom: 0.5rem;">📊 JSON & OASIS SARIF v2.1.0 完全対応</div>
            <p style="font-size: 0.88rem; color: #c9d1d9; line-height: 1.5; margin: 0;">
              GUI でのワンクリック保存に加え、CLI（<code>--json</code>、<code>--sarif</code>、<code>--lang=ja|en|ko</code>）により <b>TFalke、Microsoft Intune、SIEM</b> へ直接連携可能です。
            </p>
          </div>
        </div>

        <div style="margin-top: 1.5rem; background: #0d1117; border: 1px solid #21262d; border-radius: 8px; padding: 0.9rem 1.2rem; font-family: Consolas, monospace; font-size: 0.85rem; color: #79c0ff; overflow-x: auto;">
          <span style="color: #8b949e;"># TFalke / Intune パイプライン連携コマンド例</span><br/>
          <span>.\\DeviceAuditor.exe --json --lang=ja --out="audit_report.json"</span><br/>
          <span>.\\DeviceAuditor.exe --sarif --out="cve_audit.sarif"</span>
        </div>
      </div>
    </section>
"""

def update_html_files():
    configs = [
        (os.path.join(DOCS_DIR, "index.html"), AUDITOR_HTML_KO),
        (os.path.join(DOCS_DIR, "index.en.html"), AUDITOR_HTML_EN),
        (os.path.join(DOCS_DIR, "index.ja.html"), AUDITOR_HTML_JA),
        (os.path.join(DOCS_DIR, "en", "index.html"), AUDITOR_HTML_EN),
        (os.path.join(DOCS_DIR, "ja", "index.html"), AUDITOR_HTML_JA),
    ]

    for path, section_html in configs:
        if not os.path.exists(path):
            continue
        with open(path, "r", encoding="utf-8") as f:
            content = f.read()

        # Remove existing #auditor section if present
        content = re.sub(r'<!-- Dedicated Zero-Touch Auditor Section -->[\s\S]*?</section>', '', content)

        # Insert before <section id="search">
        target = '<section id="search">'
        if target in content:
            new_content = content.replace(target, section_html + "\n    " + target)
            with open(path, "w", encoding="utf-8") as f:
                f.write(new_content)
            print(f"[+] Added Auditor section to {path}")

def update_readme_files():
    # Update README.md (Korean)
    ko_path = os.path.join(BASE_DIR, "README.md")
    with open(ko_path, "r", encoding="utf-8") as f:
        ko_text = f.read()

    auditor_doc_ko = """
### 🛡️ 무변형 제로-터치 엔터프라이즈 감사기 (DeviceAuditor.exe - 무료/오픈 배포)

> **"An audit that fights the EDR or needs a rollback plan just does not get run. A lightweight, read only way to check endpoint state is a much easier sell to the security team."**  
> — *Naseeba Kanu (Co-founder at TFalke)*

보안팀과 CISO의 실제 엔터프라이즈 감사 제약사항을 적극 반영하여 제작된 **100% 무변형(Zero Host Mutation) 읽기 전용 감사기**입니다:
- **100% 읽기 전용(Read-Only)**: 레지스트리 쓰기 0건, 서비스 중단 0건, 파일 수정 0건을 코드 레벨에서 보장하며, 시스템을 전혀 변경하지 않으므로 보안팀의 **롤백 계획(Rollback Plan)이나 변경 관리 티켓이 일체 불필요**합니다.
- **EDR 무간섭(Zero EDR Friction)**: CrowdStrike, SentinelOne, Defender 등 어떤 백신/EDR과도 충돌하지 않고 무음 점검합니다.
- **3개 국어(한국어, 영어, 일본어) GUI 동시 지원**: 클릭 한 번으로 UI 언어 및 감사 증적을 즉시 전환합니다.
- **머신 리더블 리포트 (JSON & OASIS SARIF v2.1.0)**: TFalke, Microsoft Intune, SIEM 파이프라인에 즉시 연동됩니다.

```powershell
# 1. 초경량 JSON 감사 보고서 추출 (TFalke / Intune 연동)
.\\DeviceAuditor.exe --json --lang=ko --out="endpoint_audit.json"

# 2. 엔터프라이즈 표준 OASIS SARIF v2.1.0 보고서 추출
.\\DeviceAuditor.exe --sarif --out="endpoint_audit.sarif"

# 3. 콘솔 요약 테이블 출력
.\\DeviceAuditor.exe --table --lang=ko
```
"""

    if "DeviceAuditor.exe" not in ko_text:
        target = "### ⚡ 초고속 원클릭 설치 및 실행 (PowerShell One-Liner Quick-Install)"
        idx = ko_text.find(target)
        if idx != -1:
            ko_text = ko_text[:idx] + auditor_doc_ko + "\n---\n\n" + ko_text[idx:]
            with open(ko_path, "w", encoding="utf-8") as f:
                f.write(ko_text)
            print("[+] Updated README.md with DeviceAuditor documentation")

    # Update README.en.md (English)
    en_path = os.path.join(BASE_DIR, "README.en.md")
    if os.path.exists(en_path):
        with open(en_path, "r", encoding="utf-8") as f:
            en_text = f.read()

        if "DeviceAuditor.exe" not in en_text:
            target = "### ⚡ Zero-Friction One-Liner Quick-Install (PowerShell)"
            idx = en_text.find(target)
            if idx != -1:
                en_text = en_text[:idx] + auditor_doc_en + "\n---\n\n" + en_text[idx:]
                with open(en_path, "w", encoding="utf-8") as f:
                    f.write(en_text)
                print("[+] Updated README.en.md with DeviceAuditor documentation")

    # Update README.ja.md (Japanese)
    ja_path = os.path.join(BASE_DIR, "README.ja.md")
    if os.path.exists(ja_path):
        with open(ja_path, "r", encoding="utf-8") as f:
            ja_text = f.read()

        if "DeviceAuditor.exe" not in ja_text:
            target = "### ⚡ ワンクリック高速インストール＆実行（PowerShell One-Liner）"
            idx = ja_text.find(target)
            if idx != -1:
                ja_text = ja_text[:idx] + auditor_doc_ja + "\n---\n\n" + ja_text[idx:]
                with open(ja_path, "w", encoding="utf-8") as f:
                    f.write(ja_text)
                print("[+] Updated README.ja.md with DeviceAuditor documentation")

if __name__ == "__main__":
    update_html_files()
    update_readme_files()
