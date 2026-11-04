# -*- coding: utf-8 -*-
import os
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS_DIR = os.path.join(BASE_DIR, "docs")

ko_clean = """      <div class="stats-grid" id="stats">
        <div class="stat-card">
          <div class="stat-number">433건</div>
          <div class="stat-label">CISA KEV & Windows 실측 시그니처</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">249,280건</div>
          <div class="stat-label">공식 NVD/MITRE 글로벌 실시간 연동</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">87종</div>
          <div class="stat-label">전방위 자율 국방 도구 매트릭스</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">0 Byte</div>
          <div class="stat-label">DeviceAuditor 무변형 읽기 전용</div>
        </div>
      </div>"""

en_clean = """      <div class="stats-grid" id="stats">
        <div class="stat-card">
          <div class="stat-number">433</div>
          <div class="stat-label">CISA KEV & Windows Verified Signatures</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">249,280</div>
          <div class="stat-label">Official NVD/MITRE Global Real-Time Sync</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">87 Tools</div>
          <div class="stat-label">Comprehensive Cyber Defense Matrix</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">0 Byte</div>
          <div class="stat-label">DeviceAuditor Zero-Touch Read-Only</div>
        </div>
      </div>"""

ja_clean = """      <div class="stats-grid" id="stats">
        <div class="stat-card">
          <div class="stat-number">433件</div>
          <div class="stat-label">CISA KEV & Windows 実測シグネチャ</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">249,280件</div>
          <div class="stat-label">公式 NVD/MITRE グローバルリアルタイム連携</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">87種</div>
          <div class="stat-label">自律サイバー防衛ツールマトリクス</div>
        </div>
        <div class="stat-card">
          <div class="stat-number">0 Byte</div>
          <div class="stat-label">DeviceAuditor 無変形 読み取り専用</div>
        </div>
      </div>"""

files = [
    (os.path.join(DOCS_DIR, "index.html"), ko_clean),
    (os.path.join(DOCS_DIR, "index.en.html"), en_clean),
    (os.path.join(DOCS_DIR, "index.ja.html"), ja_clean),
    (os.path.join(DOCS_DIR, "en", "index.html"), en_clean),
    (os.path.join(DOCS_DIR, "ja", "index.html"), ja_clean),
]

for p, replacement in files:
    with open(p, "r", encoding="utf-8") as f:
        html = f.read()

    # Find start of stats-grid and end of the block before install-box
    start_tag = '<div class="stats-grid" id="stats">'
    s_idx = html.find(start_tag)
    end_tag = '<div class="install-box" id="install">'
    e_idx = html.find(end_tag)

    if s_idx != -1 and e_idx != -1:
        # replace between s_idx and e_idx
        html = html[:s_idx] + replacement.strip() + "\n\n      " + html[e_idx:]
        with open(p, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"[+] Fixed clean 4 stats cards in {p}")
    else:
        print(f"[-] Could not find markers in {p}")
