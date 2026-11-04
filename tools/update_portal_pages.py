# -*- coding: utf-8 -*-
"""
HTML Portal Updater for CVE Security Operations Suite v11.5 Master Edition
Updates all 5 HTML pages:
- docs/index.html (KO)
- docs/index.en.html (EN)
- docs/index.ja.html (JA)
- docs/en/index.html (EN)
- docs/ja/index.html (JA)
"""

import os
import re

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCS_DIR = os.path.join(BASE_DIR, "docs")

def get_js_search_code(lang):
    ko_loading = "🌐 [MITRE/NVD 글로벌 실시간 연동] 공식 CVE 데이터베이스에서 레코드를 실시간 조회 중입니다..."
    en_loading = "🌐 [MITRE/NVD Global Live Query] Fetching official record in real time..."
    ja_loading = "🌐 [MITRE/NVD グローバルリアルタイム照会] 公式CVEデータベースからレコードを照会中..."

    loading_msg = ko_loading if lang == 'ko' else (ja_loading if lang == 'ja' else en_loading)

    return f"""  <script src="cve-catalog.js"></script>
  <script>
    const CURRENT_LANG = "{lang}";
    let currentCategory = "all";
    let searchQuery = "";
    let currentPage = 1;
    const PAGE_SIZE = 10;
    let filteredList = [];

    // Real-time MITRE API Live Lookup State
    let liveQueryAbortController = null;
    let isFetchingLiveCve = false;
    let liveCveItem = null;
    let liveCveError = null;

    function copyInstallCmd() {{
      const text = document.getElementById('cmd-text').innerText;
      navigator.clipboard.writeText(text).then(() => {{
        const btn = document.querySelector('.btn-copy');
        const orig = btn.innerText;
        btn.innerText = 'Copied!';
        btn.style.background = '#00e676';
        btn.style.color = '#000';
        setTimeout(() => {{
          btn.innerText = orig;
          btn.style.background = '#1c2638';
          btn.style.color = '#fff';
        }}, 2000);
      }});
    }}

    function copyCmd(cmdText, btnEl) {{
      navigator.clipboard.writeText(cmdText).then(() => {{
        const orig = btnEl.innerText;
        btnEl.innerText = 'OK!';
        btnEl.style.background = '#00e676';
        btnEl.style.color = '#000';
        setTimeout(() => {{
          btnEl.innerText = orig;
          btnEl.style.background = '#1c2638';
          btnEl.style.color = '#cbd5e1';
        }}, 1500);
      }});
    }}

    function setCategory(cat) {{
      currentCategory = cat;
      document.querySelectorAll('.filter-pill').forEach(btn => {{
        btn.classList.toggle('active', btn.getAttribute('onclick').includes("'" + cat + "'"));
      }});
      currentPage = 1;
      applyFilter();
    }}

    function onSearchInput(val) {{
      searchQuery = val.trim().toLowerCase();
      currentPage = 1;
      applyFilter();
    }}

    function clearSearch() {{
      const input = document.getElementById('cve-search');
      input.value = '';
      searchQuery = '';
      currentPage = 1;
      liveCveItem = null;
      liveCveError = null;
      isFetchingLiveCve = false;
      applyFilter();
    }}

    async function fetchMitreLiveCve(cveId) {{
      if (liveQueryAbortController) {{
        liveQueryAbortController.abort();
      }}
      liveQueryAbortController = new AbortController();
      isFetchingLiveCve = true;
      liveCveItem = null;
      liveCveError = null;
      renderTable();

      try {{
        const res = await fetch(`https://cveawg.mitre.org/api/cve/${{cveId}}`, {{
          signal: liveQueryAbortController.signal
        }});
        if (!res.ok) {{
          if (res.status === 404) {{
            liveCveError = CURRENT_LANG === 'ko' 
              ? `공식 MITRE / NVD 데이터베이스에 ${{cveId}} 공식 레코드가 존재하지 않습니다 (404 Not Found).`
              : (CURRENT_LANG === 'ja'
                ? `公式 MITRE / NVD データベースに ${{cveId}} の公式レコードが存在しません (404 Not Found)。`
                : `Official MITRE / NVD database has no published record for ${{cveId}} (404 Not Found).`);
          }} else {{
            liveCveError = `MITRE API HTTP ${{res.status}}`;
          }}
          isFetchingLiveCve = false;
          renderTable();
          return;
        }}
        const data = await res.json();
        const cna = data.containers?.cna || {{}};
        const meta = data.cveMetadata || {{}};
        const title = cna.title || cna.descriptions?.[0]?.value || 'Official NVD/MITRE Global CVE Record';
        const desc = cna.descriptions?.[0]?.value || title;
        
        let score = 7.5;
        let sevLabel = "High";
        if (cna.metrics && cna.metrics.length > 0) {{
          const m = cna.metrics[0];
          const cvss = m.cvssV3_1 || m.cvssV3_0 || m.cvssV4_0;
          if (cvss) {{
            score = cvss.baseScore || score;
            sevLabel = cvss.baseSeverity || (score >= 9.0 ? 'Critical' : (score >= 7.0 ? 'High' : 'Medium'));
          }}
        }}
        const sev = `${{sevLabel}} (${{score.toFixed(1)}})`;

        let product = "Global Software / OS Component";
        if (cna.affected && cna.affected.length > 0) {{
          product = cna.affected[0].product || cna.affected[0].vendor || product;
        }}

        let refUrl = `https://www.cve.org/CVERecord?id=${{cveId}}`;
        if (cna.references && cna.references.length > 0) {{
          refUrl = cna.references[0].url || refUrl;
        }}

        const rawJsonStr = JSON.stringify(data).toLowerCase();
        const isKev = rawJsonStr.includes('"kev"') || rawJsonStr.includes('known-exploited');

        liveCveItem = {{
          id: meta.cveId || cveId,
          year: parseInt(cveId.split('-')[1]) || 2024,
          score: score,
          sev: sev,
          sevLabel: sevLabel,
          kev: isKev,
          isGlobalLive: true,
          comp: `${{product}} (GLOBAL)`,
          engine: "internal",
          ko: {{
            title: `${{product}} ${{title}} (공식 MITRE 실시간 조회)`,
            vuln: `${{desc}} [MITRE CVE Services v5.2 공식 레코드 실시간 조회됨]`,
            detect: `공식 벤더 보안 권고 및 패치 적용 여부를 점검합니다.`,
            remed: `공식 보안 권고 및 업데이트 패치 적용: ${{refUrl}}`,
            fix: `공식 보안 권고 및 업데이트 패치 적용: ${{refUrl}}`
          }},
          en: {{
            title: `${{product}} ${{title}} (Official MITRE Live Query)`,
            vuln: `${{desc}} [Queried live from MITRE CVE Services v5.2]`,
            detect: `Audits official vendor security advisory and patch release.`,
            remed: `Apply official security patch and vendor advisory: ${{refUrl}}`,
            fix: `Apply official security patch and vendor advisory: ${{refUrl}}`
          }},
          ja: {{
            title: `${{product}} ${{title}} (公式 MITRE リアルタイム照会)`,
            vuln: `${{desc}} [MITRE CVE Services v5.2 公式レコードリアルタイム照会済]`,
            detect: `公式ベンダーのセキュリティ勧告およびパッチ適用状況を点検します。`,
            remed: `公式セキュリティパッチおよび勧告を適用: ${{refUrl}}`,
            fix: `公式セキュリティパッチおよび勧告を適用: ${{refUrl}}`
          }},
          cmd: `Start-Process "${{refUrl}}"`
        }};

        isFetchingLiveCve = false;
        applyFilter();
      }} catch (err) {{
        if (err.name !== 'AbortError') {{
          liveCveError = `API Query Error: ${{err.message}}`;
          isFetchingLiveCve = false;
          renderTable();
        }}
      }}
    }}

    function applyFilter() {{
      if (!window.CVE_CATALOG) return;
      
      let list = window.CVE_CATALOG.slice();

      // Category filter
      if (currentCategory === 'kev') {{
        list = list.filter(item => item.kev);
      }} else if (currentCategory === 'critical') {{
        list = list.filter(item => item.score >= 9.0);
      }} else if (currentCategory === 'kernel') {{
        list = list.filter(item => (item.cat || item.category) === 'kernel');
      }} else if (currentCategory === 'network') {{
        list = list.filter(item => (item.cat || item.category) === 'network');
      }} else if (currentCategory === 'auth') {{
        list = list.filter(item => (item.cat || item.category) === 'auth');
      }} else if (currentCategory === 'rpc') {{
        list = list.filter(item => (item.cat || item.category) === 'spooler' || (item.cat || item.category) === 'rpc');
      }}

      // Text search filter
      if (searchQuery) {{
        list = list.filter(item => {{
          const localized = item[CURRENT_LANG] || item.en;
          const str = (item.id + ' ' + item.comp + ' ' + item.sev + ' ' + localized.vuln + ' ' + (localized.fix || localized.remed || '') + ' ' + item.engine + ' ' + (item.category || item.cat || '')).toLowerCase();
          return str.includes(searchQuery);
        }});

        // If specific CVE ID is queried (e.g. CVE-2024-21413)
        const cveMatch = searchQuery.match(/cve-\\d{{4}}-\\d+/i);
        if (cveMatch) {{
          const targetId = cveMatch[0].toUpperCase();
          const foundLocal = list.some(item => item.id.toUpperCase() === targetId);
          if (!foundLocal) {{
            if (liveCveItem && liveCveItem.id.toUpperCase() === targetId) {{
              list.unshift(liveCveItem);
            }} else if (!isFetchingLiveCve && (!liveCveError || !liveCveError.includes(targetId))) {{
              fetchMitreLiveCve(targetId);
            }}
          }}
        }} else if (/^\\d{{4}}$/.test(searchQuery)) {{
          const yearItems = window.CVE_CATALOG.filter(item => item.id.includes(searchQuery) || (item[CURRENT_LANG] || item.en).vuln.includes(searchQuery));
          if (yearItems.length > 0) {{
            list = yearItems;
          }}
        }}
      }}

      filteredList = list;
      renderTable();
    }}

    function renderTable() {{
      const tbody = document.getElementById('cve-body');
      const countEl = document.getElementById('cve-count');
      const curPageEl = document.getElementById('page-current');
      const totalPageEl = document.getElementById('page-total');
      const prevBtn = document.getElementById('btn-prev');
      const nextBtn = document.getElementById('btn-next');

      const totalItems = filteredList.length;
      const totalPages = Math.max(1, Math.ceil(totalItems / PAGE_SIZE));

      if (currentPage > totalPages) currentPage = totalPages;
      if (currentPage < 1) currentPage = 1;

      countEl.innerText = totalItems.toLocaleString();
      curPageEl.innerText = currentPage;
      totalPageEl.innerText = totalPages;

      prevBtn.disabled = (currentPage === 1);
      nextBtn.disabled = (currentPage === totalPages);

      if (isFetchingLiveCve) {{
        tbody.innerHTML = `
          <tr>
            <td colspan="5" style="text-align: center; padding: 2.5rem; color: #58a6ff;">
              <div style="font-size: 1.15rem; font-weight: 700; margin-bottom: 0.5rem;">{loading_msg}</div>
              <div style="font-size: 0.85rem; color: #8b949e;">Querying official MITRE CVE Services API (https://cveawg.mitre.org/api/cve/${{searchQuery.toUpperCase()}})...</div>
            </td>
          </tr>`;
        return;
      }}

      if (totalItems === 0) {{
        const errorText = liveCveError ? `<div style="color: #f85149; font-weight: 600; margin-bottom: 0.5rem;">${{liveCveError}}</div>` : '';
        const helpText = CURRENT_LANG === 'ko'
          ? '특정 CVE ID (예: <code>CVE-2024-38063</code>, <code>CVE-2024-21413</code>), 프로토콜 (<code>SMB</code>, <code>Kerberos</code>, <code>QUIC</code>)을 입력하거나 전체 보기를 클릭하세요.'
          : (CURRENT_LANG === 'ja'
            ? '特定のCVE ID (例: <code>CVE-2024-38063</code>, <code>CVE-2024-21413</code>)、プロトコル (<code>SMB</code>, <code>Kerberos</code>, <code>QUIC</code>) を入力するか、全体表示をクリックしてください。'
            : 'Try searching for a CVE ID (e.g. <code>CVE-2024-38063</code>, <code>CVE-2024-21413</code>), a protocol (<code>SMB</code>, <code>Kerberos</code>, <code>QUIC</code>), or click View All.');
        
        tbody.innerHTML = `
          <tr>
            <td colspan="5" style="text-align: center; padding: 2.5rem; color: var(--text-muted);">
              ${{errorText}}
              <div style="font-size: 1.1rem; margin-bottom: 0.5rem;">🔍 No matching CVE signature found for "${{searchQuery}}"</div>
              <div style="font-size: 0.85rem;">${{helpText}}</div>
            </td>
          </tr>`;
        return;
      }}

      const start = (currentPage - 1) * PAGE_SIZE;
      const pageItems = filteredList.slice(start, start + PAGE_SIZE);

      let html = '';
      pageItems.forEach(item => {{
        const localized = item[CURRENT_LANG] || item.en;
        const sevClass = item.score >= 9.0 ? 'badge-critical' : (item.score >= 7.0 ? 'badge-high' : 'badge-medium');
        const kevBadge = item.kev ? '<span class="badge-kev">CISA KEV</span>' : '';
        const dynBadge = item.isGlobalLive ? '<span class="badge-dynamic">🌐 MITRE 실시간</span>' : '';
        
        let engineLabel;
        if (CURRENT_LANG === 'ko') {{
          engineLabel = item.engine === 'external' ? '외부 경계면' : '내부 호스트';
        }} else if (CURRENT_LANG === 'ja') {{
          engineLabel = item.engine === 'external' ? '外部境界' : '内部ホスト';
        }} else {{
          engineLabel = item.engine === 'external' ? 'External Perimeter' : 'Internal Host';
        }}

        const fixText = localized.fix || localized.remed || 'Official Security Update';
        const copyBtn = item.cmd ? `<button class="btn-table-copy" onclick="copyCmd('${{item.cmd.replace(/'/g, "\\\\'") }}', this)" title="Copy PowerShell/CMD remediation command">📋</button>` : '';

        html += `
          <tr>
            <td>
              <div style="font-weight:700; color: #fff;">${{item.id}}</div>
              <div style="display:flex; gap:4px; margin-top:4px; flex-wrap:wrap;">
                ${{kevBadge}} ${{dynBadge}}
              </div>
            </td>
            <td><span class="${{sevClass}}">${{item.sev}}</span></td>
            <td>
              <div style="font-weight:600; color:#e2e8f0;">${{item.comp}}</div>
              <div style="font-size:0.8rem; color:var(--text-muted); margin-top:2px;">${{localized.vuln}}</div>
            </td>
            <td>
              <div style="font-size:0.85rem; color:#cbd5e1; margin-bottom:4px;">${{fixText}}</div>
              <div style="display:flex; align-items:center; gap:6px;">
                <code style="font-size:0.75rem; overflow-x:hidden; text-overflow:ellipsis; max-width:240px; display:inline-block; white-space:nowrap;">${{item.cmd || 'N/A'}}</code>
                ${{copyBtn}}
              </div>
            </td>
            <td>
              <span class="badge-engine">${{engineLabel}}</span>
            </td>
          </tr>
        `;
      }});

      tbody.innerHTML = html;
    }}

    function prevPage() {{
      if (currentPage > 1) {{
        currentPage--;
        renderTable();
      }}
    }}

    function nextPage() {{
      const totalPages = Math.ceil(filteredList.length / PAGE_SIZE);
      if (currentPage < totalPages) {{
        currentPage++;
        renderTable();
      }}
    }}

    document.addEventListener('DOMContentLoaded', () => {{
      applyFilter();
    }});
  </script>
</body>
</html>"""

def update_page(file_path, lang):
    with open(file_path, 'r', encoding='utf-8') as f:
        html = f.read()

    # 1. Update Hero Stats Grid
    if lang == 'ko':
        hero_stats = """      <div class="stats-grid" id="stats">
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
        search_bar_stat = """        <div class="search-stats-bar">
          <div>공식 CISA KEV & Windows 실측 시그니처: <b id="cve-count">433</b>건 검색됨 (글로벌 NVD/MITRE 249,280건 CVE 전수 실시간 API 즉시 조회 연동)</div>
          <div class="pagination-info">페이지 <span id="page-current">1</span> / <span id="page-total">1</span></div>
        </div>"""
    elif lang == 'ja':
        hero_stats = """      <div class="stats-grid" id="stats">
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
        search_bar_stat = """        <div class="search-stats-bar">
          <div>公式 CISA KEV & Windows 実測シグネチャ: <b id="cve-count">433</b>件 検索中 (全249,280件 グローバルNVD/MITRE CVE リアルタイムAPI直接照会対応)</div>
          <div class="pagination-info">ページ <span id="page-current">1</span> / <span id="page-total">1</span></div>
        </div>"""
    else: # en
        hero_stats = """      <div class="stats-grid" id="stats">
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
        search_bar_stat = """        <div class="search-stats-bar">
          <div>Official CISA KEV & Windows Signatures: <b id="cve-count">433</b> loaded (Live MITRE/NVD API query for all 249,280 global CVEs supported)</div>
          <div class="pagination-info">Page <span id="page-current">1</span> / <span id="page-total">1</span></div>
        </div>"""

    # Replace stats-grid
    stats_pattern = re.compile(r'<div class="stats-grid" id="stats">.*?</div>\s*</div>', re.DOTALL)
    if stats_pattern.search(html):
        html = stats_pattern.sub(hero_stats, html, count=1)
        print(f"[+] Replaced stats-grid in {file_path}")
    else:
        print(f"[-] Could not find stats-grid in {file_path}")

    # Replace search-stats-bar
    search_bar_pattern = re.compile(r'<div class="search-stats-bar">.*?</div>\s*</div>', re.DOTALL)
    if search_bar_pattern.search(html):
        html = search_bar_pattern.sub(search_bar_stat, html, count=1)
        print(f"[+] Replaced search-stats-bar in {file_path}")
    else:
        print(f"[-] Could not find search-stats-bar in {file_path}")

    # Replace bottom scripts with unified robust search logic
    script_idx = html.find('<script src="cve-catalog.js">')
    if script_idx == -1:
        script_idx = html.find('<script src="../cve-catalog.js">')
    if script_idx == -1:
        script_idx = html.find('<script>\n    const CURRENT_LANG')

    if script_idx != -1:
        html = html[:script_idx] + get_js_search_code(lang)
        print(f"[+] Replaced JS search engine in {file_path}")
    else:
        print(f"[-] Could not find script section in {file_path}")

    with open(file_path, 'w', encoding='utf-8') as f:
        f.write(html)
    print(f"[+] Successfully wrote {file_path}")

def main():
    pages = [
        (os.path.join(DOCS_DIR, "index.html"), "ko"),
        (os.path.join(DOCS_DIR, "index.en.html"), "en"),
        (os.path.join(DOCS_DIR, "index.ja.html"), "ja"),
        (os.path.join(DOCS_DIR, "en", "index.html"), "en"),
        (os.path.join(DOCS_DIR, "ja", "index.html"), "ja"),
    ]
    for p, lang in pages:
        update_page(p, lang)

if __name__ == '__main__':
    main()
