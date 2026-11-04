# -*- coding: utf-8 -*-
import sys

sys.stdout.reconfigure(encoding='utf-8')

aud_path = r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\src\AuditorProgram.cs'

with open(aud_path, 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Clean docstrings & CLI banners & JSON specification
text = text.replace(
    "/// Tailored specifically to Naseeba Kanu (Co-founder at TFalke)'s enterprise requirements:",
    "/// Tailored specifically for zero-touch enterprise audit & compliance requirements:"
)

text = text.replace(
    'Console.WriteLine("  Device Zero-Touch Auditor v11.5 (Naseeba Kanu 엔터프라이즈 감사기)");',
    'Console.WriteLine("  Device Zero-Touch Auditor v11.5 (독립 감사자 전용 무변형 에디션)");'
)
text = text.replace(
    'Console.WriteLine("  Device Zero-Touch Auditor v11.5 (Naseeba Kanu 企業監査モデル)");',
    'Console.WriteLine("  Device Zero-Touch Auditor v11.5 (独立監査者専用・無変形エディション)");'
)
text = text.replace(
    'Console.WriteLine("  Device Zero-Touch Auditor v11.5 (Naseeba Kanu Enterprise Model)");',
    'Console.WriteLine("  Device Zero-Touch Auditor v11.5 (Independent Zero-Touch Auditor Edition)");'
)

text = text.replace(
    'sb.AppendLine("  \\\"specification\\\": \\\"Naseeba Kanu Enterprise SecOps Model\\\",");',
    'sb.AppendLine("  \\\"specification\\\": \\\"Zero-Touch Endpoint Audit Model\\\",");'
)

# 2. GetAppFont font family improvement
old_get_app_font = '''        private Font GetAppFont(float size, FontStyle style = FontStyle.Regular)
        {
            string family = "Segoe UI";
            if (_currentLang == AppLanguage.KO) family = "맑은 고딕";
            else if (_currentLang == AppLanguage.JA) family = "Yu Gothic UI";

            try
            {
                return new Font(family, size, style);
            }
            catch
            {
                return new Font(FontFamily.GenericSansSerif, size, style);
            }
        }'''

new_get_app_font = '''        private Font GetAppFont(float size, FontStyle style = FontStyle.Regular)
        {
            string family = "Segoe UI";
            if (_currentLang == AppLanguage.JA) family = "Yu Gothic UI";

            try
            {
                return new Font(family, size, style);
            }
            catch
            {
                return new Font(FontFamily.GenericSansSerif, size, style);
            }
        }'''

assert old_get_app_font in text, "old_get_app_font not found"
text = text.replace(old_get_app_font, new_get_app_font)

# 3. Header layout in InitUi - fix overlap
old_header_layout = '''            // Top Header Panel
            _pnlHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 94,
                Padding = new Padding(16, 10, 16, 10)
            };

            _lblTitle = new Label
            {
                Font = GetAppFont(12.5f, FontStyle.Bold),
                AutoSize = true,
                Location = new Point(16, 10)
            };

            _lblPill = new Label
            {
                Font = GetAppFont(8f, FontStyle.Bold),
                Padding = new Padding(8, 4, 8, 4),
                AutoSize = true
            };

            _lblHostInfo = new Label
            {
                Font = GetAppFont(8.5f, FontStyle.Regular),
                AutoSize = true,
                Location = new Point(18, 40)
            };

            _lblMetrics = new Label
            {
                Font = GetAppFont(9.5f, FontStyle.Bold),
                AutoSize = true,
                Location = new Point(18, 64)
            };

            _pnlHeaderRight = new FlowLayoutPanel
            {
                Dock = DockStyle.Right,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Padding = new Padding(0, 8, 10, 0)
            };

            _btnThemeToggle = CreateActionButton("☀️ Light", 85, 27, ToggleTheme);
            _btnLangKo = CreateActionButton("🇰🇷 한국어", 85, 27, () => SetLanguage(AppLanguage.KO));
            _btnLangEn = CreateActionButton("🇺🇸 English", 85, 27, () => SetLanguage(AppLanguage.EN));
            _btnLangJa = CreateActionButton("🇯🇵 日本語", 85, 27, () => SetLanguage(AppLanguage.JA));

            _pnlHeaderRight.Controls.AddRange(new Control[] { _btnThemeToggle, _btnLangKo, _btnLangEn, _btnLangJa });

            _pnlHeader.Controls.Add(_lblTitle);
            _pnlHeader.Controls.Add(_lblPill);
            _pnlHeader.Controls.Add(_lblHostInfo);
            _pnlHeader.Controls.Add(_lblMetrics);
            _pnlHeader.Controls.Add(_pnlHeaderRight);'''

new_header_layout = '''            // Top Header Panel (Exact 4-Row Collision-Free Design)
            _pnlHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 118,
                Padding = new Padding(16, 8, 16, 8)
            };

            _lblTitle = new Label
            {
                Font = GetAppFont(12.5f, FontStyle.Bold),
                AutoSize = true,
                Location = new Point(16, 12)
            };

            _pnlHeaderRight = new FlowLayoutPanel
            {
                Dock = DockStyle.Right,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Padding = new Padding(0, 10, 12, 0)
            };

            _btnThemeToggle = CreateActionButton("☀️ Light", 80, 26, ToggleTheme);
            _btnLangKo = CreateActionButton("🇰🇷 한국어", 80, 26, () => SetLanguage(AppLanguage.KO));
            _btnLangEn = CreateActionButton("🇺🇸 English", 80, 26, () => SetLanguage(AppLanguage.EN));
            _btnLangJa = CreateActionButton("🇯🇵 日本語", 80, 26, () => SetLanguage(AppLanguage.JA));
            _pnlHeaderRight.Controls.AddRange(new Control[] { _btnThemeToggle, _btnLangKo, _btnLangEn, _btnLangJa });

            // Row 2: Verification Pill (100% collision-free on its own dedicated row)
            _lblPill = new Label
            {
                Font = GetAppFont(8.25f, FontStyle.Bold),
                Padding = new Padding(8, 3, 8, 3),
                AutoSize = true,
                Location = new Point(16, 44)
            };

            // Row 3: Host & Detected OS telemetry
            _lblHostInfo = new Label
            {
                Font = GetAppFont(8.5f, FontStyle.Regular),
                AutoSize = true,
                Location = new Point(16, 72)
            };

            // Row 4: Metrics summary
            _lblMetrics = new Label
            {
                Font = GetAppFont(9f, FontStyle.Bold),
                AutoSize = true,
                Location = new Point(16, 94)
            };

            _pnlHeader.Controls.Add(_pnlHeaderRight);
            _pnlHeader.Controls.Add(_lblTitle);
            _pnlHeader.Controls.Add(_lblPill);
            _pnlHeader.Controls.Add(_lblHostInfo);
            _pnlHeader.Controls.Add(_lblMetrics);'''

assert old_header_layout in text, "old_header_layout not found"
text = text.replace(old_header_layout, new_header_layout)

# 4. In UpdateLocalization: clean personal names and use OsEnvironmentDetector
old_loc_block = '''            if (_currentLang == AppLanguage.KO)
            {
                this.Text = "Device Zero-Touch Auditor v11.5 (Naseeba Kanu 엔터프라이즈 감사기)";
                _lblTitle.Text = "🛡️ Device Zero-Touch Auditor — 100% 읽기 전용 엔드포인트 감사";
                _lblPill.Text = "검증 완료: 100% 읽기 전용 | 롤백 계획 불필요 | EDR 무간섭";
                _lblHostInfo.Text = string.Format("호스트: {0} | OS: {1} | 진단 대상: 127.0.0.1 | 0바이트 시스템 변경 보장",
                    Environment.MachineName, Environment.OSVersion.VersionString);
                _lblFilterText.Text = "필터:";
                _lblTierText.Text = "진단 단계:";
                _lblSearchText.Text = "검색:";
                _btnReAudit.Text = "🔄 재감사";
                _lblGuard.Text = "🔒 100% 무변형 감사: 레지스트리 쓰기 0건 • 롤백 계획 불필요 • TFalke 및 Intune 파이프라인 즉시 연동";
                _btnCopyJson.Text = "📋 JSON 복사";
                _btnExportJson.Text = "💾 JSON 저장";
                _btnExportSarif.Text = "📊 SARIF 저장";

                _lvResults.Columns[0].Text = "CVE 식별자";
                _lvResults.Columns[1].Text = "위험도";
                _lvResults.Columns[2].Text = "진단 상태";
                _lvResults.Columns[3].Text = "영향 컴포넌트";
                _lvResults.Columns[4].Text = "엔드포인트 실시간 감사 증적";
            }
            else if (_currentLang == AppLanguage.JA)
            {
                this.Text = "Device Zero-Touch Auditor v11.5 (Naseeba Kanu 企業監査モデル)";
                _lblTitle.Text = "🛡️ Device Zero-Touch Auditor — 100% 読み取り専用エンドポイント状態監査";
                _lblPill.Text = "検証済み: 100% 読み取り専用 | ロールバック不要 | EDR 完全互換";
                _lblHostInfo.Text = string.Format("ホスト: {0} | OS: {1} | 診断対象: 127.0.0.1 | 0バイト変更保証",
                    Environment.MachineName, Environment.OSVersion.VersionString);
                _lblFilterText.Text = "フィルター:";
                _lblTierText.Text = "診断段階:";
                _lblSearchText.Text = "検索:";
                _btnReAudit.Text = "🔄 再監査";
                _lblGuard.Text = "🔒 100% 非侵襲監査: レジストリ書き込み0件 • ロールバック計画不要 • TFalke & Intune 即時連携";
                _btnCopyJson.Text = "📋 JSON コピー";
                _btnExportJson.Text = "💾 JSON 保存";
                _btnExportSarif.Text = "📊 SARIF 保存";

                _lvResults.Columns[0].Text = "CVE識別子";
                _lvResults.Columns[1].Text = "深刻度";
                _lvResults.Columns[2].Text = "診断状態";
                _lvResults.Columns[3].Text = "影響コンポーネント";
                _lvResults.Columns[4].Text = "エンドポイントリアルタイム監査証跡";
            }
            else
            {
                this.Text = "Device Zero-Touch Auditor v11.5 (Naseeba Kanu Enterprise Model)";
                _lblTitle.Text = "🛡️ Device Zero-Touch Auditor — 100% Read-Only Endpoint State";
                _lblPill.Text = "VERIFIED 100% READ-ONLY | ZERO ROLLBACK REQUIRED | EDR COMPLIANT";
                _lblHostInfo.Text = string.Format("Host: {0} | OS: {1} | Target: 127.0.0.1 | 0 Bytes Written Guaranteed",
                    Environment.MachineName, Environment.OSVersion.VersionString);
                _lblFilterText.Text = "Filter:";
                _lblTierText.Text = "Scan Tier:";
                _lblSearchText.Text = "Search:";
                _btnReAudit.Text = "🔄 Re-Audit";
                _lblGuard.Text = "🔒 100% Read-Only: Zero Host Mutation • No Rollback Plan Required • TFalke & Intune Ready";
                _btnCopyJson.Text = "📋 Copy JSON";
                _btnExportJson.Text = "💾 Save JSON";
                _btnExportSarif.Text = "📊 Save SARIF";'''

new_loc_block = '''            string hostSummary = OsEnvironmentDetector.GetHostOsSummary();
            if (_currentLang == AppLanguage.KO)
            {
                this.Text = "Device Zero-Touch Auditor v11.5 (독립 감사자 전용 무변형 에디션)";
                _lblTitle.Text = "🛡️ Device Zero-Touch Auditor — 100% 읽기 전용 엔드포인트 감사";
                _lblPill.Text = "검증 완료: 100% 읽기 전용 | 롤백 계획 불필요 | EDR 무간섭 | 0바이트 시스템 변경 보장";
                _lblHostInfo.Text = string.Format("호스트: {0} | 판정 OS: {1} | 진단 대상: 127.0.0.1",
                    Environment.MachineName, hostSummary);
                _lblFilterText.Text = "필터:";
                _lblTierText.Text = "진단 단계:";
                _lblSearchText.Text = "검색:";
                _btnReAudit.Text = "🔄 재감사";
                _lblGuard.Text = "🔒 100% 무변형 감사: 레지스트리 쓰기 0건 • 롤백 계획 불필요 • EDR 무간섭 • 엔터프라이즈 파이프라인 즉시 연동";
                _btnCopyJson.Text = "📋 JSON 복사";
                _btnExportJson.Text = "💾 JSON 저장";
                _btnExportSarif.Text = "📊 SARIF 저장";

                _lvResults.Columns[0].Text = "CVE 식별자";
                _lvResults.Columns[1].Text = "위험도";
                _lvResults.Columns[2].Text = "진단 상태";
                _lvResults.Columns[3].Text = "영향 컴포넌트";
                _lvResults.Columns[4].Text = "엔드포인트 실시간 감사 증적";
            }
            else if (_currentLang == AppLanguage.JA)
            {
                this.Text = "Device Zero-Touch Auditor v11.5 (独立監査者専用・無変形エディション)";
                _lblTitle.Text = "🛡️ Device Zero-Touch Auditor — 100% 読み取り専用エンドポイント状態監査";
                _lblPill.Text = "検証済み: 100% 読み取り専用 | ロールバック不要 | EDR 完全互換 | 0バイト無変形保証";
                _lblHostInfo.Text = string.Format("ホスト: {0} | 判定OS: {1} | 診断対象: 127.0.0.1",
                    Environment.MachineName, hostSummary);
                _lblFilterText.Text = "フィルター:";
                _lblTierText.Text = "診断段階:";
                _lblSearchText.Text = "検索:";
                _btnReAudit.Text = "🔄 再監査";
                _lblGuard.Text = "🔒 100% 非侵襲監査: レジストリ書き込み0件 • ロールバック計画不要 • EDR完全互換 • 企業パイプライン即時連携";
                _btnCopyJson.Text = "📋 JSON コピー";
                _btnExportJson.Text = "💾 JSON 保存";
                _btnExportSarif.Text = "📊 SARIF 保存";

                _lvResults.Columns[0].Text = "CVE識別子";
                _lvResults.Columns[1].Text = "深刻度";
                _lvResults.Columns[2].Text = "診断状態";
                _lvResults.Columns[3].Text = "影響コンポーネント";
                _lvResults.Columns[4].Text = "エンドポイントリアルタイム監査証跡";
            }
            else
            {
                this.Text = "Device Zero-Touch Auditor v11.5 (Independent Zero-Touch Auditor Edition)";
                _lblTitle.Text = "🛡️ Device Zero-Touch Auditor — 100% Read-Only Endpoint State Audit";
                _lblPill.Text = "VERIFIED 100% READ-ONLY | ZERO ROLLBACK REQUIRED | EDR COMPLIANT | 0 BYTES MUTATION";
                _lblHostInfo.Text = string.Format("Host: {0} | Detected OS: {1} | Target: 127.0.0.1",
                    Environment.MachineName, hostSummary);
                _lblFilterText.Text = "Filter:";
                _lblTierText.Text = "Scan Tier:";
                _lblSearchText.Text = "Search:";
                _btnReAudit.Text = "🔄 Re-Audit";
                _lblGuard.Text = "🔒 100% Read-Only: Zero Host Mutation • No Rollback Plan Required • EDR Compliant • Enterprise Pipeline Ready";
                _btnCopyJson.Text = "📋 Copy JSON";
                _btnExportJson.Text = "💾 Save JSON";
                _btnExportSarif.Text = "📊 Save SARIF";'''

assert old_loc_block in text, "old_loc_block not found"
text = text.replace(old_loc_block, new_loc_block)

with open(aud_path, 'w', encoding='utf-8') as f:
    f.write(text)

print('AuditorProgram.cs patched successfully with complete privacy protection and zero-overlap layout')
