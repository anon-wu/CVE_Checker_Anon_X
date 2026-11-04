# -*- coding: utf-8 -*-
import sys

sys.stdout.reconfigure(encoding='utf-8')

ui_path = r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\src\SharedUi.cs'

with open(ui_path, 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Update ColumnStyles for header: 42% / 58%
old_cols = '''            header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 46f));
            header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 54f));'''
new_cols = '''            header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 42f));
            header.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 58f));'''

assert old_cols in text, "old_cols not found"
text = text.replace(old_cols, new_cols)

# 2. Update WrapContents = false in headerActions
old_actions = '''            FlowLayoutPanel headerActions = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                WrapContents = true,
                FlowDirection = FlowDirection.RightToLeft,
                BackColor = Color.Transparent,
                Margin = new Padding(0)
            };'''
new_actions = '''            FlowLayoutPanel headerActions = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                WrapContents = false,
                FlowDirection = FlowDirection.RightToLeft,
                BackColor = Color.Transparent,
                Margin = new Padding(0)
            };'''

assert old_actions in text, "old_actions not found"
text = text.replace(old_actions, new_actions)

# 3. Update button widths and labels in headerActions
old_btn_av = '''            _btnHeaderAntivirusStatus = UiKit.Action(I18n.T("[AV] 백신 공존 (21종+)", "[AV] セキュリティ共存 (21種+)", "[AV] AV Coexistence (21+ Engines)"), Color.FromArgb(20, 83, 45), Color.FromArgb(187, 247, 208), 9f);
            _btnHeaderAntivirusStatus.FlatAppearance.BorderSize = 1;
            _btnHeaderAntivirusStatus.FlatAppearance.BorderColor = Color.FromArgb(34, 197, 94);'''

new_btn_av = '''            _btnHeaderAntivirusStatus = UiKit.Action(I18n.T("[AV] 백신 공존 (21종+)", "[AV] セキュリティ共存 (21種+)", "[AV] AV Coex (21+)"), Color.FromArgb(20, 83, 45), Color.FromArgb(187, 247, 208), 9f);
            _btnHeaderAntivirusStatus.Width = 135;
            _btnHeaderAntivirusStatus.FlatAppearance.BorderSize = 1;
            _btnHeaderAntivirusStatus.FlatAppearance.BorderColor = Color.FromArgb(34, 197, 94);'''

assert old_btn_av in text, "old_btn_av not found"
text = text.replace(old_btn_av, new_btn_av)

old_theme_btn = '''            _btnThemeToggle = UiKit.Action("☀ White Mode", Color.FromArgb(34, 43, 62), Color.FromArgb(255, 215, 0), 9f);
            _btnThemeToggle.FlatAppearance.BorderSize = 1;
            _btnThemeToggle.FlatAppearance.BorderColor = Color.FromArgb(80, 100, 140);'''

new_theme_btn = '''            _btnThemeToggle = UiKit.Action("☀ White Mode", Color.FromArgb(34, 43, 62), Color.FromArgb(255, 215, 0), 9f);
            _btnThemeToggle.Width = 110;
            _btnThemeToggle.FlatAppearance.BorderSize = 1;
            _btnThemeToggle.FlatAppearance.BorderColor = Color.FromArgb(80, 100, 140);'''

assert old_theme_btn in text, "old_theme_btn not found"
text = text.replace(old_theme_btn, new_theme_btn)

# 4. In RefreshLocalization:
old_refresh_av = '_btnHeaderAntivirusStatus.Text = I18n.T("[AV] 백신 공존 (21종+)", "[AV] セキュリティ共存 (21種+)", "[AV] AV Coexistence (21+ Engines)");'
new_refresh_av = '_btnHeaderAntivirusStatus.Text = I18n.T("[AV] 백신 공존 (21종+)", "[AV] セキュリティ共存 (21種+)", "[AV] AV Coex (21+)");'

assert old_refresh_av in text, "old_refresh_av not found"
text = text.replace(old_refresh_av, new_refresh_av)

# 5. In RefreshLocalization: Subtitle with OS detection info
old_subtitle = '''            _lblAppSubtitle.Text = I18n.T(
                "2026-11-04 최신 CVE 실측 진단 및 87종 전방위 자율 사이버 보안 관제 포털",
                "2026-11-04 最新CVE実測診断および87種全方位自律セキュリティポータル",
                "2026-11-04 CVE Live Audit & 87 Enterprise Autonomous Cyber Defense Portal");'''

new_subtitle = '''            if (_kind == ScannerKind.InternalDevice)
            {
                string hostOs = _context != null && !string.IsNullOrEmpty(_context.DetectedHostOs) ? _context.DetectedHostOs : OsEnvironmentDetector.GetHostOsSummary();
                _lblAppSubtitle.Text = I18n.T(
                    string.Format("판정 OS: {0} | OS 관련 CVE 100% 실측 진단 포털", hostOs),
                    string.Format("判定OS: {0} | OS関連CVE 100%実測診断ポータル", hostOs),
                    string.Format("Detected OS: {0} | 100% OS-Relevant CVE Audit Portal", hostOs));
            }
            else
            {
                string targetOs = _context != null && !string.IsNullOrEmpty(_context.DetectedTargetOs) ? _context.DetectedTargetOs : "Multi-OS Network Boundary";
                _lblAppSubtitle.Text = I18n.T(
                    string.Format("원격 대상({0}) OS 판정: {1} | 경계면 노출 CVE 진단", _context != null ? _context.TargetIp : "127.0.0.1", targetOs),
                    string.Format("リモート対象({0}) OS判定: {1} | 境界露出CVE診断", _context != null ? _context.TargetIp : "127.0.0.1", targetOs),
                    string.Format("Target({0}) OS Fingerprint: {1} | Perimeter Exposure CVE Audit", _context != null ? _context.TargetIp : "127.0.0.1", targetOs));
            }'''

assert old_subtitle in text, "old_subtitle not found"
text = text.replace(old_subtitle, new_subtitle)

with open(ui_path, 'w', encoding='utf-8') as f:
    f.write(text)

print('SharedUi.cs patched successfully with AV Coex position lock and OS detection subtitle')
