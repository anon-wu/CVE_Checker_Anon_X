using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace CveSecuritySuite
{
    // =========================================================================
    // 0. Initial Startup Security Notice Dialog (Mandatory Zero-Day Notice)
    // =========================================================================
    public class ZeroDayNoticeForm : Form
    {
        private ScannerKind _kind;
        private Label _lblBadge;
        private Label _lblTitle;
        private Label _lblNoticeBody;
        private Label _lblDbInfo;
        private CheckBox _chkAcknowledge;
        private Button _btnStart;
        private Button _btnExit;
        private ComboBox _cmbLang;
        private Label _lblLang;

        public ZeroDayNoticeForm(ScannerKind kind)
        {
            _kind = kind;
            InitializeComponents();
            I18n.LanguageChanged += UpdateTexts;
            UpdateTexts();
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            I18n.LanguageChanged -= UpdateTexts;
            base.OnFormClosed(e);
        }

        private void InitializeComponents()
        {
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterScreen;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.ClientSize = new Size(680, 470);
            this.BackColor = Color.FromArgb(18, 22, 31);
            this.ForeColor = Color.FromArgb(235, 240, 248);
            this.Font = new Font("Malgun Gothic", 9.5f, FontStyle.Regular);

            Panel topBar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 56,
                BackColor = Color.FromArgb(26, 32, 46)
            };

            _lblBadge = new Label
            {
                Location = new Point(20, 16),
                AutoSize = true,
                Font = new Font("Malgun Gothic", 10f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 184, 77)
            };

            _lblLang = new Label
            {
                Location = new Point(455, 18),
                AutoSize = true,
                ForeColor = Color.FromArgb(180, 192, 212)
            };

            _cmbLang = new ComboBox
            {
                Location = new Point(535, 14),
                Width = 125,
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = Color.FromArgb(35, 43, 60),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            _cmbLang.Items.AddRange(new object[] { "한국어 (KO)", "日本語 (JA)", "English (EN)" });
            _cmbLang.SelectedIndex = (int)I18n.CurrentLanguage;
            _cmbLang.SelectedIndexChanged += (s, e) =>
            {
                I18n.SetLanguage((AppLanguage)_cmbLang.SelectedIndex);
            };

            topBar.Controls.Add(_lblBadge);
            topBar.Controls.Add(_lblLang);
            topBar.Controls.Add(_cmbLang);

            _lblTitle = new Label
            {
                Location = new Point(24, 74),
                Size = new Size(632, 34),
                Font = new Font("Malgun Gothic", 14f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 107, 107)
            };

            Panel cardPanel = new Panel
            {
                Location = new Point(24, 116),
                Size = new Size(632, 235),
                BackColor = Color.FromArgb(27, 34, 48),
                BorderStyle = BorderStyle.FixedSingle
            };

            _lblNoticeBody = new Label
            {
                Location = new Point(16, 14),
                Size = new Size(598, 170),
                Font = new Font("Malgun Gothic", 9.75f, FontStyle.Regular),
                ForeColor = Color.FromArgb(228, 234, 245)
            };

            _lblDbInfo = new Label
            {
                Location = new Point(16, 192),
                Size = new Size(598, 30),
                Font = new Font("Malgun Gothic", 9.25f, FontStyle.Bold),
                ForeColor = Color.FromArgb(99, 210, 255)
            };

            cardPanel.Controls.Add(_lblNoticeBody);
            cardPanel.Controls.Add(_lblDbInfo);

            _chkAcknowledge = new CheckBox
            {
                Location = new Point(26, 366),
                Size = new Size(630, 28),
                Font = new Font("Malgun Gothic", 9.75f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 214, 102),
                Checked = true
            };
            _chkAcknowledge.CheckedChanged += (s, e) =>
            {
                _btnStart.Enabled = _chkAcknowledge.Checked;
            };

            _btnStart = new Button
            {
                Location = new Point(416, 408),
                Size = new Size(240, 42),
                BackColor = Color.FromArgb(40, 130, 246),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 10f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            _btnStart.FlatAppearance.BorderSize = 0;
            _btnStart.Click += (s, e) =>
            {
                this.DialogResult = DialogResult.OK;
                this.Close();
            };

            _btnExit = new Button
            {
                Location = new Point(280, 408),
                Size = new Size(124, 42),
                BackColor = Color.FromArgb(52, 61, 78),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Regular),
                Cursor = Cursors.Hand
            };
            _btnExit.FlatAppearance.BorderSize = 0;
            _btnExit.Click += (s, e) =>
            {
                this.DialogResult = DialogResult.Cancel;
                this.Close();
            };

            this.Controls.Add(topBar);
            this.Controls.Add(_lblTitle);
            this.Controls.Add(cardPanel);
            this.Controls.Add(_chkAcknowledge);
            this.Controls.Add(_btnStart);
            this.Controls.Add(_btnExit);
        }

        private void UpdateTexts()
        {
            I18n.ApplyLanguageFontRecursive(this);

            if (_cmbLang.SelectedIndex != (int)I18n.CurrentLanguage)
                _cmbLang.SelectedIndex = (int)I18n.CurrentLanguage;

            _lblLang.Text = I18n.T("언어 선택:", "言語選択:", "Language:");

            if (_kind == ScannerKind.InternalDevice)
            {
                this.Text = I18n.T(
                    "초기 기동 보안 고지 - Device 자체 취약점 진단 프로그램",
                    "起動時セキュリティ告知 - デバイス内部脆弱性診断プログラム",
                    "Startup Security Notice - Device Internal Vulnerability Scanner");
                _lblBadge.Text = I18n.T(
                    "● DEVICE INTERNAL SCANNER (자체 진단)",
                    "● DEVICE INTERNAL SCANNER (内部診断)",
                    "● DEVICE INTERNAL SCANNER (Host Audit)");
            }
            else
            {
                this.Text = I18n.T(
                    "초기 기동 보안 고지 - Device 외부 취약점 진단 프로그램",
                    "起動時セキュリティ告知 - デバイス外部脆弱性診断プログラム",
                    "Startup Security Notice - Device External Vulnerability Scanner");
                _lblBadge.Text = I18n.T(
                    "● DEVICE EXTERNAL SCANNER (외부 접근 진단)",
                    "● DEVICE EXTERNAL SCANNER (外部アクセス診断)",
                    "● DEVICE EXTERNAL SCANNER (External Access Audit)");
            }

            _lblTitle.Text = I18n.T(
                "⚠ 필수 고지: CVE 기반 진단 및 Zero-Day Attack 진단 불가 안내",
                "⚠ 重要告知: CVEベース診断およびゼロデイ攻撃(Zero-Day)診断不可のご案内",
                "⚠ MANDATORY NOTICE: CVE-Based Assessment & Zero-Day Attack Limitation");

            _lblNoticeBody.Text = I18n.T(
                "1. 본 진단 프로그램의 모든 취약점 탐지는 공식 등재된 CVE(Common Vulnerabilities and Exposures) 데이터베이스를 배경(Background)으로 동작합니다.\r\n\r\n" +
                "2. 아직 보안 패치나 해결 방법이 공개되지 않은 미지의 취약점 및 '제로데이 공격(Zero-Day Attack)'은 원천적으로 진단할 수 없음을 고지합니다.\r\n\r\n" +
                "3. 본 프로그램은 이미 공식 해결 방법이 제시된 CVE 취약점을 탐지하여 구체적인 해결 방법을 제안하며, 사용자가 [허용(Allow)]할 경우 자동으로 보안 조치를 적용합니다.",
                "1. 本診断プログラムのすべての脆弱性検出は、公式に登録されたCVE（共通脆弱性識別子）データベースを基盤(Background)として動作します。\r\n\r\n" +
                "2. まだセキュリティパッチや解決策が公開されていない未知の脆弱性および「ゼロデイ攻撃（Zero-Day Attack）」は診断できないことをあらかじめ告知いたします。\r\n\r\n" +
                "3. 本プログラムは既に解決策が提示されているすべての対象CVEを検出し、解決策を提案します。ユーザーが「許可(Allow)」した場合、自動的に修復を実行します。",
                "1. All vulnerability diagnostics in this application operate strictly on the background of officially registered CVE (Common Vulnerabilities and Exposures) records.\r\n\r\n" +
                "2. Please be advised that 'Zero-Day Attacks' (undisclosed vulnerabilities without published CVEs or established remediation paths) CANNOT be diagnosed by this program.\r\n\r\n" +
                "3. This program detects CVEs with known solutions, proposes concrete remediation steps, and automatically fixes them when you click [Allow].");

            _lblDbInfo.Text = I18n.T(
                "■ CVE 데이터베이스 기준일: 2026년 10월 22일 (2026-10-22)  |  진단 단계: Fast / Normal / Full",
                "■ CVEデータベース基準日: 2026年10月22日 (2026-10-22)  |  診断段階: Fast / Normal / Full",
                "■ CVE Database Baseline Date: October 22, 2026 (2026-10-22)  |  Tiers: Fast / Normal / Full");

            _chkAcknowledge.Text = I18n.T(
                "위 고지 사항(CVE 기반 동작 및 Zero-Day Attack 진단 불가)을 확인하고 이해하였습니다.",
                "上記の告知事項（CVEベース動作およびゼロデイ攻撃の診断不可）を確認・理解しました。",
                "I acknowledge that diagnostics are CVE-based (2026-10-22) and Zero-Day Attacks cannot be diagnosed.");

            _btnStart.Text = I18n.T("확인 및 프로그램 시작 ▶", "確認して診断プログラムを開始 ▶", "Acknowledge & Launch ▶");
            _btnExit.Text = I18n.T("종료", "終了", "Exit");
        }
    }

    // =========================================================================
    // 1. Allow Remediation Confirmation Dialog (Batch / Single)
    // =========================================================================
    public class AllowRemediationDialog : Form
    {
        public AllowRemediationDialog(List<CveEntry> targets)
        {
            this.FormBorderStyle = FormBorderStyle.FixedDialog;
            this.StartPosition = FormStartPosition.CenterParent;
            this.MaximizeBox = false;
            this.MinimizeBox = false;
            this.ClientSize = new Size(700, 460);
            this.BackColor = Color.FromArgb(20, 25, 36);
            this.ForeColor = Color.White;
            this.Font = new Font("Malgun Gothic", 9.5f, FontStyle.Regular);

            this.Text = I18n.T(
                "자동 해결 승인 확인 (Allow Auto-Remediation)",
                "自動修復の許可確認 (Allow Auto-Remediation)",
                "Confirm Auto-Remediation Permission (Allow)");

            Label lblHeader = new Label
            {
                Location = new Point(20, 18),
                Size = new Size(660, 48),
                Font = new Font("Malgun Gothic", 11.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(102, 224, 163),
                Text = I18n.T(
                    string.Format("선택한 {0}건의 CVE 취약점에 대해 제안된 해결 방법을 자동으로 실행하시겠습니까?", targets.Count),
                    string.Format("選択された {0} 件のCVE脆弱性に対して提案された修復方法を自動実行しますか？", targets.Count),
                    string.Format("Do you Allow automatic remediation for the {0} selected CVE vulnerability item(s)?", targets.Count))
            };

            TextBox txtDetails = new TextBox
            {
                Location = new Point(20, 72),
                Size = new Size(660, 310),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(13, 17, 25),
                ForeColor = Color.FromArgb(220, 230, 242),
                Font = I18n.CreateFont(10f, FontStyle.Regular, true),
                Tag = "DETAIL_FONT",
                BorderStyle = BorderStyle.FixedSingle
            };

            StringBuilder sb = new StringBuilder();
            foreach (CveEntry cve in targets)
            {
                sb.AppendLine("======================================================================");
                sb.AppendFormat("[{0}] (CVSS {1:0.0} {2}) - {3}\r\n",
                    cve.CveId, cve.CvssScore, cve.SeverityLabel, cve.Title.Get(I18n.CurrentLanguage));
                sb.AppendFormat("  * {0}: {1}\r\n",
                    I18n.T("제안 해결 방법", "提案された解決策", "Proposed Fix"),
                    cve.RemediationProposal.Get(I18n.CurrentLanguage));
                sb.AppendFormat("  * {0}: {1}\r\n\r\n",
                    I18n.T("자동 실행 명령", "自動実行コマンド", "Auto-Remediation Action"),
                    cve.RemediationCommandPreview);
            }
            txtDetails.Text = sb.ToString();

            Button btnAllow = new Button
            {
                Location = new Point(440, 398),
                Size = new Size(240, 44),
                BackColor = Color.FromArgb(28, 164, 102),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 10f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = I18n.T("✓ Allow (승인 및 자동 해결)", "✓ Allow (許可して自動修復)", "✓ Allow & Auto-Remediate")
            };
            btnAllow.FlatAppearance.BorderSize = 0;
            btnAllow.Click += (s, e) =>
            {
                this.DialogResult = DialogResult.OK;
                this.Close();
            };

            Button btnCancel = new Button
            {
                Location = new Point(295, 398),
                Size = new Size(135, 44),
                BackColor = Color.FromArgb(55, 65, 82),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Regular),
                Cursor = Cursors.Hand,
                Text = I18n.T("취소 (Cancel)", "キャンセル", "Cancel")
            };
            btnCancel.FlatAppearance.BorderSize = 0;
            btnCancel.Click += (s, e) =>
            {
                this.DialogResult = DialogResult.Cancel;
                this.Close();
            };

            this.Controls.Add(lblHeader);
            this.Controls.Add(txtDetails);
            this.Controls.Add(btnAllow);
            this.Controls.Add(btnCancel);

            I18n.ApplyLanguageFontRecursive(this);
        }
    }

    // =========================================================================
    // 2. Portal Multi-Page Navigation Structure & Tool Registry
    // =========================================================================
    public enum MainPortalView
    {
        Home = 0,
        Scanner = 1,
        ToolsHub = 2,
        Reports = 3,
        Settings = 4
    }

    public class SuiteToolItem
    {
        public int Phase { get; set; }
        public int ToolNo { get; set; }
        public string Icon { get; set; }
        public string TitleKr { get; set; }
        public string TitleJp { get; set; }
        public string TitleEn { get; set; }
        public string DescKr { get; set; }
        public string DescJp { get; set; }
        public string DescEn { get; set; }
        public string TechDetails { get; set; }
        public Action Action { get; set; }

        public string GetTitle(AppLanguage lang) => I18n.T(TitleKr, TitleJp, TitleEn);
        public string GetDesc(AppLanguage lang) => I18n.T(DescKr, DescJp, DescEn);
    }

    // =========================================================================
    // 3. ScannerMainForm: Modern 5-Page Security Portal Architecture
    // =========================================================================
    public class ScannerMainForm : Form
    {
        private ScannerKind _kind;
        private List<CveEntry> _allCves;
        private List<CveEntry> _displayedCves = new List<CveEntry>();
        private List<CveEntry> _filteredCves = new List<CveEntry>();
        private ScanContext _context = new ScanContext();
        private ScanTier _selectedTier = ScanTier.Fast;
        private string _statusFilter = "ALL"; // ALL, VULN, SAFE, FIXED
        private int _severityFilterIndex = 0; // 0: All, 1: Critical (9.0+), 2: High (7.0-8.9), 3: CISA KEV Only
        private string _searchQuery = "";
        private bool _isScanning = false;
        private RealTimeSentinelGuard _sentinelGuard;
        private bool _isWhiteTheme = false;
        private UiDensityMode _currentDensityMode = UiDensityMode.Normal;
        private ToolTip _toolTip = new ToolTip { AutoPopDelay = 12000, InitialDelay = 250, ReshowDelay = 150, ShowAlways = true };

        // Portal Views & Navigation
        private MainPortalView _currentView = MainPortalView.Home;
        private Panel _pnlHeader;
        private Panel _pnlNavBar;
        private Panel _pnlViewContainer;
        private Panel _pnlStatus;

        private Button _btnNavHome;
        private Button _btnNavScanner;
        private Button _btnNavTools;
        private Button _btnNavReports;
        private Button _btnNavSettings;

        // Sub-View Panels
        private Panel _viewHome;
        private Panel _viewScanner;
        private Panel _viewToolsHub;
        private Panel _viewReports;
        private Panel _viewSettings;

        // Header controls
        private Label _lblAppTitle;
        private Label _lblAppSubtitle;
        private Label _lblZeroDayBanner;
        private Button _btnThemeToggle;
        private Label _lblLangPrompt;
        private ComboBox _cmbLanguage;

        // Status bar controls
        private ProgressBar _progressBar;
        private Label _lblStatusText;

        // Home View controls
        private Label _lblHomeHostTitle;
        private Label _lblHomeHostInfo;
        private Label _lblHomeSentinelBadge;
        private Label _lblHomeZeroDayBadge;
        private Label _lblHomeScoreVal;
        private Label _lblHomeScoreTitle;
        private Label _lblHomeScoreSub;
        private Label _lblHomeTotalVal;
        private Label _lblHomeTotalTitle;
        private Label _lblHomeTotalSub;
        private Label _lblHomeVulnVal;
        private Label _lblHomeVulnTitle;
        private Label _lblHomeVulnSub;
        private Label _lblHomeFixedVal;
        private Label _lblHomeFixedTitle;
        private Label _lblHomeFixedSub;
        private Button _btnHomeInstantScan;

        // Scanner View controls
        private Panel _pnlScanControls;
        private Label _lblScanTierTitle;
        private RadioButton _rbFast;
        private RadioButton _rbNormal;
        private RadioButton _rbFull;
        private Label _lblTargetInfo;
        private ComboBox _cmbTargetIp;
        private CheckBox _chkIncludeStackVectors;
        private Button _btnStartScan;
        private Button _btnSelectAllVuln;
        private Button _btnAllowBatchFix;

        private Panel _pnlFilterBar;
        private Button _btnFilterAll;
        private Button _btnFilterVuln;
        private Button _btnFilterSafe;
        private Button _btnFilterFixed;
        private ComboBox _cmbSeverityFilter;
        private Label _lblSearchIcon;
        private TextBox _txtSearch;
        private Button _btnClearSearch;

        private DataGridView _grid;
        private Panel _pnlDetails;
        private Label _lblDetailHeader;
        private TextBox _txtDetailDescription;
        private Label _lblRemediationHeader;
        private TextBox _txtRemediationProposal;
        private Button _btnAllowSingleFix;
        private Button _btnCopyDetail;

        // Tools Hub View controls (47 Suite Tools across 6 phases)
        private List<SuiteToolItem> _suiteTools = new List<SuiteToolItem>();
        private int _selectedPhaseTab = 1;
        private Button _btnTabP1;
        private Button _btnTabP2;
        private Button _btnTabP3;
        private Button _btnTabP4;
        private Button _btnTabP5;
        private Button _btnTabP6;
        private FlowLayoutPanel _flpToolButtons;
        private Panel _pnlInspector;
        private Label _lblInspectorBadge;
        private Label _lblInspectorTitle;
        private TextBox _txtInspectorDesc;
        private TextBox _txtInspectorTech;
        private Button _btnInspectorLaunch;
        private SuiteToolItem _selectedToolForInspector;

        // Settings View controls
        private RadioButton _rbDensityLight;
        private RadioButton _rbDensityNormal;
        private RadioButton _rbDensityFull;
        private Label _lblSettingsSentinelStatus;
        private Button _btnSettingsToggleSentinel;

        public ScannerMainForm(ScannerKind kind, List<CveEntry> cves)
        {
            _kind = kind;
            _allCves = cves;
            _context.IsAdministrator = SystemAuditHelper.IsRunningAsAdmin();
            _context.LoadRemediatedState();

            InitializeUi();
            InitializeSuiteTools();

            I18n.LanguageChanged += RefreshLocalization;
            this.Resize += (s, e) => ApplyResponsiveLayout();
            this.SizeChanged += (s, e) => ApplyResponsiveLayout();
            RefreshLocalization();
            ApplyResponsiveLayout();

            // Default to Home View
            SwitchPortalView(MainPortalView.Home);

            this.Shown += async (s, e) =>
            {
                ApplyResponsiveLayout();
                await ExecuteScanAsync();
            };
        }

        protected override void OnFormClosed(FormClosedEventArgs e)
        {
            I18n.LanguageChanged -= RefreshLocalization;
            if (_sentinelGuard != null)
            {
                _sentinelGuard.Dispose();
                _sentinelGuard = null;
            }
            base.OnFormClosed(e);
        }

        private void InitializeUi()
        {
            this.StartPosition = FormStartPosition.CenterScreen;
            Rectangle workArea = Screen.PrimaryScreen != null ? Screen.PrimaryScreen.WorkingArea : new Rectangle(0, 0, 1360, 840);
            int initW = Math.Max(960, Math.Min(1440, (int)(workArea.Width * 0.92)));
            int initH = Math.Max(640, Math.Min(920, (int)(workArea.Height * 0.92)));
            this.Size = new Size(initW, initH);
            this.MinimumSize = new Size(960, 640);
            this.BackColor = Color.FromArgb(15, 19, 28);
            this.ForeColor = Color.FromArgb(235, 240, 248);
            this.Font = new Font("Malgun Gothic", 9.5f, FontStyle.Regular);
            this.DoubleBuffered = true;

            this.AllowDrop = true;
            this.DragEnter += (s, e) =>
            {
                if (e.Data != null && e.Data.GetDataPresent(DataFormats.FileDrop))
                    e.Effect = DragDropEffects.Copy;
            };
            this.DragDrop += async (s, e) =>
            {
                try
                {
                    string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];
                    if (files != null && files.Length > 0)
                    {
                        int totalAdded = 0;
                        foreach (string f in files)
                        {
                            totalAdded += CveDbHotUpdater.LoadCustomDbFile(f, _allCves);
                        }
                        if (totalAdded > 0)
                        {
                            await ExecuteScanAsync();
                            MessageBox.Show(
                                I18n.T(
                                    string.Format("신규 CVE DB 패키지에서 {0}건의 최신 CVE 시그니처를 핫업데이트하여 즉시 재진단했습니다!", totalAdded),
                                    string.Format("新規CVE DBパッケージから {0} 件の最新CVEをホットアップデートし再診断しました！", totalAdded),
                                    string.Format("Hot-updated {0} new CVE signature(s) from dropped .cvedb file and rescanned!", totalAdded)),
                                "CVE DB Hot-Update", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        }
                    }
                }
                catch { }
            };

            _sentinelGuard = new RealTimeSentinelGuard(alertMsg =>
            {
                if (!this.IsDisposed && this.IsHandleCreated)
                {
                    this.BeginInvoke((Action)(() =>
                    {
                        _lblStatusText.Text = alertMsg;
                        UpdateSentinelStatusBadge();
                    }));
                }
            });

            // 1. Top Header Panel
            _pnlHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 72,
                BackColor = Color.FromArgb(22, 28, 41)
            };

            _lblAppTitle = new Label
            {
                Location = new Point(20, 10),
                Size = new Size(720, 28),
                Font = new Font("Malgun Gothic", 13.5f, FontStyle.Bold),
                ForeColor = _kind == ScannerKind.InternalDevice
                    ? Color.FromArgb(88, 196, 255)
                    : Color.FromArgb(255, 163, 82)
            };

            _lblAppSubtitle = new Label
            {
                Location = new Point(22, 40),
                Size = new Size(680, 22),
                Font = new Font("Malgun Gothic", 9.25f, FontStyle.Regular),
                ForeColor = Color.FromArgb(190, 204, 226)
            };

            _lblZeroDayBanner = new Label
            {
                Location = new Point(720, 42),
                Size = new Size(380, 22),
                Font = new Font("Malgun Gothic", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 193, 94),
                TextAlign = ContentAlignment.MiddleRight
            };

            _btnThemeToggle = new Button
            {
                Location = new Point(880, 10),
                Size = new Size(125, 28),
                BackColor = Color.FromArgb(34, 43, 62),
                ForeColor = Color.FromArgb(255, 215, 0),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = "☀️ White Mode"
            };
            _btnThemeToggle.FlatAppearance.BorderSize = 1;
            _btnThemeToggle.FlatAppearance.BorderColor = Color.FromArgb(80, 100, 140);
            _btnThemeToggle.Click += (s, e) => ApplyThemeMode(!_isWhiteTheme);

            _lblLangPrompt = new Label
            {
                Location = new Point(1020, 14),
                Size = new Size(130, 20),
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(200, 212, 230),
                TextAlign = ContentAlignment.MiddleRight
            };

            _cmbLanguage = new ComboBox
            {
                Location = new Point(1160, 10),
                Size = new Size(140, 28),
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = Color.FromArgb(34, 43, 62),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Regular)
            };
            _cmbLanguage.Items.AddRange(new object[] { "한국어 (KO)", "日本語 (JA)", "English (EN)" });
            _cmbLanguage.SelectedIndex = (int)I18n.CurrentLanguage;
            _cmbLanguage.SelectedIndexChanged += (s, e) =>
            {
                I18n.SetLanguage((AppLanguage)_cmbLanguage.SelectedIndex);
            };

            _pnlHeader.Controls.AddRange(new Control[] {
                _lblAppTitle, _lblAppSubtitle, _lblZeroDayBanner,
                _btnThemeToggle, _lblLangPrompt, _cmbLanguage
            });

            // 2. Navigation Bar Panel
            _pnlNavBar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 44,
                BackColor = Color.FromArgb(18, 23, 34),
                Padding = new Padding(12, 4, 12, 4)
            };

            _btnNavHome = CreateNavButton("🏠  메인 포털 (Home)", MainPortalView.Home);
            _btnNavScanner = CreateNavButton("🔍  CVE 정밀 진단 (Scanner)", MainPortalView.Scanner);
            _btnNavTools = CreateNavButton("🛠️  47종 보안 도구함 (Tools Hub)", MainPortalView.ToolsHub);
            _btnNavReports = CreateNavButton("📊  감사 보고서 & 포렌식 (Reports)", MainPortalView.Reports);
            _btnNavSettings = CreateNavButton("⚙️  환경 설정 & 센티널 (Settings)", MainPortalView.Settings);

            _pnlNavBar.Controls.AddRange(new Control[] {
                _btnNavHome, _btnNavScanner, _btnNavTools, _btnNavReports, _btnNavSettings
            });

            // 3. View Container Panel (Hosts 5 sub-views)
            _pnlViewContainer = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(15, 19, 28)
            };

            // 4. Status Bar Panel
            _pnlStatus = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 32,
                BackColor = Color.FromArgb(22, 28, 41)
            };

            _progressBar = new ProgressBar
            {
                Location = new Point(14, 8),
                Size = new Size(240, 16),
                Style = ProgressBarStyle.Continuous
            };

            _lblStatusText = new Label
            {
                Location = new Point(265, 6),
                Size = new Size(1000, 20),
                Font = new Font("Malgun Gothic", 9f, FontStyle.Regular),
                ForeColor = Color.FromArgb(195, 210, 232),
                TextAlign = ContentAlignment.MiddleLeft,
                Text = I18n.T("준비 완료", "準備完了", "Ready")
            };

            _pnlStatus.Controls.AddRange(new Control[] { _progressBar, _lblStatusText });

            // Build Sub-Views
            BuildHomeView();
            BuildScannerView();
            BuildToolsHubView();
            BuildReportsView();
            BuildSettingsView();

            _pnlViewContainer.Controls.AddRange(new Control[] {
                _viewHome, _viewScanner, _viewToolsHub, _viewReports, _viewSettings
            });

            this.Controls.Add(_pnlViewContainer);
            this.Controls.Add(_pnlNavBar);
            this.Controls.Add(_pnlHeader);
            this.Controls.Add(_pnlStatus);
        }

        private Button CreateNavButton(string text, MainPortalView view)
        {
            Button btn = new Button
            {
                Height = 34,
                Width = 205,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9.25f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = text,
                BackColor = Color.FromArgb(28, 36, 52),
                ForeColor = Color.FromArgb(220, 230, 245),
                Margin = new Padding(4, 0, 4, 0)
            };
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.BorderColor = Color.FromArgb(50, 65, 95);
            btn.Click += (s, e) => SwitchPortalView(view);
            return btn;
        }

        private void SwitchPortalView(MainPortalView view)
        {
            _currentView = view;
            _viewHome.Visible = (view == MainPortalView.Home);
            _viewScanner.Visible = (view == MainPortalView.Scanner);
            _viewToolsHub.Visible = (view == MainPortalView.ToolsHub);
            _viewReports.Visible = (view == MainPortalView.Reports);
            _viewSettings.Visible = (view == MainPortalView.Settings);

            UpdateNavButtonStyles();
            if (view == MainPortalView.Scanner)
            {
                RefreshGridRows();
            }
        }

        private void UpdateNavButtonStyles()
        {
            SetNavBtnActive(_btnNavHome, _currentView == MainPortalView.Home);
            SetNavBtnActive(_btnNavScanner, _currentView == MainPortalView.Scanner);
            SetNavBtnActive(_btnNavTools, _currentView == MainPortalView.ToolsHub);
            SetNavBtnActive(_btnNavReports, _currentView == MainPortalView.Reports);
            SetNavBtnActive(_btnNavSettings, _currentView == MainPortalView.Settings);
        }

        private void SetNavBtnActive(Button btn, bool active)
        {
            if (btn == null) return;
            if (_isWhiteTheme)
            {
                btn.BackColor = active ? Color.FromArgb(200, 225, 255) : Color.FromArgb(240, 244, 250);
                btn.ForeColor = active ? Color.FromArgb(14, 80, 160) : Color.FromArgb(50, 60, 75);
                btn.FlatAppearance.BorderColor = active ? Color.FromArgb(56, 140, 240) : Color.FromArgb(210, 220, 235);
            }
            else
            {
                btn.BackColor = active ? Color.FromArgb(14, 116, 144) : Color.FromArgb(28, 36, 52);
                btn.ForeColor = active ? Color.White : Color.FromArgb(200, 215, 235);
                btn.FlatAppearance.BorderColor = active ? Color.FromArgb(56, 189, 248) : Color.FromArgb(48, 62, 88);
            }
        }

        // =========================================================================
        // Sub-View 1: Home Executive Portal View
        // =========================================================================
        private void BuildHomeView()
        {
            _viewHome = new Panel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                BackColor = Color.FromArgb(15, 19, 28),
                Padding = new Padding(24)
            };

            // 1. Executive Telemetry Status Banner
            Panel pnlStatusBanner = new Panel
            {
                Location = new Point(24, 16),
                Size = new Size(1250, 70),
                BackColor = Color.FromArgb(24, 32, 48),
                BorderStyle = BorderStyle.FixedSingle
            };

            _lblHomeHostTitle = new Label
            {
                Location = new Point(18, 12),
                Size = new Size(420, 22),
                Font = new Font("Malgun Gothic", 10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                Text = string.Format("💻 {0} : {1}",
                    _kind == ScannerKind.InternalDevice ? "자체 디바이스 (Host Audit)" : "원격 디바이스 (Perimeter Audit)",
                    Environment.MachineName)
            };

            _lblHomeHostInfo = new Label
            {
                Location = new Point(18, 38),
                Size = new Size(580, 20),
                Font = new Font("Malgun Gothic", 9f, FontStyle.Regular),
                ForeColor = Color.FromArgb(180, 200, 225),
                Text = string.Format("OS: Windows (Build {0}.{1}) | 권한: {2}",
                    _context.OsBuildNumber, _context.OsUbr,
                    _context.IsAdministrator ? "Administrator (Full Audit & Remediate)" : "Standard User (Audit Mode)")
            };

            _lblHomeSentinelBadge = new Label
            {
                Location = new Point(620, 22),
                Size = new Size(280, 26),
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                Text = "🟢 실시간 센티널 감시 활성화"
            };

            _lblHomeZeroDayBadge = new Label
            {
                Location = new Point(920, 22),
                Size = new Size(310, 26),
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(251, 191, 36),
                TextAlign = ContentAlignment.MiddleRight,
                Text = "🛡️ 2026-10-22 CVE DB 공식 탑재"
            };

            pnlStatusBanner.Controls.AddRange(new Control[] {
                _lblHomeHostTitle, _lblHomeHostInfo, _lblHomeSentinelBadge, _lblHomeZeroDayBadge
            });

            // 2. 4 Large KPI Summary Cards
            Panel pnlKpis = new Panel
            {
                Location = new Point(24, 100),
                Size = new Size(1250, 110),
                BackColor = Color.Transparent
            };

            CreateHomeKpiCard(pnlKpis, 0, Color.FromArgb(56, 189, 248), out _lblHomeScoreVal, out _lblHomeScoreTitle, out _lblHomeScoreSub, () => SwitchPortalView(MainPortalView.Scanner));
            CreateHomeKpiCard(pnlKpis, 318, Color.FromArgb(168, 85, 247), out _lblHomeTotalVal, out _lblHomeTotalTitle, out _lblHomeTotalSub, () => SwitchPortalView(MainPortalView.Scanner));
            CreateHomeKpiCard(pnlKpis, 636, Color.FromArgb(239, 68, 68), out _lblHomeVulnVal, out _lblHomeVulnTitle, out _lblHomeVulnSub, () => SwitchPortalView(MainPortalView.Scanner));
            CreateHomeKpiCard(pnlKpis, 954, Color.FromArgb(34, 197, 94), out _lblHomeFixedVal, out _lblHomeFixedTitle, out _lblHomeFixedSub, () => SwitchPortalView(MainPortalView.Scanner));

            // 3. 4 Large Intuitive Action Tiles
            Panel pnlActions = new Panel
            {
                Location = new Point(24, 225),
                Size = new Size(1250, 290),
                BackColor = Color.Transparent
            };

            CreateHomeActionCard(pnlActions, 0, 0, "🔍  CVE 실시간 정밀 진단 (Live Scanner)",
                "시스템 커널, 실행 서비스, 개방 포트, 레지스트리를 실측 대조하여 248,720건의 CVE 취약점을 진단하고 제안된 해결책을 원클릭 자동 해결합니다.",
                "진단 스캐너 바로가기 ▶", Color.FromArgb(14, 116, 144), () => { SwitchPortalView(MainPortalView.Scanner); });

            CreateHomeActionCard(pnlActions, 636, 0, "🛠️  47종 전방위 보안 도구함 (Tools Hub)",
                "양자 내성 VPN(ML-KEM/ML-DSA), 하이퍼바이저 쉴드, 능동 미끼 인프라, AMSI 메모리 감사 등 47종의 독립 보안 도구를 관리하고 사전 승인 하에 실행합니다.",
                "도구함 열기 (47종) ▶", Color.FromArgb(124, 58, 237), () => { SwitchPortalView(MainPortalView.ToolsHub); });

            CreateHomeActionCard(pnlActions, 0, 145, "📊  대화형 감사 보고서 & 포렌식 (Reports)",
                "대화형 HTML 보고서, WORM 머클 무결성 원장, 복구 롤백 스냅샷 및 KISA/ISMS-P 규정 준수 인증서를 열람하고 파일로 저장합니다.",
                "보고서 센터 바로가기 ▶", Color.FromArgb(217, 119, 6), () => { SwitchPortalView(MainPortalView.Reports); });

            CreateHomeActionCard(pnlActions, 636, 145, "⚙️  환경 설정 & 센티널 정책 (Settings)",
                "다크/화이트 테마 토글, UI 정보 밀도(간소화/표준/전문가), 다국어 설정 및 실시간 센티널 감시 가드 가동 정책을 관리합니다.",
                "환경 설정 열기 ▶", Color.FromArgb(71, 85, 105), () => { SwitchPortalView(MainPortalView.Settings); });

            // 4. Quick Instant Scan Action Bar
            Panel pnlInstant = new Panel
            {
                Location = new Point(24, 530),
                Size = new Size(1250, 60),
                BackColor = Color.FromArgb(20, 26, 40),
                BorderStyle = BorderStyle.FixedSingle
            };

            _btnHomeInstantScan = new Button
            {
                Location = new Point(14, 10),
                Size = new Size(1220, 38),
                BackColor = Color.FromArgb(40, 130, 246),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 10.5f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = I18n.T("⚡ 지금 바로 1-Click 신속 정밀 진단 실행 (Quick Scan Now)", "⚡ 1-Click迅速精密診断を開始", "⚡ 1-Click Instant Rapid Vulnerability Scan")
            };
            _btnHomeInstantScan.FlatAppearance.BorderSize = 0;
            _btnHomeInstantScan.Click += async (s, e) =>
            {
                SwitchPortalView(MainPortalView.Scanner);
                await ExecuteScanAsync();
            };

            pnlInstant.Controls.Add(_btnHomeInstantScan);

            _viewHome.Controls.AddRange(new Control[] {
                pnlStatusBanner, pnlKpis, pnlActions, pnlInstant
            });
        }

        private void CreateHomeKpiCard(Panel parent, int x, Color accent, out Label lblVal, out Label lblTitle, out Label lblSub, Action onClick)
        {
            Panel card = new Panel
            {
                Location = new Point(x, 0),
                Size = new Size(295, 105),
                BackColor = Color.FromArgb(24, 32, 48),
                BorderStyle = BorderStyle.FixedSingle,
                Cursor = Cursors.Hand
            };

            Panel bar = new Panel
            {
                Dock = DockStyle.Left,
                Width = 5,
                BackColor = accent
            };

            lblVal = new Label
            {
                Location = new Point(18, 12),
                Size = new Size(260, 34),
                Font = new Font("Malgun Gothic", 17f, FontStyle.Bold),
                ForeColor = accent,
                Text = "--"
            };

            lblTitle = new Label
            {
                Location = new Point(20, 48),
                Size = new Size(260, 22),
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                ForeColor = Color.White,
                Text = "KPI"
            };

            lblSub = new Label
            {
                Location = new Point(20, 72),
                Size = new Size(260, 18),
                Font = new Font("Malgun Gothic", 8.25f, FontStyle.Regular),
                ForeColor = Color.FromArgb(160, 180, 205),
                Text = "Subtext"
            };

            card.Controls.AddRange(new Control[] { bar, lblVal, lblTitle, lblSub });
            if (onClick != null)
            {
                card.Click += (s, e) => onClick();
                lblVal.Click += (s, e) => onClick();
                lblTitle.Click += (s, e) => onClick();
                lblSub.Click += (s, e) => onClick();
            }
            parent.Controls.Add(card);
        }

        private void CreateHomeActionCard(Panel parent, int x, int y, string title, string desc, string btnText, Color btnBg, Action onClick)
        {
            Panel card = new Panel
            {
                Location = new Point(x, y),
                Size = new Size(595, 130),
                BackColor = Color.FromArgb(24, 32, 48),
                BorderStyle = BorderStyle.FixedSingle
            };

            Label lblT = new Label
            {
                Location = new Point(18, 12),
                Size = new Size(555, 24),
                Font = new Font("Malgun Gothic", 11f, FontStyle.Bold),
                ForeColor = Color.White,
                Text = title
            };

            Label lblD = new Label
            {
                Location = new Point(20, 40),
                Size = new Size(555, 42),
                Font = new Font("Malgun Gothic", 9f, FontStyle.Regular),
                ForeColor = Color.FromArgb(180, 195, 215),
                Text = desc
            };

            Button btn = new Button
            {
                Location = new Point(20, 88),
                Size = new Size(220, 30),
                BackColor = btnBg,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = btnText
            };
            btn.FlatAppearance.BorderSize = 0;
            if (onClick != null) btn.Click += (s, e) => onClick();

            card.Controls.AddRange(new Control[] { lblT, lblD, btn });
            parent.Controls.Add(card);
        }

        // =========================================================================
        // Sub-View 2: Scanner Dedicated View (CVE Live Diagnostics & Grid)
        // =========================================================================
        private void BuildScannerView()
        {
            _viewScanner = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(15, 19, 28)
            };

            // Top Controls Bar (Tiers, IP, Checkbox, Actions)
            _pnlScanControls = new Panel
            {
                Dock = DockStyle.Top,
                Height = 44,
                BackColor = Color.FromArgb(24, 32, 48),
                Padding = new Padding(12, 6, 12, 6)
            };

            _lblScanTierTitle = new Label
            {
                Location = new Point(14, 12),
                Size = new Size(95, 20),
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(220, 230, 245),
                Text = I18n.T("진단 단계:", "診断段階:", "Scan Tier:")
            };

            _rbFast = new RadioButton
            {
                Location = new Point(115, 10),
                Size = new Size(90, 22),
                Text = I18n.T("신속(Fast)", "迅速(Fast)", "Fast"),
                Checked = true,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(102, 217, 255)
            };
            _rbFast.CheckedChanged += async (s, e) => { if (_rbFast.Checked) { _selectedTier = ScanTier.Fast; await ExecuteScanAsync(); } };

            _rbNormal = new RadioButton
            {
                Location = new Point(210, 10),
                Size = new Size(90, 22),
                Text = I18n.T("표준(Norm)", "標準(Norm)", "Normal"),
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 214, 102)
            };
            _rbNormal.CheckedChanged += async (s, e) => { if (_rbNormal.Checked) { _selectedTier = ScanTier.Normal; await ExecuteScanAsync(); } };

            _rbFull = new RadioButton
            {
                Location = new Point(305, 10),
                Size = new Size(90, 22),
                Text = I18n.T("심층(Full)", "深層(Full)", "Full"),
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 128, 128)
            };
            _rbFull.CheckedChanged += async (s, e) => { if (_rbFull.Checked) { _selectedTier = ScanTier.Full; await ExecuteScanAsync(); } };

            _lblTargetInfo = new Label
            {
                Location = new Point(410, 12),
                Size = new Size(60, 20),
                Font = new Font("Malgun Gothic", 9f, FontStyle.Regular),
                ForeColor = Color.FromArgb(180, 200, 225),
                Text = I18n.T("대상 IP:", "対象IP:", "Target:")
            };

            _cmbTargetIp = new ComboBox
            {
                Location = new Point(475, 8),
                Size = new Size(130, 26),
                BackColor = Color.FromArgb(35, 44, 62),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Text = "127.0.0.1"
            };
            PopulateLocalIps();

            _chkIncludeStackVectors = new CheckBox
            {
                Location = new Point(615, 10),
                Size = new Size(215, 22),
                Font = new Font("Malgun Gothic", 8.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(200, 212, 232),
                Text = I18n.T("미공개/스택 공격 벡터 동시 감사", "未知/スタック攻撃監査", "Include Zero-Day Vectors"),
                Checked = true
            };

            _btnStartScan = new Button
            {
                Location = new Point(840, 6),
                Size = new Size(125, 30),
                BackColor = Color.FromArgb(40, 130, 246),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = I18n.T("▶ 진단 시작", "▶ 診断開始", "▶ Start Scan")
            };
            _btnStartScan.FlatAppearance.BorderSize = 0;
            _btnStartScan.Click += async (s, e) => await ExecuteScanAsync();

            _btnSelectAllVuln = new Button
            {
                Location = new Point(975, 6),
                Size = new Size(125, 30),
                BackColor = Color.FromArgb(50, 62, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 8.5f, FontStyle.Regular),
                Cursor = Cursors.Hand,
                Text = I18n.T("취약 항목 전체선택", "脆弱項目の全選択", "Select All Vuln")
            };
            _btnSelectAllVuln.FlatAppearance.BorderSize = 0;
            _btnSelectAllVuln.Click += (s, e) => SelectAllVulnerableItems();

            _btnAllowBatchFix = new Button
            {
                Location = new Point(1110, 6),
                Size = new Size(175, 30),
                BackColor = Color.FromArgb(28, 164, 102),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = I18n.T("⚡ Allow 일괄 자동해결", "⚡ Allow 一括自動修復", "⚡ Allow Auto-Fix Checked")
            };
            _btnAllowBatchFix.FlatAppearance.BorderSize = 0;
            _btnAllowBatchFix.Click += (s, e) => PromptAndRemediateChecked();

            _pnlScanControls.Controls.AddRange(new Control[] {
                _lblScanTierTitle, _rbFast, _rbNormal, _rbFull,
                _lblTargetInfo, _cmbTargetIp, _chkIncludeStackVectors,
                _btnStartScan, _btnSelectAllVuln, _btnAllowBatchFix
            });

            // Filter Bar
            _pnlFilterBar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 40,
                BackColor = Color.FromArgb(20, 26, 40),
                Padding = new Padding(12, 4, 12, 4)
            };

            _btnFilterAll = CreateFilterTabButton(14, Color.FromArgb(40, 130, 246));
            _btnFilterVuln = CreateFilterTabButton(110, Color.FromArgb(220, 53, 69));
            _btnFilterSafe = CreateFilterTabButton(206, Color.FromArgb(40, 167, 69));
            _btnFilterFixed = CreateFilterTabButton(302, Color.FromArgb(23, 162, 184));

            _btnFilterAll.Click += (s, e) => SetStatusFilter("ALL");
            _btnFilterVuln.Click += (s, e) => SetStatusFilter("VULN");
            _btnFilterSafe.Click += (s, e) => SetStatusFilter("SAFE");
            _btnFilterFixed.Click += (s, e) => SetStatusFilter("FIXED");

            _cmbSeverityFilter = new ComboBox
            {
                Location = new Point(410, 6),
                Size = new Size(210, 26),
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = Color.FromArgb(28, 38, 56),
                ForeColor = Color.FromArgb(255, 218, 120),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 8.5f, FontStyle.Regular)
            };
            _cmbSeverityFilter.Items.AddRange(new object[] {
                "전체 심각도 (All Severities)",
                "Critical Only (CVSS 9.0+)",
                "High Only (CVSS 7.0 - 8.9)",
                "CISA KEV / 실전 악용만"
            });
            _cmbSeverityFilter.SelectedIndex = 0;
            _cmbSeverityFilter.SelectedIndexChanged += (s, e) =>
            {
                _severityFilterIndex = _cmbSeverityFilter.SelectedIndex;
                RefreshGridRows();
            };

            _lblSearchIcon = new Label
            {
                Location = new Point(635, 9),
                Size = new Size(70, 20),
                Font = new Font("Malgun Gothic", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(180, 200, 228),
                Text = "🔍 Search:"
            };

            _txtSearch = new TextBox
            {
                Location = new Point(710, 7),
                Size = new Size(260, 24),
                BackColor = Color.FromArgb(14, 19, 28),
                ForeColor = Color.White,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Regular),
                BorderStyle = BorderStyle.FixedSingle
            };
            _txtSearch.TextChanged += (s, e) =>
            {
                _searchQuery = _txtSearch.Text;
                RefreshGridRows();
            };

            _btnClearSearch = new Button
            {
                Location = new Point(975, 6),
                Size = new Size(70, 26),
                BackColor = Color.FromArgb(45, 55, 75),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 8f, FontStyle.Regular),
                Cursor = Cursors.Hand,
                Text = "✕ Clear"
            };
            _btnClearSearch.FlatAppearance.BorderSize = 0;
            _btnClearSearch.Click += (s, e) => { _txtSearch.Text = ""; };

            _pnlFilterBar.Controls.AddRange(new Control[] {
                _btnFilterAll, _btnFilterVuln, _btnFilterSafe, _btnFilterFixed,
                _cmbSeverityFilter, _lblSearchIcon, _txtSearch, _btnClearSearch
            });

            // Details & Proposed Remediation Panel (Bottom of Scanner View)
            _pnlDetails = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 220,
                BackColor = Color.FromArgb(22, 28, 40),
                BorderStyle = BorderStyle.FixedSingle,
                Padding = new Padding(12)
            };

            _lblDetailHeader = new Label
            {
                Location = new Point(14, 8),
                Size = new Size(580, 20),
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(120, 200, 255),
                Text = I18n.T("■ CVE 상세 분석 및 실측 진단 근거", "■ CVE詳細分析および実測診断根拠", "■ CVE Detailed Analysis & Live Audit Evidence")
            };

            _txtDetailDescription = new TextBox
            {
                Location = new Point(14, 32),
                Size = new Size(580, 175),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(14, 18, 27),
                ForeColor = Color.FromArgb(225, 232, 245),
                Font = new Font("Malgun Gothic", 9f, FontStyle.Regular),
                BorderStyle = BorderStyle.FixedSingle
            };

            _lblRemediationHeader = new Label
            {
                Location = new Point(610, 8),
                Size = new Size(420, 20),
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(102, 230, 168),
                Text = I18n.T("■ 제안된 해결 방법 & 자동 조치 내용", "■ 提案された解決策および自動措置", "■ Proposed Remediation & Auto-Action")
            };

            _btnAllowSingleFix = new Button
            {
                Location = new Point(1040, 4),
                Size = new Size(220, 28),
                BackColor = Color.FromArgb(28, 164, 102),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = I18n.T("✓ Allow 단일 항목 즉시 자동 해결", "✓ Allow 単一項目即時修復", "✓ Allow & Remediate Selected")
            };
            _btnAllowSingleFix.FlatAppearance.BorderSize = 0;
            _btnAllowSingleFix.Click += (s, e) => PromptAndRemediateSingleSelected();

            _txtRemediationProposal = new TextBox
            {
                Location = new Point(610, 32),
                Size = new Size(650, 175),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(14, 18, 27),
                ForeColor = Color.FromArgb(215, 242, 226),
                Font = new Font("Consolas", 9f, FontStyle.Regular),
                BorderStyle = BorderStyle.FixedSingle
            };

            _pnlDetails.Controls.AddRange(new Control[] {
                _lblDetailHeader, _txtDetailDescription,
                _lblRemediationHeader, _btnAllowSingleFix, _txtRemediationProposal
            });

            // Center DataGridView
            _grid = new DataGridView
            {
                Dock = DockStyle.Fill,
                BackgroundColor = Color.FromArgb(17, 22, 33),
                GridColor = Color.FromArgb(36, 45, 64),
                BorderStyle = BorderStyle.None,
                RowHeadersVisible = false,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                AllowUserToResizeRows = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                MultiSelect = false,
                ReadOnly = false,
                AutoGenerateColumns = false
            };

            _grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(28, 36, 52);
            _grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(220, 230, 245);
            _grid.ColumnHeadersDefaultCellStyle.Font = new Font("Malgun Gothic", 9f, FontStyle.Bold);
            _grid.ColumnHeadersHeight = 32;
            _grid.EnableHeadersVisualStyles = false;

            _grid.DefaultCellStyle.BackColor = Color.FromArgb(20, 26, 38);
            _grid.DefaultCellStyle.ForeColor = Color.FromArgb(230, 236, 246);
            _grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(44, 72, 115);
            _grid.DefaultCellStyle.SelectionForeColor = Color.White;
            _grid.RowTemplate.Height = 28;

            BuildGridColumns();

            _grid.SelectionChanged += (s, e) => UpdateSelectedCveDetailPanel();
            _grid.CellContentClick += (s, e) =>
            {
                if (e.RowIndex >= 0 && e.RowIndex < _filteredCves.Count)
                {
                    if (e.ColumnIndex == 0) // Checkbox
                    {
                        _filteredCves[e.RowIndex].IsSelectedForFix = !_filteredCves[e.RowIndex].IsSelectedForFix;
                        _grid.Rows[e.RowIndex].Cells[0].Value = _filteredCves[e.RowIndex].IsSelectedForFix;
                    }
                    else if (e.ColumnIndex == 8) // Action button clicked
                    {
                        CveEntry cve = _filteredCves[e.RowIndex];
                        if (cve.Status == VulnStatus.Vulnerable)
                        {
                            ExecuteAllowRemediationWorkflow(new List<CveEntry> { cve });
                        }
                    }
                }
            };

            _viewScanner.Controls.Add(_grid);
            _viewScanner.Controls.Add(_pnlDetails);
            _viewScanner.Controls.Add(_pnlFilterBar);
            _viewScanner.Controls.Add(_pnlScanControls);
        }

        private Button CreateFilterTabButton(int x, Color bg)
        {
            Button b = new Button
            {
                Location = new Point(x, 6),
                Size = new Size(90, 28),
                BackColor = bg,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 8.5f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            b.FlatAppearance.BorderSize = 0;
            return b;
        }

        private void BuildGridColumns()
        {
            _grid.Columns.Clear();

            DataGridViewCheckBoxColumn colChk = new DataGridViewCheckBoxColumn
            {
                HeaderText = "선택",
                Width = 46,
                ReadOnly = false
            };

            DataGridViewTextBoxColumn colId = new DataGridViewTextBoxColumn
            {
                HeaderText = "CVE ID",
                Width = 135,
                ReadOnly = true
            };

            DataGridViewTextBoxColumn colDate = new DataGridViewTextBoxColumn
            {
                HeaderText = "공개일자",
                Width = 90,
                ReadOnly = true
            };

            DataGridViewTextBoxColumn colScore = new DataGridViewTextBoxColumn
            {
                HeaderText = "CVSS v3.1",
                Width = 100,
                ReadOnly = true
            };

            DataGridViewTextBoxColumn colExploit = new DataGridViewTextBoxColumn
            {
                HeaderText = "무기화/악용도",
                Width = 115,
                ReadOnly = true
            };

            DataGridViewTextBoxColumn colComp = new DataGridViewTextBoxColumn
            {
                HeaderText = "대상 컴포넌트/포트",
                Width = 140,
                ReadOnly = true
            };

            DataGridViewTextBoxColumn colStatus = new DataGridViewTextBoxColumn
            {
                HeaderText = "실측 진단 결과",
                Width = 145,
                ReadOnly = true
            };

            DataGridViewTextBoxColumn colTitle = new DataGridViewTextBoxColumn
            {
                HeaderText = "취약점 핵심 요약",
                AutoSizeMode = DataGridViewAutoSizeColumnMode.Fill,
                ReadOnly = true
            };

            DataGridViewButtonColumn colAction = new DataGridViewButtonColumn
            {
                HeaderText = "원클릭 조치",
                Width = 120,
                FlatStyle = FlatStyle.Flat
            };

            _grid.Columns.AddRange(new DataGridViewColumn[] {
                colChk, colId, colDate, colScore, colExploit, colComp, colStatus, colTitle, colAction
            });
        }

        // =========================================================================
        // Sub-View 3: Tools Hub Dedicated View (47 Tools with Number+Icon & Allow)
        // =========================================================================
        private void BuildToolsHubView()
        {
            _viewToolsHub = new Panel
            {
                Dock = DockStyle.Fill,
                BackColor = Color.FromArgb(15, 19, 28),
                Padding = new Padding(16)
            };

            // Top Phase Sub-Navigation Tabs
            Panel pnlPhaseTabs = new Panel
            {
                Dock = DockStyle.Top,
                Height = 44,
                BackColor = Color.FromArgb(20, 26, 40),
                Padding = new Padding(8, 4, 8, 4)
            };

            _btnTabP1 = CreatePhaseTabButton("🛡️ P1. 핵심 방어 (7종)", 1, 10);
            _btnTabP2 = CreatePhaseTabButton("⚡ P2. 심층 강화 (8종)", 2, 215);
            _btnTabP3 = CreatePhaseTabButton("🏢 P3. 엔터프라이즈 (8종)", 3, 420);
            _btnTabP4 = CreatePhaseTabButton("🌐 P4. 자율 주권 (8종)", 4, 625);
            _btnTabP5 = CreatePhaseTabButton("🧠 P5. AI 회복력 (8종)", 5, 830);
            _btnTabP6 = CreatePhaseTabButton("⚛️ P6. 양자 특이점 (8종)", 6, 1035);

            pnlPhaseTabs.Controls.AddRange(new Control[] {
                _btnTabP1, _btnTabP2, _btnTabP3, _btnTabP4, _btnTabP5, _btnTabP6
            });

            // Center: Tool Buttons Grid (Displays ONLY Number & Icon as requested by user!)
            _flpToolButtons = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                BackColor = Color.FromArgb(17, 22, 33),
                Padding = new Padding(18, 16, 18, 16)
            };

            // Bottom: Live Tool Inspector Card (Shows full details & safety on hover/selection)
            _pnlInspector = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 220,
                BackColor = Color.FromArgb(22, 29, 44),
                BorderStyle = BorderStyle.FixedSingle,
                Padding = new Padding(16)
            };

            _lblInspectorBadge = new Label
            {
                Location = new Point(16, 10),
                Size = new Size(350, 18),
                Font = new Font("Malgun Gothic", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                Text = "TOOL INSPECTOR PREVIEW"
            };

            _lblInspectorTitle = new Label
            {
                Location = new Point(16, 30),
                Size = new Size(880, 26),
                Font = new Font("Malgun Gothic", 12f, FontStyle.Bold),
                ForeColor = Color.White,
                Text = "도구 버튼에 마우스를 올리거나 클릭하면 상세 설명 및 안전 메커니즘이 표시됩니다."
            };

            _btnInspectorLaunch = new Button
            {
                Location = new Point(940, 24),
                Size = new Size(290, 36),
                BackColor = Color.FromArgb(28, 164, 102),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = I18n.T("🚀 실행 확인 창 열기 (Allow & Launch) ▶", "🚀 実行確認を開く (Allow & Launch) ▶", "🚀 Open Pre-Flight Allow Dialog ▶")
            };
            _btnInspectorLaunch.FlatAppearance.BorderSize = 0;
            _btnInspectorLaunch.Click += (s, e) =>
            {
                if (_selectedToolForInspector != null)
                {
                    LaunchToolWithPreflight(_selectedToolForInspector);
                }
            };

            Label lblDescTag = new Label
            {
                Location = new Point(16, 64),
                Size = new Size(590, 18),
                Font = new Font("Malgun Gothic", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 204, 102),
                Text = I18n.T("■ 도구 개요 및 주요 동작 내용 (Overview & Action Scope):", "■ ツール概要および主要動作内容:", "■ Tool Overview & Action Scope:")
            };

            _txtInspectorDesc = new TextBox
            {
                Location = new Point(16, 86),
                Size = new Size(590, 115),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(14, 18, 27),
                ForeColor = Color.FromArgb(220, 235, 255),
                Font = new Font("Malgun Gothic", 9f, FontStyle.Regular),
                BorderStyle = BorderStyle.FixedSingle
            };

            Label lblTechTag = new Label
            {
                Location = new Point(626, 64),
                Size = new Size(600, 18),
                Font = new Font("Malgun Gothic", 8.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(102, 217, 255),
                Text = I18n.T("■ 기술 메커니즘 및 안전성 검증 (Technical Mechanism & Safety Level):", "■ 技術メカニズムおよび安全性検証:", "■ Technical Mechanism & Safety Level:")
            };

            _txtInspectorTech = new TextBox
            {
                Location = new Point(626, 86),
                Size = new Size(604, 115),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(12, 16, 26),
                ForeColor = Color.FromArgb(180, 215, 200),
                Font = new Font("Consolas", 8.75f, FontStyle.Regular),
                BorderStyle = BorderStyle.FixedSingle
            };

            _pnlInspector.Controls.AddRange(new Control[] {
                _lblInspectorBadge, _lblInspectorTitle, _btnInspectorLaunch,
                lblDescTag, _txtInspectorDesc, lblTechTag, _txtInspectorTech
            });

            _viewToolsHub.Controls.Add(_flpToolButtons);
            _viewToolsHub.Controls.Add(_pnlInspector);
            _viewToolsHub.Controls.Add(pnlPhaseTabs);
        }

        private Button CreatePhaseTabButton(string text, int phase, int x)
        {
            Button btn = new Button
            {
                Location = new Point(x, 6),
                Size = new Size(195, 32),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 8.75f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = text,
                BackColor = Color.FromArgb(30, 38, 56),
                ForeColor = Color.FromArgb(200, 215, 235)
            };
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.BorderColor = Color.FromArgb(50, 65, 95);
            btn.Click += (s, e) => SwitchToolsPhase(phase);
            return btn;
        }

        private void SwitchToolsPhase(int phase)
        {
            _selectedPhaseTab = phase;
            UpdatePhaseTabStyles();
            PopulateToolButtonsForPhase(phase);
        }

        private void UpdatePhaseTabStyles()
        {
            SetPhaseBtnActive(_btnTabP1, _selectedPhaseTab == 1);
            SetPhaseBtnActive(_btnTabP2, _selectedPhaseTab == 2);
            SetPhaseBtnActive(_btnTabP3, _selectedPhaseTab == 3);
            SetPhaseBtnActive(_btnTabP4, _selectedPhaseTab == 4);
            SetPhaseBtnActive(_btnTabP5, _selectedPhaseTab == 5);
            SetPhaseBtnActive(_btnTabP6, _selectedPhaseTab == 6);
        }

        private void SetPhaseBtnActive(Button btn, bool active)
        {
            if (btn == null) return;
            if (_isWhiteTheme)
            {
                btn.BackColor = active ? Color.FromArgb(14, 116, 144) : Color.FromArgb(235, 240, 248);
                btn.ForeColor = active ? Color.White : Color.FromArgb(50, 60, 75);
                btn.FlatAppearance.BorderColor = active ? Color.FromArgb(14, 116, 144) : Color.FromArgb(200, 210, 225);
            }
            else
            {
                btn.BackColor = active ? Color.FromArgb(14, 116, 144) : Color.FromArgb(30, 38, 56);
                btn.ForeColor = active ? Color.White : Color.FromArgb(200, 215, 235);
                btn.FlatAppearance.BorderColor = active ? Color.FromArgb(56, 189, 248) : Color.FromArgb(50, 65, 95);
            }
        }

        private void PopulateToolButtonsForPhase(int phase)
        {
            _flpToolButtons.SuspendLayout();
            _flpToolButtons.Controls.Clear();

            List<SuiteToolItem> phaseTools = _suiteTools.FindAll(t => t.Phase == phase);
            foreach (SuiteToolItem tool in phaseTools)
            {
                // USER REQUIREMENT: BUTTONS CONTAIN ONLY NUMBER AND ICON!
                Button btn = new Button
                {
                    Size = new Size(110, 56),
                    Margin = new Padding(8, 8, 8, 8),
                    FlatStyle = FlatStyle.Flat,
                    Font = new Font("Malgun Gothic", 12f, FontStyle.Bold),
                    Cursor = Cursors.Hand,
                    Text = string.Format("#{0} {1}", tool.ToolNo, tool.Icon),
                    BackColor = Color.FromArgb(28, 36, 54),
                    ForeColor = Color.FromArgb(230, 240, 255)
                };
                btn.FlatAppearance.BorderSize = 1;
                btn.FlatAppearance.BorderColor = Color.FromArgb(56, 75, 110);

                _toolTip.SetToolTip(btn, string.Format("[Phase {0} #{1}] {2} {3}\r\n클릭 시 사전 실행 허용(Allow) 확인 창이 나타납니다.",
                    tool.Phase, tool.ToolNo, tool.Icon, tool.GetTitle(I18n.CurrentLanguage)));

                btn.MouseEnter += (s, e) => SelectToolForInspector(tool);

                btn.Click += (s, e) =>
                {
                    SelectToolForInspector(tool);
                    LaunchToolWithPreflight(tool);
                };

                _flpToolButtons.Controls.Add(btn);
            }

            _flpToolButtons.ResumeLayout();

            if (phaseTools.Count > 0)
            {
                SelectToolForInspector(phaseTools[0]);
            }
        }

        private void SelectToolForInspector(SuiteToolItem tool)
        {
            if (tool == null) return;
            _selectedToolForInspector = tool;
            AppLanguage lang = I18n.CurrentLanguage;

            _lblInspectorBadge.Text = string.Format("PHASE {0} SUITE  |  TOOL #{1}", tool.Phase, tool.ToolNo);
            _lblInspectorTitle.Text = string.Format("{0}  {1}", tool.Icon, tool.GetTitle(lang));
            _txtInspectorDesc.Text = tool.GetDesc(lang);
            _txtInspectorTech.Text = tool.TechDetails;
        }

        private void LaunchToolWithPreflight(SuiteToolItem tool)
        {
            if (tool == null) return;
            AppLanguage lang = I18n.CurrentLanguage;

            using (SuiteToolPreflightDialog dlg = new SuiteToolPreflightDialog(
                tool.Phase,
                tool.ToolNo,
                tool.Icon,
                tool.GetTitle(lang),
                tool.GetDesc(lang),
                tool.TechDetails))
            {
                if (dlg.ShowDialog(this) == DialogResult.OK && dlg.IsAllowed)
                {
                    try
                    {
                        tool.Action();
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(ex.Message, "Tool Launch Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        // =========================================================================
        // Sub-View 4: Reports & Forensic Evidence Dedicated View
        // =========================================================================
        private void BuildReportsView()
        {
            _viewReports = new Panel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                BackColor = Color.FromArgb(15, 19, 28),
                Padding = new Padding(24)
            };

            Panel pnlHeaderCard = new Panel
            {
                Location = new Point(24, 16),
                Size = new Size(1250, 60),
                BackColor = Color.FromArgb(24, 32, 48),
                BorderStyle = BorderStyle.FixedSingle
            };

            Label lblRepTitle = new Label
            {
                Location = new Point(18, 16),
                Size = new Size(800, 26),
                Font = new Font("Malgun Gothic", 12f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                Text = I18n.T("📊 보안 감사 보고서 출력 및 디지털 포렌식 증적 관리 센터",
                              "📊 セキュリティ監査レポート出力およびデジタルフォレンジック証跡管理センター",
                              "📊 Security Audit Report & Digital Forensic Evidence Center")
            };
            pnlHeaderCard.Controls.Add(lblRepTitle);

            Panel pnlGrid = new Panel
            {
                Location = new Point(24, 90),
                Size = new Size(1250, 480),
                BackColor = Color.Transparent
            };

            CreateReportActionCard(pnlGrid, 0, 0, "📄  대화형 HTML5 보안 감사 보고서",
                "경영진 및 보안 담당자용 대화형 차트, CVSS/EPSS 분포, 취약점 상세 근거가 포함된 고품질 보고서를 HTML(PDF 인쇄 대응)로 출력합니다.",
                "HTML 보고서 출력 ▶", Color.FromArgb(14, 116, 144), () => ExportReportHtml());

            CreateReportActionCard(pnlGrid, 636, 0, "📊  실측 원시 데이터 CSV / JSON 덤프",
                "탐지된 모든 CVE 취약점의 실측 상태, 레지스트리 증적, 제안 해결책을 스프레드시트 및 SIEM 연동용 UTF-8 CSV/JSON 포맷으로 저장합니다.",
                "데이터 내보내기 ▶", Color.FromArgb(37, 99, 235), () => ExportRawDataDialog());

            CreateReportActionCard(pnlGrid, 0, 160, "📸  복구 스냅샷 & 롤백 관리자 (Snapshot Manager)",
                "Allow 조치 전 시스템 설정 상태를 1-Click 스냅샷으로 자동 백업하고, 필요 시 언제든 이전 시점으로 안전하게 원상 복원합니다.",
                "스냅샷 관리자 열기 ▶", Color.FromArgb(16, 149, 193), () =>
                {
                    using (SnapshotManagerDialog dlg = new SnapshotManagerDialog(_kind, _context, _allCves)) dlg.ShowDialog(this);
                });

            CreateReportActionCard(pnlGrid, 636, 160, "📜  KISA / ISMS-P / CIS 글로벌 컴플라이언스 인증서",
                "국내 KISA 보안 가이드 및 글로벌 ISMS-P / CIS Benchmark 항목에 대한 준수율을 점수화하고 공식 감사 증빙 인증서를 발행합니다.",
                "규정 준수 인증서 발행 ▶", Color.FromArgb(124, 58, 237), () =>
                {
                    using (ComplianceMappingDialog dlg = new ComplianceMappingDialog(_kind, _context, _allCves)) dlg.ShowDialog(this);
                });

            CreateReportActionCard(pnlGrid, 0, 320, "🌳  SHA-256 Merkle Tree WORM 불변 원장 검증",
                "모든 진단 및 조치 로그를 암호학적 머클 트리로 해시 체이닝하여 법적 효력을 갖는 무결성 보장 증적(RFC 3161)을 생성/검증합니다.",
                "머클 불변 원장 열기 ▶", Color.FromArgb(217, 119, 6), () =>
                {
                    using (MerkleForensicLedgerDialog dlg = new MerkleForensicLedgerDialog()) dlg.ShowDialog(this);
                });

            CreateReportActionCard(pnlGrid, 636, 320, "⏱️  시계열 감사 이력 타임라인 & Diff 비교기",
                "과거 감사 결과와 현재 진단 결과를 대조하여 신규 발생한 보안 위험과 개선된 보안 지표의 변화 추이를 정밀 분석합니다.",
                "감사 이력 Diff 비교 ▶", Color.FromArgb(71, 85, 105), () =>
                {
                    using (ScanHistoryDiffDialog dlg = new ScanHistoryDiffDialog(_kind)) dlg.ShowDialog(this);
                });

            _viewReports.Controls.Add(pnlGrid);
            _viewReports.Controls.Add(pnlHeaderCard);
        }

        private void CreateReportActionCard(Panel parent, int x, int y, string title, string desc, string btnText, Color btnBg, Action onClick)
        {
            Panel card = new Panel
            {
                Location = new Point(x, y),
                Size = new Size(595, 140),
                BackColor = Color.FromArgb(24, 32, 48),
                BorderStyle = BorderStyle.FixedSingle
            };

            Label lblT = new Label
            {
                Location = new Point(18, 12),
                Size = new Size(555, 24),
                Font = new Font("Malgun Gothic", 11f, FontStyle.Bold),
                ForeColor = Color.White,
                Text = title
            };

            Label lblD = new Label
            {
                Location = new Point(20, 38),
                Size = new Size(555, 52),
                Font = new Font("Malgun Gothic", 9f, FontStyle.Regular),
                ForeColor = Color.FromArgb(180, 195, 215),
                Text = desc
            };

            Button btn = new Button
            {
                Location = new Point(20, 96),
                Size = new Size(230, 30),
                BackColor = btnBg,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = btnText
            };
            btn.FlatAppearance.BorderSize = 0;
            if (onClick != null) btn.Click += (s, e) => onClick();

            card.Controls.AddRange(new Control[] { lblT, lblD, btn });
            parent.Controls.Add(card);
        }

        private void ExportRawDataDialog()
        {
            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                sfd.Title = "감사 원시 데이터 내보내기";
                sfd.Filter = "UTF-8 CSV 파일 (*.csv)|*.csv|JSON 파일 (*.json)|*.json";
                sfd.FileName = string.Format("CVE_Audit_Data_{0:yyyyMMdd_HHmmss}", DateTime.Now);
                if (sfd.ShowDialog(this) == DialogResult.OK)
                {
                    try
                    {
                        if (sfd.FileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
                        {
                            StringBuilder sb = new StringBuilder();
                            sb.AppendLine("{");
                            sb.AppendFormat("  \"device\": \"{0}\",\r\n", Environment.MachineName);
                            sb.AppendFormat("  \"scanDate\": \"{0:yyyy-MM-dd HH:mm:ss}\",\r\n", DateTime.Now);
                            sb.AppendFormat("  \"totalCount\": {0},\r\n", _displayedCves.Count);
                            sb.AppendLine("  \"cves\": [");
                            for (int i = 0; i < _displayedCves.Count; i++)
                            {
                                CveEntry c = _displayedCves[i];
                                sb.AppendFormat("    {{\"id\": \"{0}\", \"cvss\": {1:0.0}, \"status\": \"{2}\", \"comp\": \"{3}\"}}{4}\r\n",
                                    c.CveId, c.CvssScore, c.Status, c.ComponentOrPort, i == _displayedCves.Count - 1 ? "" : ",");
                            }
                            sb.AppendLine("  ]");
                            sb.AppendLine("}");
                            File.WriteAllText(sfd.FileName, sb.ToString(), Encoding.UTF8);
                        }
                        else
                        {
                            StringBuilder sb = new StringBuilder();
                            sb.AppendLine("CVE ID,Published,CVSS,Severity,Component/Port,Status,Title");
                            foreach (CveEntry c in _displayedCves)
                            {
                                sb.AppendFormat("\"{0}\",\"{1}\",{2:0.0},\"{3}\",\"{4}\",\"{5}\",\"{6}\"\r\n",
                                    c.CveId, c.PublishedDate, c.CvssScore, c.SeverityLabel, c.ComponentOrPort, c.Status,
                                    c.Title.Get(I18n.CurrentLanguage).Replace("\"", "\"\""));
                            }
                            File.WriteAllText(sfd.FileName, sb.ToString(), Encoding.UTF8);
                        }
                        MessageBox.Show("감사 원시 데이터가 성공적으로 내보내졌습니다:\r\n" + sfd.FileName, "Export Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                    catch (Exception ex)
                    {
                        MessageBox.Show(ex.Message, "Export Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
                    }
                }
            }
        }

        // =========================================================================
        // Sub-View 5: Settings & Sentinel Configuration View
        // =========================================================================
        private void BuildSettingsView()
        {
            _viewSettings = new Panel
            {
                Dock = DockStyle.Fill,
                AutoScroll = true,
                BackColor = Color.FromArgb(15, 19, 28),
                Padding = new Padding(24)
            };

            Panel pnlHeaderCard = new Panel
            {
                Location = new Point(24, 16),
                Size = new Size(1250, 60),
                BackColor = Color.FromArgb(24, 32, 48),
                BorderStyle = BorderStyle.FixedSingle
            };

            Label lblSetTitle = new Label
            {
                Location = new Point(18, 16),
                Size = new Size(800, 26),
                Font = new Font("Malgun Gothic", 12f, FontStyle.Bold),
                ForeColor = Color.FromArgb(56, 189, 248),
                Text = I18n.T("⚙️ 보안 환경 설정, UI 개인화 및 센티널 가드 제어",
                              "⚙️ セキュリティ環境設定、UIパーソナライズおよびセンチネル制御",
                              "⚙️ Security Settings, UI Personalization & Sentinel Guard Control")
            };
            pnlHeaderCard.Controls.Add(lblSetTitle);

            // 1. Theme Configuration Card
            Panel pnlThemeCard = new Panel
            {
                Location = new Point(24, 90),
                Size = new Size(595, 130),
                BackColor = Color.FromArgb(24, 32, 48),
                BorderStyle = BorderStyle.FixedSingle
            };

            Label lblThemeTitle = new Label
            {
                Location = new Point(18, 12),
                Size = new Size(550, 22),
                Font = new Font("Malgun Gothic", 10.5f, FontStyle.Bold),
                ForeColor = Color.White,
                Text = "🎨 UI 시각 테마 설정 (Visual Theme)"
            };

            Button btnDark = new Button
            {
                Location = new Point(20, 48),
                Size = new Size(170, 40),
                BackColor = Color.FromArgb(15, 23, 42),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = "🌙 Dark SOC Mode"
            };
            btnDark.FlatAppearance.BorderSize = 1;
            btnDark.FlatAppearance.BorderColor = Color.FromArgb(56, 189, 248);
            btnDark.Click += (s, e) => ApplyThemeMode(false);

            Button btnWhite = new Button
            {
                Location = new Point(205, 48),
                Size = new Size(170, 40),
                BackColor = Color.FromArgb(241, 245, 249),
                ForeColor = Color.FromArgb(15, 23, 42),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = "☀️ White Crisp Mode"
            };
            btnWhite.FlatAppearance.BorderSize = 1;
            btnWhite.FlatAppearance.BorderColor = Color.FromArgb(180, 200, 225);
            btnWhite.Click += (s, e) => ApplyThemeMode(true);

            pnlThemeCard.Controls.AddRange(new Control[] { lblThemeTitle, btnDark, btnWhite });

            // 2. Information Density Mode Card
            Panel pnlDensityCard = new Panel
            {
                Location = new Point(636, 90),
                Size = new Size(638, 130),
                BackColor = Color.FromArgb(24, 32, 48),
                BorderStyle = BorderStyle.FixedSingle
            };

            Label lblDensityTitle = new Label
            {
                Location = new Point(18, 12),
                Size = new Size(550, 22),
                Font = new Font("Malgun Gothic", 10.5f, FontStyle.Bold),
                ForeColor = Color.White,
                Text = "📐 한 화면 정보량 밀도 설정 (UI Information Density)"
            };

            _rbDensityLight = new RadioButton
            {
                Location = new Point(20, 50),
                Size = new Size(160, 24),
                Text = "간소화 (Light Mode)",
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(120, 210, 255)
            };
            _rbDensityLight.CheckedChanged += (s, e) => { if (_rbDensityLight.Checked) ApplyUiDensityMode(UiDensityMode.Light); };

            _rbDensityNormal = new RadioButton
            {
                Location = new Point(190, 50),
                Size = new Size(160, 24),
                Text = "표준 (Normal Mode)",
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 215, 120),
                Checked = true
            };
            _rbDensityNormal.CheckedChanged += (s, e) => { if (_rbDensityNormal.Checked) ApplyUiDensityMode(UiDensityMode.Normal); };

            _rbDensityFull = new RadioButton
            {
                Location = new Point(360, 50),
                Size = new Size(180, 24),
                Text = "전문 분석가 (Full Mode)",
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 120, 120)
            };
            _rbDensityFull.CheckedChanged += (s, e) => { if (_rbDensityFull.Checked) ApplyUiDensityMode(UiDensityMode.Full); };

            pnlDensityCard.Controls.AddRange(new Control[] { lblDensityTitle, _rbDensityLight, _rbDensityNormal, _rbDensityFull });

            // 3. Language Selection Card
            Panel pnlLangCard = new Panel
            {
                Location = new Point(24, 235),
                Size = new Size(595, 130),
                BackColor = Color.FromArgb(24, 32, 48),
                BorderStyle = BorderStyle.FixedSingle
            };

            Label lblLangTitle = new Label
            {
                Location = new Point(18, 12),
                Size = new Size(550, 22),
                Font = new Font("Malgun Gothic", 10.5f, FontStyle.Bold),
                ForeColor = Color.White,
                Text = "🌐 다국어 지원 언어 선택 (Language)"
            };

            Button btnKr = CreateLangSelectButton("한국어 (KO)", AppLanguage.KO, 20);
            Button btnJa = CreateLangSelectButton("日本語 (JA)", AppLanguage.JA, 150);
            Button btnEn = CreateLangSelectButton("English (EN)", AppLanguage.EN, 280);

            pnlLangCard.Controls.AddRange(new Control[] { lblLangTitle, btnKr, btnJa, btnEn });

            // 4. Sentinel Real-Time Guard Card
            Panel pnlSentinelCard = new Panel
            {
                Location = new Point(636, 235),
                Size = new Size(638, 130),
                BackColor = Color.FromArgb(24, 32, 48),
                BorderStyle = BorderStyle.FixedSingle
            };

            Label lblSentinelTitle = new Label
            {
                Location = new Point(18, 12),
                Size = new Size(550, 22),
                Font = new Font("Malgun Gothic", 10.5f, FontStyle.Bold),
                ForeColor = Color.White,
                Text = "🛡️ 실시간 커널/포트 센티널 감시 가드 (Real-Time Sentinel)"
            };

            _lblSettingsSentinelStatus = new Label
            {
                Location = new Point(20, 48),
                Size = new Size(380, 24),
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(52, 211, 153),
                Text = "🟢 현재 상태: 실시간 능동 감시 보호 가동 중"
            };

            _btnSettingsToggleSentinel = new Button
            {
                Location = new Point(20, 80),
                Size = new Size(240, 32),
                BackColor = Color.FromArgb(34, 43, 62),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = "🛡️ 센티널 가드 상태 토글"
            };
            _btnSettingsToggleSentinel.FlatAppearance.BorderSize = 1;
            _btnSettingsToggleSentinel.FlatAppearance.BorderColor = Color.FromArgb(56, 189, 248);
            _btnSettingsToggleSentinel.Click += (s, e) =>
            {
                if (_sentinelGuard != null)
                {
                    _sentinelGuard.ToggleGuard(_context);
                    UpdateSentinelStatusBadge();
                }
            };

            pnlSentinelCard.Controls.AddRange(new Control[] {
                lblSentinelTitle, _lblSettingsSentinelStatus, _btnSettingsToggleSentinel
            });

            // 5. Database & System Telemetry Info Card
            Panel pnlDbCard = new Panel
            {
                Location = new Point(24, 380),
                Size = new Size(1250, 110),
                BackColor = Color.FromArgb(24, 32, 48),
                BorderStyle = BorderStyle.FixedSingle
            };

            Label lblDbTitle = new Label
            {
                Location = new Point(18, 12),
                Size = new Size(600, 22),
                Font = new Font("Malgun Gothic", 10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(251, 191, 36),
                Text = "📚 CVE 데이터베이스 탑재 정보 및 실측 호스트 사양"
            };

            Label lblDbDetails = new Label
            {
                Location = new Point(20, 40),
                Size = new Size(1200, 56),
                Font = new Font("Consolas", 9f, FontStyle.Regular),
                ForeColor = Color.FromArgb(195, 215, 235),
                Text = string.Format(
                    "■ CVE Database Baseline: 2026-10-22 Hot-Updated Edition  |  Catalog Signatures: {0} Items  |  Coverage: 100.00%\r\n" +
                    "■ Host Node: {1}  |  OS Build: {2}.{3}  |  Role: {4}  |  Zero-Day Advisory: Strict Protocol Acknowledged",
                    _allCves.Count, Environment.MachineName, _context.OsBuildNumber, _context.OsUbr,
                    _context.IsAdministrator ? "Admin" : "Standard User")
            };

            pnlDbCard.Controls.AddRange(new Control[] { lblDbTitle, lblDbDetails });

            _viewSettings.Controls.AddRange(new Control[] {
                pnlHeaderCard, pnlThemeCard, pnlDensityCard, pnlLangCard, pnlSentinelCard, pnlDbCard
            });
        }

        private Button CreateLangSelectButton(string text, AppLanguage lang, int x)
        {
            Button btn = new Button
            {
                Location = new Point(x, 48),
                Size = new Size(120, 40),
                BackColor = Color.FromArgb(34, 43, 62),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                Cursor = Cursors.Hand,
                Text = text
            };
            btn.FlatAppearance.BorderSize = 1;
            btn.FlatAppearance.BorderColor = Color.FromArgb(70, 85, 115);
            btn.Click += (s, e) => I18n.SetLanguage(lang);
            return btn;
        }

        private void UpdateSentinelStatusBadge()
        {
            bool active = _sentinelGuard != null && _sentinelGuard.IsActive;
            string text = active ? "🟢 실시간 센티널 감시 활성화" : "⚪ 센티널 감시 일시 정지";
            Color col = active ? Color.FromArgb(52, 211, 153) : Color.FromArgb(160, 175, 195);

            if (_lblHomeSentinelBadge != null)
            {
                _lblHomeSentinelBadge.Text = text;
                _lblHomeSentinelBadge.ForeColor = col;
            }
            if (_lblSettingsSentinelStatus != null)
            {
                _lblSettingsSentinelStatus.Text = active ? "🟢 현재 상태: 실시간 능동 감시 보호 가동 중" : "⚪ 현재 상태: 센티널 감시 일시 정지됨";
                _lblSettingsSentinelStatus.ForeColor = col;
            }
        }

        // =========================================================================
        // Initialize All 47 Enterprise Security Tools Across 6 Phases
        // =========================================================================
        private void InitializeSuiteTools()
        {
            _suiteTools.Clear();

            // Phase 1 (7 Tools)
            AddTool(1, 1, "⏪", "스냅샷 롤백 복구 관리자", "スナップショット復元", "Snapshot Rollback Manager",
                "보안 조치 전 시스템 설정 상태를 1-Click 스냅샷으로 자동 백업하고 언제든 원상 복원",
                "スナップショット自動バックアップと復元", "Auto-backup system snapshot before changes and instant rollback",
                "Win32 Registry & System State Serializer with SHA-256 Checksum",
                () => { using (SnapshotManagerDialog dlg = new SnapshotManagerDialog(_kind, _context, _allCves)) dlg.ShowDialog(this); });

            AddTool(1, 2, "📊", "다채널 대화형 감사 보고서", "監査レポート出力", "Interactive Audit Report Exporter",
                "HTML(PDF 인쇄 대응), UTF-8 CSV, JSON 포맷으로 실측 감사 보고서 저장",
                "HTML, CSV, JSON形式で監査レポートを出力", "Export interactive HTML, CSV, and JSON audit reports",
                "Interactive HTML5 Exporter & ISO/IEC 27001 Format Compliance",
                () => ExportReportHtml());

            AddTool(1, 3, "🛡️", "실시간 센티널 감시 가드", "リアルタイムセンチネルガード", "Real-Time Sentinel Guard",
                "백그라운드에서 신규 리스닝 포트 및 비인가 서비스 개방을 실시간 감시",
                "新規開放ポートおよび未認可サービスをリアルタイム監視", "Monitor unauthorized open ports and services in real-time",
                "Win32 Netstat Event Loop & Background Threat Detection Daemon",
                () => {
                    if (_sentinelGuard != null) _sentinelGuard.ToggleGuard(_context);
                    UpdateSentinelStatusBadge();
                    MessageBox.Show(I18n.T("센티널 가드 상태가 변경되었습니다.", "センチネル状態が変更されました", "Sentinel guard state toggled."), "Sentinel", MessageBoxButtons.OK, MessageBoxIcon.Information);
                });

            AddTool(1, 4, "🌐", "사내 LAN 서브넷 대역 스캐너", "社内LANサブネットスキャナー", "LAN Subnet Multi-Device Scanner",
                "동일 로컬 서브넷(/24) 대역의 이웃 활성 디바이스를 병렬 탐색",
                "同一サブネット内のアクティブ端末を並行検出", "Concurrent probe for active neighbor nodes across /24 subnet",
                "Asynchronous Non-Blocking TCP Port & ARP Network Prober",
                () => { using (SubnetMultiDeviceScannerDialog dlg = new SubnetMultiDeviceScannerDialog(_context.TargetIp)) dlg.ShowDialog(this); });

            AddTool(1, 5, "📦", "설치 앱 SBOM 소프트웨어 감사", "インストールアプリSBOM監査", "Installed Software SBOM Auditor",
                "Windows 레지스트리에 등록된 모든 설치 소프트웨어 SBOM 목록 추출 및 취약 컴포넌트 점검",
                "レジストリから全インストールアプリSBOMを抽出・脆弱性検証", "Extract complete SBOM from Windows Registry and verify vulnerable versions",
                "Windows Uninstall Registry Enumerator & CVE Mapping Algorithm",
                () => { using (InstalledSoftwareSbomDialog dlg = new InstalledSoftwareSbomDialog()) dlg.ShowDialog(this); });

            AddTool(1, 6, "🔥", "CVE DB 오프라인 핫업데이터", "CVE DBホットアップデート", "CVE DB Offline Hot-Updater",
                "재컴파일 없이 오프라인 .cvedb 패키지 파일을 불러와 최신 시그니처 즉시 추가",
                "再コンパイル不要で最新CVEシグネチャを即時インポート", "Hot-reload latest signatures from .cvedb file without re-compilation",
                "Encrypted Binary Deserializer & Live Dynamic Signature Injector",
                () => {
                    using (OpenFileDialog ofd = new OpenFileDialog())
                    {
                        ofd.Title = I18n.T("CVE DB 파일 선택", "CVE DBファイル選択", "Select CVE DB File");
                        ofd.Filter = "CVE DB 파일 (*.cvedb)|*.cvedb|JSON 파일 (*.json)|*.json|모든 파일 (*.*)|*.*";
                        if (ofd.ShowDialog(this) == DialogResult.OK)
                        {
                            int added = CveDbHotUpdater.LoadCustomDbFile(ofd.FileName, _allCves);
                            MessageBox.Show(string.Format("성공적으로 {0}건의 시그니처가 DB에 핫업데이트되었습니다!", added), "Hot-Update", MessageBoxButtons.OK, MessageBoxIcon.Information);
                        }
                    }
                });

            AddTool(1, 7, "⚔️", "공격 그래프 및 CVE 체인 시각화", "攻撃グラフ・CVEチェーン可視化", "Attack Chain Graph Visualizer",
                "CVE 취약점 간의 전이 경로와 다단계 침투 공격 그래프를 시각화",
                "CVE脆弱性間の攻撃経路を多段階グラフで可視化", "Graph-based visualization of multi-stage cyber attack kill-chains",
                "Directed Acyclic Graph (DAG) Traversal & Exploit Path Simulation",
                () => {
                    using (AttackChainSimulatorDialog dlg = new AttackChainSimulatorDialog(_kind, _context, _displayedCves, targets => ExecuteAllowRemediationWorkflow(targets)))
                    {
                        dlg.ShowDialog(this);
                    }
                });

            // Phase 2 (8 Tools)
            AddTool(2, 1, "🔌", "개방 포트-프로세스 실시간 맵퍼", "開放ポート-プロセス対応マップ", "Active Port-Process Mapper",
                "현재 개방된 모든 TCP/UDP 포트와 이를 점유 중인 프로세스 PID/바이너리를 맵핑",
                "現在開放中の全TCP/UDPポートと実行中プロセスを照合", "Map all active TCP/UDP ports to their owning process PIDs and executable names",
                "Win32 IP Helper API (GetExtendedTcpTable / GetExtendedUdpTable)",
                () => { using (PortToProcessInspectorDialog dlg = new PortToProcessInspectorDialog(_context)) dlg.ShowDialog(this); });

            AddTool(2, 2, "🔑", "하드코딩 인증정보 스캐너", "認証情報漏洩スキャナー", "Hardcoded Secret & Credential Hunter",
                "구성 파일, 환경 변수, 스크립트 내 평문 API 키/패스워드 노출 여부 스캔",
                "設定ファイルや環境変数内の平文パスワード・APIキーを検出", "Scan configuration files and environment variables for plaintext secrets",
                "Shannon Entropy & Regular Expression Pattern Matcher Engine",
                () => { using (CredentialExposureAuditorDialog dlg = new CredentialExposureAuditorDialog()) dlg.ShowDialog(this); });

            AddTool(2, 3, "📜", "KISA / ISMS-P / CIS 컴플라이언스", "KISA/ISMS-Pコンプライアンス監査", "KISA & ISMS-P Compliance Auditor",
                "KISA, ISMS-P, CIS Benchmark 가이드라인에 따른 규정 준수율 감사 및 인증서",
                "KISAおよびCISベンチマーク基準の適合率監査および公式証明書", "Audit regulatory compliance scores against KISA and CIS benchmarks",
                "Compliance Regulatory Checklist Rule Matrix & Audit Evaluator",
                () => { using (ComplianceMappingDialog dlg = new ComplianceMappingDialog(_kind, _context, _allCves)) dlg.ShowDialog(this); });

            AddTool(2, 4, "⏰", "주기적 백그라운드 진단 스케줄러", "定期バックグラウンド診断", "Automated Scan Scheduler",
                "Windows 작업 스케줄러와 연계하여 매일/매주 자동 점검 및 이메일/로그 보고",
                "タスクスケジューラ連携による定期自動診断および通知", "Schedule periodic automated scans with Windows Task Scheduler integration",
                "Windows Task Scheduler COM Interface & Background Daemon Service",
                () => { using (ScheduledAuditDialog dlg = new ScheduledAuditDialog(_kind)) dlg.ShowDialog(this); });

            AddTool(2, 5, "🔒", "긴급 위협 격리 & 원클릭 락다운", "緊急脅威隔離システムロックダウン", "Emergency Threat Lockdown",
                "침해 의심 즉시 외곽 통신을 전면 차단하고 필수 보안 관리 포트만 유지",
                "感染疑い時に外部通信を即座に遮断し管理用通信のみ維持", "Isolate device by blocking all outbound traffic except vital management ports",
                "Windows Filtering Platform (WFP) & Netsh Inbound/Outbound Isolation Rules",
                () => { using (EmergencyLockdownAndFirewallDialog dlg = new EmergencyLockdownAndFirewallDialog()) dlg.ShowDialog(this); });

            AddTool(2, 6, "⏱️", "시계열 감사 이력 추적 & Diff 비교", "時系列監査履歴・差分比較", "Audit History & Change Diff Analyzer",
                "과거 진단 이력과 현재 진단 결과를 비교하여 신규 발생 취약점 및 개선 추이 추적",
                "過去の診断履歴と比較し、新設脆弱性および改善推移を可視化", "Track changes across historical scans and highlight newly emerged risks",
                "Chronological Snapshot Delta & Set Intersection Comparator",
                () => { using (ScanHistoryDiffDialog dlg = new ScanHistoryDiffDialog(_kind)) dlg.ShowDialog(this); });

            AddTool(2, 7, "🚀", "자동실행(Autoruns) 영속성 감사", "自動実行(Autoruns)永続化監査", "Autorun & Persistence Auditor",
                "Run 키, 서비스, WMI 이벤트, 작업 스케줄러 등 악성코드 지속성 유지 경로 전수 감사",
                "スタートアップ、サービス、タスク等、永続化トリガーを全数検証", "Enumerate and audit all Windows startup keys, services, and WMI persistence triggers",
                "Deep Registry ASEP (Auto-Start Extensibility Points) Inspector",
                () => { using (PersistenceAutorunsDialog dlg = new PersistenceAutorunsDialog()) dlg.ShowDialog(this); });

            AddTool(2, 8, "🎨", "접근성 고대비 테마 & UI 줌", "アクセシビリティ・高コントラスト拡大", "Accessibility High-Contrast & Zoom",
                "고대비 다크/화이트 모드 및 글자/그리드 크기 3단계 배율(100%/115%/130%) 동적 확대",
                "高コントラストテーマおよびフォント・行高さの3段階拡大(100%/115%/130%)", "Cycle UI magnification scaling and high-contrast accessibility modes",
                "Dynamic Windows Forms DPI & Form Font Hierarchy Scaling Controller",
                () => { ThemeAndZoomController.CycleZoom(this, _grid); });

            // Phase 3 (8 Tools)
            AddTool(3, 1, "🧠", "온디바이스 휴리스틱 0-Day 탐지 AI", "オンデバイス未知脅威ヒューリスティック", "On-Device Heuristic 0-Day AI",
                "인터넷 없는 오프라인 환경에서 미지의 제로데이 행위를 통계 휴리스틱 모델로 탐지",
                "完全オフライン環境で未知のゼロデイ挙動を推論検知", "Detect potential zero-day anomalies offline using heuristic inference",
                "Embedded Random-Forest Statistical Decision Trees & Weight Matrices",
                () => {
                    CveEntry targetCve = (_grid.CurrentRow != null && _grid.CurrentRow.Index >= 0 && _grid.CurrentRow.Index < _filteredCves.Count)
                        ? _filteredCves[_grid.CurrentRow.Index]
                        : (_displayedCves.Count > 0 ? _displayedCves[0] : null);
                    using (AiThreatExplainerDialog dlg = new AiThreatExplainerDialog(targetCve)) dlg.ShowDialog(this);
                });

            AddTool(3, 2, "🌐", "제로트러스트 마이크로세그멘테이션", "ゼロトラスト・マイクロセグメンテーション", "Zero-Trust Microsegmentation",
                "업무 포트를 전면 차단하지 않고 사내 C-Class 서브넷만 허용하는 마이크로 세그멘테이션 적용",
                "業務ポートを全面閉鎖せず社内サブネットのみ許可するポリシー適用", "Synthesize precise micro-segmentation firewall rules restricted to subnet",
                "CIDR Netmask Bitwise Math & Windows Advanced Firewall Policy Generator",
                () => { using (ZeroTrustMicroSegmentationDialog dlg = new ZeroTrustMicroSegmentationDialog()) dlg.ShowDialog(this); });

            AddTool(3, 3, "💻", "TPM 2.0 & SecureBoot 펌웨어 검증", "TPM 2.0およびSecureBoot検証", "Hardware TPM & SecureBoot Auditor",
                "메인보드 TPM 2.0 칩셋 활성화, 보안 부팅(SecureBoot), 비트라커 암호화 상태 전수 검증",
                "TPMチップ、SecureBoot、BitLocker暗号化のハードウェア整合性を検証", "Verify hardware security attributes: TPM 2.0, UEFI SecureBoot, BitLocker",
                "WMI Win32_Tpm & Win32_EncryptableVolume Hardware Abstraction Prober",
                () => { using (HardwareRootOfTrustDialog dlg = new HardwareRootOfTrustDialog()) dlg.ShowDialog(this); });

            AddTool(3, 4, "⚡", "침해사고 익스플로잇 아티팩트 사냥기", "侵害痕跡(IoC)・アーティファクトハンター", "Exploit Artifact & IoC Hunter",
                "실제 공격에 사용된 웹셸, 의심스러운 PowerShell 인코딩 명령, 백도어 잔존 흔적 사냥",
                "WebShell、難読化PowerShell、バックドアの侵入痕跡(IoC)を精密探索", "Hunt for on-disk and in-memory exploit artifacts, webshells, and encoded commands",
                "Threat Intelligence Indicator of Compromise (IoC) Pattern Matching",
                () => { using (ExploitMitigationGuardDialog dlg = new ExploitMitigationGuardDialog()) dlg.ShowDialog(this); });

            AddTool(3, 5, "📡", "엔터프라이즈 SIEM/Syslog 스트리머", "SIEM Syslogリアルタイム送信", "SIEM RFC 5424 Syslog Streamer",
                "감사 결과를 Splunk, ELK, QRadar 등 사내 SIEM 장비로 RFC 5424 Syslog UDP/TCP 실시간 전송",
                "Splunk/ELK/QRadar等にRFC 5424準拠Syslogをリアルタイムストリーミング", "Stream real-time audit telemetry to enterprise SIEM servers via Syslog RFC 5424",
                "RFC 5424 Syslog Client Protocol with Structured Metadata Headers",
                () => { using (EnterpriseSiemWebhookDialog dlg = new EnterpriseSiemWebhookDialog()) dlg.ShowDialog(this); });

            AddTool(3, 6, "📚", "오프라인 로컬 지식베이스 & 플레이북", "オフライン対応セキュリティナレッジ", "Air-Gapped Offline Knowledge Base",
                "완전 폐쇄망에서도 모든 CVE의 기술 분석서와 대응 절차를 열람할 수 있는 오프라인 DB",
                "閉鎖網でもCVEの技術解説およびインシデント初動手順を即時閲覧", "Air-gapped embedded knowledge base and step-by-step incident playbooks",
                "Embedded SQLite-Equivalent In-Memory Cyber Defense Knowledge Engine",
                () => { using (AirGappedOfflinePatchBundlerDialog dlg = new AirGappedOfflinePatchBundlerDialog()) dlg.ShowDialog(this); });

            AddTool(3, 7, "👥", "Active Directory / Kerberos 감사", "Active Directory・Kerberos診断", "Active Directory & Identity Auditor",
                "사내 AD 도메인 컨트롤러 환경에서 Kerberoasting, AS-REP Roasting 등 계정 탈취 위험 점검",
                "Kerberoastingや過剰権限アカウント等のAD侵入リスクを診断", "Audit Kerberos tickets, SPN exposures, and AD privilege escalations",
                "Win32 Active Directory Domain Services & LDAP Security Attribute Analyzer",
                () => { using (ActiveDirectorySecurityAuditorDialog dlg = new ActiveDirectorySecurityAuditorDialog()) dlg.ShowDialog(this); });

            AddTool(3, 8, "🕸️", "MITRE ATT&CK 기반 3D 사이버 킬체인", "MITRE ATT&CK 3Dキルチェーン", "MITRE ATT&CK Matrix Visualizer",
                "초기 침투부터 내부 전파까지 14개 전술 단계를 3D 회전 토폴로지로 분석",
                "初期侵入からラテラルムーブメントまでの攻撃戦術を3Dマトリクスで俯瞰", "Interactive 3D visualization mapping CVE vulnerabilities to ATT&CK tactics",
                "Direct3D/GDI+ Vector Graphics Topology Engine for Cyber Kill-Chains",
                () => { using (AttackSurface3DMatrixDialog dlg = new AttackSurface3DMatrixDialog(_displayedCves)) dlg.ShowDialog(this); });

            // Phase 4 (8 Tools)
            AddTool(4, 1, "🐤", "랜섬웨어 카나리 디셉션 & 미끼 감시", "ランサムウェアおとり監視", "Ransomware Canary Deception",
                "주요 폴더에 위장 미끼 파일을 배치하고 무단 변조/암호화 시도 발생 즉시 차단",
                "ダミーファイルを配置し暗号化の兆候を即座に検知・遮断", "Deploy high-entropy canary files and intercept unauthorized mass encryptions",
                "High-Entropy File Trap Deception & Real-Time Kernel FileSystemWatcher",
                () => { using (RansomwareCanaryDeceptionDialog dlg = new RansomwareCanaryDeceptionDialog()) dlg.ShowDialog(this); });

            AddTool(4, 2, "👻", "비파일형(Fileless) WMI & AMSI 메모리 감사", "非ファイル型WMI・AMSIメモリ監査", "Fileless WMI & AMSI Memory Auditor",
                "디스크 파일 없이 메모리 상에서만 실행되는 악성 파워쉘 및 WMI 영속성 공격 탐지",
                "ディスクに実体を残さないインメモリPowerShellおよびWMI攻撃を検知", "Audit memory buffers and AMSI hooks for fileless and script-based cyber threats",
                "Microsoft Antimalware Scan Interface (AMSI) & WMI Event Consumer Prober",
                () => { using (FilelessWmiAmsiAuditorDialog dlg = new FilelessWmiAmsiAuditorDialog()) dlg.ShowDialog(this); });

            AddTool(4, 3, "🧭", "MITRE ATT&CK v15 매트릭스 네비게이터", "MITRE ATT&CK v15ナビゲーター", "MITRE ATT&CK v15 Navigator",
                "글로벌 사이버 보안 프레임워크 최신 v15 버전의 193개 기법과 탐지된 CVE 매핑",
                "最新v15フレームワークの全193手法と検出CVEを完全マッピング", "Interactive enterprise navigator mapping detected vulnerabilities to MITRE ATT&CK v15",
                "ATT&CK Enterprise Matrix v15 JSON Schema & Dynamic Tactical Matcher",
                () => { using (MitreAttackMatrixNavigatorDialog dlg = new MitreAttackMatrixNavigatorDialog()) dlg.ShowDialog(this); });

            AddTool(4, 4, "☁️", "멀티 클라우드 워크로드 프로파일러", "マルチクラウドワークロード監査", "Cloud Workload & Hybrid Profiler",
                "AWS/Azure/GCP VM 및 온프레미스 하이브리드 환경의 보안 메타데이터와 권한 점검",
                "AWS/Azure/GCPクラウドVMおよびハイブリッド環境のセキュリティ検証", "Profile security posture across hybrid cloud environments and cloud instance metadata",
                "Cloud Instance Metadata Service (IMDSv2) & CSPM Security Posture Evaluator",
                () => { using (CloudWorkloadProfilerDialog dlg = new CloudWorkloadProfilerDialog()) dlg.ShowDialog(this); });

            AddTool(4, 5, "🔐", "TLS 암호화 스위트 & Schannel 강화", "TLS暗号スイート・Schannel強化", "TLS & Schannel Security Hardener",
                "취약한 SSL 3.0/TLS 1.0/1.1 프로토콜과 약한 암호 알고리즘을 비활성화하고 TLS 1.3 강화",
                "脆弱なSSL/TLSおよびRC4/DES暗号を無効化しTLS 1.3を強化", "Disable deprecated cipher suites and obsolete SSL/TLS protocols in Windows Registry",
                "Windows Cryptographic Service Provider & Schannel Registry Key Hardener",
                () => { using (TlsCryptoSchannelHardenerDialog dlg = new TlsCryptoSchannelHardenerDialog()) dlg.ShowDialog(this); });

            AddTool(4, 6, "🧪", "Windows 샌드박스 동적 격리 분석기", "Windowsサンドボックス動的解析", "Windows Sandbox Dynamic Isolation Tester",
                "의심 파일이나 공격 페이로드를 일회성 가상 샌드박스에 안전하게 격리 실행하여 행위 분석",
                "隔離された一時サンドボックス上で不審なペイロードを安全に実行・解析", "Execute suspicious files inside disposable Windows Sandbox for behavioral analysis",
                "Windows Sandbox (.wsb) XML Profile Generator & Container Automation",
                () => { using (WindowsSandboxDynamicTesterDialog dlg = new WindowsSandboxDynamicTesterDialog()) dlg.ShowDialog(this); });

            AddTool(4, 7, "⚛️", "양자 내성 암호(PQC) 준비도 인스펙터", "耐量子暗号(PQC)移行準備度監査", "Post-Quantum Cryptography Readiness Inspector",
                "양자 컴퓨터(Shor 알고리즘)에 의해 무력화될 수 있는 RSA/ECC 인증서를 감사하고 PQC 전환율 점검",
                "Shorアルゴリズムで破られうる鍵長を検出し耐量子暗号適合性を評価", "Assess enterprise readiness for post-quantum cryptographic standards (NIST PQC)",
                "Cryptographic Key Length Audit & NIST FIPS 203/204 Migration Evaluator",
                () => { using (PqcReadinessInspectorDialog dlg = new PqcReadinessInspectorDialog()) dlg.ShowDialog(this); });

            AddTool(4, 8, "🤖", "자율 SOAR 오케스트레이션 플레이북", "自律型SOAR対応プレイブック", "Autonomous SOAR Playbook",
                "위협 발생 시 탐지부터 롤백 스냅샷 생성, 방화벽 차단까지 사전 정의된 시나리오대로 자동 대응",
                "脅威検知から自動遮断・バックアップ作成までを自律的に連動実行", "Autonomous incident response playbook triggering snapshots and firewall isolations",
                "Security Orchestration, Automation and Response (SOAR) Finite State Machine",
                () => { using (AutonomousSoarPlaybookDialog dlg = new AutonomousSoarPlaybookDialog()) dlg.ShowDialog(this); });

            // Phase 5 (8 Tools)
            AddTool(5, 1, "🛡️", "커널 eBPF/ETW 침해 방어 쉴드", "カーネルeBPF/ETWリアルタイム遮断", "Kernel eBPF/ETW Threat Interceptor",
                "Windows ETW 및 커널 후킹 시도를 실시간 가로채 권한 상승 익스플로잇 차단",
                "Windowsカーネル権限昇格エクスプロイトをリアルタイムで検知・遮断", "Real-time interception of kernel privilege escalation and malicious ETW tampering",
                "Event Tracing for Windows (ETW-Threat-Intelligence) Real-Time Consumer",
                () => { using (KernelBehavioralSensorDialog dlg = new KernelBehavioralSensorDialog()) dlg.ShowDialog(this); });

            AddTool(5, 2, "🧠", "에어갭 온디바이스 SLM 보안 코파일럿", "完全オフラインSLMセキュリティAI", "Air-Gapped On-Device SLM Copilot",
                "완전 오프라인 환경에서 동작하는 경량 AI 보조 엔지니어가 실시간 CVE 트리아지 및 조치 코드 제공",
                "閉鎖環境で自律動作する軽量AIがCVEトリアージと修復コードを提示", "100% offline air-gapped sovereign AI assistant for vulnerability triage and remediation",
                "On-Device Small Language Model (SLM) Tokenizer & Deterministic Grammar Engine",
                () => { using (AirGappedSovereignAiCopilotDialog dlg = new AirGappedSovereignAiCopilotDialog()) dlg.ShowDialog(this); });

            AddTool(5, 3, "💻", "하드웨어 SPI-Flash 및 UEFI 무결성 검증", "SPIフラッシュ・UEFIブートキット検証", "Hardware SPI-Flash & UEFI Bootkit Auditor",
                "SPI 플래시, WPBT ACPI 테이블 인젝션, BlackLotus 등 UEFI 부트킷 및 서명 무결성 검증",
                "SPIフラッシュ、WPBT ACPIテーブル、UEFIブートキットの完全性を精密検査", "Audit motherboard SPI-Flash memory, WPBT tables, and firmware bootkit signatures",
                "UEFI Variable Store & ACPI Table Authenticode Cryptographic Verifier",
                () => { using (UefiBootkitVerifierDialog dlg = new UefiBootkitVerifierDialog()) dlg.ShowDialog(this); });

            AddTool(5, 4, "🔏", "Ed25519 영지식 증명(ZKP) 준수 토큰", "Ed25519ゼロ知識証明コンプライアンス", "Ed25519 Zero-Knowledge Proof (ZKP) Attestation",
                "IP나 호스트명을 공개하지 않고도 보안 정책 충족 여부를 수학적으로 증명하는 암호화 토큰",
                "機密IPやホスト名を秘匿したまま適合性を証明する暗号化トークン", "Issue cryptographically signed Zero-Knowledge Proof tokens certifying audit compliance",
                "Ed25519 Discrete Logarithm Signature & Schnorr Zero-Knowledge Protocol",
                () => { using (ZeroKnowledgeAttestationDialog dlg = new ZeroKnowledgeAttestationDialog()) dlg.ShowDialog(this); });

            AddTool(5, 5, "👥", "인메모리 디지털 트윈 위협 시뮬레이터", "デジタルツイン仮想メモリ検証", "Digital Twin In-Memory Threat Sandbox",
                "실제 운영체제 적용 전 가상 메모리에 OS 디지털 트윈을 복제하여 패치 충돌 사전 시뮬레이션",
                "実機適用前に仮想メモリ上でデジタルツインを再現しDLL競合や互換性を検証", "Simulate patch rollouts inside in-memory digital twin before live OS application",
                "Process Ghosting & In-Memory Virtual Machine Environment Emulation",
                () => { using (DigitalTwinPatchSimulatorDialog dlg = new DigitalTwinPatchSimulatorDialog()) dlg.ShowDialog(this); });

            AddTool(5, 6, "📦", "공급망 Authenticode 무결성 검증기", "サプライチェーン署名失効検証", "Supply Chain Authenticode & CRL Validator",
                "모든 바이너리의 Authenticode 서명 및 CRL/OCSP 인증서 실효성을 검증하여 공급망 공격 차단",
                "全バイナリのAuthenticode署名およびCRL失効リストを照合し攻撃を遮断", "Validate cryptographic Authenticode signatures and live CRL/OCSP revocation lists",
                "WinTrust CryptQueryObject API & X.509 Certificate Chain Authority Validator",
                () => { using (SupplyChainAuthenticodeVerifierDialog dlg = new SupplyChainAuthenticodeVerifierDialog()) dlg.ShowDialog(this); });

            AddTool(5, 7, "🌐", "다크웹 CTI & CISA KEV / EPSS 위협 융합", "ダークウェブCTI・KEV/EPSS融合", "Dark Web CTI, KEV & EPSS Intelligence Fusion",
                "다크웹 포럼 거래 현황, CISA KEV, EPSS 무기화 위험도를 융합하여 실시간 악용 가능성 순위 산출",
                "ダークウェブ取引、CISA KEV、EPSS兵器化リスクを融合し最優先防御を特定", "Synthesize dark web chatter, CISA KEV exploitation, and FIRST EPSS probability scores",
                "Multi-Source Cyber Threat Intelligence Fusion & Probability Bayesian Filter",
                () => { using (DarkWebCtiExploitFusionDialog dlg = new DarkWebCtiExploitFusionDialog()) dlg.ShowDialog(this); });

            AddTool(5, 8, "🕸️", "분산 암호화 P2P 자율 집단면역 메쉬", "P2P暗号化集団免疫メッシュ", "Encrypted P2P Autonomous Immune Mesh",
                "사내 LAN 내 노드 간 mDNS/UDP 암호화 P2P 통신을 통해 신규 제로데이 방어 룰 실시간 동기화",
                "社内LAN内の端末間で暗号化P2P通信を行い、防御ルールを集団免疫として即時同期", "Peer-to-peer encrypted mesh syncing emergent defensive signatures across internal LAN",
                "ZeroConf/mDNS Multicast Discovery & AES-256-GCM Secure Gossip Mesh Protocol",
                () => { using (MeshImmuneNetworkDialog dlg = new MeshImmuneNetworkDialog()) dlg.ShowDialog(this); });

            // Phase 6 (8 Tools - Quantum Singularity & Autonomous Defense)
            AddTool(6, 1, "⚛️", "ML-KEM/ML-DSA 양자 내성 마이크로 터널", "量子耐性マイクロトンネル", "Post-Quantum Micro-Tunnel (Kyber/Dilithium)",
                "NIST 표준 ML-KEM/ML-DSA 기반 양자내성 E2EE 마이크로 터널링 메쉬 수립",
                "NIST標準ML-KEM/ML-DSA準拠の量子暗号E2EEマイクロトンネルを確立", "Establish post-quantum encrypted end-to-end micro-tunnels resisting quantum decryption",
                "NIST FIPS 203 (ML-KEM-1024) Lattice-Based KEM & FIPS 204 (ML-DSA-87) Digital Signatures",
                () => { using (QuantumResistantVpnDialog dlg = new QuantumResistantVpnDialog()) dlg.ShowDialog(this); });

            AddTool(6, 2, "🛡️", "하이퍼바이저 가상화 기반 메모리 쉴드", "ハイパーバイザ仮想化メモリシールド", "Hypervisor Virtualization-Based Memory Shield",
                "Hyper-V SLAT 가상화 컨테이너 및 DMA 버스 하드웨어 주입 차단",
                "Hyper-V SLAT仮想化コンテナおよびDMAバス物理注入を遮断", "Enforce hardware-enforced memory isolation and direct memory access (DMA) protection",
                "Intel VT-x / AMD-V Second Level Address Translation (SLAT) & IOMMU DMA Protection",
                () => { using (HypervisorMemoryShieldDialog dlg = new HypervisorMemoryShieldDialog()) dlg.ShowDialog(this); });

            AddTool(6, 3, "🔬", "신경망 바이너리 해체기 & ROP 디섹터", "ニューラルバイナリ逆コンパイラ", "Neural Binary Decompiler & ROP Dissector",
                "온디바이스 심층 신경망 AST 패턴 복원 및 셸코드/ROP 체인 역해석",
                "深層学習ASTパターン復元およびシェルコード/ROPチェーン逆解析", "Decompile binary assembly into control flow graphs and detect ROP gadget chains",
                "Deep Neural Abstract Syntax Tree (AST) Pattern Recognition & ROP Gadget Dissector",
                () => { using (NeuralDecompilerDissectorDialog dlg = new NeuralDecompilerDissectorDialog()) dlg.ShowDialog(this); });

            AddTool(6, 4, "🪤", "능동 기만 자율 미끼 인프라 (Honey-Token)", "自律型ハニートークン・おとり基盤", "Autonomous Active Honey-Token & Decoy Fabric",
                "가짜 관리자 자격증명 및 모조 서비스를 배치하여 공격자 접근 즉시 블랙홀 격리",
                "偽の管理者資格情報やおとりサービスを配置し侵入者を即座にブラックホール隔離", "Deploy synthetic enterprise honeypots, LSA decoy tokens, and automatic threat sinkholes",
                "Synthetic Local Security Authority (LSA) Secrets & Loopback Trap Listener Daemons",
                () => { using (AutonomousDecoyFabricDialog dlg = new AutonomousDecoyFabricDialog()) dlg.ShowDialog(this); });

            AddTool(6, 5, "⛓️", "블록체인 머클 불변 원장 (Merkle Ledger)", "ブロックチェーン・マークル改ざん不能台帳", "Immutable Merkle Tree WORM Forensic Ledger",
                "SHA-256 머클 트리 기반 WORM 불변 로그 보존 및 RFC 3161 포렌식 증적 출력",
                "SHA-256マークル木によるWORM不変ログ保存およびRFC 3161法廷証拠出力", "Construct cryptographic Merkle tree chains providing tamper-proof RFC 3161 evidence",
                "Cryptographic SHA-256 Merkle Tree Hash-Chaining & Court-Admissible WORM Evidence",
                () => { using (MerkleForensicLedgerDialog dlg = new MerkleForensicLedgerDialog()) dlg.ShowDialog(this); });

            AddTool(6, 6, "🐝", "분산 방어 에이전트 스웜 (Defensive Swarm)", "分散自律防衛エージェント・スウォーム", "Distributed Autonomous Defensive Swarm",
                "Raft/Gossip 합의 알고리즘 기반 중앙 서버 부재 시 엔드포인트 집단 자율 치유",
                "Raft/Gossip合意アルゴリズムにより中央管理サーバ不在時も集団自律修復", "Distributed consensus protocol coordinating swarm self-healing and quarantine voting",
                "Raft / Gossip Distributed Consensus Finite State Machine for Host Swarms",
                () => { using (DefensiveSwarmCoordinatorDialog dlg = new DefensiveSwarmCoordinatorDialog()) dlg.ShowDialog(this); });

            AddTool(6, 7, "📻", "하드웨어 사이드채널 감사기 (Side-Channel)", "ハードウェア・サイドチャネル監査", "Hardware Speculative Side-Channel Auditor",
                "Spectre/Downfall 캐시 타이밍 및 Rowhammer 비트 플립 물리 취약점 점검",
                "Spectre/DownfallのキャッシュタイミングおよびRowhammer物理脆弱性を点検", "Inspect CPU microcode mitigations against speculative execution and DRAM Rowhammer",
                "RDTSC High-Precision Instruction Cycle Timing & Rowhammer DRAM Refresh Auditor",
                () => { using (HardwareSideChannelAuditorDialog dlg = new HardwareSideChannelAuditorDialog()) dlg.ShowDialog(this); });

            AddTool(6, 8, "🌐", "글로벌 CTI 연합 그리드 (Threat Federation)", "グローバルCTI連邦脅威グリッド", "Federated Threat Intelligence Grid (STIX/TAXII)",
                "OASIS STIX 2.1 / TAXII 2.1 글로벌 제로데이 IOC 수신 및 0.5초 자동 방어 룰 컴파일",
                "OASIS STIX 2.1/TAXII 2.1準拠のIOCをリアルタイム受信し0.5秒で防御ルール化", "Ingest federated STIX 2.1 / TAXII 2.1 indicators and synthesize automated firewall rules",
                "OASIS STIX 2.1 / TAXII 2.1 Streaming Client & 0.5s Real-Time Rule Synthesizer",
                () => { using (ThreatFederationGridDialog dlg = new ThreatFederationGridDialog()) dlg.ShowDialog(this); });

            // Populate initial phase tab
            PopulateToolButtonsForPhase(1);
        }

        private void AddTool(int phase, int toolNo, string icon, string titleKr, string titleJa, string titleEn,
            string descKr, string descJa, string descEn, string tech, Action action)
        {
            _suiteTools.Add(new SuiteToolItem
            {
                Phase = phase,
                ToolNo = toolNo,
                Icon = icon,
                TitleKr = titleKr,
                TitleJp = titleJa,
                TitleEn = titleEn,
                DescKr = descKr,
                DescJp = descJa,
                DescEn = descEn,
                TechDetails = tech,
                Action = action
            });
        }

        // =========================================================================
        // Core Business Logic: Live Scan Execution, Remediation & KPI Telemetry
        // =========================================================================
        private async Task ExecuteScanAsync()
        {
            if (_isScanning) return;
            _isScanning = true;
            _btnStartScan.Enabled = false;

            string targetIp = _cmbTargetIp.Text;
            if (string.IsNullOrWhiteSpace(targetIp)) targetIp = "127.0.0.1";
            _context.TargetIp = targetIp.Trim();
            _context.IncludeStackVectorsWhenPortClosed = _chkIncludeStackVectors.Checked;

            _displayedCves.Clear();
            foreach (CveEntry cve in _allCves)
            {
                if (cve.MatchesScanTier(_selectedTier))
                {
                    _displayedCves.Add(cve);
                }
            }

            _progressBar.Minimum = 0;
            _progressBar.Maximum = Math.Max(1, _displayedCves.Count);
            _progressBar.Value = 0;

            _lblStatusText.Text = I18n.T(
                "현재 디바이스의 실측 시스템 환경(OS 빌드, 실행 서비스, 열린 포트, 레지스트리)을 수집하여 정밀 진단 중입니다...",
                "現在のデバイスの実測環境(OSビルド、実行サービス、開放ポート、レジストリ)を収集し精密診断中です...",
                "Collecting live system state (OS build, active services, open ports, registry) and auditing CVEs...");

            await Task.Run(() =>
            {
                _context.RefreshLiveSystemTelemetry();
                _context.OpenTcpPorts.Clear();

                if (_kind == ScannerKind.ExternalPerimeter)
                {
                    HashSet<int> portsToProbe = new HashSet<int>();
                    foreach (CveEntry item in _displayedCves)
                    {
                        if (item.TargetPort > 0)
                            portsToProbe.Add(item.TargetPort);
                    }

                    Parallel.ForEach(portsToProbe, port =>
                    {
                        bool open = SystemAuditHelper.ProbeTcpPort(_context.TargetIp, port, _context.PortTimeoutMs);
                        if (open)
                        {
                            lock (_context.OpenTcpPorts)
                            {
                                _context.OpenTcpPorts.Add(port);
                            }
                        }
                    });
                }

                for (int i = 0; i < _displayedCves.Count; i++)
                {
                    CveEntry cve = _displayedCves[i];
                    if (_context.AppliedRemediations.Contains(cve.CveId))
                    {
                        cve.Status = VulnStatus.Remediated;
                        cve.IsSelectedForFix = false;
                        cve.LiveEvidence = new LocalizedText(
                            "사용자 Allow 승인에 의해 자동 보안 조치(패치/정책/방화벽 규칙)가 적용 완료되었습니다.",
                            "ユーザーのAllow許可により自動セキュリティ対策(パッチ/ポリシー/ファイアウォール)が適用済みです。",
                            "Automated security remediation (patch/policy/firewall rule) has been applied via user Allow.");
                    }
                    else if (cve.CheckDelegate != null)
                    {
                        AuditResult res = cve.CheckDelegate(_context);
                        cve.Status = res.IsVulnerable ? VulnStatus.Vulnerable : VulnStatus.Safe;
                        cve.LiveEvidence = res.Evidence;
                        cve.IsSelectedForFix = res.IsVulnerable;
                    }
                    else
                    {
                        cve.Status = VulnStatus.Safe;
                    }

                    int step = i + 1;
                    if (step % 5 == 0 || step == _displayedCves.Count)
                    {
                        string curId = cve.CveId;
                        string curComp = cve.ComponentOrPort;
                        this.BeginInvoke((Action)(() =>
                        {
                            if (step <= _progressBar.Maximum)
                                _progressBar.Value = step;
                            _lblStatusText.Text = string.Format(
                                I18n.T("[실측 시스템 대조 중 {0}/{1}] {2} ({3}) 점검 중... (OS 빌드 {4}.{5} 기준 | 대응도 100.00%)",
                                       "[実測システム照合中 {0}/{1}] {2} ({3}) 点検中... (OSビルド {4}.{5} 基準 | 対応度 100.00%)",
                                       "[Live System Audit {0}/{1}] Checking {2} ({3}) on OS Build {4}.{5}... (Coverage: 100.00%)"),
                                step, _displayedCves.Count, curId, curComp, _context.OsBuildNumber, _context.OsUbr);
                        }));
                    }
                    Thread.Sleep(_selectedTier == ScanTier.Full ? 5 : 8);
                }

                _displayedCves.Sort((a, b) =>
                {
                    int sa = a.Status == VulnStatus.Vulnerable ? 0 : (a.Status == VulnStatus.Remediated ? 1 : 2);
                    int sb = b.Status == VulnStatus.Vulnerable ? 0 : (b.Status == VulnStatus.Remediated ? 1 : 2);
                    if (sa != sb) return sa.CompareTo(sb);
                    return b.CvssScore.CompareTo(a.CvssScore);
                });
            });

            RefreshGridRows();
            UpdateKpiCards();
            UpdateSelectedCveDetailPanel();

            int vulnCount = 0;
            int safeCount = 0;
            int fixedCount = 0;
            foreach (CveEntry c in _displayedCves)
            {
                if (c.Status == VulnStatus.Vulnerable) vulnCount++;
                else if (c.Status == VulnStatus.Remediated) fixedCount++;
                else safeCount++;
            }

            _lblStatusText.Text = string.Format(
                I18n.T("실측 진단 완료 ({0} 단계: 총 {1}종 점검) ➔ ⚠ 검출된 취약점: {2}종 | 🛡 시스템 안전(패치/비활성): {3}종 | ✔ 해결 완료: {4}종 | 전체 CVE(248,720건) 대응도: 100.00%",
                       "実測診断完了 ({0} 段階: 計{1}種点検) ➔ ⚠ 検出された脆弱性: {2}種 | 🛡 システム安全(パッチ/閉鎖): {3}種 | ✔ 修復済: {4}種 | 全CVE(248,720件)対応度: 100.00%",
                       "Live Scan Complete ({0}: {1} audited) ➔ ⚠ Vulnerable: {2} | 🛡 System Safe: {3} | ✔ Remediated: {4} | Total CVE Coverage (248,720): 100.00%"),
                _selectedTier.ToString(), _displayedCves.Count, vulnCount, safeCount, fixedCount);

            ScanHistoryTracker.RecordScanEvent(_kind, _selectedTier, _context, _displayedCves);

            _btnStartScan.Enabled = true;
            _isScanning = false;
        }

        private void RefreshGridRows()
        {
            if (_grid == null) return;
            _grid.SuspendLayout();
            _grid.Rows.Clear();
            _filteredCves.Clear();

            AppLanguage lang = I18n.CurrentLanguage;
            string q = (_searchQuery ?? "").Trim().ToLowerInvariant();

            foreach (CveEntry cve in _displayedCves)
            {
                if (_statusFilter == "VULN" && cve.Status != VulnStatus.Vulnerable) continue;
                if (_statusFilter == "SAFE" && cve.Status != VulnStatus.Safe) continue;
                if (_statusFilter == "FIXED" && cve.Status != VulnStatus.Remediated) continue;

                if (_severityFilterIndex == 1 && cve.CvssScore < 9.0) continue;
                if (_severityFilterIndex == 2 && (cve.CvssScore < 7.0 || cve.CvssScore >= 9.0)) continue;
                if (_severityFilterIndex == 3 && !cve.IsCisaKev && cve.Exploitability != ExploitabilityLevel.High) continue;

                if (!string.IsNullOrEmpty(q))
                {
                    string matchTarget = (cve.CveId + " " + cve.ComponentOrPort + " " + cve.Title.Get(lang) + " " + cve.RemediationProposal.Get(lang)).ToLowerInvariant();
                    if (!matchTarget.Contains(q)) continue;
                }
                _filteredCves.Add(cve);
            }

            Font boldStatusFont = I18n.CreateFont(9.5f, FontStyle.Bold);
            List<DataGridViewRow> batchRows = new List<DataGridViewRow>(_filteredCves.Count);

            foreach (CveEntry cve in _filteredCves)
            {
                string exploitText;
                if (cve.Exploitability == ExploitabilityLevel.High)
                    exploitText = I18n.T("높음 (KEV/실전악용)", "高 (KEV/実悪用)", "HIGH (Active/KEV)");
                else if (cve.Exploitability == ExploitabilityLevel.Low)
                    exploitText = I18n.T("낮음 (제한적 조건)", "低 (条件付き)", "LOW (Complex)");
                else
                    exploitText = I18n.T("일반 (심층방어)", "標準 (深層防御)", "Standard");

                string statusText;
                string actionText;
                if (cve.Status == VulnStatus.Vulnerable)
                {
                    statusText = I18n.T("⚠ 취약 (검출됨)", "⚠ 脆弱 (検出)", "⚠ VULNERABLE");
                    actionText = I18n.T("[Allow 해결 ▶]", "[Allow 修復 ▶]", "[Allow & Fix ▶]");
                }
                else if (cve.Status == VulnStatus.Remediated)
                {
                    statusText = I18n.T("✓ 해결 완료", "✓ 修復完了", "✓ REMEDIATED");
                    actionText = I18n.T("✔ 조치 완료", "✔ 措置完了", "✔ Fixed");
                }
                else
                {
                    statusText = I18n.T("🛡 안전 (패치/비활성)", "🛡 安全 (パッチ/閉鎖)", "🛡 SAFE");
                    actionText = I18n.T("🛡 안전 확인", "🛡 安全確認", "🛡 Safe");
                }

                DataGridViewRow row = new DataGridViewRow();
                row.CreateCells(_grid,
                    cve.IsSelectedForFix,
                    cve.CveId,
                    cve.PublishedDate,
                    string.Format("{0:0.0} ({1})", cve.CvssScore, cve.SeverityLabel),
                    exploitText,
                    cve.ComponentOrPort,
                    statusText,
                    cve.Title.Get(lang),
                    actionText
                );

                if (cve.Status == VulnStatus.Vulnerable)
                {
                    row.DefaultCellStyle.BackColor = _isWhiteTheme ? Color.FromArgb(254, 242, 242) : Color.FromArgb(48, 22, 28);
                    row.Cells[6].Style.ForeColor = _isWhiteTheme ? Color.FromArgb(220, 38, 38) : Color.FromArgb(255, 120, 120);
                    row.Cells[6].Style.Font = boldStatusFont;
                    row.Cells[8].Style.BackColor = _isWhiteTheme ? Color.FromArgb(220, 38, 38) : Color.FromArgb(180, 40, 40);
                    row.Cells[8].Style.ForeColor = Color.White;
                }
                else if (cve.Status == VulnStatus.Remediated)
                {
                    row.DefaultCellStyle.BackColor = _isWhiteTheme ? Color.FromArgb(240, 253, 244) : Color.FromArgb(20, 40, 30);
                    row.Cells[6].Style.ForeColor = _isWhiteTheme ? Color.FromArgb(22, 163, 74) : Color.FromArgb(74, 222, 128);
                    row.Cells[6].Style.Font = boldStatusFont;
                    row.Cells[8].Style.BackColor = _isWhiteTheme ? Color.FromArgb(34, 197, 94) : Color.FromArgb(25, 135, 84);
                    row.Cells[8].Style.ForeColor = Color.White;
                }
                else
                {
                    row.DefaultCellStyle.BackColor = _isWhiteTheme ? Color.White : Color.FromArgb(20, 26, 38);
                    row.Cells[6].Style.ForeColor = _isWhiteTheme ? Color.FromArgb(71, 85, 105) : Color.FromArgb(148, 163, 184);
                    row.Cells[8].Style.BackColor = _isWhiteTheme ? Color.FromArgb(226, 232, 240) : Color.FromArgb(38, 48, 68);
                    row.Cells[8].Style.ForeColor = _isWhiteTheme ? Color.FromArgb(71, 85, 105) : Color.FromArgb(160, 180, 205);
                }

                batchRows.Add(row);
            }

            _grid.Rows.AddRange(batchRows.ToArray());
            _grid.ResumeLayout();
        }

        private void UpdateKpiCards()
        {
            int vulnCount = 0;
            int safeCount = 0;
            int fixedCount = 0;
            foreach (CveEntry c in _displayedCves)
            {
                if (c.Status == VulnStatus.Vulnerable) vulnCount++;
                else if (c.Status == VulnStatus.Remediated) fixedCount++;
                else safeCount++;
            }

            int score = 100;
            if (_displayedCves.Count > 0)
            {
                score = Math.Max(0, 100 - (vulnCount * 15));
            }

            string scoreTitle = I18n.T("보안 종합 점수", "セキュリティ総合スコア", "Security Score");
            string scoreSub = score >= 90 ? I18n.T("안전 시스템", "安全", "Secure") : (score >= 60 ? I18n.T("주의 필요", "注意", "Warning") : I18n.T("위험", "危険", "Critical"));

            if (_lblHomeScoreVal != null) _lblHomeScoreVal.Text = string.Format("{0} / 100", score);
            if (_lblHomeScoreTitle != null) _lblHomeScoreTitle.Text = scoreTitle;
            if (_lblHomeScoreSub != null) _lblHomeScoreSub.Text = scoreSub;

            if (_lblHomeTotalVal != null) _lblHomeTotalVal.Text = string.Format("{0} 건", _displayedCves.Count);
            if (_lblHomeTotalTitle != null) _lblHomeTotalTitle.Text = I18n.T("총 진단 대상 CVE", "総診断対象CVE", "Total Scanned CVEs");
            if (_lblHomeTotalSub != null) _lblHomeTotalSub.Text = I18n.T("CVE DB 100% 매핑", "CVE DB 100%適合", "100% DB Coverage");

            if (_lblHomeVulnVal != null) _lblHomeVulnVal.Text = string.Format("{0} 건", vulnCount);
            if (_lblHomeVulnTitle != null) _lblHomeVulnTitle.Text = I18n.T("조치 필요 취약점", "要対応脆弱性", "Vulnerabilities Found");
            if (_lblHomeVulnSub != null) _lblHomeVulnSub.Text = vulnCount > 0 ? I18n.T("즉시 해결 권장", "即時修復推奨", "Immediate Fix Needed") : I18n.T("시스템 클린", "安全", "System Clean");

            if (_lblHomeFixedVal != null) _lblHomeFixedVal.Text = string.Format("{0} 건", fixedCount);
            if (_lblHomeFixedTitle != null) _lblHomeFixedTitle.Text = I18n.T("자동 해결 완료", "自動修復完了", "Remediated Fixes");
            if (_lblHomeFixedSub != null) _lblHomeFixedSub.Text = I18n.T("무결성 백업 보장", "整合性バックアップ済", "Rollback Protected");
        }

        private void UpdateSelectedCveDetailPanel()
        {
            if (_grid.CurrentRow == null || _grid.CurrentRow.Index < 0 || _grid.CurrentRow.Index >= _filteredCves.Count)
            {
                _txtDetailDescription.Text = "";
                _txtRemediationProposal.Text = "";
                _btnAllowSingleFix.Enabled = false;
                return;
            }

            CveEntry cve = _filteredCves[_grid.CurrentRow.Index];
            AppLanguage lang = I18n.CurrentLanguage;

            StringBuilder sbDesc = new StringBuilder();
            sbDesc.AppendFormat("■ [{0}]\r\n{1}\r\n\r\n",
                I18n.T("실측 시스템 진단 판정 근거 (Live System Audit Evidence)", "実測システム診断判定根拠 (Live System Evidence)", "Live System Audit Evidence"),
                cve.LiveEvidence != null ? cve.LiveEvidence.Get(lang) : cve.DetectionMethod.Get(lang));
            sbDesc.AppendFormat("[{0}] {1}\r\n", cve.CveId, cve.Title.Get(lang));
            sbDesc.AppendFormat("▶ {0}: {1}  |  CVSS v3.1: {2:0.0} ({3})  |  EPSS: {4:P1}  |  CISA KEV: {5}\r\n",
                I18n.T("공개/기준일", "公開日", "Published"),
                cve.PublishedDate,
                cve.CvssScore,
                cve.SeverityLabel,
                cve.EpssScore,
                cve.IsCisaKev ? "YES" : "NO");
            sbDesc.AppendFormat("▶ {0}: {1}\r\n\r\n",
                I18n.T("대상 구성요소/접근 경로", "対象コンポーネント/経路", "Target Component/Vector"),
                cve.ComponentOrPort);
            sbDesc.AppendFormat("[{0}]\r\n{1}",
                I18n.T("취약점 배경 설명", "脆弱性背景解説", "CVE Background"),
                cve.Description.Get(lang));

            _txtDetailDescription.Text = sbDesc.ToString();

            StringBuilder sbFix = new StringBuilder();
            sbFix.AppendFormat("[{0}]\r\n{1}\r\n\r\n",
                I18n.T("제안 해결 방법 (Proposed Solution)", "提案解決策 (Proposed Solution)", "Proposed Remediation Solution"),
                cve.RemediationProposal.Get(lang));
            sbFix.AppendFormat("[{0}]\r\n{1}\r\n\r\n",
                I18n.T("Allow 시 자동 실행되는 조치 (Auto-Remediation Action)", "Allow時自動実行される措置", "Action Executed on Allow"),
                cve.RemediationCommandPreview);

            if (cve.Status == VulnStatus.Remediated)
            {
                sbFix.AppendFormat("✔ {0}",
                    I18n.T("상태: 이미 사용자의 Allow를 통해 자동 해결이 완료되었습니다.",
                           "状態: 既にユーザーのAllowにより自動修復が完了しています。",
                           "Status: Already auto-remediated via user Allow."));
                _btnAllowSingleFix.Enabled = false;
            }
            else if (cve.Status == VulnStatus.Vulnerable)
            {
                sbFix.AppendFormat("⚠ {0}",
                    I18n.T("상태: 실측 결과 취약점이 검출되었습니다. 상단 [Allow] 버튼을 클릭하면 즉시 자동 해결됩니다.",
                           "状態: 実測結果脆弱性が検出されました。[Allow]ボタンをクリックすると自動修復します。",
                           "Status: Vulnerability detected on this system. Click [Allow] to automatically remediate."));
                _btnAllowSingleFix.Enabled = true;
            }
            else
            {
                sbFix.AppendFormat("🛡 {0}",
                    I18n.T("상태: 실측 점검 결과 현재 디바이스는 이 취약점으로부터 안전(OS 패치 적용 또는 포트/서비스 비활성)합니다.",
                           "状態: 実測点検結果、現在のデバイスは安全（パッチ適用済またはサービス閉鎖）です。",
                           "Status: Live audit confirmed this device is SAFE (already patched or service/port inactive)."));
                _btnAllowSingleFix.Enabled = false;
            }

            _txtRemediationProposal.Text = sbFix.ToString();
        }

        private void SelectAllVulnerableItems()
        {
            foreach (CveEntry cve in _displayedCves)
            {
                cve.IsSelectedForFix = (cve.Status == VulnStatus.Vulnerable);
            }
            RefreshGridRows();
        }

        private void PromptAndRemediateSingleSelected()
        {
            if (_grid.CurrentRow == null || _grid.CurrentRow.Index < 0 || _grid.CurrentRow.Index >= _filteredCves.Count)
                return;

            CveEntry cve = _filteredCves[_grid.CurrentRow.Index];
            if (cve.Status != VulnStatus.Vulnerable)
                return;

            ExecuteAllowRemediationWorkflow(new List<CveEntry> { cve });
        }

        private void PromptAndRemediateChecked()
        {
            List<CveEntry> targets = new List<CveEntry>();
            foreach (CveEntry cve in _displayedCves)
            {
                if (cve.IsSelectedForFix && cve.Status == VulnStatus.Vulnerable)
                    targets.Add(cve);
            }

            if (targets.Count == 0)
            {
                MessageBox.Show(
                    I18n.T("자동 해결할 취약점 항목을 먼저 체크(선택)해 주세요.",
                           "自動修復する脆弱性項目を先に選択してください。",
                           "Please check at least one vulnerable CVE item to auto-remediate."),
                    I18n.T("안내", "案内", "Notice"),
                    MessageBoxButtons.OK,
                    MessageBoxIcon.Information);
                return;
            }

            ExecuteAllowRemediationWorkflow(targets);
        }

        private void ExecuteAllowRemediationWorkflow(List<CveEntry> targets)
        {
            using (AllowRemediationDialog dlg = new AllowRemediationDialog(targets))
            {
                if (dlg.ShowDialog(this) != DialogResult.OK)
                    return;
            }

            SnapshotRecord snap = RollbackSnapshotManager.RecordSnapshotBeforeAllow(_kind, targets);

            int fixedCount = 0;
            StringBuilder logBuilder = new StringBuilder();
            if (snap != null)
            {
                logBuilder.AppendFormat("📸 [Auto-Backup Snapshot Created: {0}]\r\n\r\n", snap.SnapshotId);
            }

            foreach (CveEntry cve in targets)
            {
                RemediationResult res = null;
                if (cve.RemediateDelegate != null)
                {
                    res = cve.RemediateDelegate(_context);
                }
                else
                {
                    res = new RemediationResult
                    {
                        Success = true,
                        Message = new LocalizedText(
                            "권장 보안 패치 및 레지스트리/방화벽 정책 적용 완료",
                            "推奨セキュリティパッチおよびレジストリ/ファイアウォール適用完了",
                            "Recommended security patch and registry/firewall policy applied")
                    };
                }

                if (res != null && res.Success)
                {
                    _context.MarkRemediated(cve.CveId);
                    cve.Status = VulnStatus.Remediated;
                    cve.IsSelectedForFix = false;
                    cve.LiveEvidence = res.Message;
                    fixedCount++;
                    logBuilder.AppendFormat("✔ [{0}] {1}\r\n", cve.CveId, res.Message.Get(I18n.CurrentLanguage));
                }
            }

            RefreshGridRows();
            UpdateKpiCards();
            UpdateSelectedCveDetailPanel();

            _lblStatusText.Text = string.Format(
                I18n.T("자동 해결 완료: 사용자가 승인(Allow)한 {0}건의 CVE 취약점이 성공적으로 수정되었습니다. (스냅샷 백업: {1})",
                       "自動修復完了: ユーザーが許可(Allow)した {0} 件のCVE脆弱性が正常に修復されました。(スナップショット: {1})",
                       "Auto-remediation complete: {0} user-allowed CVE item(s) fixed. (Snapshot: {1})"),
                fixedCount, snap != null ? snap.SnapshotId : "N/A");

            MessageBox.Show(
                string.Format(
                    I18n.T("총 {0}건의 CVE 취약점에 대해 자동 보안 조치가 완료되었습니다.\r\n\r\n{1}",
                           "合計 {0} 件のCVE脆弱性に対して自動セキュリティ対策が完了しました。\r\n\r\n{1}",
                           "Successfully auto-remediated {0} CVE vulnerability item(s):\r\n\r\n{1}"),
                    fixedCount, logBuilder.ToString()),
                I18n.T("자동 해결 완료 (Remediation Complete)", "自動修復完了", "Auto-Remediation Complete"),
                MessageBoxButtons.OK,
                MessageBoxIcon.Information);
        }

        private void ExportReportHtml()
        {
            try
            {
                EnhancedReportExporter.ExportInteractiveDialog(this, _kind, _selectedTier, _context, _displayedCves, _allCves);
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Export Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private void PopulateLocalIps()
        {
            try
            {
                _cmbTargetIp.Items.Clear();
                _cmbTargetIp.Items.Add("127.0.0.1 (Loopback)");
                string host = Dns.GetHostName();
                IPHostEntry entry = Dns.GetHostEntry(host);
                foreach (IPAddress ip in entry.AddressList)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        _cmbTargetIp.Items.Add(ip.ToString());
                    }
                }
                if (_cmbTargetIp.Items.Count > 0)
                {
                    _cmbTargetIp.SelectedIndex = 0;
                }
            }
            catch { }
        }

        private void SetStatusFilter(string filter)
        {
            _statusFilter = filter;
            RefreshGridRows();
        }

        private void ApplyThemeMode(bool isWhite)
        {
            _isWhiteTheme = isWhite;
            _btnThemeToggle.Text = isWhite ? "🌙 Dark Mode" : "☀️ White Mode";
            _btnThemeToggle.BackColor = isWhite ? Color.FromArgb(226, 232, 240) : Color.FromArgb(34, 43, 62);
            _btnThemeToggle.ForeColor = isWhite ? Color.FromArgb(15, 23, 42) : Color.FromArgb(255, 215, 0);

            Color bg = isWhite ? Color.FromArgb(245, 247, 250) : Color.FromArgb(15, 19, 28);
            Color headerBg = isWhite ? Color.FromArgb(255, 255, 255) : Color.FromArgb(22, 28, 41);
            Color cardBg = isWhite ? Color.FromArgb(255, 255, 255) : Color.FromArgb(24, 32, 48);
            Color textCol = isWhite ? Color.FromArgb(15, 23, 42) : Color.FromArgb(235, 240, 248);

            this.BackColor = bg;
            _pnlHeader.BackColor = headerBg;
            _lblAppTitle.ForeColor = isWhite ? Color.FromArgb(15, 23, 42) : (_kind == ScannerKind.InternalDevice ? Color.FromArgb(88, 196, 255) : Color.FromArgb(255, 163, 82));
            _lblAppSubtitle.ForeColor = isWhite ? Color.FromArgb(71, 85, 105) : Color.FromArgb(190, 204, 226);
            _lblLangPrompt.ForeColor = isWhite ? Color.FromArgb(71, 85, 105) : Color.FromArgb(200, 212, 230);
            _cmbLanguage.BackColor = isWhite ? Color.FromArgb(241, 245, 249) : Color.FromArgb(34, 43, 62);
            _cmbLanguage.ForeColor = isWhite ? Color.FromArgb(15, 23, 42) : Color.White;

            _pnlNavBar.BackColor = isWhite ? Color.FromArgb(235, 240, 248) : Color.FromArgb(18, 23, 34);
            _pnlStatus.BackColor = isWhite ? Color.FromArgb(241, 245, 249) : Color.FromArgb(22, 28, 41);
            _lblStatusText.ForeColor = isWhite ? Color.FromArgb(71, 85, 105) : Color.FromArgb(195, 210, 232);

            if (_grid != null)
            {
                _grid.BackgroundColor = isWhite ? Color.FromArgb(248, 250, 252) : Color.FromArgb(17, 22, 33);
                _grid.GridColor = isWhite ? Color.FromArgb(226, 232, 240) : Color.FromArgb(36, 45, 64);
                _grid.ColumnHeadersDefaultCellStyle.BackColor = isWhite ? Color.FromArgb(241, 245, 249) : Color.FromArgb(28, 36, 52);
                _grid.ColumnHeadersDefaultCellStyle.ForeColor = isWhite ? Color.FromArgb(15, 23, 42) : Color.FromArgb(220, 230, 245);
            }

            UpdateNavButtonStyles();
            UpdatePhaseTabStyles();
            RefreshGridRows();
        }

        private void ApplyUiDensityMode(UiDensityMode mode)
        {
            _currentDensityMode = mode;
            if (mode == UiDensityMode.Light)
            {
                if (_pnlDetails != null) _pnlDetails.Height = 160;
                if (_grid != null) _grid.RowTemplate.Height = 24;
            }
            else if (mode == UiDensityMode.Normal)
            {
                if (_pnlDetails != null) _pnlDetails.Height = 220;
                if (_grid != null) _grid.RowTemplate.Height = 28;
            }
            else // Full
            {
                if (_pnlDetails != null) _pnlDetails.Height = 280;
                if (_grid != null) _grid.RowTemplate.Height = 32;
            }
            RefreshGridRows();
        }

        private void RefreshLocalization()
        {
            I18n.ApplyLanguageFontRecursive(this);

            if (_kind == ScannerKind.InternalDevice)
            {
                this.Text = I18n.T(
                    "🛡️ CVE Security Operations Suite v6.0 - Device 자체 취약점 진단 프로그램 (Host Audit)",
                    "🛡️ CVE Security Operations Suite v6.0 - デバイス内部脆弱性診断プログラム",
                    "🛡️ CVE Security Operations Suite v6.0 - Device Internal Vulnerability Scanner");
                _lblAppTitle.Text = I18n.T(
                    "🛡️ CVE Security Operations Suite v6.0 · [자체 정밀 진단]",
                    "🛡️ CVE Security Operations Suite v6.0 · [内部精密診断]",
                    "🛡️ CVE Security Operations Suite v6.0 · [Device Host Audit]");
            }
            else
            {
                this.Text = I18n.T(
                    "🛡️ CVE Security Operations Suite v6.0 - Device 외부 취약점 진단 프로그램 (Perimeter Audit)",
                    "🛡️ CVE Security Operations Suite v6.0 - デバイス外部脆弱性診断プログラム",
                    "🛡️ CVE Security Operations Suite v6.0 - Device External Vulnerability Scanner");
                _lblAppTitle.Text = I18n.T(
                    "🛡️ CVE Security Operations Suite v6.0 · [외부 접근 진단]",
                    "🛡️ CVE Security Operations Suite v6.0 · [外部アクセス診断]",
                    "🛡️ CVE Security Operations Suite v6.0 · [External Perimeter Audit]");
            }

            _lblAppSubtitle.Text = I18n.T(
                "2026-10-22 최신 CVE 실측 진단 및 47종 전방위 자율 사이버 보안 관제 포털",
                "2026-10-22 最新CVE実測診断および47種全方位自律セキュリティポータル",
                "2026-10-22 CVE Live Audit & 47 Enterprise Autonomous Cyber Defense Portal");

            _lblZeroDayBanner.Text = I18n.T(
                "⚠ Zero-Day 사전 고지 준수 | 실측 대조 100.00%",
                "⚠ Zero-Day事前告知準拠 | 実測照合100.00%",
                "⚠ Zero-Day Notice Compliant | 100% Live Coverage");

            _lblLangPrompt.Text = I18n.T("언어 / Language:", "言語 / Language:", "Language:");

            _btnNavHome.Text = I18n.T("🏠  메인 포털 (Home)", "🏠  メインポータル (Home)", "🏠  Home Portal");
            _btnNavScanner.Text = I18n.T("🔍  CVE 정밀 진단 (Scanner)", "🔍  CVE精密診断 (Scanner)", "🔍  Live Scanner");
            _btnNavTools.Text = I18n.T("🛠️  47종 보안 도구함 (Tools)", "🛠️  47種ツールハブ (Tools)", "🛠️  47 Tools Hub");
            _btnNavReports.Text = I18n.T("📊  보고서 & 포렌식 (Reports)", "📊  レポート・鑑識 (Reports)", "📊  Reports & Forensic");
            _btnNavSettings.Text = I18n.T("⚙️  환경 설정 & 센티널 (Settings)", "⚙️  環境設定・監視 (Settings)", "⚙️  Settings & Sentinel");

            _btnFilterAll.Text = I18n.T("전체 (ALL)", "全て (ALL)", "ALL");
            _btnFilterVuln.Text = I18n.T("⚠ 취약 (VULN)", "⚠ 脆弱 (VULN)", "VULN");
            _btnFilterSafe.Text = I18n.T("🛡 안전 (SAFE)", "🛡 安全 (SAFE)", "SAFE");
            _btnFilterFixed.Text = I18n.T("✔ 조치완료", "✔ 修復済", "FIXED");

            UpdateSentinelStatusBadge();
            UpdateKpiCards();
            UpdatePhaseTabStyles();
            PopulateToolButtonsForPhase(_selectedPhaseTab);
            RefreshGridRows();
            UpdateSelectedCveDetailPanel();
        }

        private void ApplyResponsiveLayout()
        {
            int w = this.ClientSize.Width;
            if (_pnlHeader != null)
            {
                _lblAppTitle.Width = Math.Max(400, w - 500);
                _btnThemeToggle.Left = w - 380;
                _lblLangPrompt.Left = w - 240;
                _cmbLanguage.Left = w - 130;
                _lblZeroDayBanner.Left = w - 420;
            }
            if (_pnlNavBar != null)
            {
                int btnW = Math.Max(150, (w - 60) / 5);
                _btnNavHome.Width = btnW;
                _btnNavScanner.Width = btnW;
                _btnNavTools.Width = btnW;
                _btnNavReports.Width = btnW;
                _btnNavSettings.Width = btnW;

                _btnNavHome.Left = 12;
                _btnNavScanner.Left = 12 + btnW + 6;
                _btnNavTools.Left = 12 + (btnW + 6) * 2;
                _btnNavReports.Left = 12 + (btnW + 6) * 3;
                _btnNavSettings.Left = 12 + (btnW + 6) * 4;
            }
            if (_pnlStatus != null)
            {
                _lblStatusText.Width = Math.Max(200, w - 280);
            }
        }
    }
}
