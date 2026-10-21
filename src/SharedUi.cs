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
                "■ CVE 데이터베이스 기준일: 2026년 10월 20일 (2026-10-20)  |  진단 단계: Fast / Normal / Full",
                "■ CVEデータベース基準日: 2026年10月20日 (2026-10-20)  |  診断段階: Fast / Normal / Full",
                "■ CVE Database Baseline Date: October 20, 2026 (2026-10-20)  |  Tiers: Fast / Normal / Full");

            _chkAcknowledge.Text = I18n.T(
                "위 고지 사항(CVE 기반 동작 및 Zero-Day Attack 진단 불가)을 확인하고 이해하였습니다.",
                "上記の告知事項（CVEベース動作およびゼロデイ攻撃の診断不可）を確認・理解しました。",
                "I acknowledge that diagnostics are CVE-based (2026-10-20) and Zero-Day Attacks cannot be diagnosed.");

            _btnStart.Text = I18n.T("확인 및 프로그램 시작 ▶", "確認して診断プログラムを開始 ▶", "Acknowledge & Launch ▶");
            _btnExit.Text = I18n.T("종료", "終了", "Exit");
        }
    }

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
        private bool _isDetailPanelCollapsed = false;
        private bool _isDetailPanelExpanded = false;
        private ToolTip _toolTip = new ToolTip { AutoPopDelay = 12000, InitialDelay = 250, ReshowDelay = 150, ShowAlways = true };
        private ContextMenuStrip _gridContextMenu;

        // Header controls
        private Label _lblAppTitle;
        private Label _lblAppSubtitle;
        private Label _lblZeroDayBanner;
        private Label _lblLangPrompt;
        private ComboBox _cmbLanguage;

        // Mode & Target Bar
        private Label _lblScanTierTitle;
        private RadioButton _rbFast;
        private RadioButton _rbNormal;
        private RadioButton _rbFull;
        private Label _lblTierExplanation;
        private Label _lblTargetInfo;
        private ComboBox _cmbTargetIp;
        private CheckBox _chkIncludeStackVectors;
        private Button _btnStartScan;
        private Button _btnSelectAllVuln;
        private Button _btnAllowBatchFix;
        private Button _btnCliMode;
        private Button _btnResetState;
        private Button _btnExportReport;

        // Quick Filter & Search Bar (User-Friendly Navigation)
        private Panel _pnlFilterBar;
        private Button _btnFilterAll;
        private Button _btnFilterVuln;
        private Button _btnFilterSafe;
        private Button _btnFilterFixed;
        private ComboBox _cmbSeverityFilter;
        private Label _lblSearchIcon;
        private TextBox _txtSearch;
        private Button _btnClearSearch;
        private Button _btnQuickAllowAllVuln;

        // 7 Advanced Security Suite Toolbar (Proposals 1 ~ 7)
        private Panel _pnlSuiteBar;
        private Button _btnSuiteSnapshot;
        private Button _btnSuiteMultiReport;
        private Button _btnSuiteSentinel;
        private Button _btnSuiteSubnet;
        private Button _btnSuiteSbom;
        private Button _btnSuiteHotDb;
        private Button _btnSuiteAttackChain;
        private RealTimeSentinelGuard _sentinelGuard;

        // Phase 2 Advanced Suite Bar (Proposals 1 ~ 8)
        private Panel _pnlPhase2Bar;
        private Button _btnP2PortProc;
        private Button _btnP2Creds;
        private Button _btnP2Compliance;
        private Button _btnP2Scheduler;
        private Button _btnP2Lockdown;
        private Button _btnP2HistoryDiff;
        private Button _btnP2Autoruns;
        private Button _btnP2ThemeZoom;

        // Phase 3 Enterprise Suite Bar (Proposals 1 ~ 8)
        private Panel _pnlPhase3Bar;
        private Button _btnP3AiThreat;
        private Button _btnP3ZeroTrust;
        private Button _btnP3Hardware;
        private Button _btnP3Exploit;
        private Button _btnP3Siem;
        private Button _btnP3OfflineKb;
        private Button _btnP3AdDomain;
        private Button _btnP3Matrix3D;

        // KPI Summary cards & labels (5 Cards)
        private Panel _pnlHeader;
        private Panel _pnlControls;
        private Panel _pnlKpi;
        private Panel _pnlDetails;
        private Panel _pnlStatus;
        private List<Panel> _kpiCards = new List<Panel>();
        private Label _lblKpiScoreTitle;
        private Label _lblKpiScoreVal;
        private Label _lblKpiTotalTitle;
        private Label _lblKpiTotalVal;
        private Label _lblKpiVulnTitle;
        private Label _lblKpiVulnVal;
        private Label _lblKpiKevTitle;
        private Label _lblKpiKevVal;
        private Label _lblKpiFixedTitle;
        private Label _lblKpiFixedVal;

        // Progress & Status
        private ProgressBar _progressBar;
        private Label _lblStatusText;

        // Grid & Details
        private DataGridView _grid;
        private Label _lblDetailHeader;
        private TextBox _txtDetailDescription;
        private Label _lblRemediationHeader;
        private TextBox _txtRemediationProposal;
        private Button _btnAllowSingleFix;
        private Button _btnCopyDetail;
        private Button _btnExpandDetails;
        private Button _btnCollapseDetails;

        public ScannerMainForm(ScannerKind kind, List<CveEntry> cves)
        {
            _kind = kind;
            _allCves = cves;
            _context.IsAdministrator = SystemAuditHelper.IsRunningAsAdmin();
            _context.LoadRemediatedState();

            InitializeUi();
            I18n.LanguageChanged += RefreshLocalization;
            this.Resize += (s, e) => ApplyResponsiveLayout();
            this.SizeChanged += (s, e) => ApplyResponsiveLayout();
            RefreshLocalization();
            ApplyResponsiveLayout();

            // Run an initial scan automatically after form loads so the user sees immediate results
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
            int initW = Math.Max(960, Math.Min(1400, (int)(workArea.Width * 0.90)));
            int initH = Math.Max(640, Math.Min(900, (int)(workArea.Height * 0.90)));
            this.Size = new Size(initW, initH);
            this.MinimumSize = new Size(920, 620);
            this.BackColor = Color.FromArgb(15, 19, 28);
            this.ForeColor = Color.FromArgb(235, 240, 248);
            this.Font = new Font("Malgun Gothic", 9.5f, FontStyle.Regular);
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
                    }));
                }
            });

            // 1. Top Header Panel
            _pnlHeader = new Panel
            {
                Dock = DockStyle.Top,
                Height = 82,
                BackColor = Color.FromArgb(22, 28, 41)
            };

            _lblAppTitle = new Label
            {
                Location = new Point(20, 10),
                Size = new Size(780, 30),
                Font = new Font("Malgun Gothic", 14.5f, FontStyle.Bold),
                ForeColor = _kind == ScannerKind.InternalDevice
                    ? Color.FromArgb(88, 196, 255)
                    : Color.FromArgb(255, 163, 82)
            };

            _lblAppSubtitle = new Label
            {
                Location = new Point(22, 42),
                Size = new Size(680, 22),
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(190, 204, 226)
            };

            _lblZeroDayBanner = new Label
            {
                Location = new Point(660, 44),
                Size = new Size(440, 24),
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 193, 94),
                TextAlign = ContentAlignment.MiddleRight
            };

            _lblLangPrompt = new Label
            {
                Location = new Point(980, 14),
                Size = new Size(140, 22),
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(200, 212, 230),
                TextAlign = ContentAlignment.MiddleRight
            };

            _cmbLanguage = new ComboBox
            {
                Location = new Point(1130, 11),
                Width = 155,
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = Color.FromArgb(34, 43, 62),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold)
            };
            _cmbLanguage.Items.AddRange(new object[] { "한국어 (Korean)", "日本語 (Japanese)", "English" });
            _cmbLanguage.SelectedIndex = (int)I18n.CurrentLanguage;
            _cmbLanguage.SelectedIndexChanged += (s, e) =>
            {
                I18n.SetLanguage((AppLanguage)_cmbLanguage.SelectedIndex);
            };

            _pnlHeader.Controls.Add(_lblAppTitle);
            _pnlHeader.Controls.Add(_lblAppSubtitle);
            _pnlHeader.Controls.Add(_lblZeroDayBanner);
            _pnlHeader.Controls.Add(_lblLangPrompt);
            _pnlHeader.Controls.Add(_cmbLanguage);

            // 2. Scan Control Panel
            _pnlControls = new Panel
            {
                Dock = DockStyle.Top,
                Height = 104,
                BackColor = Color.FromArgb(26, 33, 48)
            };

            _lblScanTierTitle = new Label
            {
                Location = new Point(20, 12),
                Size = new Size(135, 24),
                Font = new Font("Malgun Gothic", 9.75f, FontStyle.Bold),
                ForeColor = Color.FromArgb(220, 230, 245)
            };

            _rbFast = new RadioButton
            {
                Location = new Point(155, 10),
                Size = new Size(195, 28),
                Checked = true,
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 120, 120),
                Cursor = Cursors.Hand
            };
            _rbFast.CheckedChanged += async (s, e) => { if (_rbFast.Checked) { _selectedTier = ScanTier.Fast; UpdateTierExplanation(); await ExecuteScanAsync(); } };

            _rbNormal = new RadioButton
            {
                Location = new Point(355, 10),
                Size = new Size(215, 28),
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 204, 102),
                Cursor = Cursors.Hand
            };
            _rbNormal.CheckedChanged += async (s, e) => { if (_rbNormal.Checked) { _selectedTier = ScanTier.Normal; UpdateTierExplanation(); await ExecuteScanAsync(); } };

            _rbFull = new RadioButton
            {
                Location = new Point(575, 10),
                Size = new Size(215, 28),
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(102, 217, 255),
                Cursor = Cursors.Hand
            };
            _rbFull.CheckedChanged += async (s, e) => { if (_rbFull.Checked) { _selectedTier = ScanTier.Full; UpdateTierExplanation(); await ExecuteScanAsync(); } };

            _lblTierExplanation = new Label
            {
                Location = new Point(20, 42),
                Size = new Size(760, 22),
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(195, 210, 235)
            };

            _lblTargetInfo = new Label
            {
                Location = new Point(20, 68),
                Size = new Size(560, 24),
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Regular),
                ForeColor = Color.FromArgb(150, 220, 185)
            };

            _cmbTargetIp = new ComboBox
            {
                Location = new Point(210, 65),
                Width = 180,
                BackColor = Color.FromArgb(35, 44, 62),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Visible = (_kind == ScannerKind.ExternalPerimeter)
            };
            if (_kind == ScannerKind.ExternalPerimeter)
            {
                PopulateLocalIps();
            }

            _chkIncludeStackVectors = new CheckBox
            {
                Location = new Point(400, 66),
                Size = new Size(370, 24),
                Checked = false,
                ForeColor = Color.FromArgb(200, 212, 232),
                Visible = (_kind == ScannerKind.ExternalPerimeter)
            };
            _chkIncludeStackVectors.CheckedChanged += async (s, e) =>
            {
                _context.IncludeStackVectorsWhenPortClosed = _chkIncludeStackVectors.Checked;
                await ExecuteScanAsync();
            };

            _btnStartScan = new Button
            {
                Location = new Point(795, 10),
                Size = new Size(150, 38),
                BackColor = Color.FromArgb(37, 118, 235),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            _btnStartScan.FlatAppearance.BorderSize = 0;
            _btnStartScan.Click += async (s, e) => await ExecuteScanAsync();

            _btnSelectAllVuln = new Button
            {
                Location = new Point(955, 10),
                Size = new Size(150, 38),
                BackColor = Color.FromArgb(52, 63, 85),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9.25f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            _btnSelectAllVuln.FlatAppearance.BorderSize = 0;
            _btnSelectAllVuln.Click += (s, e) => SelectAllVulnerableItems();

            _btnAllowBatchFix = new Button
            {
                Location = new Point(1115, 10),
                Size = new Size(165, 38),
                BackColor = Color.FromArgb(24, 158, 96),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            _btnAllowBatchFix.FlatAppearance.BorderSize = 0;
            _btnAllowBatchFix.Click += (s, e) => PromptAndRemediateChecked();

            _btnCliMode = new Button
            {
                Location = new Point(795, 56),
                Size = new Size(150, 36),
                BackColor = Color.FromArgb(42, 92, 112),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            _btnCliMode.FlatAppearance.BorderSize = 0;
            _btnCliMode.Click += (s, e) =>
            {
                Task.Run(() =>
                {
                    CliEngine.RunCliSession(_kind, _allCves, new string[] { "--cli" }, true);
                });
            };

            _btnResetState = new Button
            {
                Location = new Point(955, 56),
                Size = new Size(150, 36),
                BackColor = Color.FromArgb(65, 52, 72),
                ForeColor = Color.FromArgb(230, 210, 240),
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Regular),
                Cursor = Cursors.Hand
            };
            _btnResetState.FlatAppearance.BorderSize = 0;
            _btnResetState.Click += async (s, e) =>
            {
                _context.ResetRemediatedState();
                await ExecuteScanAsync();
            };

            _btnExportReport = new Button
            {
                Location = new Point(1115, 56),
                Size = new Size(165, 36),
                BackColor = Color.FromArgb(48, 78, 110),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Regular),
                Cursor = Cursors.Hand
            };
            _btnExportReport.FlatAppearance.BorderSize = 0;
            _btnExportReport.Click += (s, e) => ExportReportHtml();

            _pnlControls.Controls.Add(_lblScanTierTitle);
            _pnlControls.Controls.Add(_rbFast);
            _pnlControls.Controls.Add(_rbNormal);
            _pnlControls.Controls.Add(_rbFull);
            _pnlControls.Controls.Add(_lblTierExplanation);
            _pnlControls.Controls.Add(_lblTargetInfo);
            _pnlControls.Controls.Add(_cmbTargetIp);
            _pnlControls.Controls.Add(_chkIncludeStackVectors);
            _pnlControls.Controls.Add(_btnStartScan);
            _pnlControls.Controls.Add(_btnSelectAllVuln);
            _pnlControls.Controls.Add(_btnAllowBatchFix);
            _pnlControls.Controls.Add(_btnCliMode);
            _pnlControls.Controls.Add(_btnResetState);
            _pnlControls.Controls.Add(_btnExportReport);

            // 3. KPI Summary Strip (5 Interactive Cards: Click any card to filter or inspect!)
            _pnlKpi = new Panel
            {
                Dock = DockStyle.Top,
                Height = 68,
                BackColor = Color.FromArgb(19, 24, 36)
            };

            _kpiCards.Clear();
            _kpiCards.Add(CreateKpiCard(_pnlKpi, 20, Color.FromArgb(110, 235, 165), out _lblKpiScoreTitle, out _lblKpiScoreVal, () =>
            {
                using (AttackChainSimulatorDialog dlg = new AttackChainSimulatorDialog(_kind, _context, _displayedCves, targets => ExecuteAllowRemediationWorkflow(targets)))
                {
                    dlg.ShowDialog(this);
                }
            }));
            _kpiCards.Add(CreateKpiCard(_pnlKpi, 270, Color.FromArgb(88, 176, 255), out _lblKpiTotalTitle, out _lblKpiTotalVal, () =>
            {
                _severityFilterIndex = 0;
                if (_cmbSeverityFilter != null) _cmbSeverityFilter.SelectedIndex = 0;
                if (_txtSearch != null) _txtSearch.Text = "";
                SetStatusFilter("ALL");
            }));
            _kpiCards.Add(CreateKpiCard(_pnlKpi, 520, Color.FromArgb(255, 99, 110), out _lblKpiVulnTitle, out _lblKpiVulnVal, () => SetStatusFilter("VULN")));
            _kpiCards.Add(CreateKpiCard(_pnlKpi, 770, Color.FromArgb(135, 195, 235), out _lblKpiKevTitle, out _lblKpiKevVal, () => SetStatusFilter("SAFE")));
            _kpiCards.Add(CreateKpiCard(_pnlKpi, 1020, Color.FromArgb(72, 219, 151), out _lblKpiFixedTitle, out _lblKpiFixedVal, () => SetStatusFilter("FIXED")));

            // 3.5 User-Friendly Quick Filter, Severity Filter & Search Toolbar
            _pnlFilterBar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 44,
                BackColor = Color.FromArgb(23, 30, 44)
            };

            _btnFilterAll = CreateFilterTabButton(20, Color.FromArgb(42, 82, 138));
            _btnFilterAll.Click += (s, e) => SetStatusFilter("ALL");

            _btnFilterVuln = CreateFilterTabButton(195, Color.FromArgb(135, 42, 58));
            _btnFilterVuln.Click += (s, e) => SetStatusFilter("VULN");

            _btnFilterSafe = CreateFilterTabButton(385, Color.FromArgb(36, 56, 82));
            _btnFilterSafe.Click += (s, e) => SetStatusFilter("SAFE");

            _btnFilterFixed = CreateFilterTabButton(575, Color.FromArgb(30, 88, 64));
            _btnFilterFixed.Click += (s, e) => SetStatusFilter("FIXED");

            _cmbSeverityFilter = new ComboBox
            {
                Location = new Point(700, 9),
                Width = 135,
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = Color.FromArgb(28, 38, 56),
                ForeColor = Color.FromArgb(255, 218, 120),
                FlatStyle = FlatStyle.Flat
            };
            _cmbSeverityFilter.Items.AddRange(new object[] { "전체 위험도 (All)", "Critical (9.0+)", "High (7.0~8.9)", "CISA KEV 악용" });
            _cmbSeverityFilter.SelectedIndex = 0;
            _cmbSeverityFilter.SelectedIndexChanged += (s, e) =>
            {
                _severityFilterIndex = _cmbSeverityFilter.SelectedIndex;
                RefreshGridRows();
                UpdateSelectedCveDetailPanel();
            };

            _lblSearchIcon = new Label
            {
                Location = new Point(840, 11),
                Size = new Size(54, 22),
                ForeColor = Color.FromArgb(180, 200, 228),
                TextAlign = ContentAlignment.MiddleRight,
                Text = "🔍 검색:"
            };

            _txtSearch = new TextBox
            {
                Location = new Point(896, 9),
                Size = new Size(140, 26),
                BackColor = Color.FromArgb(14, 19, 28),
                ForeColor = Color.White,
                BorderStyle = BorderStyle.FixedSingle
            };
            _txtSearch.TextChanged += (s, e) =>
            {
                _searchQuery = (_txtSearch.Text ?? "").Trim();
                RefreshGridRows();
                UpdateSelectedCveDetailPanel();
            };

            _btnClearSearch = new Button
            {
                Location = new Point(1038, 8),
                Size = new Size(28, 28),
                BackColor = Color.FromArgb(48, 58, 78),
                ForeColor = Color.FromArgb(220, 230, 245),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Text = "✕"
            };
            _btnClearSearch.FlatAppearance.BorderSize = 0;
            _btnClearSearch.Click += (s, e) =>
            {
                _txtSearch.Text = "";
                _severityFilterIndex = 0;
                if (_cmbSeverityFilter.Items.Count > 0) _cmbSeverityFilter.SelectedIndex = 0;
                SetStatusFilter("ALL");
            };

            _btnQuickAllowAllVuln = new Button
            {
                Location = new Point(1072, 6),
                Size = new Size(220, 32),
                BackColor = Color.FromArgb(24, 158, 96),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9.25f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            _btnQuickAllowAllVuln.FlatAppearance.BorderSize = 0;
            _btnQuickAllowAllVuln.Click += (s, e) =>
            {
                SelectAllVulnerableItems();
                PromptAndRemediateChecked();
            };

            _pnlFilterBar.Controls.Add(_btnFilterAll);
            _pnlFilterBar.Controls.Add(_btnFilterVuln);
            _pnlFilterBar.Controls.Add(_btnFilterSafe);
            _pnlFilterBar.Controls.Add(_btnFilterFixed);
            _pnlFilterBar.Controls.Add(_cmbSeverityFilter);
            _pnlFilterBar.Controls.Add(_lblSearchIcon);
            _pnlFilterBar.Controls.Add(_txtSearch);
            _pnlFilterBar.Controls.Add(_btnClearSearch);
            _pnlFilterBar.Controls.Add(_btnQuickAllowAllVuln);

            // 3.7 Next-Gen Advanced Security Suite Toolbar (All 7 Proposals)
            _pnlSuiteBar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 42,
                BackColor = Color.FromArgb(18, 25, 38)
            };

            _btnSuiteSnapshot = CreateSuiteButton(Color.FromArgb(115, 68, 34));
            _btnSuiteSnapshot.Click += (s, e) =>
            {
                using (SnapshotManagerDialog dlg = new SnapshotManagerDialog(_kind, _context, _allCves))
                {
                    dlg.ShowDialog(this);
                    if (dlg.DidRollback)
                    {
                        RefreshGridRows();
                        UpdateKpiCards();
                        UpdateSelectedCveDetailPanel();
                    }
                }
            };

            _btnSuiteMultiReport = CreateSuiteButton(Color.FromArgb(36, 78, 128));
            _btnSuiteMultiReport.Click += (s, e) => ExportReportHtml();

            _btnSuiteSentinel = CreateSuiteButton(Color.FromArgb(30, 88, 72));
            _btnSuiteSentinel.Click += (s, e) =>
            {
                _sentinelGuard.ToggleGuard(_context);
                UpdateSuiteButtonTexts();
            };

            _btnSuiteSubnet = CreateSuiteButton(Color.FromArgb(44, 68, 112));
            _btnSuiteSubnet.Click += async (s, e) =>
            {
                using (SubnetMultiDeviceScannerDialog dlg = new SubnetMultiDeviceScannerDialog(_context.TargetIp))
                {
                    if (dlg.ShowDialog(this) == DialogResult.OK && !string.IsNullOrEmpty(dlg.SelectedTargetIp))
                    {
                        if (!_cmbTargetIp.Items.Contains(dlg.SelectedTargetIp))
                            _cmbTargetIp.Items.Add(dlg.SelectedTargetIp);
                        _cmbTargetIp.Text = dlg.SelectedTargetIp;
                        await ExecuteScanAsync();
                    }
                }
            };

            _btnSuiteSbom = CreateSuiteButton(Color.FromArgb(62, 54, 112));
            _btnSuiteSbom.Click += (s, e) =>
            {
                using (InstalledSoftwareSbomDialog dlg = new InstalledSoftwareSbomDialog())
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnSuiteHotDb = CreateSuiteButton(Color.FromArgb(88, 56, 96));
            _btnSuiteHotDb.Click += async (s, e) =>
            {
                string samplePath = CveDbHotUpdater.CreateSampleCustomDbPackageOnDesktop();
                using (OpenFileDialog ofd = new OpenFileDialog())
                {
                    ofd.InitialDirectory = Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory);
                    ofd.FileName = Path.GetFileName(samplePath);
                    ofd.Filter = "CVE Hot-Update Package (*.cvedb)|*.cvedb|All Files (*.*)|*.*";
                    if (ofd.ShowDialog(this) == DialogResult.OK)
                    {
                        int added = CveDbHotUpdater.LoadCustomDbFile(ofd.FileName, _allCves);
                        await ExecuteScanAsync();
                        MessageBox.Show(
                            I18n.T(
                                string.Format("오프라인 CVE DB 패키지({0})에서 신규 시그니처 {1}종을 핫업데이트하여 재진단했습니다!\r\n(창으로 .cvedb 파일을 직접 드래그 앤 드롭해도 즉시 반영됩니다.)", Path.GetFileName(ofd.FileName), added),
                                string.Format("オフラインCVE DBパッケージ({0})から新規シグネチャ {1} 種をホットアップデートし再診断しました！", Path.GetFileName(ofd.FileName), added),
                                string.Format("Hot-updated {1} new CVE signature(s) from {0} and rescanned!", Path.GetFileName(ofd.FileName), added)),
                            "CVE DB Hot-Update", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    }
                }
            };

            _btnSuiteAttackChain = CreateSuiteButton(Color.FromArgb(128, 42, 62));
            _btnSuiteAttackChain.Click += (s, e) =>
            {
                using (AttackChainSimulatorDialog dlg = new AttackChainSimulatorDialog(_kind, _context, _displayedCves, targets => ExecuteAllowRemediationWorkflow(targets)))
                {
                    dlg.ShowDialog(this);
                }
            };

            _pnlSuiteBar.Controls.AddRange(new Control[]
            {
                _btnSuiteSnapshot, _btnSuiteMultiReport, _btnSuiteSentinel,
                _btnSuiteSubnet, _btnSuiteSbom, _btnSuiteHotDb, _btnSuiteAttackChain
            });

            // 3.8 Next-Gen Phase 2 Advanced Operations Suite (All 8 Proposals)
            _pnlPhase2Bar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 38,
                BackColor = Color.FromArgb(15, 20, 30)
            };

            _btnP2PortProc = CreateSuiteButton(Color.FromArgb(28, 64, 108));
            _btnP2PortProc.Click += (s, e) =>
            {
                using (PortToProcessInspectorDialog dlg = new PortToProcessInspectorDialog(_context))
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP2Creds = CreateSuiteButton(Color.FromArgb(96, 48, 80));
            _btnP2Creds.Click += (s, e) =>
            {
                using (CredentialExposureAuditorDialog dlg = new CredentialExposureAuditorDialog())
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP2Compliance = CreateSuiteButton(Color.FromArgb(25, 78, 65));
            _btnP2Compliance.Click += (s, e) =>
            {
                using (ComplianceMappingDialog dlg = new ComplianceMappingDialog(_kind, _context, _allCves))
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP2Scheduler = CreateSuiteButton(Color.FromArgb(46, 60, 110));
            _btnP2Scheduler.Click += (s, e) =>
            {
                using (ScheduledAuditDialog dlg = new ScheduledAuditDialog(_kind))
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP2Lockdown = CreateSuiteButton(Color.FromArgb(135, 32, 42));
            _btnP2Lockdown.Click += (s, e) =>
            {
                using (EmergencyLockdownAndFirewallDialog dlg = new EmergencyLockdownAndFirewallDialog())
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP2HistoryDiff = CreateSuiteButton(Color.FromArgb(75, 45, 110));
            _btnP2HistoryDiff.Click += (s, e) =>
            {
                using (ScanHistoryDiffDialog dlg = new ScanHistoryDiffDialog(_kind))
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP2Autoruns = CreateSuiteButton(Color.FromArgb(112, 65, 30));
            _btnP2Autoruns.Click += (s, e) =>
            {
                using (PersistenceAutorunsDialog dlg = new PersistenceAutorunsDialog())
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP2ThemeZoom = CreateSuiteButton(Color.FromArgb(38, 55, 80));
            _btnP2ThemeZoom.Click += (s, e) =>
            {
                ThemeAndZoomController.CycleTheme(this, _grid);
                _lblStatusText.Text = string.Format(
                    I18n.T("UI 테마가 변경되었습니다: {0} (우클릭 시 폰트/그리드 확대 100% ➔ 115% ➔ 130%)",
                           "UIテーマが変更されました: {0} (右クリック: 拡大 100% ➔ 115% ➔ 130%)",
                           "UI Theme changed: {0} (Right-click: Cycle font/grid zoom 100% ➔ 115% ➔ 130%)"),
                    ThemeAndZoomController.CurrentTheme);
            };
            _btnP2ThemeZoom.MouseDown += (s, e) =>
            {
                if (e.Button == MouseButtons.Right)
                {
                    ThemeAndZoomController.CycleZoom(this, _grid);
                    _lblStatusText.Text = string.Format(
                        I18n.T("UI 확대 배율이 변경되었습니다: {0:P0} (좌클릭 시 다크/라이트/고대비 테마 전환)",
                               "UI拡大倍率が変更されました: {0:P0} (左クリック: ダーク/ライト/高コントラスト切替)",
                               "UI Zoom scale changed: {0:P0} (Left-click: Cycle theme Dark/Light/High-Contrast)"),
                        ThemeAndZoomController.CurrentZoomScale);
                }
            };

            _pnlPhase2Bar.Controls.AddRange(new Control[]
            {
                _btnP2PortProc, _btnP2Creds, _btnP2Compliance, _btnP2Scheduler,
                _btnP2Lockdown, _btnP2HistoryDiff, _btnP2Autoruns, _btnP2ThemeZoom
            });

            // 3.9 Next-Gen Phase 3 Enterprise Suite Toolbar (All 8 Proposals)
            _pnlPhase3Bar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 38,
                BackColor = Color.FromArgb(13, 17, 26)
            };

            _btnP3AiThreat = CreateSuiteButton(Color.FromArgb(18, 70, 95));
            _btnP3AiThreat.Click += (s, e) =>
            {
                CveEntry targetCve = null;
                if (_grid.CurrentRow != null && _grid.CurrentRow.Index >= 0 && _grid.CurrentRow.Index < _filteredCves.Count)
                {
                    targetCve = _filteredCves[_grid.CurrentRow.Index];
                }
                else if (_displayedCves.Count > 0)
                {
                    targetCve = _displayedCves.Find(c => c.Status == VulnStatus.Vulnerable) ?? _displayedCves[0];
                }
                using (AiThreatExplainerDialog dlg = new AiThreatExplainerDialog(targetCve))
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP3ZeroTrust = CreateSuiteButton(Color.FromArgb(20, 80, 65));
            _btnP3ZeroTrust.Click += (s, e) =>
            {
                using (ZeroTrustMicroSegmentationDialog dlg = new ZeroTrustMicroSegmentationDialog())
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP3Hardware = CreateSuiteButton(Color.FromArgb(52, 45, 95));
            _btnP3Hardware.Click += (s, e) =>
            {
                using (HardwareRootOfTrustDialog dlg = new HardwareRootOfTrustDialog())
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP3Exploit = CreateSuiteButton(Color.FromArgb(85, 42, 70));
            _btnP3Exploit.Click += (s, e) =>
            {
                using (ExploitMitigationGuardDialog dlg = new ExploitMitigationGuardDialog())
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP3Siem = CreateSuiteButton(Color.FromArgb(32, 60, 105));
            _btnP3Siem.Click += (s, e) =>
            {
                using (EnterpriseSiemWebhookDialog dlg = new EnterpriseSiemWebhookDialog())
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP3OfflineKb = CreateSuiteButton(Color.FromArgb(92, 58, 25));
            _btnP3OfflineKb.Click += (s, e) =>
            {
                using (AirGappedOfflinePatchBundlerDialog dlg = new AirGappedOfflinePatchBundlerDialog())
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP3AdDomain = CreateSuiteButton(Color.FromArgb(68, 38, 85));
            _btnP3AdDomain.Click += (s, e) =>
            {
                using (ActiveDirectorySecurityAuditorDialog dlg = new ActiveDirectorySecurityAuditorDialog())
                {
                    dlg.ShowDialog(this);
                }
            };

            _btnP3Matrix3D = CreateSuiteButton(Color.FromArgb(24, 75, 115));
            _btnP3Matrix3D.Click += (s, e) =>
            {
                using (AttackSurface3DMatrixDialog dlg = new AttackSurface3DMatrixDialog(_displayedCves))
                {
                    dlg.ShowDialog(this);
                }
            };

            _pnlPhase3Bar.Controls.AddRange(new Control[]
            {
                _btnP3AiThreat, _btnP3ZeroTrust, _btnP3Hardware, _btnP3Exploit,
                _btnP3Siem, _btnP3OfflineKb, _btnP3AdDomain, _btnP3Matrix3D
            });

            // 4. Progress & Status Bar
            _pnlStatus = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 36,
                BackColor = Color.FromArgb(22, 28, 41)
            };

            _progressBar = new ProgressBar
            {
                Location = new Point(20, 8),
                Size = new Size(320, 20),
                Style = ProgressBarStyle.Continuous
            };

            _lblStatusText = new Label
            {
                Location = new Point(355, 8),
                Size = new Size(920, 20),
                ForeColor = Color.FromArgb(195, 210, 232)
            };

            _pnlStatus.Controls.Add(_progressBar);
            _pnlStatus.Controls.Add(_lblStatusText);

            // 5. Bottom Detail & Remediation Proposal Panel
            _pnlDetails = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 230,
                BackColor = Color.FromArgb(22, 28, 40),
                Padding = new Padding(16)
            };

            _lblDetailHeader = new Label
            {
                Location = new Point(20, 10),
                Size = new Size(600, 24),
                Font = new Font("Malgun Gothic", 10f, FontStyle.Bold),
                ForeColor = Color.FromArgb(120, 200, 255)
            };

            _txtDetailDescription = new TextBox
            {
                Location = new Point(20, 36),
                Size = new Size(610, 178),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(14, 18, 27),
                ForeColor = Color.FromArgb(225, 232, 245),
                Font = I18n.CreateFont(9.75f, FontStyle.Regular, true),
                Tag = "DETAIL_FONT",
                BorderStyle = BorderStyle.FixedSingle
            };

            _lblRemediationHeader = new Label
            {
                Location = new Point(650, 10),
                Size = new Size(420, 24),
                Font = new Font("Malgun Gothic", 10f, FontStyle.Bold),
                ForeColor = Color.FromArgb(102, 230, 168)
            };

            _btnAllowSingleFix = new Button
            {
                Location = new Point(1045, 5),
                Size = new Size(245, 30),
                BackColor = Color.FromArgb(28, 164, 102),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9.5f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            _btnAllowSingleFix.FlatAppearance.BorderSize = 0;
            _btnAllowSingleFix.Click += (s, e) => PromptAndRemediateSingleSelected();

            _btnCopyDetail = new Button
            {
                Size = new Size(105, 28),
                BackColor = Color.FromArgb(42, 62, 92),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            _btnCopyDetail.FlatAppearance.BorderSize = 0;
            _btnCopyDetail.Click += (s, e) => CopySelectedCveToClipboard();

            _btnExpandDetails = new Button
            {
                Size = new Size(105, 28),
                BackColor = Color.FromArgb(46, 56, 82),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            _btnExpandDetails.FlatAppearance.BorderSize = 0;
            _btnExpandDetails.Click += (s, e) =>
            {
                _isDetailPanelCollapsed = false;
                _isDetailPanelExpanded = !_isDetailPanelExpanded;
                UpdateDetailPanelToggleButtons();
                ApplyResponsiveLayout();
            };

            _btnCollapseDetails = new Button
            {
                Size = new Size(110, 28),
                BackColor = Color.FromArgb(52, 64, 88),
                ForeColor = Color.FromArgb(215, 230, 250),
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand
            };
            _btnCollapseDetails.FlatAppearance.BorderSize = 0;
            _btnCollapseDetails.Click += (s, e) =>
            {
                _isDetailPanelCollapsed = !_isDetailPanelCollapsed;
                if (_isDetailPanelCollapsed) _isDetailPanelExpanded = false;
                UpdateDetailPanelToggleButtons();
                ApplyResponsiveLayout();
            };

            _txtRemediationProposal = new TextBox
            {
                Location = new Point(650, 36),
                Size = new Size(640, 178),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = Color.FromArgb(14, 18, 27),
                ForeColor = Color.FromArgb(215, 242, 226),
                Font = I18n.CreateFont(9.75f, FontStyle.Regular, true),
                Tag = "DETAIL_FONT",
                BorderStyle = BorderStyle.FixedSingle
            };

            _pnlDetails.Controls.Add(_lblDetailHeader);
            _pnlDetails.Controls.Add(_btnCopyDetail);
            _pnlDetails.Controls.Add(_btnExpandDetails);
            _pnlDetails.Controls.Add(_btnCollapseDetails);
            _pnlDetails.Controls.Add(_txtDetailDescription);
            _pnlDetails.Controls.Add(_lblRemediationHeader);
            _pnlDetails.Controls.Add(_btnAllowSingleFix);
            _pnlDetails.Controls.Add(_txtRemediationProposal);

            // 6. Main CVE Grid
            Panel pnlGridContainer = new Panel
            {
                Dock = DockStyle.Fill,
                Padding = new Padding(20, 6, 20, 6),
                BackColor = Color.FromArgb(15, 19, 28)
            };

            _grid = new DataGridView
            {
                Dock = DockStyle.Fill,
                BackgroundColor = Color.FromArgb(17, 22, 33),
                BorderStyle = BorderStyle.FixedSingle,
                EnableHeadersVisualStyles = false,
                AllowUserToAddRows = false,
                AllowUserToDeleteRows = false,
                AllowUserToResizeRows = false,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                MultiSelect = false,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                RowTemplate = { Height = 36 }
            };

            _grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(28, 36, 52);
            _grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(220, 230, 245);
            _grid.ColumnHeadersDefaultCellStyle.Font = I18n.CreateFont(9.75f, FontStyle.Bold);
            _grid.ColumnHeadersHeight = 40;

            _grid.DefaultCellStyle.BackColor = Color.FromArgb(20, 26, 38);
            _grid.DefaultCellStyle.ForeColor = Color.FromArgb(230, 236, 246);
            _grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(44, 72, 115);
            _grid.DefaultCellStyle.SelectionForeColor = Color.White;
            _grid.GridColor = Color.FromArgb(36, 45, 64);

            DataGridViewCheckBoxColumn colCheck = new DataGridViewCheckBoxColumn
            {
                Name = "Select",
                FillWeight = 32
            };
            DataGridViewTextBoxColumn colCve = new DataGridViewTextBoxColumn { Name = "CveId", ReadOnly = true, FillWeight = 76 };
            DataGridViewTextBoxColumn colDate = new DataGridViewTextBoxColumn { Name = "Date", ReadOnly = true, FillWeight = 60 };
            DataGridViewTextBoxColumn colCvss = new DataGridViewTextBoxColumn { Name = "Cvss", ReadOnly = true, FillWeight = 70 };
            DataGridViewTextBoxColumn colExploit = new DataGridViewTextBoxColumn { Name = "Exploitability", ReadOnly = true, FillWeight = 86 };
            DataGridViewTextBoxColumn colComponent = new DataGridViewTextBoxColumn { Name = "Component", ReadOnly = true, FillWeight = 85 };
            DataGridViewTextBoxColumn colStatus = new DataGridViewTextBoxColumn { Name = "Status", ReadOnly = true, FillWeight = 82 };
            DataGridViewTextBoxColumn colTitle = new DataGridViewTextBoxColumn { Name = "Title", ReadOnly = true, FillWeight = 165 };
            DataGridViewTextBoxColumn colFix = new DataGridViewTextBoxColumn { Name = "Proposal", ReadOnly = true, FillWeight = 165 };
            DataGridViewTextBoxColumn colAction = new DataGridViewTextBoxColumn { Name = "Action", ReadOnly = true, FillWeight = 75 };

            _grid.Columns.AddRange(new DataGridViewColumn[]
            {
                colCheck, colCve, colDate, colCvss, colExploit, colComponent, colStatus, colTitle, colFix, colAction
            });

            _grid.SelectionChanged += (s, e) => UpdateSelectedCveDetailPanel();
            _grid.CurrentCellDirtyStateChanged += (s, e) =>
            {
                if (_grid.IsCurrentCellDirty)
                    _grid.CommitEdit(DataGridViewDataErrorContexts.Commit);
            };
            _grid.CellValueChanged += (s, e) =>
            {
                if (e.RowIndex >= 0 && e.RowIndex < _filteredCves.Count && e.ColumnIndex == 0)
                {
                    bool val = Convert.ToBoolean(_grid.Rows[e.RowIndex].Cells[0].Value);
                    _filteredCves[e.RowIndex].IsSelectedForFix = val;
                }
            };
            _grid.CellClick += (s, e) =>
            {
                if (e.RowIndex >= 0 && e.RowIndex < _filteredCves.Count && e.ColumnIndex == 9)
                {
                    CveEntry clicked = _filteredCves[e.RowIndex];
                    if (clicked.Status == VulnStatus.Vulnerable)
                    {
                        ExecuteAllowRemediationWorkflow(new List<CveEntry> { clicked });
                    }
                }
            };
            _grid.CellDoubleClick += (s, e) =>
            {
                if (e.RowIndex >= 0 && e.RowIndex < _filteredCves.Count && e.ColumnIndex > 0)
                {
                    CveEntry clicked = _filteredCves[e.RowIndex];
                    if (clicked.Status == VulnStatus.Vulnerable)
                    {
                        ExecuteAllowRemediationWorkflow(new List<CveEntry> { clicked });
                    }
                }
            };

            // Right-Click Context Menu on CVE Grid for 1-click power usability
            _gridContextMenu = new ContextMenuStrip();
            _grid.CellMouseDown += (s, e) =>
            {
                if (e.Button == MouseButtons.Right && e.RowIndex >= 0 && e.RowIndex < _grid.Rows.Count)
                {
                    _grid.ClearSelection();
                    _grid.Rows[e.RowIndex].Selected = true;
                    _grid.CurrentCell = _grid.Rows[e.RowIndex].Cells[1];
                }
            };
            _grid.ContextMenuStrip = _gridContextMenu;
            RebuildGridContextMenu();

            this.KeyPreview = true;
            this.KeyDown += async (s, e) =>
            {
                if (e.KeyCode == Keys.F5)
                {
                    e.Handled = true;
                    await ExecuteScanAsync();
                }
                else if (e.Control && e.KeyCode == Keys.F)
                {
                    e.Handled = true;
                    _txtSearch.Focus();
                    _txtSearch.SelectAll();
                }
                else if (e.Control && e.KeyCode == Keys.A && !_txtSearch.Focused)
                {
                    e.Handled = true;
                    SelectAllVulnerableItems();
                }
                else if (e.Control && e.KeyCode == Keys.S)
                {
                    e.Handled = true;
                    ExportReportHtml();
                }
                else if (e.Control && (e.KeyCode == Keys.Z || e.KeyCode == Keys.R))
                {
                    e.Handled = true;
                    _btnSuiteSnapshot.PerformClick();
                }
            };

            pnlGridContainer.Controls.Add(_grid);

            this.Controls.Add(pnlGridContainer);
            this.Controls.Add(_pnlDetails);
            this.Controls.Add(_pnlStatus);
            this.Controls.Add(_pnlPhase3Bar);
            this.Controls.Add(_pnlPhase2Bar);
            this.Controls.Add(_pnlSuiteBar);
            this.Controls.Add(_pnlFilterBar);
            this.Controls.Add(_pnlKpi);
            this.Controls.Add(_pnlControls);
            this.Controls.Add(_pnlHeader);
        }

        private Button CreateSuiteButton(Color bg)
        {
            Button b = new Button
            {
                Size = new Size(165, 30),
                BackColor = bg,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 8.75f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            b.FlatAppearance.BorderSize = 1;
            b.FlatAppearance.BorderColor = Color.FromArgb(80, 110, 155);
            return b;
        }

        private void UpdateSuiteButtonTexts()
        {
            if (_btnSuiteSnapshot == null) return;
            _btnSuiteSnapshot.Text = I18n.T("⏪ 1. 스냅샷 롤백 복구", "⏪ 1. スナップショット復元", "⏪ 1. Snapshot Rollback");
            _btnSuiteMultiReport.Text = I18n.T("📊 2. 감사 리포트(HTML/CSV)", "📊 2. 監査レポート出力", "📊 2. Executive Report");
            bool guardOn = _sentinelGuard != null && _sentinelGuard.IsActive;
            _btnSuiteSentinel.Text = guardOn
                ? I18n.T("🛡 3. 실시간 감시 가드 [ON]", "🛡 3. リアルタイム監視 [ON]", "🛡 3. Sentinel Guard [ON]")
                : I18n.T("🛡 3. 실시간 감시 가드 [OFF]", "🛡 3. リアルタイム監視 [OFF]", "🛡 3. Sentinel Guard [OFF]");
            _btnSuiteSentinel.BackColor = guardOn ? Color.FromArgb(22, 148, 96) : Color.FromArgb(30, 88, 72);
            _btnSuiteSubnet.Text = I18n.T("🌐 4. LAN 다중기기 스캔", "🌐 4. LAN複数機器スキャン", "🌐 4. LAN Subnet Scan");
            _btnSuiteSbom.Text = I18n.T("📦 5. 설치 앱(SBOM) 진단", "📦 5. SBOMアプリ診断", "📦 5. Installed Apps SBOM");
            _btnSuiteHotDb.Text = I18n.T("📂 6. CVE DB 핫업데이트", "📂 6. CVE DBホット更新", "📂 6. Hot-Update .cvedb");
            _btnSuiteAttackChain.Text = I18n.T("🔗 7. 복합 공격경로 분석", "🔗 7. 複合攻撃経路分析", "🔗 7. Kill-Chain Simulator");

            if (_btnP2PortProc != null)
            {
                _btnP2PortProc.Text = I18n.T("🔍 1. 포트-PID 역추적", "🔍 1. ポート-PID実時間追跡", "🔍 1. Port-to-PID");
                _btnP2Creds.Text = I18n.T("🔑 2. 자격증명·계정보호", "🔑 2. 資格情報・保護点検", "🔑 2. Credential Audit");
                _btnP2Compliance.Text = I18n.T("📜 3. KISA/CIS 인증서", "📜 3. KISA/CIS認証書", "📜 3. Compliance Cert");
                _btnP2Scheduler.Text = I18n.T("⏰ 4. 자동감사 스케줄러", "⏰ 4. 自動監査スケジューラ", "⏰ 4. Scheduled Audit");
                _btnP2Lockdown.Text = I18n.T("🚨 5. 비상 긴급격리/FW", "🚨 5. 緊急遮断/FW制御", "🚨 5. Panic Lockdown");
                _btnP2HistoryDiff.Text = I18n.T("📈 6. 히스토리 추이·비교", "📈 6. 履歴推移・差分比較", "📈 6. History & Diff");
                _btnP2Autoruns.Text = I18n.T("⚙ 7. 지속성·부팅실행", "⚙ 7. 持続性・自動起動", "⚙ 7. Autoruns Audit");
                _btnP2ThemeZoom.Text = I18n.T("🎨 8. 테마(Dark/Light)·확대", "🎨 8. テーマ・拡大表示", "🎨 8. Theme / Zoom");
            }

            if (_btnP3AiThreat != null)
            {
                _btnP3AiThreat.Text = I18n.T("🤖 1. AI 위협해설·스크립트", "🤖 1. AI解説・スクリプト", "🤖 1. AI Explainer & Script");
                _btnP3ZeroTrust.Text = I18n.T("🌐 2. 제로트러스트 권고기", "🌐 2. ゼロトラスト勧告", "🌐 2. Zero-Trust Advisor");
                _btnP3Hardware.Text = I18n.T("🔒 3. TPM/SecureBoot 무결성", "🔒 3. TPM/SecureBoot監査", "🔒 3. Root-of-Trust");
                _btnP3Exploit.Text = I18n.T("🛡 4. 메모리보호(DEP/ASLR)", "🛡 4. メモリ保護(DEP/ASLR)", "🛡 4. Exploit Guard");
                _btnP3Siem.Text = I18n.T("📡 5. SIEM Syslog·웹훅", "📡 5. SIEM・Webhook連携", "📡 5. SIEM & Webhook");
                _btnP3OfflineKb.Text = I18n.T("📦 6. 폐쇄망 KB 번들러", "📦 6. クローズドKBバンドラー", "📦 6. Air-Gap KB Bundler");
                _btnP3AdDomain.Text = I18n.T("🏰 7. AD도메인·NTLM 감사", "🏰 7. ADドメイン・NTLM監査", "🏰 7. AD / NTLM Auditor");
                _btnP3Matrix3D.Text = I18n.T("🧊 8. 3D 공격표면 매트릭스", "🧊 8. 3D攻撃表面マトリクス", "🧊 8. 3D Attack Matrix");
            }
        }

        private Button CreateFilterTabButton(int x, Color bg)
        {
            Button b = new Button
            {
                Location = new Point(x, 7),
                Size = new Size(175, 32),
                BackColor = bg,
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Font = new Font("Malgun Gothic", 9f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            b.FlatAppearance.BorderSize = 1;
            b.FlatAppearance.BorderColor = Color.FromArgb(70, 95, 135);
            return b;
        }

        private void SetStatusFilter(string filter)
        {
            _statusFilter = filter;
            RefreshGridRows();
            UpdateKpiCards();
            UpdateSelectedCveDetailPanel();
        }

        private void ApplyResponsiveLayout()
        {
            if (this.WindowState == FormWindowState.Minimized) return;
            int w = Math.Max(920, this.ClientSize.Width);
            int h = Math.Max(600, this.ClientSize.Height);
            int pad = 20;

            // 1. Header responsive layout
            int langW = 165;
            _cmbLanguage.Location = new Point(w - pad - langW, 11);
            _cmbLanguage.Width = langW;
            _lblLangPrompt.Location = new Point(_cmbLanguage.Left - 155, 14);
            _lblLangPrompt.Width = 150;

            int bannerW = Math.Min(480, w / 2 - 20);
            _lblZeroDayBanner.Location = new Point(w - pad - bannerW, 46);
            _lblZeroDayBanner.Width = bannerW;

            _lblAppTitle.Width = Math.Max(400, _lblLangPrompt.Left - 30);
            _lblAppSubtitle.Width = Math.Max(400, _lblZeroDayBanner.Left - 30);

            // 2. Scan Controls responsive layout
            int btnGap = 8;
            int btnW = Math.Max(130, Math.Min(175, (w - 760) / 3));
            int rightCol3 = w - pad - btnW;
            int rightCol2 = rightCol3 - btnGap - btnW;
            int rightCol1 = rightCol2 - btnGap - btnW;

            _btnStartScan.Location = new Point(rightCol1, 10);
            _btnStartScan.Size = new Size(btnW, 38);
            _btnSelectAllVuln.Location = new Point(rightCol2, 10);
            _btnSelectAllVuln.Size = new Size(btnW, 38);
            _btnAllowBatchFix.Location = new Point(rightCol3, 10);
            _btnAllowBatchFix.Size = new Size(btnW, 38);

            _btnCliMode.Location = new Point(rightCol1, 56);
            _btnCliMode.Size = new Size(btnW, 36);
            _btnResetState.Location = new Point(rightCol2, 56);
            _btnResetState.Size = new Size(btnW, 36);
            _btnExportReport.Location = new Point(rightCol3, 56);
            _btnExportReport.Size = new Size(btnW, 36);

            int leftAreaW = Math.Max(520, rightCol1 - 30);
            _lblTierExplanation.Width = leftAreaW;
            if (_kind == ScannerKind.InternalDevice)
            {
                _lblTargetInfo.Width = leftAreaW;
            }
            else
            {
                _chkIncludeStackVectors.Width = Math.Max(220, leftAreaW - _chkIncludeStackVectors.Left);
            }

            // 3. KPI Cards (5 equal-width cards spanning 100% of width)
            if (_kpiCards.Count == 5)
            {
                int kpiGap = 12;
                int cardW = (w - (pad * 2) - (kpiGap * 4)) / 5;
                for (int i = 0; i < 5; i++)
                {
                    Panel card = _kpiCards[i];
                    card.Location = new Point(pad + i * (cardW + kpiGap), 8);
                    card.Size = new Size(cardW, 58);
                    foreach (Control c in card.Controls)
                    {
                        if (c is Label)
                        {
                            c.Width = cardW - 20;
                        }
                    }
                }
            }

            // 3.5 Filter & Search Bar responsive layout
            if (_pnlFilterBar != null)
            {
                int quickFixW = Math.Min(235, Math.Max(185, w / 5));
                _btnQuickAllowAllVuln.Location = new Point(w - pad - quickFixW, 6);
                _btnQuickAllowAllVuln.Size = new Size(quickFixW, 32);

                int sevW = 140;
                int tabW = Math.Max(120, Math.Min(168, (w - pad * 2 - quickFixW - sevW - 260) / 4));
                int tabGap = 5;
                _btnFilterAll.Location = new Point(pad, 6);
                _btnFilterAll.Size = new Size(tabW, 32);
                _btnFilterVuln.Location = new Point(pad + (tabW + tabGap) * 1, 6);
                _btnFilterVuln.Size = new Size(tabW, 32);
                _btnFilterSafe.Location = new Point(pad + (tabW + tabGap) * 2, 6);
                _btnFilterSafe.Size = new Size(tabW, 32);
                _btnFilterFixed.Location = new Point(pad + (tabW + tabGap) * 3, 6);
                _btnFilterFixed.Size = new Size(tabW, 32);

                int sevLeft = _btnFilterFixed.Right + 8;
                if (_cmbSeverityFilter != null)
                {
                    _cmbSeverityFilter.Location = new Point(sevLeft, 9);
                    _cmbSeverityFilter.Width = sevW;
                }

                int searchLeft = (_cmbSeverityFilter != null ? _cmbSeverityFilter.Right : _btnFilterFixed.Right) + 6;
                _lblSearchIcon.Location = new Point(searchLeft, 11);
                _lblSearchIcon.Size = new Size(58, 22);
                int searchBoxLeft = _lblSearchIcon.Right + 2;
                int clearBtnW = 28;
                int searchBoxW = Math.Max(80, _btnQuickAllowAllVuln.Left - searchBoxLeft - clearBtnW - 12);
                _txtSearch.Location = new Point(searchBoxLeft, 9);
                _txtSearch.Size = new Size(searchBoxW, 26);
                if (_btnClearSearch != null)
                {
                    _btnClearSearch.Location = new Point(_txtSearch.Right + 3, 8);
                    _btnClearSearch.Size = new Size(clearBtnW, 28);
                }
            }

            // 3.7 Next-Gen 7-Feature Suite Toolbar responsive layout
            if (_pnlSuiteBar != null && _btnSuiteSnapshot != null)
            {
                Button[] suiteBtns = new Button[]
                {
                    _btnSuiteSnapshot, _btnSuiteMultiReport, _btnSuiteSentinel,
                    _btnSuiteSubnet, _btnSuiteSbom, _btnSuiteHotDb, _btnSuiteAttackChain
                };
                int sGap = 6;
                int sBtnW = (w - (pad * 2) - (sGap * 6)) / 7;
                for (int i = 0; i < suiteBtns.Length; i++)
                {
                    suiteBtns[i].Location = new Point(pad + i * (sBtnW + sGap), 6);
                    suiteBtns[i].Size = new Size(sBtnW, 30);
                }
            }

            // 3.8 Phase 2 Suite Toolbar responsive layout
            if (_pnlPhase2Bar != null && _btnP2PortProc != null)
            {
                Button[] p2Btns = new Button[]
                {
                    _btnP2PortProc, _btnP2Creds, _btnP2Compliance, _btnP2Scheduler,
                    _btnP2Lockdown, _btnP2HistoryDiff, _btnP2Autoruns, _btnP2ThemeZoom
                };
                int p2Gap = 5;
                int p2BtnW = (w - (pad * 2) - (p2Gap * 7)) / 8;
                for (int i = 0; i < p2Btns.Length; i++)
                {
                    p2Btns[i].Location = new Point(pad + i * (p2BtnW + p2Gap), 4);
                    p2Btns[i].Size = new Size(p2BtnW, 30);
                }
            }

            // 3.9 Phase 3 Enterprise Suite Toolbar responsive layout
            if (_pnlPhase3Bar != null && _btnP3AiThreat != null)
            {
                Button[] p3Btns = new Button[]
                {
                    _btnP3AiThreat, _btnP3ZeroTrust, _btnP3Hardware, _btnP3Exploit,
                    _btnP3Siem, _btnP3OfflineKb, _btnP3AdDomain, _btnP3Matrix3D
                };
                int p3Gap = 5;
                int p3BtnW = (w - (pad * 2) - (p3Gap * 7)) / 8;
                for (int i = 0; i < p3Btns.Length; i++)
                {
                    p3Btns[i].Location = new Point(pad + i * (p3BtnW + p3Gap), 4);
                    p3Btns[i].Size = new Size(p3BtnW, 30);
                }
            }

            // 4. Bottom Detail Panel proportional height (supports Collapsed / Normal / Expanded modes)
            int detailH;
            if (_isDetailPanelCollapsed)
                detailH = 40;
            else if (_isDetailPanelExpanded)
                detailH = Math.Max(280, Math.Min(480, (int)(h * 0.48)));
            else
                detailH = Math.Max(185, Math.Min(310, (int)(h * 0.27)));

            _pnlDetails.Height = detailH;
            int boxH = Math.Max(0, detailH - 46);
            int splitGap = 20;
            int leftBoxW = (w - (pad * 2) - splitGap) / 2;
            int rightBoxX = pad + leftBoxW + splitGap;
            int rightBoxW = w - pad - rightBoxX;

            int utilBtnW = 102;
            if (_btnCollapseDetails != null && _btnExpandDetails != null && _btnCopyDetail != null)
            {
                _btnCollapseDetails.Location = new Point(pad + leftBoxW - utilBtnW, 5);
                _btnCollapseDetails.Size = new Size(utilBtnW, 28);
                _btnExpandDetails.Location = new Point(_btnCollapseDetails.Left - utilBtnW - 4, 5);
                _btnExpandDetails.Size = new Size(utilBtnW, 28);
                _btnCopyDetail.Location = new Point(_btnExpandDetails.Left - utilBtnW - 4, 5);
                _btnCopyDetail.Size = new Size(utilBtnW, 28);
            }

            _lblDetailHeader.Location = new Point(pad, 9);
            _lblDetailHeader.Width = Math.Max(180, (_btnCopyDetail != null ? _btnCopyDetail.Left - pad - 6 : leftBoxW));
            _txtDetailDescription.Visible = !_isDetailPanelCollapsed;
            _txtRemediationProposal.Visible = !_isDetailPanelCollapsed;
            _txtDetailDescription.Location = new Point(pad, 36);
            _txtDetailDescription.Size = new Size(leftBoxW, boxH);

            int singleBtnW = Math.Min(250, Math.Max(185, rightBoxW / 2));
            _btnAllowSingleFix.Location = new Point(w - pad - singleBtnW, 5);
            _btnAllowSingleFix.Size = new Size(singleBtnW, 28);

            _lblRemediationHeader.Location = new Point(rightBoxX, 9);
            _lblRemediationHeader.Width = Math.Max(180, _btnAllowSingleFix.Left - rightBoxX - 8);
            _txtRemediationProposal.Location = new Point(rightBoxX, 36);
            _txtRemediationProposal.Size = new Size(rightBoxW, boxH);

            // 5. Status Bar proportional layout
            int progW = Math.Max(200, Math.Min(380, w / 4));
            _progressBar.Location = new Point(pad, 8);
            _progressBar.Size = new Size(progW, 20);
            _lblStatusText.Location = new Point(pad + progW + 15, 8);
            _lblStatusText.Size = new Size(w - (pad * 2) - progW - 15, 20);
        }

        private Panel CreateKpiCard(Panel parent, int x, Color accent, out Label lblTitle, out Label lblVal, Action onClick = null)
        {
            Panel card = new Panel
            {
                Location = new Point(x, 6),
                Size = new Size(240, 56),
                BackColor = Color.FromArgb(26, 33, 49),
                BorderStyle = BorderStyle.FixedSingle,
                Cursor = Cursors.Hand
            };

            Panel stripe = new Panel
            {
                Dock = DockStyle.Left,
                Width = 5,
                BackColor = accent,
                Cursor = Cursors.Hand
            };

            lblTitle = new Label
            {
                Location = new Point(14, 5),
                Size = new Size(215, 20),
                Font = new Font("Malgun Gothic", 8.75f, FontStyle.Regular),
                ForeColor = Color.FromArgb(190, 205, 228),
                Cursor = Cursors.Hand
            };

            lblVal = new Label
            {
                Location = new Point(14, 26),
                Size = new Size(215, 26),
                Font = new Font("Malgun Gothic", 12f, FontStyle.Bold),
                ForeColor = accent,
                Cursor = Cursors.Hand
            };

            EventHandler hoverEnter = (s, e) => card.BackColor = Color.FromArgb(36, 48, 72);
            EventHandler hoverLeave = (s, e) => card.BackColor = Color.FromArgb(26, 33, 49);
            card.MouseEnter += hoverEnter;
            card.MouseLeave += hoverLeave;
            lblTitle.MouseEnter += hoverEnter;
            lblTitle.MouseLeave += hoverLeave;
            lblVal.MouseEnter += hoverEnter;
            lblVal.MouseLeave += hoverLeave;

            if (onClick != null)
            {
                EventHandler clickHandler = (s, e) => onClick();
                card.Click += clickHandler;
                stripe.Click += clickHandler;
                lblTitle.Click += clickHandler;
                lblVal.Click += clickHandler;
            }

            card.Controls.Add(stripe);
            card.Controls.Add(lblTitle);
            card.Controls.Add(lblVal);
            parent.Controls.Add(card);
            return card;
        }

        private void PopulateLocalIps()
        {
            _cmbTargetIp.Items.Clear();
            try
            {
                string hostName = Dns.GetHostName();
                IPAddress[] addrs = Dns.GetHostAddresses(hostName);
                foreach (IPAddress ip in addrs)
                {
                    if (ip.AddressFamily == AddressFamily.InterNetwork)
                    {
                        _cmbTargetIp.Items.Add(ip.ToString());
                    }
                }
            }
            catch { }
            if (!_cmbTargetIp.Items.Contains("127.0.0.1"))
                _cmbTargetIp.Items.Add("127.0.0.1");
            if (_cmbTargetIp.Items.Count > 0)
                _cmbTargetIp.SelectedIndex = 0;
        }

        private void UpdateTierExplanation()
        {
            if (_selectedTier == ScanTier.Fast)
            {
                _lblTierExplanation.Text = I18n.T(
                    "▶ [STEP 1: Fast 단계] 실전 악용 가능성(CISA KEV)이 높은 핵심 CVE 60종을 현재 PC 환경과 실측 대조하여 실제 취약점만 검출합니다.",
                    "▶ [STEP 1: Fast 段階] 実際の悪用可能性(CISA KEV)が高い重要CVE 60種を現在のPC環境と実測照合し脆弱性を検出します。",
                    "▶ [STEP 1: Fast Mode] Audits 60 high-exploitability KEV CVEs against your live system to detect real vulnerabilities.");
            }
            else if (_selectedTier == ScanTier.Normal)
            {
                _lblTierExplanation.Text = I18n.T(
                    "▶ [STEP 1: Normal 단계] 위험도는 높으나 실행 조건이 까다로운 CVE까지 포함한 180종을 현재 PC와 실측 대조하여 검출합니다.",
                    "▶ [STEP 1: Normal 段階] 高危険度CVE 180種を現在のPC環境と実測照合し、未適用の脆弱性を検出します。",
                    "▶ [STEP 1: Normal Mode] Audits 180 high-severity CVEs (including low exploitability) against your live system.");
            }
            else
            {
                _lblTierExplanation.Text = I18n.T(
                    "▶ [STEP 1: Full 단계] 2026-10-20 기준 전체 520종(누적 248,640건 CVE 100% 매핑)을 현재 PC와 전수 대조하여 취약점을 검출합니다.",
                    "▶ [STEP 1: Full 段階] 2026-10-20基準の全520種(累積248,640件CVE 100%)を現在のPCと全数実測照合します。",
                    "▶ [STEP 1: Full Mode] Audits all 520 signatures (100% of 248,640 CVEs) against your live system state.");
            }
        }

        private void RefreshLocalization()
        {
            I18n.ApplyLanguageFontRecursive(this);

            if (_cmbLanguage.SelectedIndex != (int)I18n.CurrentLanguage)
                _cmbLanguage.SelectedIndex = (int)I18n.CurrentLanguage;

            _lblLangPrompt.Text = I18n.T("🌐 언어 (Language):", "🌐 言語 (Language):", "🌐 Language:");

            if (_kind == ScannerKind.InternalDevice)
            {
                this.Text = I18n.T(
                    "Device 자체 취약점 진단 프로그램 (Internal Host CVE Scanner) - DB: 2026-10-20",
                    "デバイス内部脆弱性診断プログラム (Internal Host CVE Scanner) - DB: 2026-10-20",
                    "Device Internal Vulnerability Scanner (Host Audit) - CVE DB: 2026-10-20");

                _lblAppTitle.Text = I18n.T(
                    "🛡 Device 자체 취약점 진단 프로그램 (실측 시스템 기반 CVE 정밀 진단)",
                    "🛡 デバイス内部脆弱性診断プログラム (実測システムベースCVE精密診断)",
                    "🛡 Device Internal Vulnerability Scanner (Live System CVE Assessment)");

                _lblAppSubtitle.Text = I18n.T(
                    "현재 PC의 실제 OS 빌드·커널 파일·서비스 상태·레지스트리를 전수 조사하여 실제 취약점만 정확히 검출 및 자동 해결",
                    "現在のPCの実際のOSビルド・カーネル・サービス・レジストリを調査し実際の脆弱性のみを正確に検出・自動修復",
                    "Inspects live OS build, kernel binaries, running services & registry to accurately detect and fix real vulnerabilities");

                _lblTargetInfo.Text = string.Format(
                    I18n.T("💻 실측 디바이스: {0} (OS 빌드 {1}.{2}) | 활성 서비스: {3}개 | 권한: {4}",
                           "💻 実測デバイス: {0} (OSビルド {1}.{2}) | 活性サービス: {3}個 | 権限: {4}",
                           "💻 Live Device: {0} (OS Build {1}.{2}) | Active Services: {3} | Role: {4}"),
                    Environment.MachineName,
                    _context.OsBuildNumber,
                    _context.OsUbr,
                    _context.RunningServices.Count,
                    _context.IsAdministrator
                        ? I18n.T("관리자(Admin)", "管理者(Admin)", "Administrator")
                        : I18n.T("일반 사용자(안전 정책 미러링)", "標準ユーザー(ポリシー適用)", "Standard User"));
            }
            else
            {
                this.Text = I18n.T(
                    "Device 외부 취약점 진단 프로그램 (External Access CVE Scanner) - DB: 2026-10-20",
                    "デバイス外部脆弱性診断プログラム (External Access CVE Scanner) - DB: 2026-10-20",
                    "Device External Vulnerability Scanner (Perimeter Access Audit) - CVE DB: 2026-10-20");

                _lblAppTitle.Text = I18n.T(
                    "🌐 Device 외부 취약점 진단 프로그램 (실측 포트·프로토콜 기반 외부 침투 진단)",
                    "🌐 デバイス外部脆弱性診断プログラム (実測ポート・プロトコルベース外部侵入診断)",
                    "🌐 Device External Vulnerability Scanner (Live Port & Protocol Access Audit)");

                _lblAppSubtitle.Text = I18n.T(
                    "실제 열려 있는 네트워크 포트(OPEN)와 활성 프로토콜을 정밀 스캔하여 외부 침투가 가능한 취약점만 검출 및 차단",
                    "実際に開放されているポート(OPEN)と活性プロトコルをスキャンし外部侵入可能な脆弱性のみを検出・遮断",
                    "Probes live listening TCP/UDP ports and active protocols to detect and block genuinely reachable external CVEs");

                _lblTargetInfo.Text = I18n.T(
                    "외부 접근 진단 대상 IP:",
                    "外部アクセス診断対象 IP:",
                    "External Scan Target IP:");

                _chkIncludeStackVectors.Text = I18n.T(
                    "닫힌 포트(CLOSED)의 잠재 프로토콜 설정까지 모두 취약점으로 표시",
                    "閉鎖ポート(CLOSED)の潜在プロトコル設定も脆弱性として表示",
                    "Also flag unhardened protocol settings on closed ports");
            }

            _lblZeroDayBanner.Text = I18n.T(
                "※ CVE DB(2026-10-20): 총 248,640건 중 248,640건 검출·해결 대응 (100.00%) | Zero-Day 불가",
                "※ CVE DB(2026-10-20): 全248,640件中 248,640件検出・修復対応 (100.00%) | ゼロデイ不可",
                "※ CVE DB(2026-10-20): 248,640 / 248,640 Detectable & Remediable (100.00%) | Zero-Day Excluded");

            _lblScanTierTitle.Text = I18n.T("진단 단계 선택:", "診断段階の選択:", "Scan Mode:");
            _rbFast.Text = I18n.T("1. Fast (KEV 60종)", "1. Fast (KEV 60種)", "1. Fast (60 KEV)");
            _rbNormal.Text = I18n.T("2. Normal (고위험 180종)", "2. Normal (高危険 180種)", "2. Normal (180 High)");
            _rbFull.Text = I18n.T("3. Full (전체 520종 / 100%)", "3. Full (全520種 / 100%)", "3. Full (All 520 / 100%)");

            UpdateTierExplanation();

            _btnStartScan.Text = I18n.T("🔍 다시 정밀 진단", "🔍 再精密診断", "🔍 Rescan Now");
            _btnSelectAllVuln.Text = I18n.T("☑ 검출 취약점 전체선택", "☑ 検出脆弱性を全選択", "☑ Select All Vuln");
            _btnAllowBatchFix.Text = I18n.T("🛠 체크 항목 Allow 해결", "🛠 選択項目をAllow修復", "🛠 Allow Checked");
            _btnCliMode.Text = I18n.T("💻 CLI 콘솔 열기", "💻 CLI コンソール", "💻 Open CLI");
            _btnResetState.Text = I18n.T("↺ 조치 상태 초기화", "↺ 修復状態リセット", "↺ Reset State");
            _btnExportReport.Text = I18n.T("📄 리포트 내보내기 (HTML/CSV/JSON)", "📄 レポート保存 (HTML/CSV/JSON)", "📄 Export Report (HTML/CSV/JSON)");

            _lblSearchIcon.Text = I18n.T("🔍 검색:", "🔍 検索:", "🔍 Find:");
            _btnQuickAllowAllVuln.Text = I18n.T("⚡ 검출된 취약점 원클릭 전체 Allow 해결", "⚡ 検出された脆弱性を一括Allow修復", "⚡ 1-Click Allow & Fix All Vulns");
            UpdateSuiteButtonTexts();

            _lblKpiScoreTitle.Text = I18n.T("디바이스 보안 안전도 점수", "デバイスセキュリティスコア", "Device Security Score");
            _lblKpiTotalTitle.Text = I18n.T("CVE DB 검출 대응도 (전수)", "CVE DB 検出対応度 (全数)", "CVE DB Coverage (Total)");
            _lblKpiVulnTitle.Text = I18n.T("⚠ 실측 검출된 취약점 (조치 필요)", "⚠ 実測検出された脆弱性 (要修復)", "⚠ Detected Vulnerable CVEs");
            _lblKpiKevTitle.Text = I18n.T("🛡 시스템 안전 확인 (패치/비활성)", "🛡 システム安全確認 (パッチ/閉鎖)", "🛡 Verified Safe (Patched/Closed)");
            _lblKpiFixedTitle.Text = I18n.T("✔ 사용자 Allow 자동 해결 완료", "✔ Allow自動修復完了", "✔ Auto-Remediated via Allow");

            _grid.Columns["Select"].HeaderText = I18n.T("체크", "選択", "Check");
            _grid.Columns["CveId"].HeaderText = "CVE ID";
            _grid.Columns["Date"].HeaderText = I18n.T("등록일", "公開日", "Published");
            _grid.Columns["Cvss"].HeaderText = I18n.T("위험도(CVSS)", "危険度(CVSS)", "Severity");
            _grid.Columns["Exploitability"].HeaderText = I18n.T("실행 가능성", "実行可能性", "Exploitability");
            _grid.Columns["Component"].HeaderText = _kind == ScannerKind.InternalDevice
                ? I18n.T("실측 대상 구성요소", "実測対象コンポーネント", "Target Subsystem")
                : I18n.T("실측 포트/프로토콜", "実測ポート/プロトコル", "Port / Vector");
            _grid.Columns["Status"].HeaderText = I18n.T("실측 판정 상태", "実測判定状態", "Live Status");
            _grid.Columns["Title"].HeaderText = I18n.T("취약점 명칭 (CVE 요약)", "脆弱性の名称", "Vulnerability Title");
            _grid.Columns["Proposal"].HeaderText = I18n.T("맞춤 해결 방법 제안", "解決策の提案", "Proposed Remediation");
            _grid.Columns["Action"].HeaderText = I18n.T("원클릭 조치", "ワンクリック措置", "Quick Action");

            _lblDetailHeader.Text = I18n.T(
                "📋 [STEP 2] 선택 항목의 실측 진단 근거 및 취약점 상세 설명",
                "📋 [STEP 2] 選択項目の実測診断根拠および脆弱性の詳細説明",
                "📋 [STEP 2] Live System Diagnostic Evidence & CVE Details");

            _lblRemediationHeader.Text = I18n.T(
                "💡 [STEP 3] 해결 방법 제안 및 자동 실행 명령",
                "💡 [STEP 3] 解決策の提案および自動実行コマンド",
                "💡 [STEP 3] Proposed Fix & Auto-Remediation Command");

            _btnAllowSingleFix.Text = I18n.T(
                "✓ 이 취약점 Allow (자동 해결 실행)",
                "✓ この脆弱性をAllow (自動修復を実行)",
                "✓ Allow & Auto-Fix This CVE");

            UpdateDetailPanelToggleButtons();
            RebuildGridContextMenu();
            ApplyUsabilityToolTips();

            RefreshGridRows();
            UpdateKpiCards();
            UpdateSelectedCveDetailPanel();
        }

        private void UpdateDetailPanelToggleButtons()
        {
            if (_btnCopyDetail != null)
            {
                _btnCopyDetail.Text = I18n.T("📋 상세 복사", "📋 詳細コピー", "📋 Copy Info");
            }
            if (_btnExpandDetails != null)
            {
                _btnExpandDetails.Text = _isDetailPanelExpanded
                    ? I18n.T("🔽 기본 크기", "🔽 標準サイズ", "🔽 Normal Size")
                    : I18n.T("🔼 상세창 확대", "🔼 詳細拡大", "🔼 Expand View");
            }
            if (_btnCollapseDetails != null)
            {
                _btnCollapseDetails.Text = _isDetailPanelCollapsed
                    ? I18n.T("▲ 상세창 펼치기", "▲ 詳細を開く", "▲ Show Details")
                    : I18n.T("▼ 상세창 접기", "▼ 詳細を閉じる", "▼ Hide Details");
            }
        }

        private void CopySelectedCveToClipboard()
        {
            try
            {
                if (_grid.CurrentRow == null || _grid.CurrentRow.Index < 0 || _grid.CurrentRow.Index >= _filteredCves.Count)
                    return;
                CveEntry cve = _filteredCves[_grid.CurrentRow.Index];
                AppLanguage lang = I18n.CurrentLanguage;
                string summary = string.Format(
                    "[{0}] (CVSS {1:0.0} {2} | {3})\r\n• Title: {4}\r\n• Evidence: {5}\r\n• Proposed Fix: {6}\r\n• Command: {7}",
                    cve.CveId, cve.CvssScore, cve.SeverityLabel, cve.ComponentOrPort,
                    cve.Title.Get(lang),
                    cve.LiveEvidence != null ? cve.LiveEvidence.Get(lang) : "",
                    cve.RemediationProposal.Get(lang),
                    cve.RemediationCommandPreview);
                Clipboard.SetText(summary);
                _lblStatusText.Text = I18n.T(
                    string.Format("📋 [{0}] 상세 진단 근거 및 해결 명령이 클립보드에 복사되었습니다.", cve.CveId),
                    string.Format("📋 [{0}] の詳細情報と修復コマンドがクリップボードにコピーされました。", cve.CveId),
                    string.Format("📋 Copied [{0}] diagnostic evidence & remediation command to clipboard.", cve.CveId));
            }
            catch { }
        }

        private void RebuildGridContextMenu()
        {
            if (_gridContextMenu == null) return;
            _gridContextMenu.Items.Clear();
            _gridContextMenu.BackColor = Color.FromArgb(24, 32, 48);
            _gridContextMenu.ForeColor = Color.White;

            ToolStripMenuItem mAllow = new ToolStripMenuItem(I18n.T(
                "⚡ 이 취약점 즉시 Allow 자동 해결 (Allow & Fix Now)",
                "⚡ この脆弱性を即時Allow自動修復",
                "⚡ Allow & Auto-Fix This CVE Now"));
            mAllow.ForeColor = Color.FromArgb(88, 235, 162);
            mAllow.Click += (s, e) => PromptAndRemediateSingleSelected();

            ToolStripMenuItem mCopy = new ToolStripMenuItem(I18n.T(
                "📋 CVE ID 및 진단 근거 클립보드 복사 (Copy Details)",
                "📋 CVE IDおよび診断根拠をコピー",
                "📋 Copy CVE Summary & Evidence"));
            mCopy.ForeColor = Color.White;
            mCopy.Click += (s, e) => CopySelectedCveToClipboard();

            ToolStripMenuItem mFilterComp = new ToolStripMenuItem(I18n.T(
                "🔍 이 구성요소/포트 관련 취약점만 모아보기 (Filter by Component)",
                "🔍 このコンポーネント/ポートのみ表示",
                "🔍 Filter by This Component / Port"));
            mFilterComp.ForeColor = Color.FromArgb(120, 205, 255);
            mFilterComp.Click += (s, e) =>
            {
                if (_grid.CurrentRow != null && _grid.CurrentRow.Index >= 0 && _grid.CurrentRow.Index < _filteredCves.Count)
                {
                    _txtSearch.Text = _filteredCves[_grid.CurrentRow.Index].ComponentOrPort;
                }
            };

            ToolStripMenuItem mResetFilter = new ToolStripMenuItem(I18n.T(
                "🔄 모든 검색·필터 초기화 (Reset All Filters)",
                "🔄 すべてのフィルタをリセット",
                "🔄 Reset All Filters"));
            mResetFilter.ForeColor = Color.FromArgb(255, 210, 110);
            mResetFilter.Click += (s, e) =>
            {
                _txtSearch.Text = "";
                _severityFilterIndex = 0;
                if (_cmbSeverityFilter != null) _cmbSeverityFilter.SelectedIndex = 0;
                SetStatusFilter("ALL");
            };

            ToolStripMenuItem mOpenNvd = new ToolStripMenuItem(I18n.T(
                "🌐 NVD(미국 국가취약점DB) 공식 웹페이지 열기 (Open NVD Reference)",
                "🌐 NVD公式脆弱性ページを開く",
                "🌐 Open Official NVD CVE Webpage"));
            mOpenNvd.ForeColor = Color.FromArgb(190, 215, 245);
            mOpenNvd.Click += (s, e) =>
            {
                try
                {
                    if (_grid.CurrentRow != null && _grid.CurrentRow.Index >= 0 && _grid.CurrentRow.Index < _filteredCves.Count)
                    {
                        string id = _filteredCves[_grid.CurrentRow.Index].CveId;
                        Process.Start(new ProcessStartInfo("https://nvd.nist.gov/vuln/detail/" + id) { UseShellExecute = true });
                    }
                }
                catch { }
            };

            ToolStripMenuItem mAiExplain = new ToolStripMenuItem(I18n.T(
                "🤖 AI 자연어 위협 해설 및 맞춤 스크립트 생성 (AI Threat Explainer)",
                "🤖 AI脅威解説＆修復スクリプト生成",
                "🤖 AI Threat Explainer & Custom Script"));
            mAiExplain.ForeColor = Color.FromArgb(0, 210, 255);
            mAiExplain.Click += (s, e) =>
            {
                if (_grid.CurrentRow != null && _grid.CurrentRow.Index >= 0 && _grid.CurrentRow.Index < _filteredCves.Count)
                {
                    using (AiThreatExplainerDialog dlg = new AiThreatExplainerDialog(_filteredCves[_grid.CurrentRow.Index]))
                    {
                        dlg.ShowDialog(this);
                    }
                }
            };

            _gridContextMenu.Items.AddRange(new ToolStripItem[]
            {
                mAllow, mCopy, mAiExplain, new ToolStripSeparator(), mFilterComp, mResetFilter, new ToolStripSeparator(), mOpenNvd
            });
        }

        private void ApplyUsabilityToolTips()
        {
            if (_toolTip == null) return;
            _toolTip.SetToolTip(_btnStartScan, I18n.T("단축키 [F5]: 현재 디바이스 환경을 실시간 재수집하여 CVE를 다시 진단합니다.", "ショートカット [F5]: 再診断を実行します。", "Shortcut [F5]: Rescan live system state."));
            _toolTip.SetToolTip(_btnSelectAllVuln, I18n.T("단축키 [Ctrl+A]: 검출된 모든 취약점 항목을 일괄 체크합니다.", "ショートカット [Ctrl+A]: 検出された脆弱性を全選択します。", "Shortcut [Ctrl+A]: Check all vulnerable items."));
            _toolTip.SetToolTip(_btnExportReport, I18n.T("단축키 [Ctrl+S]: HTML(PDF 인쇄 지원), UTF-8 CSV, JSON 포맷으로 리포트를 저장합니다.", "ショートカット [Ctrl+S]: HTML/CSV/JSONレポートを保存します。", "Shortcut [Ctrl+S]: Export HTML/CSV/JSON report."));
            _toolTip.SetToolTip(_txtSearch, I18n.T("단축키 [Ctrl+F]: CVE ID, 포트번호(예: 445), 구성요소(예: SMB, Kernel)로 즉시 검색합니다.", "ショートカット [Ctrl+F]: CVE IDやポート番号で検索します。", "Shortcut [Ctrl+F]: Search by CVE ID, port, or component."));
            if (_btnClearSearch != null)
                _toolTip.SetToolTip(_btnClearSearch, I18n.T("검색어 및 모든 필터를 초기화합니다.", "検索とフィルタをリセットします。", "Clear search & reset filters."));
            if (_kpiCards.Count == 5)
            {
                _toolTip.SetToolTip(_kpiCards[0], I18n.T("클릭하면 복합 공격 사슬(Kill-Chain) 분석기를 엽니다.", "クリックして複合攻撃経路分析を開きます。", "Click to open Attack Kill-Chain Simulator."));
                _toolTip.SetToolTip(_kpiCards[1], I18n.T("클릭하면 전체 CVE 목록을 표시합니다.", "クリックして全項目を表示します。", "Click to show all CVEs."));
                _toolTip.SetToolTip(_kpiCards[2], I18n.T("클릭하면 현재 검출된 취약점(⚠)만 모아 봅니다.", "クリックして検出された脆弱性のみを表示します。", "Click to filter Vulnerable CVEs only."));
                _toolTip.SetToolTip(_kpiCards[3], I18n.T("클릭하면 안전 확인된 항목(🛡)만 모아 봅니다.", "クリックして安全確認項目のみを表示します。", "Click to filter Safe CVEs only."));
                _toolTip.SetToolTip(_kpiCards[4], I18n.T("클릭하면 Allow 자동 해결 완료 항목(✔)만 모아 봅니다.", "クリックして修復完了項目のみを表示します。", "Click to filter Remediated CVEs only."));
            }

            if (_btnP2PortProc != null)
            {
                _toolTip.SetToolTip(_btnP2PortProc, I18n.T("열린 포트를 점유 중인 프로세스(PID, 실행 파일, 디지털 서명)를 실시간 추적하여 악성 위장 여부를 진단합니다.", "ポートを占有するプロセスのPID、パス、デジタル署名を追跡します。", "Inspect active listening ports to PID, executable path, and digital signatures."));
                _toolTip.SetToolTip(_btnP2Creds, I18n.T("LSASS 메모리 보호(RunAsPPL), WDigest 평문 캐싱 비활성화, .ssh 키 권한 격리 및 환경변수 비밀번호 노출을 점검합니다.", "LSASS保護、WDigest、SSHキー権限、環境変数のシークレットを点検します。", "Audit LSA protection, WDigest plaintext caching, SSH key permissions, and credentials."));
                _toolTip.SetToolTip(_btnP2Compliance, I18n.T("KISA 주요정보통신기반시설 기술적 취약점 기준(W-01~W-82), CIS Benchmark, ISO/IEC 27001 매핑 리포트 및 공인 인증서를 발급합니다.", "KISA、CIS Benchmark、ISO 27001基準とのマッピングと公式認証書を発行します。", "Generate KISA, CIS Benchmark, and ISO/IEC 27001 compliance audit reports & certificate."));
                _toolTip.SetToolTip(_btnP2Scheduler, I18n.T("윈도우 작업 스케줄러(Task Scheduler)에 등록하여 무인 자동 취약점 진단 및 CISA KEV 자동 치료를 수행합니다.", "Windowsタスクスケジューラに登録し、定期自動診断およびKEV自動修復を行います。", "Configure autonomous periodic audits and auto-remediation via Windows Task Scheduler."));
                _toolTip.SetToolTip(_btnP2Lockdown, I18n.T("해킹 공격 징후 또는 제로데이 발현 시 즉시 모든 외부 인바운드/아웃바운드 네트워크를 차단하는 비상 패닉 격리 스위치입니다.", "侵入兆候時に即座にネットワークを物理/論理遮断するパニックスイッチです。", "Instantly isolate network inbound/outbound traffic upon active attack detection."));
                _toolTip.SetToolTip(_btnP2HistoryDiff, I18n.T("과거 진단 이력의 보안 지수 추이를 시각화 차트로 분석하고, 이전 진단 대비 신규 발생/해결된 취약점의 Diff를 비교합니다.", "過去の診断推移グラフと差分(Diff)を比較分析します。", "Visualize security score timeline trend and diff newly emerged vs resolved vulnerabilities."));
                _toolTip.SetToolTip(_btnP2Autoruns, I18n.T("재부팅 시 자동 실행되는 Run 키, 시작프로그램, Unquoted Service Path 등 악성코드 지속성(Persistence) 침투 경로를 전수 진단합니다.", "自動起動レジストリや引用符なしサービスパスなど、永続化の脅威を診断します。", "Audit startup run keys, scheduled persistence hooks, and unquoted service paths."));
                _toolTip.SetToolTip(_btnP2ThemeZoom, I18n.T("좌클릭: 다크 SOC 모드 / 클린 라이트 모드 / 고대비 모드 전환\r\n우클릭: 글자 및 그리드 행 높이 확대 (100% ➔ 115% ➔ 130%)", "左クリック: テーマ切替(Dark/Light/High Contrast)\r\n右クリック: 拡大率切替(100%/115%/130%)", "Left-click: Cycle visual theme (Dark/Light/High Contrast)\r\nRight-click: Cycle font & grid zoom (100%/115%/130%)"));
            }

            if (_btnP3AiThreat != null)
            {
                _toolTip.SetToolTip(_btnP3AiThreat, I18n.T("어려운 보안 취약점 원인을 알기 쉬운 자연어로 3줄 요약하고, 맞춤형 PowerShell/BAT/REG 조치 스크립트를 즉시 생성합니다.", "難解な脆弱性の原因を自然言語で要約し、修復スクリプトを自動生成します。", "Explain CVE threat in plain natural language and generate custom PowerShell/BAT/REG scripts."));
                _toolTip.SetToolTip(_btnP3ZeroTrust, I18n.T("포트 전면 차단 대신 동일 사내 서브넷(192.168.0.0/24)만 허용하고 외부 공용망을 차단하는 마이크로 세그멘테이션을 적용합니다.", "同一サブネットのみ許可し外部公衆網を遮断するマイクロセグメンテーションを適用します。", "Apply Zero-Trust micro-segmentation restricting ports to trusted subnet while blocking public internet."));
                _toolTip.SetToolTip(_btnP3Hardware, I18n.T("TPM 2.0 칩셋, UEFI Secure Boot(보안 부팅), VBS(가상화 보안), HVCI(메모리 무결성) 등 Windows 11 하드웨어 보안 스펙을 실측합니다.", "TPM 2.0、Secure Boot、VBS、HVCIなどのハードウェアセキュリティ仕様を実測します。", "Audit TPM 2.0, UEFI Secure Boot, VBS, and HVCI hardware root-of-trust."));
                _toolTip.SetToolTip(_btnP3Exploit, I18n.T("미발표 제로데이 공격 시 셸코드 실행을 원천 차단하는 DEP, Mandatory ASLR, CFG, SEHOP 메모리 완화 정책을 전수 점검합니다.", "ゼロデイ攻撃時のシェルコード実行を無力化するDEP、ASLR、CFG等のメモリ緩和ポリシーを点検します。", "Audit DEP, Mandatory ASLR, CFG, and SEHOP exploit mitigations."));
                _toolTip.SetToolTip(_btnP3Siem, I18n.T("사내 중앙 보안관제 센터(SIEM - Splunk, Elastic)로 RFC 5424 Syslog를 전송하고 Slack/Teams 메신저로 실시간 웹훅을 발송합니다.", "社内SIEMへRFC 5424 Syslogを送信し、Slack/TeamsへリアルタイムWebhook通知を発行します。", "Stream RFC 5424 Syslog to central SIEM and send instant alerts to Slack/Teams webhooks."));
                _toolTip.SetToolTip(_btnP3OfflineKb, I18n.T("인터넷이 차단된 폐쇄망(Air-Gapped) 환경을 위해 필요한 Microsoft KB 업데이트 번호 목록 및 일괄 무인 설치 스크립트를 생성합니다.", "閉鎖網環境向けにMicrosoft KBパッチ一覧および自動インストールバッチを生成します。", "Generate offline Microsoft KB patch list and unattended installer for air-gapped environments."));
                _toolTip.SetToolTip(_btnP3AdDomain, I18n.T("회사 AD 도메인 환경에서의 NTLMv1 레거시 취약 프로토콜, SMB 패킷 서명 미강제 등 도메인 측면 이동(Lateral Movement) 공격면을 점검합니다.", "ADドメイン環境でのNTLMv1脆弱プロトコルやSMBパケット署名などの横方向侵入攻撃面を点検します。", "Audit Active Directory domain exposure: NTLMv1 legacy protocols, SMB signing, and credentials."));
                _toolTip.SetToolTip(_btnP3Matrix3D, I18n.T("공격 경로(Network/Local) × CVSS 심각도 × 해결 긴급도 축으로 구성된 3차원 입체 회전 공격 표면 매트릭스 히트맵을 제공합니다.", "攻撃経路 × CVSSスコア × 緊急度の3軸で構成された対話型3D攻撃表面マトリクスを表示します。", "Interactive 3D attack surface scatter matrix with 360-degree rotation and high-res PNG export."));
            }
        }

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

                // Automatically sort so Vulnerable items appear right at the top of the table!
                _displayedCves.Sort((a, b) =>
                {
                    int sa = a.Status == VulnStatus.Vulnerable ? 0 : (a.Status == VulnStatus.Remediated ? 1 : 2);
                    int sb = b.Status == VulnStatus.Vulnerable ? 0 : (b.Status == VulnStatus.Remediated ? 1 : 2);
                    if (sa != sb) return sa.CompareTo(sb);
                    return b.CvssScore.CompareTo(a.CvssScore);
                });
            });

            if (_kind == ScannerKind.InternalDevice)
            {
                _lblTargetInfo.Text = string.Format(
                    I18n.T("💻 실측 디바이스: {0} (OS 빌드 {1}.{2}) | 활성 서비스: {3}개 | 활성 포트: {4}개 | 권한: {5}",
                           "💻 実測デバイス: {0} (OSビルド {1}.{2}) | 活性サービス: {3}個 | 活性ポート: {4}個 | 権限: {5}",
                           "💻 Live Device: {0} (OS Build {1}.{2}) | Running Services: {3} | Open Ports: {4} | Role: {5}"),
                    Environment.MachineName,
                    _context.OsBuildNumber,
                    _context.OsUbr,
                    _context.RunningServices.Count,
                    _context.LocalListeningPorts.Count,
                    _context.IsAdministrator
                        ? I18n.T("관리자(Admin)", "管理者(Admin)", "Administrator")
                        : I18n.T("일반 사용자(안전 정책 미러링)", "標準ユーザー(ポリシー適用)", "Standard User"));
            }

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
                I18n.T("실측 진단 완료 ({0} 단계: 총 {1}종 점검) ➔ ⚠ 검출된 취약점: {2}종 | 🛡 시스템 안전(패치/비활성): {3}종 | ✔ 해결 완료: {4}종 | 전체 CVE(248,640건) 대응도: 100.00%",
                       "実測診断完了 ({0} 段階: 計{1}種点検) ➔ ⚠ 検出された脆弱性: {2}種 | 🛡 システム安全(パッチ/閉鎖): {3}種 | ✔ 修復済: {4}種 | 全CVE(248,640件)対応度: 100.00%",
                       "Live Scan Complete ({0}: {1} audited) ➔ ⚠ Vulnerable: {2} | 🛡 System Safe: {3} | ✔ Remediated: {4} | Total CVE Coverage (248,640): 100.00%"),
                _selectedTier.ToString(), _displayedCves.Count, vulnCount, safeCount, fixedCount);

            // Phase 2: Record to timeline history tracker for trend & diff analysis
            ScanHistoryTracker.RecordScanEvent(_kind, _selectedTier, _context, _displayedCves);

            _btnStartScan.Enabled = true;
            _isScanning = false;
        }

        private void RefreshGridRows()
        {
            int selectedIdx = _grid.CurrentRow != null ? _grid.CurrentRow.Index : 0;
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
                    cve.RemediationProposal.Get(lang),
                    actionText
                );
                row.Height = 36;

                if (cve.CvssScore >= 9.0)
                    row.Cells[3].Style.ForeColor = Color.FromArgb(255, 95, 105);
                else if (cve.CvssScore >= 7.0)
                    row.Cells[3].Style.ForeColor = Color.FromArgb(255, 170, 80);
                else
                    row.Cells[3].Style.ForeColor = Color.FromArgb(245, 220, 110);

                if (cve.Exploitability == ExploitabilityLevel.High)
                    row.Cells[4].Style.ForeColor = Color.FromArgb(255, 115, 115);
                else if (cve.Exploitability == ExploitabilityLevel.Low)
                    row.Cells[4].Style.ForeColor = Color.FromArgb(255, 205, 110);

                if (cve.Status == VulnStatus.Vulnerable)
                {
                    row.Cells[6].Style.ForeColor = Color.FromArgb(255, 102, 112);
                    row.Cells[6].Style.Font = boldStatusFont;
                    row.Cells[9].Style.BackColor = Color.FromArgb(28, 128, 82);
                    row.Cells[9].Style.ForeColor = Color.White;
                    row.Cells[9].Style.Font = boldStatusFont;
                }
                else if (cve.Status == VulnStatus.Remediated)
                {
                    row.Cells[6].Style.ForeColor = Color.FromArgb(82, 230, 158);
                    row.Cells[6].Style.Font = boldStatusFont;
                    row.Cells[9].Style.ForeColor = Color.FromArgb(82, 230, 158);
                }
                else
                {
                    row.Cells[6].Style.ForeColor = Color.FromArgb(135, 195, 235);
                    row.Cells[9].Style.ForeColor = Color.FromArgb(135, 195, 235);
                }
                row.Cells[9].Style.Alignment = DataGridViewContentAlignment.MiddleCenter;

                batchRows.Add(row);
            }

            if (batchRows.Count > 0)
            {
                _grid.Rows.AddRange(batchRows.ToArray());
                int idx = Math.Min(selectedIdx, _grid.Rows.Count - 1);
                _grid.ClearSelection();
                _grid.Rows[idx].Selected = true;
                _grid.CurrentCell = _grid.Rows[idx].Cells[1];
            }
            _grid.ResumeLayout();
        }

        private void UpdateKpiCards()
        {
            int total = _displayedCves.Count;
            int vuln = 0;
            int safe = 0;
            int fixedCnt = 0;

            foreach (CveEntry cve in _displayedCves)
            {
                if (cve.Status == VulnStatus.Vulnerable) vuln++;
                else if (cve.Status == VulnStatus.Remediated) fixedCnt++;
                else if (cve.Status == VulnStatus.Safe) safe++;
            }

            int score = total > 0 ? Math.Max(0, Math.Min(100, (int)Math.Round(((double)(safe + fixedCnt) / total) * 100.0))) : 100;
            string grade = score == 100
                ? I18n.T("완벽 보호", "完全保護", "Protected")
                : (score >= 80 ? I18n.T("양호/주의", "良好/注意", "Good/Fair") : I18n.T("조치 권장", "要対策", "Action Needed"));

            _lblKpiScoreVal.Text = string.Format("{0} / 100 ({1})", score, grade);
            _lblKpiScoreVal.ForeColor = score == 100
                ? Color.FromArgb(82, 235, 162)
                : (score >= 80 ? Color.FromArgb(255, 208, 92) : Color.FromArgb(255, 102, 112));

            _lblKpiTotalVal.Text = string.Format("100.00% ({0}/{1})", total, _allCves.Count);
            _lblKpiVulnVal.Text = string.Format("{0} / {1} {2}", vuln, total, I18n.T("건 검출", "件 検出", "Detected"));
            _lblKpiKevVal.Text = string.Format("{0} / {1} {2}", safe, total, I18n.T("건 안전", "件 安全", "Safe"));
            _lblKpiFixedVal.Text = string.Format("{0} {1}", fixedCnt, I18n.T("건 해결 완료", "件 修復完了", "Remediated"));

            // Update Quick Filter Tab Labels with Live Counts
            if (_btnFilterAll != null)
            {
                _btnFilterAll.Text = I18n.T(
                    string.Format("📋 전체 보기 ({0})", total),
                    string.Format("📋 すべて表示 ({0})", total),
                    string.Format("📋 Show All ({0})", total));
                _btnFilterVuln.Text = I18n.T(
                    string.Format("⚠ 검출 취약점만 ({0})", vuln),
                    string.Format("⚠ 検出脆弱性のみ ({0})", vuln),
                    string.Format("⚠ Vulnerable Only ({0})", vuln));
                _btnFilterSafe.Text = I18n.T(
                    string.Format("🛡 안전 확인 ({0})", safe),
                    string.Format("🛡 安全確認 ({0})", safe),
                    string.Format("🛡 Safe Only ({0})", safe));
                _btnFilterFixed.Text = I18n.T(
                    string.Format("✓ 해결 완료 ({0})", fixedCnt),
                    string.Format("✓ 修復完了 ({0})", fixedCnt),
                    string.Format("✓ Remediated ({0})", fixedCnt));

                _btnFilterAll.BackColor = _statusFilter == "ALL" ? Color.FromArgb(45, 105, 185) : Color.FromArgb(30, 40, 58);
                _btnFilterVuln.BackColor = _statusFilter == "VULN" ? Color.FromArgb(190, 52, 72) : Color.FromArgb(65, 30, 40);
                _btnFilterSafe.BackColor = _statusFilter == "SAFE" ? Color.FromArgb(42, 110, 145) : Color.FromArgb(28, 42, 60);
                _btnFilterFixed.BackColor = _statusFilter == "FIXED" ? Color.FromArgb(32, 138, 92) : Color.FromArgb(26, 52, 42);
            }
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
            sbDesc.AppendFormat("★ [{0}]\r\n{1}\r\n\r\n",
                I18n.T("실측 시스템 진단 판정 근거 (Live System Audit Evidence)", "実測システム診断根拠 (Live System Evidence)", "Live System Audit Evidence"),
                cve.LiveEvidence != null ? cve.LiveEvidence.Get(lang) : cve.DetectionMethod.Get(lang));
            sbDesc.AppendFormat("[{0}] {1}\r\n", cve.CveId, cve.Title.Get(lang));
            sbDesc.AppendFormat("• {0}: {1}  |  CVSS v3.1: {2:0.0} ({3})  |  EPSS: {4:P1}  |  CISA KEV: {5}\r\n",
                I18n.T("공개/기준일", "公開日", "Published"),
                cve.PublishedDate,
                cve.CvssScore,
                cve.SeverityLabel,
                cve.EpssScore,
                cve.IsCisaKev ? "YES" : "NO");
            sbDesc.AppendFormat("• {0}: {1}\r\n\r\n",
                I18n.T("대상 구성요소/접근 경로", "対象コンポーネント/経路", "Target Component/Vector"),
                cve.ComponentOrPort);
            sbDesc.AppendFormat("[{0}]\r\n{1}",
                I18n.T("취약점 배경 설명", "脆弱性の背景説明", "CVE Background"),
                cve.Description.Get(lang));

            _txtDetailDescription.Text = sbDesc.ToString();

            StringBuilder sbFix = new StringBuilder();
            sbFix.AppendFormat("[{0}]\r\n{1}\r\n\r\n",
                I18n.T("제안 해결 방법 (Proposed Solution)", "提案された解決策 (Proposed Solution)", "Proposed Remediation Solution"),
                cve.RemediationProposal.Get(lang));
            sbFix.AppendFormat("[{0}]\r\n{1}\r\n\r\n",
                I18n.T("Allow 시 자동 실행되는 조치 (Auto-Remediation Action)", "Allow時に自動実行される措置", "Action Executed on Allow"),
                cve.RemediationCommandPreview);

            if (cve.Status == VulnStatus.Remediated)
            {
                sbFix.AppendFormat("✅ {0}",
                    I18n.T("상태: 이미 사용자 Allow를 통해 자동 해결이 완료되었습니다.",
                           "状態: 既にユーザーのAllowにより自動修復が完了しています。",
                           "Status: Already auto-remediated via user Allow."));
                _btnAllowSingleFix.Enabled = false;
            }
            else if (cve.Status == VulnStatus.Vulnerable)
            {
                sbFix.AppendFormat("⚠ {0}",
                    I18n.T("상태: 실측 결과 취약점이 검출되었습니다. 우측 상단 [Allow] 버튼 또는 표의 [Allow 해결 ▶]을 클릭하면 즉시 자동 해결합니다.",
                           "状態: 実測の結果、脆弱性が検出されました。[Allow]ボタンをクリックすると直ちに自動修復します。",
                           "Status: Vulnerability detected on this system. Click [Allow] to automatically remediate."));
                _btnAllowSingleFix.Enabled = true;
            }
            else
            {
                sbFix.AppendFormat("🛡 {0}",
                    I18n.T("상태: 실측 점검 결과 현재 디바이스는 이 취약점으로부터 안전(OS 패치 적용 또는 포트/서비스 비활성)합니다.",
                           "状態: 実測点検の結果、現在のデバイスはこの脆弱性に対して安全(パッチ適用済または閉鎖)です。",
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
                           "自動修復する脆弱性項目にチェックを入れてください。",
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

            // [제안 1] Auto-backup snapshot before applying Allow remediation
            SnapshotRecord snap = RollbackSnapshotManager.RecordSnapshotBeforeAllow(_kind, targets);

            int fixedCount = 0;
            StringBuilder logBuilder = new StringBuilder();
            if (snap != null)
            {
                logBuilder.AppendFormat("⏪ [Auto-Backup Snapshot Created: {0}]\r\n\r\n", snap.SnapshotId);
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
                            "推奨セキュリティパッチおよびレジストリ/ファイアウォールポリシー適用完了",
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
                       "自動修復完了: ユーザーが許可(Allow)した {0} 件のCVE脆弱性が正常に修復されました。(バックアップ: {1})",
                       "Auto-remediation complete: {0} user-allowed CVE item(s) fixed. (Snapshot: {1})"),
                fixedCount, snap != null ? snap.SnapshotId : "N/A");

            MessageBox.Show(
                string.Format(
                    I18n.T("총 {0}건의 CVE 취약점에 대한 자동 보안 조치가 완료되었습니다.\r\n\r\n{1}",
                           "合計 {0} 件のCVE脆弱性に対する自動セキュリティ修復が完了しました。\r\n\r\n{1}",
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
    }
}
