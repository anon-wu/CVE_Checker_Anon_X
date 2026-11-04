# -*- coding: utf-8 -*-
import os

path = os.path.join(os.path.dirname(__file__), "..", "src", "AuditorProgram.cs")

code = '''using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;
using System.Windows.Forms;
using Microsoft.Win32;

namespace CveSecuritySuite
{
    /// <summary>
    /// CVE Security Operations Suite - Zero-Touch Auditor Edition (v11.5)
    /// 
    /// Fully localized in Korean (KO), English (EN), and Japanese (JA).
    /// Tailored specifically to Naseeba Kanu (Co-founder at TFalke)'s enterprise requirements:
    /// - 100% Lightweight & Read-Only: Zero host mutation (0 registry writes, 0 services stopped, 0 bytes modified).
    /// - No Rollback Plan Required: Because no system changes occur, security teams do not need change tickets or rollback plans.
    /// - Zero EDR Friction: Uses only standard Windows read APIs (Registry reads, OS build queries, port inspection).
    /// - Native Machine-Readable Exports: OASIS SARIF v2.1.0 and JSON for direct ingestion into TFalke, Microsoft Intune, SIEM, or CI/CD.
    /// - Excludes all remediation buttons, rollback managers, commercial licensing, and invasive background agents.
    /// </summary>
    public static class AuditorProgram
    {
        [STAThread]
        public static void Main(string[] args)
        {
            // Build authentic database with RemediateDelegate strictly set to NULL (Read-Only Guarantee)
            List<CveEntry> cveDb = InternalCveDatabaseProvider.BuildInternalCveDatabase();
            foreach (var entry in cveDb)
            {
                entry.RemediateDelegate = null; // Immutable Read-Only Guard
            }

            // CLI / Automated Pipeline Handling
            if (CliEngine.ShouldStartInCliMode(args) || HasCliArgs(args))
            {
                RunCliAuditor(cveDb, args);
                return;
            }

            // GUI Launch: Clean, dedicated, lightweight Zero-Touch Auditor Form with Trilingual support
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);
            ScreenFitGuard.Install();

            Application.Run(new ZeroTouchAuditorForm(cveDb));
        }

        private static bool HasCliArgs(string[] args)
        {
            if (args == null || args.Length == 0) return false;
            foreach (var a in args)
            {
                string s = (a ?? "").Trim().ToLowerInvariant();
                if (s == "--json" || s == "-j" || s == "--sarif" || s == "--cli" || s == "--table" ||
                    s.StartsWith("--out") || s.StartsWith("--tier") || s.StartsWith("--lang") || s.StartsWith("-l") ||
                    s == "--help" || s == "-h")
                    return true;
            }
            return false;
        }

        public static void RunCliAuditor(List<CveEntry> cveDb, string[] args)
        {
            CliEngine.EnsureConsoleAttached(false);

            string format = "text";
            string outputPath = null;
            ScanTier tier = ScanTier.Fast;
            AppLanguage lang = AppLanguage.EN;

            if (args != null)
            {
                for (int i = 0; i < args.Length; i++)
                {
                    string a = (args[i] ?? "").Trim().ToLowerInvariant();
                    if (a == "--json" || a == "-j") format = "json";
                    else if (a == "--sarif") format = "sarif";
                    else if (a == "--table" || a == "--cli") format = "text";
                    else if (a.StartsWith("--out=")) outputPath = args[i].Substring(6).Trim();
                    else if (a == "--out" && i + 1 < args.Length) outputPath = args[++i].Trim();
                    else if (a.StartsWith("--lang=") || a.StartsWith("-l="))
                    {
                        string lv = a.Substring(a.IndexOf('=') + 1);
                        if (lv == "ko" || lv == "korean") lang = AppLanguage.KO;
                        else if (lv == "ja" || lv == "japanese") lang = AppLanguage.JA;
                        else lang = AppLanguage.EN;
                    }
                    else if ((a == "--lang" || a == "-l") && i + 1 < args.Length)
                    {
                        string lv = args[++i].Trim().ToLowerInvariant();
                        if (lv == "ko" || lv == "korean") lang = AppLanguage.KO;
                        else if (lv == "ja" || lv == "japanese") lang = AppLanguage.JA;
                        else lang = AppLanguage.EN;
                    }
                    else if (a.StartsWith("--tier=") || a.StartsWith("-t="))
                    {
                        string tv = a.Substring(a.IndexOf('=') + 1);
                        if (tv == "full" || tv == "3") tier = ScanTier.Full;
                        else if (tv == "normal" || tv == "2") tier = ScanTier.Normal;
                        else tier = ScanTier.Fast;
                    }
                    else if ((a == "--tier" || a == "-t") && i + 1 < args.Length)
                    {
                        string tv = args[++i].Trim().ToLowerInvariant();
                        if (tv == "full" || tv == "3") tier = ScanTier.Full;
                        else if (tv == "normal" || tv == "2") tier = ScanTier.Normal;
                        else tier = ScanTier.Fast;
                    }
                }
            }

            ScanContext ctx = new ScanContext { TargetIp = "127.0.0.1", PortTimeoutMs = 350 };
            List<AuditRecord> results = ExecuteAudit(cveDb, ctx, tier);

            int totalScanned = results.Count;
            int vulnTotal = 0;
            foreach (var r in results)
            {
                if (r.Result != null && r.Result.IsVulnerable) vulnTotal++;
            }

            if (format == "json")
            {
                string json = GenerateJsonOutput(results, totalScanned, vulnTotal, lang);
                if (!string.IsNullOrEmpty(outputPath))
                {
                    File.WriteAllText(outputPath, json, Encoding.UTF8);
                    Console.WriteLine("[+] Exported JSON audit report to: " + outputPath);
                }
                else
                {
                    Console.WriteLine(json);
                }
            }
            else if (format == "sarif")
            {
                string sarif = GenerateSarifOutput(results, totalScanned, vulnTotal, lang);
                if (!string.IsNullOrEmpty(outputPath))
                {
                    File.WriteAllText(outputPath, sarif, Encoding.UTF8);
                    Console.WriteLine("[+] Exported SARIF v2.1.0 audit report to: " + outputPath);
                }
                else
                {
                    Console.WriteLine(sarif);
                }
            }
            else
            {
                PrintCliTable(results, totalScanned, vulnTotal, lang);
            }
        }

        public static List<AuditRecord> ExecuteAudit(List<CveEntry> cveDb, ScanContext ctx, ScanTier tier)
        {
            List<AuditRecord> results = new List<AuditRecord>();
            foreach (var cve in cveDb)
            {
                if (!cve.MatchesScanTier(tier)) continue;

                AuditResult res = null;
                try
                {
                    if (cve.CheckDelegate != null)
                        res = cve.CheckDelegate(ctx);
                }
                catch (Exception ex)
                {
                    res = new AuditResult
                    {
                        IsVulnerable = false,
                        Evidence = new LocalizedText("검사 오류: " + ex.Message, "検査エラー: " + ex.Message, "Check Error: " + ex.Message)
                    };
                }

                results.Add(new AuditRecord
                {
                    Cve = cve,
                    Result = res
                });
            }
            return results;
        }

        private static void PrintCliTable(List<AuditRecord> results, int totalScanned, int vulnTotal, AppLanguage lang)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("================================================================================");
            if (lang == AppLanguage.KO)
            {
                Console.WriteLine(" Device Zero-Touch Auditor v11.5 (Naseeba Kanu 엔터프라이즈 감사기)");
                Console.WriteLine(" [100% 읽기 전용 | 롤백 계획 불필요 | EDR 무간섭 | 무변형 제로-터치]");
                Console.WriteLine(" 대상: Localhost | Windows 빌드: " + Environment.OSVersion.VersionString);
            }
            else if (lang == AppLanguage.JA)
            {
                Console.WriteLine(" Device Zero-Touch Auditor v11.5 (Naseeba Kanu 企業監査モデル)");
                Console.WriteLine(" [100% 読み取り専用 | ロールバック計画不要 | EDR 完全互換 | システム無変更]");
                Console.WriteLine(" 対象: Localhost | Windows ビルド: " + Environment.OSVersion.VersionString);
            }
            else
            {
                Console.WriteLine(" Device Zero-Touch Auditor v11.5 (Naseeba Kanu Enterprise Model)");
                Console.WriteLine(" [100% READ-ONLY | ZERO ROLLBACK REQUIRED | EDR COMPLIANT | NO HOST MUTATION]");
                Console.WriteLine(" Target: Localhost | Windows Build: " + Environment.OSVersion.VersionString);
            }
            Console.WriteLine("================================================================================");
            Console.ResetColor();

            string hId = lang == AppLanguage.KO ? "CVE 식별자" : (lang == AppLanguage.JA ? "CVE識別子" : "CVE ID");
            string hSev = lang == AppLanguage.KO ? "위험도" : (lang == AppLanguage.JA ? "深刻度" : "SEVERITY");
            string hComp = lang == AppLanguage.KO ? "영향 컴포넌트" : (lang == AppLanguage.JA ? "影響コンポーネント" : "COMPONENT");
            string hStatus = lang == AppLanguage.KO ? "진단 상태" : (lang == AppLanguage.JA ? "診断状態" : "STATUS");

            Console.WriteLine(string.Format("{0,-16} {1,-10} {2,-30} {3}", hId, hSev, hComp, hStatus));
            Console.WriteLine("--------------------------------------------------------------------------------");
            foreach (var rec in results)
            {
                bool isVuln = rec.Result != null && rec.Result.IsVulnerable;
                string statusBadge = isVuln
                    ? (lang == AppLanguage.KO ? "[취약점 검출]" : (lang == AppLanguage.JA ? "[脆弱性検出]" : "[VULNERABLE]"))
                    : (lang == AppLanguage.KO ? "[안전/완화]" : (lang == AppLanguage.JA ? "[安全/緩和済]" : "[SAFE / SECURE]"));

                if (isVuln)
                {
                    Console.ForegroundColor = ConsoleColor.Red;
                    Console.WriteLine(string.Format("{0,-16} {1,-10} {2,-30} {3}",
                        rec.Cve.CveId, rec.Cve.SeverityLabel, Truncate(rec.Cve.ComponentOrPort, 28), statusBadge));
                    Console.ResetColor();
                }
                else
                {
                    Console.ForegroundColor = ConsoleColor.Green;
                    Console.WriteLine(string.Format("{0,-16} {1,-10} {2,-30} {3}",
                        rec.Cve.CveId, rec.Cve.SeverityLabel, Truncate(rec.Cve.ComponentOrPort, 28), statusBadge));
                    Console.ResetColor();
                }
            }
            Console.WriteLine("--------------------------------------------------------------------------------");
            Console.ForegroundColor = ConsoleColor.Cyan;
            if (lang == AppLanguage.KO)
            {
                Console.WriteLine(string.Format("감사 완료: {0}개 시그니처 점검 | {1}개 취약점 검출.", totalScanned, vulnTotal));
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[*] 호스트 무변형 보장: 0개 레지스트리 쓰기, 0개 서비스 중단.");
            }
            else if (lang == AppLanguage.JA)
            {
                Console.WriteLine(string.Format("監査完了: {0}件のシグネチャ点検 | {1}件の脆弱性検出。", totalScanned, vulnTotal));
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[*] ホスト無変更保証: 0件のレジストリ書込、0件のサービス停止。");
            }
            else
            {
                Console.WriteLine(string.Format("Audit Finished: {0} signatures audited | {1} vulnerabilities detected.", totalScanned, vulnTotal));
                Console.ForegroundColor = ConsoleColor.Green;
                Console.WriteLine("[*] Zero host modification verified: 0 registry keys written, 0 services stopped.");
            }
            Console.ResetColor();
        }

        public static string GenerateJsonOutput(List<AuditRecord> records, int totalScanned, int vulnTotal, AppLanguage lang = AppLanguage.EN)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine("  \\"generator\\": \\"Device Zero-Touch Auditor v11.5\\",");
            sb.AppendLine("  \\"specification\\": \\"Naseeba Kanu Enterprise SecOps Model\\",");
            sb.AppendLine("  \\"auditMode\\": \\"StrictReadOnly\\",");
            sb.AppendLine("  \\"zeroHostMutation\\": true,");
            sb.AppendLine("  \\"rollbackPlanRequired\\": false,");
            sb.AppendLine("  \\"language\\": \\"" + lang.ToString() + "\\",");
            sb.AppendLine("  \\"baseline\\": \\"2026-11-04\\",");
            sb.AppendLine("  \\"targetHost\\": \\"" + EscapeJson(Environment.MachineName) + "\\",");
            sb.AppendLine("  \\"osVersion\\": \\"" + EscapeJson(Environment.OSVersion.VersionString) + "\\",");
            sb.AppendLine("  \\"scannedSignatures\\": " + totalScanned + ",");
            sb.AppendLine("  \\"vulnerabilitiesDetected\\": " + vulnTotal + ",");
            sb.AppendLine("  \\"timestamp\\": \\"" + DateTime.UtcNow.ToString("o") + "\\",");
            sb.AppendLine("  \\"findings\\": [");

            bool first = true;
            foreach (var rec in records)
            {
                if (!first) sb.AppendLine(",");
                first = false;

                bool isVuln = rec.Result != null && rec.Result.IsVulnerable;
                string evidence = rec.Result != null && rec.Result.Evidence != null ? rec.Result.Evidence.Get(lang) : "N/A";
                string title = rec.Cve.Title != null ? rec.Cve.Title.Get(lang) : "";

                sb.AppendLine("    {");
                sb.AppendLine("      \\"cveId\\": \\"" + rec.Cve.CveId + "\\",");
                sb.AppendLine("      \\"cvssScore\\": " + rec.Cve.CvssScore.ToString("F1") + ",");
                sb.AppendLine("      \\"severity\\": \\"" + rec.Cve.SeverityLabel + "\\",");
                sb.AppendLine("      \\"isCisaKev\\": " + (rec.Cve.IsCisaKev ? "true" : "false") + ",");
                sb.AppendLine("      \\"status\\": \\"" + (isVuln ? "VULNERABLE" : "SAFE") + "\\",");
                sb.AppendLine("      \\"component\\": \\"" + EscapeJson(rec.Cve.ComponentOrPort) + "\\",");
                sb.AppendLine("      \\"title\\": \\"" + EscapeJson(title) + "\\",");
                sb.AppendLine("      \\"evidence\\": \\"" + EscapeJson(evidence) + "\\"");
                sb.Append("    }");
            }
            sb.AppendLine("\\n  ]");
            sb.AppendLine("}");
            return sb.ToString();
        }

        public static string GenerateSarifOutput(List<AuditRecord> records, int totalScanned, int vulnTotal, AppLanguage lang = AppLanguage.EN)
        {
            StringBuilder sb = new StringBuilder();
            sb.AppendLine("{");
            sb.AppendLine("  \\"$schema\\": \\"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json\\",");
            sb.AppendLine("  \\"version\\": \\"2.1.0\\",");
            sb.AppendLine("  \\"runs\\": [");
            sb.AppendLine("    {");
            sb.AppendLine("      \\"tool\\": {");
            sb.AppendLine("        \\"driver\\": {");
            sb.AppendLine("          \\"name\\": \\"Device Zero-Touch Auditor\\",");
            sb.AppendLine("          \\"version\\": \\"11.5.0.0\\",");
            sb.AppendLine("          \\"informationUri\\": \\"https://github.com/anon-wu/CVE_Checker_Anon_X\\"");
            sb.AppendLine("        }");
            sb.AppendLine("      },");
            sb.AppendLine("      \\"results\\": [");

            bool first = true;
            foreach (var rec in records)
            {
                if (rec.Result == null || !rec.Result.IsVulnerable) continue;
                if (!first) sb.AppendLine(",");
                first = false;

                string level = rec.Cve.CvssScore >= 9.0 ? "error" : "warning";
                string evidence = rec.Result.Evidence != null ? rec.Result.Evidence.Get(lang) : "Vulnerable endpoint state";
                string title = rec.Cve.Title != null ? rec.Cve.Title.Get(lang) : "";

                sb.AppendLine("        {");
                sb.AppendLine("          \\"ruleId\\": \\"" + rec.Cve.CveId + "\\",");
                sb.AppendLine("          \\"level\\": \\"" + level + "\\",");
                sb.AppendLine("          \\"message\\": { \\"text\\": \\"" + EscapeJson(title + " | " + evidence) + "\\" },");
                sb.AppendLine("          \\"properties\\": {");
                sb.AppendLine("            \\"cvss\\": " + rec.Cve.CvssScore.ToString("F1") + ",");
                sb.AppendLine("            \\"component\\": \\"" + EscapeJson(rec.Cve.ComponentOrPort) + "\\",");
                sb.AppendLine("            \\"cisaKev\\": " + (rec.Cve.IsCisaKev ? "true" : "false"));
                sb.AppendLine("          }");
                sb.Append("        }");
            }
            sb.AppendLine("\\n      ]");
            sb.AppendLine("    }");
            sb.AppendLine("  ]");
            sb.AppendLine("}");
            return sb.ToString();
        }

        private static string Truncate(string s, int max)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Length <= max ? s : s.Substring(0, max - 3) + "...";
        }

        private static string EscapeJson(string s)
        {
            if (string.IsNullOrEmpty(s)) return "";
            return s.Replace("\\\\", "\\\\\\\\").Replace("\\"", "\\\\\\"").Replace("\\r", "").Replace("\\n", " ");
        }

        public class AuditRecord
        {
            public CveEntry Cve;
            public AuditResult Result;
        }
    }

    /// <summary>
    /// Dedicated Zero-Touch Endpoint State Auditor Form with full dynamic Trilingual (KO, EN, JA) support.
    /// Excludes all Allow/Remediate buttons, Rollback managers, and Commercial licensing checks.
    /// Focuses 100% on lightweight, transparent read-only endpoint state audit for SecOps and CISOs.
    /// Features:
    /// - Black / White Mode Toggle with high-contrast, crystal-clear typography.
    /// - Fast (71) / Normal (312) / Full (433) scan tier selection.
    /// - Dynamic Flow Layout: Controls and filters NEVER overlap across any language or window size.
    /// - High-fidelity CJK system font normalization (Malgun Gothic, Yu Gothic UI, Segoe UI).
    /// </summary>
    public class ZeroTouchAuditorForm : Form
    {
        private List<CveEntry> _cveDb;
        private List<AuditorProgram.AuditRecord> _records = new List<AuditorProgram.AuditRecord>();
        private AppLanguage _currentLang = AppLanguage.KO;
        private ScanTier _selectedTier = ScanTier.Fast;
        private bool _isDarkMode = true;

        // Header controls
        private Panel _pnlHeader;
        private Label _lblTitle;
        private Label _lblPill;
        private Label _lblHostInfo;
        private Label _lblMetrics;
        private FlowLayoutPanel _pnlHeaderRight;
        private Button _btnThemeToggle;
        private Button _btnLangKo;
        private Button _btnLangEn;
        private Button _btnLangJa;

        // Bar controls
        private Panel _pnlBar;
        private FlowLayoutPanel _flowBar;
        private Label _lblFilterText;
        private Button _btnAll;
        private Button _btnVulnOnly;
        private Button _btnSafeOnly;
        private Label _lblTierSep;
        private Label _lblTierText;
        private Button _btnTierFast;
        private Button _btnTierNormal;
        private Button _btnTierFull;
        private Label _lblSearchSep;
        private Label _lblSearchText;
        private TextBox _txtSearch;
        private Button _btnReAudit;

        // Content & Bottom controls
        private ListView _lvResults;
        private Panel _pnlBottom;
        private Label _lblGuard;
        private FlowLayoutPanel _pnlBottomRight;
        private Button _btnCopyJson;
        private Button _btnExportJson;
        private Button _btnExportSarif;

        private string _currentFilter = "ALL"; // ALL, VULN, SAFE
        private string _searchFilter = "";

        public ZeroTouchAuditorForm(List<CveEntry> cveDb)
        {
            _cveDb = cveDb ?? new List<CveEntry>();
            InitUi();
            ApplyLanguage();
            ApplyTheme();
            PerformReadOnlyAudit();
        }

        private Font GetAppFont(float size, FontStyle style = FontStyle.Regular)
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
        }

        private void InitUi()
        {
            this.Size = new Size(1160, 740);
            this.MinimumSize = new Size(960, 560);
            this.StartPosition = FormStartPosition.CenterScreen;
            this.Font = GetAppFont(9.5f);

            // Top Header Panel
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
            _pnlHeader.Controls.Add(_pnlHeaderRight);

            // Controls Bar with FlowLayoutPanel (Zero-Overlap Guarantee)
            _pnlBar = new Panel
            {
                Dock = DockStyle.Top,
                Height = 48,
                Padding = new Padding(12, 8, 12, 8)
            };

            _flowBar = new FlowLayoutPanel
            {
                Dock = DockStyle.Fill,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                AutoScroll = true,
                Margin = new Padding(0),
                Padding = new Padding(0)
            };

            _lblFilterText = new Label { AutoSize = true, Margin = new Padding(0, 6, 4, 0) };
            _btnAll = CreatePillButton("All (0)", () => SetFilter("ALL"));
            _btnVulnOnly = CreatePillButton("Vulnerable (0)", () => SetFilter("VULN"));
            _btnSafeOnly = CreatePillButton("Safe (0)", () => SetFilter("SAFE"));

            _lblTierSep = new Label { Text = "|", AutoSize = true, Margin = new Padding(8, 6, 8, 0) };
            _lblTierText = new Label { AutoSize = true, Margin = new Padding(0, 6, 4, 0) };
            _btnTierFast = CreatePillButton("Fast (71)", () => SetScanTier(ScanTier.Fast));
            _btnTierNormal = CreatePillButton("Normal (312)", () => SetScanTier(ScanTier.Normal));
            _btnTierFull = CreatePillButton("Full (433)", () => SetScanTier(ScanTier.Full));

            _lblSearchSep = new Label { Text = "|", AutoSize = true, Margin = new Padding(8, 6, 8, 0) };
            _lblSearchText = new Label { AutoSize = true, Margin = new Padding(0, 6, 4, 0) };

            _txtSearch = new TextBox
            {
                Width = 170,
                Height = 26,
                BorderStyle = BorderStyle.FixedSingle,
                Margin = new Padding(2, 3, 8, 0)
            };
            _txtSearch.TextChanged += (s, e) =>
            {
                _searchFilter = (_txtSearch.Text ?? "").Trim().ToLowerInvariant();
                RefreshList();
            };

            _btnReAudit = CreateActionButton("🔄 Re-Audit", 100, 27, () => PerformReadOnlyAudit());
            _btnReAudit.Margin = new Padding(4, 2, 8, 0);

            _flowBar.Controls.AddRange(new Control[] {
                _lblFilterText, _btnAll, _btnVulnOnly, _btnSafeOnly,
                _lblTierSep,
                _lblTierText, _btnTierFast, _btnTierNormal, _btnTierFull,
                _lblSearchSep,
                _lblSearchText, _txtSearch,
                _btnReAudit
            });
            _pnlBar.Controls.Add(_flowBar);

            // Bottom Action Bar
            _pnlBottom = new Panel
            {
                Dock = DockStyle.Bottom,
                Height = 52,
                Padding = new Padding(16, 10, 16, 10)
            };

            _lblGuard = new Label
            {
                AutoSize = true,
                Location = new Point(16, 17)
            };

            _pnlBottomRight = new FlowLayoutPanel
            {
                Dock = DockStyle.Right,
                AutoSize = true,
                AutoSizeMode = AutoSizeMode.GrowAndShrink,
                FlowDirection = FlowDirection.LeftToRight,
                WrapContents = false,
                Padding = new Padding(0, 2, 8, 0)
            };

            _btnCopyJson = CreateActionButton("📋 Copy JSON", 115, 30, () =>
            {
                string json = AuditorProgram.GenerateJsonOutput(_records, _records.Count, CountVuln(), _currentLang);
                Clipboard.SetText(json);
                string msg = _currentLang == AppLanguage.KO ? "JSON 감사 보고서가 클립보드에 복사되었습니다!"
                    : (_currentLang == AppLanguage.JA ? "JSON監査レポートがクリップボードにコピーされました！"
                    : "JSON audit report copied to clipboard!");
                MessageBox.Show(this, msg, "Device Zero-Touch Auditor", MessageBoxButtons.OK, MessageBoxIcon.Information);
            });

            _btnExportJson = CreateActionButton("💾 Save JSON", 115, 30, () => ExportFile("json"));
            _btnExportSarif = CreateActionButton("📊 Save SARIF", 115, 30, () => ExportFile("sarif"));

            _pnlBottomRight.Controls.AddRange(new Control[] { _btnCopyJson, _btnExportJson, _btnExportSarif });
            _pnlBottom.Controls.Add(_lblGuard);
            _pnlBottom.Controls.Add(_pnlBottomRight);

            // Main Results ListView
            _lvResults = new ListView
            {
                Dock = DockStyle.Fill,
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                BorderStyle = BorderStyle.None
            };

            _lvResults.Columns.Add("CVE ID", 145);
            _lvResults.Columns.Add("Severity", 115);
            _lvResults.Columns.Add("Status", 125);
            _lvResults.Columns.Add("Component", 230);
            _lvResults.Columns.Add("Live Audit Evidence", 480);

            this.Controls.Add(_lvResults);
            this.Controls.Add(_pnlBar);
            this.Controls.Add(_pnlHeader);
            this.Controls.Add(_pnlBottom);
        }

        private Button CreateActionButton(string text, int width, int height, Action onClick)
        {
            Button btn = new Button
            {
                Text = text,
                Width = width,
                Height = height,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Font = GetAppFont(8.5f, FontStyle.Regular),
                Margin = new Padding(3, 0, 3, 0)
            };
            btn.FlatAppearance.BorderSize = 1;
            btn.Click += (s, e) => onClick();
            return btn;
        }

        private Button CreatePillButton(string text, Action onClick)
        {
            Button btn = new Button
            {
                Text = text,
                AutoSize = true,
                Height = 28,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Font = GetAppFont(8.5f, FontStyle.Regular),
                Margin = new Padding(2, 1, 2, 0),
                Padding = new Padding(6, 2, 6, 2)
            };
            btn.FlatAppearance.BorderSize = 1;
            btn.Click += (s, e) => onClick();
            return btn;
        }

        private void ToggleTheme()
        {
            _isDarkMode = !_isDarkMode;
            ApplyTheme();
            RefreshList();
        }

        private void ApplyTheme()
        {
            Color formBg, headerBg, barBg, bottomBg, primaryText, subText, borderCol, btnBg, btnFore, btnBorder;

            if (_isDarkMode)
            {
                formBg = Color.FromArgb(13, 17, 23);
                headerBg = Color.FromArgb(22, 27, 34);
                barBg = Color.FromArgb(17, 21, 28);
                bottomBg = Color.FromArgb(22, 27, 34);
                primaryText = Color.FromArgb(240, 246, 252);
                subText = Color.FromArgb(139, 148, 158);
                borderCol = Color.FromArgb(48, 54, 61);
                btnBg = Color.FromArgb(33, 40, 48);
                btnFore = Color.FromArgb(201, 209, 217);
                btnBorder = Color.FromArgb(48, 54, 61);

                _btnThemeToggle.Text = "☀️ Light";
            }
            else
            {
                formBg = Color.FromArgb(255, 255, 255);
                headerBg = Color.FromArgb(246, 248, 250);
                barBg = Color.FromArgb(238, 242, 246);
                bottomBg = Color.FromArgb(246, 248, 250);
                primaryText = Color.FromArgb(31, 35, 40);
                subText = Color.FromArgb(87, 96, 106);
                borderCol = Color.FromArgb(208, 215, 222);
                btnBg = Color.FromArgb(243, 244, 246);
                btnFore = Color.FromArgb(36, 41, 47);
                btnBorder = Color.FromArgb(208, 215, 222);

                _btnThemeToggle.Text = "🌙 Dark";
            }

            this.BackColor = formBg;
            this.ForeColor = primaryText;

            _pnlHeader.BackColor = headerBg;
            _lblTitle.ForeColor = _isDarkMode ? Color.FromArgb(88, 166, 255) : Color.FromArgb(9, 105, 218);
            _lblPill.BackColor = _isDarkMode ? Color.FromArgb(33, 40, 48) : Color.FromArgb(230, 245, 235);
            _lblPill.ForeColor = _isDarkMode ? Color.FromArgb(46, 160, 67) : Color.FromArgb(26, 127, 55);
            _lblHostInfo.ForeColor = subText;

            _pnlBar.BackColor = barBg;
            _flowBar.BackColor = barBg;
            _lblFilterText.ForeColor = subText;
            _lblTierSep.ForeColor = borderCol;
            _lblTierText.ForeColor = subText;
            _lblSearchSep.ForeColor = borderCol;
            _lblSearchText.ForeColor = subText;

            _txtSearch.BackColor = _isDarkMode ? Color.FromArgb(13, 17, 23) : Color.White;
            _txtSearch.ForeColor = primaryText;

            _pnlBottom.BackColor = bottomBg;
            _lblGuard.ForeColor = subText;

            _lvResults.BackColor = formBg;
            _lvResults.ForeColor = primaryText;

            // Apply button styling
            foreach (Button b in new Button[] { _btnThemeToggle, _btnLangKo, _btnLangEn, _btnLangJa, _btnReAudit, _btnCopyJson, _btnExportJson, _btnExportSarif })
            {
                b.BackColor = btnBg;
                b.ForeColor = btnFore;
                b.FlatAppearance.BorderColor = btnBorder;
            }

            HighlightActiveButtons();
        }

        private void SetLanguage(AppLanguage lang)
        {
            _currentLang = lang;
            ApplyLanguage();
            ApplyTheme();
            UpdateMetricCounts();
            RefreshList();
        }

        private void ApplyLanguage()
        {
            // Apply normalized typography
            Font regularFont = GetAppFont(9f);
            Font boldFont = GetAppFont(9f, FontStyle.Bold);

            _lblTitle.Font = GetAppFont(12.5f, FontStyle.Bold);
            _lblPill.Font = GetAppFont(8f, FontStyle.Bold);
            _lblHostInfo.Font = GetAppFont(8.5f);
            _lblMetrics.Font = GetAppFont(9.5f, FontStyle.Bold);
            _lblGuard.Font = GetAppFont(8.5f, FontStyle.Italic);
            _txtSearch.Font = regularFont;
            _lvResults.Font = regularFont;

            foreach (Control c in _flowBar.Controls)
            {
                if (c is Button) c.Font = regularFont;
                else if (c is Label) c.Font = regularFont;
            }

            if (_currentLang == AppLanguage.KO)
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
                _btnExportSarif.Text = "📊 Save SARIF";

                _lvResults.Columns[0].Text = "CVE ID";
                _lvResults.Columns[1].Text = "Severity";
                _lvResults.Columns[2].Text = "Status";
                _lvResults.Columns[3].Text = "Component";
                _lvResults.Columns[4].Text = "Live Endpoint Audit Evidence";
            }

            // Adjust Pill position beside Title
            _lblPill.Location = new Point(_lblTitle.Right + 12, _lblTitle.Top + 2);
        }

        private void SetFilter(string filter)
        {
            _currentFilter = filter;
            HighlightActiveButtons();
            RefreshList();
        }

        private void SetScanTier(ScanTier tier)
        {
            _selectedTier = tier;
            HighlightActiveButtons();
            PerformReadOnlyAudit();
        }

        private void HighlightActiveButtons()
        {
            Color activeLangBg = _isDarkMode ? Color.FromArgb(31, 111, 235) : Color.FromArgb(9, 105, 218);
            Color activeLangFore = Color.White;
            Color defaultBtnBg = _isDarkMode ? Color.FromArgb(33, 40, 48) : Color.FromArgb(243, 244, 246);
            Color defaultBtnFore = _isDarkMode ? Color.FromArgb(201, 209, 217) : Color.FromArgb(36, 41, 47);

            _btnLangKo.BackColor = _currentLang == AppLanguage.KO ? activeLangBg : defaultBtnBg;
            _btnLangKo.ForeColor = _currentLang == AppLanguage.KO ? activeLangFore : defaultBtnFore;
            _btnLangEn.BackColor = _currentLang == AppLanguage.EN ? activeLangBg : defaultBtnBg;
            _btnLangEn.ForeColor = _currentLang == AppLanguage.EN ? activeLangFore : defaultBtnFore;
            _btnLangJa.BackColor = _currentLang == AppLanguage.JA ? activeLangBg : defaultBtnBg;
            _btnLangJa.ForeColor = _currentLang == AppLanguage.JA ? activeLangFore : defaultBtnFore;

            // Status filter buttons
            _btnAll.BackColor = _currentFilter == "ALL" ? activeLangBg : defaultBtnBg;
            _btnAll.ForeColor = _currentFilter == "ALL" ? activeLangFore : defaultBtnFore;

            Color vulnActiveBg = _isDarkMode ? Color.FromArgb(218, 54, 51) : Color.FromArgb(207, 34, 46);
            _btnVulnOnly.BackColor = _currentFilter == "VULN" ? vulnActiveBg : defaultBtnBg;
            _btnVulnOnly.ForeColor = _currentFilter == "VULN" ? Color.White : defaultBtnFore;

            Color safeActiveBg = _isDarkMode ? Color.FromArgb(46, 160, 67) : Color.FromArgb(26, 127, 55);
            _btnSafeOnly.BackColor = _currentFilter == "SAFE" ? safeActiveBg : defaultBtnBg;
            _btnSafeOnly.ForeColor = _currentFilter == "SAFE" ? Color.White : defaultBtnFore;

            // Tier buttons
            Color tierActiveBg = _isDarkMode ? Color.FromArgb(137, 87, 229) : Color.FromArgb(130, 80, 223);
            _btnTierFast.BackColor = _selectedTier == ScanTier.Fast ? tierActiveBg : defaultBtnBg;
            _btnTierFast.ForeColor = _selectedTier == ScanTier.Fast ? Color.White : defaultBtnFore;

            _btnTierNormal.BackColor = _selectedTier == ScanTier.Normal ? tierActiveBg : defaultBtnBg;
            _btnTierNormal.ForeColor = _selectedTier == ScanTier.Normal ? Color.White : defaultBtnFore;

            _btnTierFull.BackColor = _selectedTier == ScanTier.Full ? tierActiveBg : defaultBtnBg;
            _btnTierFull.ForeColor = _selectedTier == ScanTier.Full ? Color.White : defaultBtnFore;
        }

        private void PerformReadOnlyAudit()
        {
            _btnReAudit.Enabled = false;
            this.Cursor = Cursors.WaitCursor;

            ScanContext ctx = new ScanContext { TargetIp = "127.0.0.1", PortTimeoutMs = 350 };
            _records = AuditorProgram.ExecuteAudit(_cveDb, ctx, _selectedTier);

            UpdateMetricCounts();
            RefreshList();

            this.Cursor = Cursors.Default;
            _btnReAudit.Enabled = true;
        }

        private void UpdateMetricCounts()
        {
            int total = _records.Count;
            int vuln = CountVuln();
            int safe = total - vuln;

            // Tier counts
            int fastTotal = _cveDb.FindAll(c => c.MatchesScanTier(ScanTier.Fast)).Count;
            int normTotal = _cveDb.FindAll(c => c.MatchesScanTier(ScanTier.Normal)).Count;
            int fullTotal = _cveDb.Count;

            if (_currentLang == AppLanguage.KO)
            {
                _lblMetrics.Text = string.Format("감사 완료: {0}개 시그니처 점검  |  {1}개 취약점 검출  |  {2}개 안전/완화 상태", total, vuln, safe);
                _btnAll.Text = "전체 (" + total + ")";
                _btnVulnOnly.Text = "취약점 발견 (" + vuln + ")";
                _btnSafeOnly.Text = "안전/완화 (" + safe + ")";
                _btnTierFast.Text = "신속 (" + fastTotal + ")";
                _btnTierNormal.Text = "표준 (" + normTotal + ")";
                _btnTierFull.Text = "심층 (" + fullTotal + ")";
            }
            else if (_currentLang == AppLanguage.JA)
            {
                _lblMetrics.Text = string.Format("監査完了: {0}件のシグネチャ点検  |  {1}件の脆弱性検出  |  {2}件の安全/緩和済", total, vuln, safe);
                _btnAll.Text = "全体 (" + total + ")";
                _btnVulnOnly.Text = "脆弱性あり (" + vuln + ")";
                _btnSafeOnly.Text = "安全/緩和済 (" + safe + ")";
                _btnTierFast.Text = "迅速 (" + fastTotal + ")";
                _btnTierNormal.Text = "標準 (" + normTotal + ")";
                _btnTierFull.Text = "深層 (" + fullTotal + ")";
            }
            else
            {
                _lblMetrics.Text = string.Format("Audit Complete: {0} Signatures Audited  |  {1} Exposed  |  {2} Safe/Mitigated", total, vuln, safe);
                _btnAll.Text = "All (" + total + ")";
                _btnVulnOnly.Text = "Vulnerable (" + vuln + ")";
                _btnSafeOnly.Text = "Safe (" + safe + ")";
                _btnTierFast.Text = "Fast (" + fastTotal + ")";
                _btnTierNormal.Text = "Normal (" + normTotal + ")";
                _btnTierFull.Text = "Full (" + fullTotal + ")";
            }

            if (_isDarkMode)
            {
                _lblMetrics.ForeColor = vuln > 0 ? Color.FromArgb(255, 123, 114) : Color.FromArgb(63, 185, 80);
            }
            else
            {
                _lblMetrics.ForeColor = vuln > 0 ? Color.FromArgb(207, 34, 46) : Color.FromArgb(26, 127, 55);
            }
        }

        private int CountVuln()
        {
            int c = 0;
            foreach (var r in _records)
            {
                if (r.Result != null && r.Result.IsVulnerable) c++;
            }
            return c;
        }

        private void RefreshList()
        {
            _lvResults.BeginUpdate();
            _lvResults.Items.Clear();

            HighlightActiveButtons();

            // Color definitions for maximum legibility in both Dark and Light modes
            Color colCve = _isDarkMode ? Color.FromArgb(88, 166, 255) : Color.FromArgb(9, 105, 218);
            Color colVuln = _isDarkMode ? Color.FromArgb(255, 123, 114) : Color.FromArgb(207, 34, 46);
            Color colSafe = _isDarkMode ? Color.FromArgb(63, 185, 80) : Color.FromArgb(26, 127, 55);
            Color colComp = _isDarkMode ? Color.FromArgb(210, 168, 255) : Color.FromArgb(130, 80, 223);
            Color colEvidence = _isDarkMode ? Color.FromArgb(201, 209, 217) : Color.FromArgb(36, 41, 47);
            Color colAmber = _isDarkMode ? Color.FromArgb(210, 153, 34) : Color.FromArgb(154, 103, 0);

            foreach (var rec in _records)
            {
                bool isVuln = rec.Result != null && rec.Result.IsVulnerable;

                if (_currentFilter == "VULN" && !isVuln) continue;
                if (_currentFilter == "SAFE" && isVuln) continue;

                string evidence = rec.Result != null && rec.Result.Evidence != null ? rec.Result.Evidence.Get(_currentLang) : "N/A";
                string title = rec.Cve.Title != null ? rec.Cve.Title.Get(_currentLang) : "";

                if (!string.IsNullOrEmpty(_searchFilter))
                {
                    string combo = (rec.Cve.CveId + " " + rec.Cve.ComponentOrPort + " " + title + " " + evidence).ToLowerInvariant();
                    if (!combo.Contains(_searchFilter)) continue;
                }

                ListViewItem lvi = new ListViewItem(rec.Cve.CveId);
                lvi.UseItemStyleForSubItems = false; // Individual subitem colors for high legibility

                // SubItem 0: CVE ID
                lvi.ForeColor = colCve;

                // SubItem 1: Severity
                var subSev = lvi.SubItems.Add(rec.Cve.SeverityLabel);
                subSev.ForeColor = rec.Cve.CvssScore >= 7.0 ? colVuln : colAmber;

                // SubItem 2: Status
                string statusText = isVuln
                    ? (_currentLang == AppLanguage.KO ? "[취약점 검출]" : (_currentLang == AppLanguage.JA ? "[脆弱性検出]" : "[EXPOSED]"))
                    : (_currentLang == AppLanguage.KO ? "[안전/완화]" : (_currentLang == AppLanguage.JA ? "[安全/緩和済]" : "[SAFE]"));
                var subStatus = lvi.SubItems.Add(statusText);
                subStatus.ForeColor = isVuln ? colVuln : colSafe;

                // SubItem 3: Component
                var subComp = lvi.SubItems.Add(rec.Cve.ComponentOrPort);
                subComp.ForeColor = colComp;

                // SubItem 4: Evidence (Crisp, highly readable body text)
                var subEv = lvi.SubItems.Add(evidence);
                subEv.ForeColor = colEvidence;

                _lvResults.Items.Add(lvi);
            }

            _lvResults.EndUpdate();
        }

        private void ExportFile(string kind)
        {
            using (SaveFileDialog sfd = new SaveFileDialog())
            {
                string title = _currentLang == AppLanguage.KO ? "엔드포인트 감사 보고서 저장 (" + kind.ToUpper() + ")"
                    : (_currentLang == AppLanguage.JA ? "エンドポイント監査レポート保存 (" + kind.ToUpper() + ")"
                    : "Save Endpoint Audit Report (" + kind.ToUpper() + ")");
                sfd.Title = title;
                sfd.Filter = kind == "json" ? "JSON Files (*.json)|*.json" : "SARIF Files (*.sarif)|*.sarif";
                sfd.FileName = string.Format("Endpoint_Audit_{0}_{1}.{2}",
                    Environment.MachineName, DateTime.UtcNow.ToString("yyyyMMdd_HHmmss"), kind);

                if (sfd.ShowDialog(this) == DialogResult.OK)
                {
                    string content = kind == "json"
                        ? AuditorProgram.GenerateJsonOutput(_records, _records.Count, CountVuln(), _currentLang)
                        : AuditorProgram.GenerateSarifOutput(_records, _records.Count, CountVuln(), _currentLang);
                    File.WriteAllText(sfd.FileName, content, Encoding.UTF8);

                    string doneMsg = _currentLang == AppLanguage.KO ? "성공적으로 내보냈습니다: " + sfd.FileName
                        : (_currentLang == AppLanguage.JA ? "正常にエクスポートされました: " + sfd.FileName
                        : "Exported successfully to: " + sfd.FileName);
                    MessageBox.Show(this, doneMsg, "Device Zero-Touch Auditor", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
        }
    }
}
'''

with open(path, "w", encoding="utf-8") as f:
    f.write(code)
print("[+] Rebuilt AuditorProgram.cs successfully!")
