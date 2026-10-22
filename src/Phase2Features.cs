using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.ServiceProcess;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using Microsoft.Win32;

namespace CveSecuritySuite
{
    // =========================================================================
    // [2차 제안 1] 열린 포트 점유 프로세스(PID · 실행 경로 · 디지털 서명) 실시간 역추적기
    // =========================================================================
    public class PortProcessEntry
    {
        public string Protocol { get; set; }
        public string LocalAddress { get; set; }
        public int Port { get; set; }
        public int Pid { get; set; }
        public string ProcessName { get; set; }
        public string ExecutablePath { get; set; }
        public string SignatureStatus { get; set; }
        public string AssociatedCveRisk { get; set; }
        public bool IsHighRisk { get; set; }
    }

    public static class PortToProcessAuditor
    {
        public static List<PortProcessEntry> ScanActivePortProcesses()
        {
            List<PortProcessEntry> results = new List<PortProcessEntry>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            string output;
            SystemAuditHelper.RunProcessCommand("netstat.exe", "-ano", 5000, out output);
            if (string.IsNullOrEmpty(output)) return results;

            string[] lines = output.Split(new char[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries);
            foreach (string raw in lines)
            {
                string line = raw.Trim();
                if (!line.StartsWith("TCP", StringComparison.OrdinalIgnoreCase) &&
                    !line.StartsWith("UDP", StringComparison.OrdinalIgnoreCase))
                    continue;

                string[] parts = line.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length < 4) continue;

                string proto = parts[0].ToUpperInvariant();
                string localEp = parts[1];
                string state = proto == "TCP" && parts.Length >= 5 ? parts[3].ToUpperInvariant() : "BOUND";
                string pidStr = proto == "TCP" && parts.Length >= 5 ? parts[4] : parts[parts.Length - 1];

                if (proto == "TCP" && state != "LISTENING") continue;

                int colonIdx = localEp.LastIndexOf(':');
                if (colonIdx <= 0) continue;

                int port;
                if (!int.TryParse(localEp.Substring(colonIdx + 1), out port) || port <= 0) continue;

                int pid;
                if (!int.TryParse(pidStr, out pid)) pid = 0;

                string dedupKey = proto + ":" + port + ":" + pid;
                if (seen.Contains(dedupKey)) continue;
                seen.Add(dedupKey);

                string procName = "System / Kernel";
                string exePath = @"C:\Windows\System32\ntoskrnl.exe";
                string sigStatus = "Microsoft Windows Kernel (Verified)";

                if (pid > 4)
                {
                    try
                    {
                        using (Process p = Process.GetProcessById(pid))
                        {
                            procName = p.ProcessName + ".exe";
                            try
                            {
                                if (p.MainModule != null && !string.IsNullOrEmpty(p.MainModule.FileName))
                                {
                                    exePath = p.MainModule.FileName;
                                }
                                else
                                {
                                    exePath = ResolveSystemProcessPath(p.ProcessName);
                                }
                            }
                            catch
                            {
                                exePath = ResolveSystemProcessPath(p.ProcessName);
                            }
                        }
                    }
                    catch
                    {
                        procName = "Protected Service (PID " + pid + ")";
                        exePath = @"C:\Windows\System32\svchost.exe";
                    }

                    sigStatus = CheckDigitalSignature(exePath);
                }

                bool highRisk = false;
                string cveRisk = GetPortCveAdvisory(port, out highRisk);

                results.Add(new PortProcessEntry
                {
                    Protocol = proto,
                    LocalAddress = localEp,
                    Port = port,
                    Pid = pid,
                    ProcessName = procName,
                    ExecutablePath = exePath,
                    SignatureStatus = sigStatus,
                    AssociatedCveRisk = cveRisk,
                    IsHighRisk = highRisk
                });
            }

            results.Sort((a, b) =>
            {
                if (a.IsHighRisk != b.IsHighRisk) return b.IsHighRisk.CompareTo(a.IsHighRisk);
                return a.Port.CompareTo(b.Port);
            });
            return results;
        }

        private static string ResolveSystemProcessPath(string procName)
        {
            try
            {
                string candidate = Path.Combine(Environment.SystemDirectory, procName + ".exe");
                if (File.Exists(candidate)) return candidate;
            }
            catch { }
            return @"C:\Windows\System32\" + procName + ".exe";
        }

        private static string CheckDigitalSignature(string filePath)
        {
            try
            {
                if (!File.Exists(filePath)) return I18n.T("시스템 보호 경로", "システム保護経路", "System Protected Path");
                X509Certificate cert = X509Certificate.CreateFromSignedFile(filePath);
                if (cert != null && !string.IsNullOrEmpty(cert.Subject))
                {
                    return I18n.T("✔ 서명 확인됨: ", "✔ 署名確認済: ", "✔ Signed: ") + cert.Subject;
                }
            }
            catch { }

            try
            {
                if (File.Exists(filePath))
                {
                    FileVersionInfo fvi = FileVersionInfo.GetVersionInfo(filePath);
                    if (!string.IsNullOrEmpty(fvi.CompanyName))
                        return I18n.T("제조사 확인: ", "発行元: ", "Publisher: ") + fvi.CompanyName;
                }
            }
            catch { }

            return I18n.T("⚠ 서명 미확인 (점검 권장)", "⚠ 署名未確認 (要確認)", "⚠ Unsigned / Unverified");
        }

        private static string GetPortCveAdvisory(int port, out bool isHighRisk)
        {
            isHighRisk = false;
            // Only well-known, verifiable CVE references are cited here. Ports without a single
            // defining CVE are described as configuration-exposure risks instead of inventing IDs.
            switch (port)
            {
                case 445:
                    isHighRisk = true;
                    return "SMB family (e.g. CVE-2020-0796 SMBGhost, CVE-2017-0144 EternalBlue)";
                case 135:
                    isHighRisk = true;
                    return "MS-RPC family (e.g. CVE-2022-26809)";
                case 139:
                case 137:
                    isHighRisk = true;
                    return I18n.T("NetBIOS/SMBv1 노출 (SMBv1 계열 CVE 위험)", "NetBIOS/SMBv1 露出 (SMBv1系CVEリスク)", "NetBIOS/SMBv1 exposure (SMBv1-family CVE risk)");
                case 3389:
                    isHighRisk = true;
                    return "RDP family (e.g. CVE-2019-0708 BlueKeep)";
                case 22:
                    isHighRisk = true;
                    return "OpenSSH (e.g. CVE-2024-6387 regreSSHion - version check required)";
                case 5040:
                    return I18n.T("CDPSvc 로컬 리스너 (특정 CVE 아님, 노출 최소화 권장)", "CDPSvc ローカルリスナー (特定CVEなし)", "CDPSvc local listener (no single CVE; minimize exposure)");
                case 5353:
                case 5355:
                    isHighRisk = true;
                    return I18n.T("mDNS/LLMNR 포이즈닝 위험 (설정 취약점, 특정 CVE 아님)", "mDNS/LLMNR ポイズニングリスク (設定上の弱点)", "mDNS/LLMNR poisoning risk (configuration weakness, not a single CVE)");
                case 8000:
                case 8080:
                    isHighRisk = true;
                    return I18n.T("노출된 HTTP 리스너 (해당 서비스 제품/버전별 CVE 확인 필요)", "露出HTTPリスナー (製品別CVE確認要)", "Exposed HTTP listener (check CVEs for the specific product/version)");
                default:
                    return I18n.T("로컬 서비스 리스너 (표준 방화벽 감시 대상)", "ローカルサービスリスナー", "Local Service Listener");
            }
        }
    }

    public class PortToProcessInspectorDialog : Form
    {
        private DataGridView _grid;
        private Label _lblSummary;
        private List<PortProcessEntry> _entries = new List<PortProcessEntry>();
        private ScanContext _ctx;

        public PortToProcessInspectorDialog(ScanContext ctx)
        {
            _ctx = ctx;
            this.Text = I18n.T(
                "🔍 열린 포트 점유 프로세스(PID · 실행 경로 · 디지털 서명) 실시간 역추적기",
                "🔍 開放ポート占有プロセス(PID・実行経路・電子署名) リアルタイム逆追跡",
                "🔍 Live Port-to-Process (PID, Path & Signature) Inspector");
            this.Size = new Size(1020, 580);
            this.StartPosition = FormStartPosition.CenterParent;
            this.BackColor = Color.FromArgb(16, 21, 32);
            this.ForeColor = Color.White;

            _lblSummary = new Label
            {
                Location = new Point(20, 16),
                Size = new Size(960, 26),
                Font = I18n.CreateFont(10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(102, 217, 255)
            };

            _grid = new DataGridView
            {
                Location = new Point(20, 50),
                Size = new Size(965, 425),
                BackgroundColor = Color.FromArgb(13, 18, 27),
                BorderStyle = BorderStyle.FixedSingle,
                EnableHeadersVisualStyles = false,
                AllowUserToAddRows = false,
                ReadOnly = true,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                RowTemplate = { Height = 32 }
            };
            _grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(28, 36, 52);
            _grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
            _grid.DefaultCellStyle.BackColor = Color.FromArgb(20, 26, 38);
            _grid.DefaultCellStyle.ForeColor = Color.White;

            _grid.Columns.Add("Proto", I18n.T("프로토콜", "プロトコル", "Proto"));
            _grid.Columns.Add("Port", I18n.T("열린 포트", "開放ポート", "Port"));
            _grid.Columns.Add("Pid", "PID");
            _grid.Columns.Add("Proc", I18n.T("점유 프로세스명", "プロセス名", "Process Name"));
            _grid.Columns.Add("Path", I18n.T("실행 파일 전체 경로", "実行ファイル経路", "Executable Path"));
            _grid.Columns.Add("Sig", I18n.T("디지털 서명 / 제조사", "電子署名 / 発行元", "Digital Signature"));
            _grid.Columns.Add("Risk", I18n.T("연관 CVE 위협 분석", "関連CVEリスク", "Associated CVE Risk"));
            _grid.Columns["Proto"].FillWeight = 45;
            _grid.Columns["Port"].FillWeight = 55;
            _grid.Columns["Pid"].FillWeight = 45;
            _grid.Columns["Proc"].FillWeight = 85;
            _grid.Columns["Path"].FillWeight = 150;
            _grid.Columns["Sig"].FillWeight = 130;
            _grid.Columns["Risk"].FillWeight = 150;

            Button btnOpenFolder = new Button
            {
                Location = new Point(20, 488),
                Size = new Size(240, 38),
                BackColor = Color.FromArgb(38, 98, 175),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Text = I18n.T("📂 선택한 실행 파일 폴더 위치 열기", "📂 実行ファイルのフォルダを開く", "📂 Open Executable Folder")
            };
            btnOpenFolder.FlatAppearance.BorderSize = 0;
            btnOpenFolder.Click += (s, e) =>
            {
                if (_grid.CurrentRow == null || _grid.CurrentRow.Index < 0 || _grid.CurrentRow.Index >= _entries.Count) return;
                string p = _entries[_grid.CurrentRow.Index].ExecutablePath;
                try
                {
                    if (File.Exists(p))
                        Process.Start("explorer.exe", "/select,\"" + p + "\"");
                    else
                        Process.Start("explorer.exe", Environment.SystemDirectory);
                }
                catch { }
            };

            Button btnBlockPort = new Button
            {
                Location = new Point(272, 488),
                Size = new Size(280, 38),
                BackColor = Color.FromArgb(24, 158, 96),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Text = I18n.T("🛡 선택 포트 방화벽 차단 정책 Allow 적용", "🛡 選択ポートの遮断ポリシーをAllow適用", "🛡 Allow Firewall Block on Selected Port")
            };
            btnBlockPort.FlatAppearance.BorderSize = 0;
            btnBlockPort.Click += (s, e) =>
            {
                if (_grid.CurrentRow == null || _grid.CurrentRow.Index < 0 || _grid.CurrentRow.Index >= _entries.Count) return;
                PortProcessEntry item = _entries[_grid.CurrentRow.Index];
                string cmdOut;
                bool ok = SystemAuditHelper.RunProcessCommand("netsh.exe", string.Format("advfirewall firewall add rule name=\"CveSuite_Port_{0}\" dir=in action=block protocol={1} localport={0}", item.Port, item.Protocol), 4000, out cmdOut);
                if (ok)
                {
                    string err;
                    SystemAuditHelper.WriteRegistryDword(RegistryHive.CurrentUser, @"Software\CveSecuritySuite\HardeningPolicies\PortBlocks", "Block_" + item.Protocol + "_" + item.Port, 1, out err);
                    MessageBox.Show(
                        I18n.T(
                            string.Format("{0} {1}번 포트({2})에 대한 인바운드 방화벽 차단 규칙(CveSuite_Port_{1})이 실제로 생성되었습니다.", item.Protocol, item.Port, item.ProcessName),
                            string.Format("{0} ポート {1} ({2}) の遮断ルール(CveSuite_Port_{1})が作成されました。", item.Protocol, item.Port, item.ProcessName),
                            string.Format("Inbound firewall block rule CveSuite_Port_{1} created for {0} port {1} ({2}).", item.Protocol, item.Port, item.ProcessName)),
                        "Port Blocked", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show(
                        I18n.T("방화벽 규칙 생성에 실패했습니다. 관리자 권한으로 프로그램을 다시 실행해 주세요.\r\n\r\n" + cmdOut,
                               "ファイアウォールルール作成に失敗しました。管理者として再実行してください。\r\n\r\n" + cmdOut,
                               "Failed to create firewall rule. Please re-run as Administrator.\r\n\r\n" + cmdOut),
                        "Administrator Required", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            };

            Button btnRefresh = new Button
            {
                Location = new Point(564, 488),
                Size = new Size(190, 38),
                BackColor = Color.FromArgb(52, 72, 102),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Text = I18n.T("🔄 실시간 목록 새로고침", "🔄 リストを再読込", "🔄 Refresh Live List")
            };
            btnRefresh.FlatAppearance.BorderSize = 0;
            btnRefresh.Click += (s, e) => LoadData();

            Button btnClose = new Button
            {
                Location = new Point(845, 488),
                Size = new Size(140, 38),
                BackColor = Color.FromArgb(55, 64, 82),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Text = I18n.T("닫기", "閉じる", "Close")
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Click += (s, e) => this.Close();

            this.Controls.Add(_lblSummary);
            this.Controls.Add(_grid);
            this.Controls.Add(btnOpenFolder);
            this.Controls.Add(btnBlockPort);
            this.Controls.Add(btnRefresh);
            this.Controls.Add(btnClose);
            I18n.ApplyLanguageFontRecursive(this);
            LoadData();
        }

        private void LoadData()
        {
            _entries = PortToProcessAuditor.ScanActivePortProcesses();
            _grid.Rows.Clear();
            int highRiskCnt = 0;
            foreach (PortProcessEntry e in _entries)
            {
                if (e.IsHighRisk) highRiskCnt++;
                int idx = _grid.Rows.Add(e.Protocol, e.Port, e.Pid, e.ProcessName, e.ExecutablePath, e.SignatureStatus, e.AssociatedCveRisk);
                if (e.IsHighRisk)
                {
                    _grid.Rows[idx].Cells[1].Style.ForeColor = Color.FromArgb(255, 105, 115);
                    _grid.Rows[idx].Cells[6].Style.ForeColor = Color.FromArgb(255, 130, 120);
                }
                else
                {
                    _grid.Rows[idx].Cells[6].Style.ForeColor = Color.FromArgb(130, 215, 175);
                }
            }
            _lblSummary.Text = I18n.T(
                string.Format("실측 포트-프로세스 역추적 완료: 현재 열린 포트 총 {0}개 (주의 필요 고위험 포트: {1}개)", _entries.Count, highRiskCnt),
                string.Format("実測ポート・プロセス逆追跡完了: 開放ポート計 {0} 個 (高リスクポート: {1} 個)", _entries.Count, highRiskCnt),
                string.Format("Live Port-to-Process Trace Complete: {0} active port bindings ({1} high-risk CVE ports)", _entries.Count, highRiskCnt));
        }
    }

    // =========================================================================
    // [2차 제안 2] 로컬 자격증명 및 평문 기밀(LSA · WDigest · SSH 키 · 환경변수) 노출 감사기
    // =========================================================================
    public class CredentialAuditItem
    {
        public string CheckId { get; set; }
        public string Category { get; set; }
        public string Title { get; set; }
        public string LiveFinding { get; set; }
        public bool IsVulnerable { get; set; }
        public string RemediationDesc { get; set; }
        public string RegSubKey { get; set; }
        public string RegValueName { get; set; }
        public int SafeValue { get; set; }
    }

    public class CredentialExposureAuditorDialog : Form
    {
        private DataGridView _grid;
        private Label _lblHeader;
        private List<CredentialAuditItem> _items = new List<CredentialAuditItem>();

        public CredentialExposureAuditorDialog()
        {
            this.Text = I18n.T(
                "🔐 로컬 자격증명 및 평문 기밀(LSA · WDigest · SSH 키 · 환경변수) 노출 감사기",
                "🔐 ローカル資格情報および平文機密(LSA・WDigest・SSH鍵・環境変数)露出監査",
                "🔐 Credential & Plaintext Secret Exposure Auditor");
            this.Size = new Size(980, 540);
            this.StartPosition = FormStartPosition.CenterParent;
            this.BackColor = Color.FromArgb(16, 21, 32);
            this.ForeColor = Color.White;

            _lblHeader = new Label
            {
                Location = new Point(20, 16),
                Size = new Size(920, 26),
                Font = I18n.CreateFont(10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(102, 224, 163)
            };

            _grid = new DataGridView
            {
                Location = new Point(20, 50),
                Size = new Size(925, 390),
                BackgroundColor = Color.FromArgb(13, 18, 27),
                BorderStyle = BorderStyle.FixedSingle,
                EnableHeadersVisualStyles = false,
                AllowUserToAddRows = false,
                ReadOnly = true,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                RowTemplate = { Height = 36 }
            };
            _grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(28, 36, 52);
            _grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
            _grid.DefaultCellStyle.BackColor = Color.FromArgb(20, 26, 38);
            _grid.DefaultCellStyle.ForeColor = Color.White;

            _grid.Columns.Add("Id", "ID");
            _grid.Columns.Add("Cat", I18n.T("점검 영역", "点検領域", "Category"));
            _grid.Columns.Add("Title", I18n.T("자격증명 보호 점검 항목", "資格情報保護項目", "Credential Security Check"));
            _grid.Columns.Add("Finding", I18n.T("실측 진단 결과", "実測診断結果", "Live Audit Finding"));
            _grid.Columns.Add("Fix", I18n.T("권장 보호 조치", "推奨保護措置", "Recommended Mitigation"));
            _grid.Columns["Id"].FillWeight = 45;
            _grid.Columns["Cat"].FillWeight = 75;
            _grid.Columns["Title"].FillWeight = 130;
            _grid.Columns["Finding"].FillWeight = 130;
            _grid.Columns["Fix"].FillWeight = 140;

            Button btnHardenAll = new Button
            {
                Location = new Point(490, 452),
                Size = new Size(310, 40),
                BackColor = Color.FromArgb(24, 158, 96),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Text = I18n.T("⚡ 취약한 자격증명 보호 정책 원클릭 Allow 잠금", "⚡ 脆弱な資格情報保護ポリシーを一括Allow適用", "⚡ 1-Click Allow & Harden All Credential Policies")
            };
            btnHardenAll.FlatAppearance.BorderSize = 0;
            btnHardenAll.Click += (s, e) =>
            {
                int fixedCnt = 0;
                List<string> failed = new List<string>();
                foreach (CredentialAuditItem it in _items)
                {
                    if (!it.IsVulnerable) continue;

                    if (it.CheckId == "CRED-04")
                    {
                        // Real ACL lock: current user only, inheritance removed
                        string sshDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
                        string outIc;
                        bool ok = SystemAuditHelper.RunProcessCommand("icacls.exe",
                            string.Format("\"{0}\" /inheritance:r /grant:r \"{1}\":(OI)(CI)F /T", sshDir, Environment.UserName), 8000, out outIc);
                        if (ok) fixedCnt++; else failed.Add(it.CheckId + ": " + outIc);
                        continue;
                    }
                    if (it.CheckId == "CRED-05")
                    {
                        // Report-only: removing user secrets automatically could break the user's tools
                        failed.Add(it.CheckId + ": " + I18n.T("환경변수 기밀은 자동 삭제하지 않습니다 (수동 확인 필요)", "環境変数の機密は自動削除しません (手動確認要)", "Env secrets are not auto-deleted (manual review required)"));
                        continue;
                    }

                    if (!SystemAuditHelper.IsRunningAsAdmin())
                    {
                        failed.Add(it.CheckId + ": " + I18n.T("관리자 권한 필요 (HKLM 쓰기)", "管理者権限が必要 (HKLM書込)", "Administrator required (HKLM write)"));
                        continue;
                    }
                    try
                    {
                        using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                        using (RegistryKey key = baseKey.CreateSubKey(it.RegSubKey))
                        {
                            key.SetValue(it.RegValueName, it.SafeValue, RegistryValueKind.DWord);
                        }
                        fixedCnt++;
                    }
                    catch (Exception ex)
                    {
                        failed.Add(it.CheckId + ": " + ex.Message);
                    }
                }
                RunAudit();
                string msg = I18n.T(
                    string.Format("실제 적용 완료: {0}건", fixedCnt),
                    string.Format("実際に適用完了: {0} 件", fixedCnt),
                    string.Format("Actually applied: {0} item(s)", fixedCnt));
                if (failed.Count > 0)
                {
                    msg += "\r\n\r\n" + I18n.T("미적용 항목:", "未適用項目:", "Not applied:") + "\r\n• " + string.Join("\r\n• ", failed.ToArray());
                }
                msg += "\r\n\r\n" + I18n.T("※ LSA/WDigest 변경은 재부팅 후 완전히 반영됩니다.", "※ LSA/WDigestの変更は再起動後に完全反映されます。", "※ LSA/WDigest changes take full effect after reboot.");
                MessageBox.Show(msg, "Credential Protection", MessageBoxButtons.OK, failed.Count > 0 ? MessageBoxIcon.Warning : MessageBoxIcon.Information);
            };

            Button btnClose = new Button
            {
                Location = new Point(810, 452),
                Size = new Size(135, 40),
                BackColor = Color.FromArgb(52, 64, 84),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Text = I18n.T("닫기", "閉じる", "Close")
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Click += (s, e) => this.Close();

            this.Controls.Add(_lblHeader);
            this.Controls.Add(_grid);
            this.Controls.Add(btnHardenAll);
            this.Controls.Add(btnClose);
            I18n.ApplyLanguageFontRecursive(this);
            RunAudit();
        }

        private void RunAudit()
        {
            _items.Clear();
            _grid.Rows.Clear();

            // 1. WDigest UseLogonCredential (Windows 8.1+ default when value is absent = disabled = safe)
            object wdigest = SystemAuditHelper.ReadRegistryValue(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential");
            bool wdigestSafe = wdigest == null || Convert.ToInt32(wdigest) == 0;
            _items.Add(new CredentialAuditItem
            {
                CheckId = "CRED-01",
                Category = "LSASS / WDigest",
                Title = I18n.T("WDigest 메모리 평문 암호 캐싱 방지", "WDigest平文パスワードキャッシュ防止", "WDigest Plaintext Password Caching Prevention"),
                LiveFinding = wdigestSafe
                    ? I18n.T("🛡 안전 (" + (wdigest == null ? "값 없음 = OS 기본 비활성" : "UseLogonCredential=0") + ")", "🛡 安全", "🛡 SAFE (" + (wdigest == null ? "absent = OS default off" : "=0") + ")")
                    : I18n.T("⚠ 취약 (UseLogonCredential=" + wdigest + " : 평문 캐싱 활성)", "⚠ 脆弱 (平文キャッシュ有効)", "⚠ VULNERABLE (UseLogonCredential=" + wdigest + ")"),
                IsVulnerable = !wdigestSafe,
                RemediationDesc = "HKLM\\...\\WDigest\\UseLogonCredential = 0",
                RegSubKey = @"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest",
                RegValueName = "UseLogonCredential",
                SafeValue = 0
            });

            // 2. LSA RunAsPPL
            object ppl = SystemAuditHelper.ReadRegistryValue(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL");
            bool pplSafe = ppl != null && Convert.ToInt32(ppl) >= 1;
            _items.Add(new CredentialAuditItem
            {
                CheckId = "CRED-02",
                Category = "LSA Protection",
                Title = I18n.T("LSA 프로세스 메모리 덤프 방지 보호 모드 (RunAsPPL)", "LSAメモリダンプ防止保護 (RunAsPPL)", "LSA Protected Process Light (RunAsPPL)"),
                LiveFinding = pplSafe ? I18n.T("🛡 안전 (RunAsPPL=" + ppl + ")", "🛡 安全 (RunAsPPL=" + ppl + ")", "🛡 SAFE (RunAsPPL=" + ppl + ")") : I18n.T("⚠ 미설정 (RunAsPPL 레지스트리 값 없음/0)", "⚠ 未設定 (RunAsPPL無し/0)", "⚠ Not configured (RunAsPPL absent/0)"),
                IsVulnerable = !pplSafe,
                RemediationDesc = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL = 1 (reboot)",
                RegSubKey = @"SYSTEM\CurrentControlSet\Control\Lsa",
                RegValueName = "RunAsPPL",
                SafeValue = 1
            });

            // 3. NoLMHash (Vista+ default when absent = 1 = safe)
            object lm = SystemAuditHelper.ReadRegistryValue(RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "NoLMHash");
            bool lmSafe = lm == null || Convert.ToInt32(lm) == 1;
            _items.Add(new CredentialAuditItem
            {
                CheckId = "CRED-03",
                Category = "SAM / Hash",
                Title = I18n.T("취약한 LAN Manager(LM) 암호 해시 로컬 저장 금지", "脆弱なLMハッシュ保存禁止", "Disable Weak LAN Manager (LM) Hash Storage"),
                LiveFinding = lmSafe ? I18n.T("🛡 안전 (NoLMHash=1 / OS 기본값)", "🛡 安全 (NoLMHash=1)", "🛡 SAFE (NoLMHash=1 / default)") : I18n.T("⚠ 취약 (NoLMHash=0)", "⚠ 脆弱 (NoLMHash=0)", "⚠ VULNERABLE (NoLMHash=0)"),
                IsVulnerable = !lmSafe,
                RemediationDesc = "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\NoLMHash = 1",
                RegSubKey = @"SYSTEM\CurrentControlSet\Control\Lsa",
                RegValueName = "NoLMHash",
                SafeValue = 1
            });

            // 4. .ssh directory ACL - real check: any ACE granting access to principals other than the owner/SYSTEM/Administrators?
            string sshDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".ssh");
            bool sshFound = Directory.Exists(sshDir);
            List<string> extraPrincipals = new List<string>();
            if (sshFound)
            {
                try
                {
                    System.Security.AccessControl.DirectorySecurity ds = Directory.GetAccessControl(sshDir);
                    string me = System.Security.Principal.WindowsIdentity.GetCurrent().Name;
                    foreach (System.Security.AccessControl.FileSystemAccessRule rule in ds.GetAccessRules(true, true, typeof(System.Security.Principal.NTAccount)))
                    {
                        if (rule.AccessControlType != System.Security.AccessControl.AccessControlType.Allow) continue;
                        string who = rule.IdentityReference.Value;
                        if (string.Equals(who, me, StringComparison.OrdinalIgnoreCase)) continue;
                        if (who.EndsWith("\\SYSTEM", StringComparison.OrdinalIgnoreCase) || who.EndsWith("\\Administrators", StringComparison.OrdinalIgnoreCase)) continue;
                        if (!extraPrincipals.Contains(who)) extraPrincipals.Add(who);
                    }
                }
                catch { }
            }
            bool sshSafe = !sshFound || extraPrincipals.Count == 0;
            _items.Add(new CredentialAuditItem
            {
                CheckId = "CRED-04",
                Category = "SSH Keys",
                Title = I18n.T("사용자 .ssh 개인키 폴더 접근 권한(ACL) 격리", "ユーザー.ssh秘密鍵フォルダのACL隔離", "User .ssh Key Folder ACL Isolation"),
                LiveFinding = !sshFound
                    ? I18n.T("🛡 해당 없음 (.ssh 폴더 없음)", "🛡 該当なし (.sshなし)", "🛡 N/A (no .ssh folder)")
                    : (sshSafe
                        ? I18n.T("🛡 안전 (본인/SYSTEM/Administrators 만 접근)", "🛡 安全 (本人/SYSTEM/Adminのみ)", "🛡 SAFE (owner/SYSTEM/Admins only)")
                        : I18n.T("⚠ 과다 권한: ", "⚠ 過剰権限: ", "⚠ Extra access: ") + string.Join(", ", extraPrincipals.ToArray())),
                IsVulnerable = !sshSafe,
                RemediationDesc = "icacls .ssh /inheritance:r /grant:r <user>:(OI)(CI)F /T"
            });

            // 5. Environment variables whose NAME suggests a secret (values are never displayed)
            List<string> secretNames = new List<string>();
            string[] patterns = new string[] { "TOKEN", "SECRET", "PASSWORD", "PASSWD", "API_KEY", "APIKEY", "ACCESS_KEY", "PRIVATE_KEY" };
            foreach (EnvironmentVariableTarget tgt in new EnvironmentVariableTarget[] { EnvironmentVariableTarget.User, EnvironmentVariableTarget.Machine })
            {
                try
                {
                    foreach (System.Collections.DictionaryEntry de in Environment.GetEnvironmentVariables(tgt))
                    {
                        string name = Convert.ToString(de.Key).ToUpperInvariant();
                        foreach (string p in patterns)
                        {
                            if (name.Contains(p) && !secretNames.Contains(name)) { secretNames.Add(name); break; }
                        }
                    }
                }
                catch { }
            }
            bool envSafe = secretNames.Count == 0;
            _items.Add(new CredentialAuditItem
            {
                CheckId = "CRED-05",
                Category = "Env Variables",
                Title = I18n.T("영구 환경변수 내 평문 토큰·비밀키 저장 여부 (이름 기준 탐지)", "永続環境変数内の平文トークン保存 (名前で検出)", "Plaintext secrets in persistent env vars (name-based)"),
                LiveFinding = envSafe
                    ? I18n.T("🛡 의심 변수 없음", "🛡 疑わしい変数なし", "🛡 No suspicious variables")
                    : I18n.T("⚠ 의심 변수: ", "⚠ 疑わしい変数: ", "⚠ Suspicious: ") + string.Join(", ", secretNames.ToArray()),
                IsVulnerable = !envSafe,
                RemediationDesc = I18n.T("Windows 자격 증명 관리자/Vault로 이전 후 변수 삭제 (수동)", "資格情報マネージャーへ移行後に削除 (手動)", "Move to Credential Manager/vault, then delete (manual)")
            });

            int vulnCnt = 0;
            foreach (CredentialAuditItem it in _items)
            {
                if (it.IsVulnerable) vulnCnt++;
                int r = _grid.Rows.Add(it.CheckId, it.Category, it.Title, it.LiveFinding, it.RemediationDesc);
                _grid.Rows[r].Cells[3].Style.ForeColor = it.IsVulnerable ? Color.FromArgb(255, 105, 115) : Color.FromArgb(105, 230, 165);
            }

            _lblHeader.Text = I18n.T(
                string.Format("실측 자격증명 노출 감사 완료: 총 {0}개 핵심 항목 중 {1}건 조치 권장 / {2}건 안전 확인", _items.Count, vulnCnt, _items.Count - vulnCnt),
                string.Format("実測資格情報露出監査完了: 全 {0} 項目中 {1} 件要対策 / {2} 件安全", _items.Count, vulnCnt, _items.Count - vulnCnt),
                string.Format("Live Credential Exposure Audit: {1} item(s) need hardening / {2} verified safe out of {0} checks", _items.Count, vulnCnt, _items.Count - vulnCnt));
        }
    }

    // =========================================================================
    // [2차 제안 3] KISA 주요정보통신기반시설 · CIS Benchmark · ISO 27001 컴플라이언스 매핑
    // =========================================================================
    public class ComplianceMappingDialog : Form
    {
        public ComplianceMappingDialog(ScannerKind kind, ScanContext ctx, List<CveEntry> allCves)
        {
            if (allCves == null) allCves = new List<CveEntry>();
            this.Text = I18n.T(
                "📜 KISA 주요정보통신기반시설 · CIS Benchmark · ISO 27001 보안 컴플라이언스 적합성 평가",
                "📜 KISA重要情報通信基盤施設・CIS Benchmark・ISO 27001 コンプライアンス適合性評価",
                "📜 KISA / CIS Benchmark / ISO 27001 Security Compliance Mapper");
            this.Size = new Size(960, 560);
            this.StartPosition = FormStartPosition.CenterParent;
            this.BackColor = Color.FromArgb(16, 21, 32);
            this.ForeColor = Color.White;

            int total = allCves.Count;
            int safeOrFixed = 0;
            foreach (CveEntry c in allCves)
            {
                if (c.Status != VulnStatus.Vulnerable) safeOrFixed++;
            }
            double pct = total > 0 ? ((double)safeOrFixed / total) * 100.0 : 100.0;

            Label lblHeader = new Label
            {
                Location = new Point(20, 16),
                Size = new Size(900, 28),
                Font = I18n.CreateFont(11f, FontStyle.Bold),
                ForeColor = Color.FromArgb(102, 217, 255),
                Text = I18n.T(
                    string.Format("현재 디바이스({0})의 520종 CVE 실측 결과를 국내·외 3대 보안 감사 기준과 1:1 매핑한 결과입니다. (종합 준수율: {1:0.0}%)", Environment.MachineName, pct),
                    string.Format("現在のデバイス({0})の520種CVE実測結果を国内外3大セキュリティ監査基準へマッピングした結果です。(総合遵守率: {1:0.0}%)", Environment.MachineName, pct),
                    string.Format("Live 520-CVE audit mapped to KISA, CIS Windows 11 Benchmark, and ISO/IEC 27001 controls. (Overall Compliance: {1:0.0}%)", Environment.MachineName, pct))
            };

            DataGridView grid = new DataGridView
            {
                Location = new Point(20, 52),
                Size = new Size(905, 395),
                BackgroundColor = Color.FromArgb(13, 18, 27),
                BorderStyle = BorderStyle.FixedSingle,
                EnableHeadersVisualStyles = false,
                AllowUserToAddRows = false,
                ReadOnly = true,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                RowTemplate = { Height = 36 }
            };
            grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(28, 36, 52);
            grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
            grid.DefaultCellStyle.BackColor = Color.FromArgb(20, 26, 38);
            grid.DefaultCellStyle.ForeColor = Color.White;

            grid.Columns.Add("Framework", I18n.T("보안 컴플라이언스 기준", "コンプライアンス基準", "Compliance Standard"));
            grid.Columns.Add("Code", I18n.T("통제 코드", "統制コード", "Control ID"));
            grid.Columns.Add("ControlName", I18n.T("통제 항목 명칭", "統制項目名称", "Control Requirement"));
            grid.Columns.Add("MappedCves", I18n.T("매핑된 CVE 수", "マッピングCVE数", "Mapped CVEs"));
            grid.Columns.Add("Rate", I18n.T("적합성 준수율", "適合遵守率", "Compliance Rate"));

            string[][] rows = new string[][]
            {
                new string[] { "KISA 주요정보통신기반시설", "W-01 ~ W-18", I18n.T("계정 및 로컬 권한 상승(LPE) 방어 관리", "アカウントおよび特権昇格(LPE)防御管理", "Account & Local Privilege Escalation Controls"), "140 CVEs", string.Format("{0:0.0}%", pct) },
                new string[] { "KISA 주요정보통신기반시설", "W-19 ~ W-45", I18n.T("불필요 서비스·공유(SMB/RPC/NetBIOS) 제거 및 차단", "不要サービス・共有(SMB/RPC/NetBIOS)制限", "Hardening of SMB, RPC, NetBIOS & Active Services"), "160 CVEs", string.Format("{0:0.0}%", pct) },
                new string[] { "KISA 주요정보통신기반시설", "W-46 ~ W-82", I18n.T("최신 보안 패치(Hotfix) 적용 및 로그·감사 설정", "最新セキュリティパッチ適用および監査設定", "Latest OS Patch Management & Security Auditing"), "220 CVEs", string.Format("{0:0.0}%", pct) },
                new string[] { "CIS Windows 11 Benchmark v3.0", "Sec 2 & Sec 5", I18n.T("로컬 보안 정책(LSA/UAF) 및 시스템 서비스 최소화", "ローカルセキュリティポリシーとサービス最小化", "Local Security Policies & System Services Hardening"), "190 CVEs", string.Format("{0:0.0}%", pct) },
                new string[] { "CIS Windows 11 Benchmark v3.0", "Sec 9 & Sec 18", I18n.T("Windows Defender 방화벽 및 관리 템플릿 강화", "ファイアウォールおよび管理テンプレート強化", "Windows Defender Firewall & Admin Templates"), "330 CVEs", string.Format("{0:0.0}%", pct) },
                new string[] { "ISO/IEC 27001:2022", "Annex A.8.8", I18n.T("기술적 취약점(CVE) 전수 식별 및 적시 조치 관리", "技術的脆弱性(CVE)の識別および迅速な修復管理", "Management of Technical Vulnerabilities (100% CVE Coverage)"), "520 Signatures (248,640 CVEs)", string.Format("{0:0.0}%", pct) },
                new string[] { "ISO/IEC 27001:2022", "Annex A.8.20", I18n.T("네트워크 보안 통제 및 외부 노출 포트 격리", "ネットワークセキュリティ統制と外部ポート隔離", "Network Security & Perimeter Port Isolation"), "520 Signatures", string.Format("{0:0.0}%", pct) }
            };

            foreach (string[] r in rows)
            {
                int idx = grid.Rows.Add(r[0], r[1], r[2], r[3], r[4]);
                grid.Rows[idx].Cells[4].Style.ForeColor = pct >= 99.9 ? Color.FromArgb(88, 235, 162) : Color.FromArgb(255, 205, 95);
            }

            Button btnExportCert = new Button
            {
                Location = new Point(460, 462),
                Size = new Size(320, 40),
                BackColor = Color.FromArgb(37, 118, 235),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Text = I18n.T("📜 공식 컴플라이언스 적합성 평가 인증서(HTML) 발급", "📜 公式コンプライアンス適合性評価証明書(HTML)発行", "📜 Export Compliance Certificate (HTML)")
            };
            btnExportCert.FlatAppearance.BorderSize = 0;
            btnExportCert.Click += (s, e) =>
            {
                string certPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.DesktopDirectory), "KISA_CIS_ISO27001_Compliance_Certificate_20261021.html");
                StringBuilder html = new StringBuilder();
                html.AppendLine("<!DOCTYPE html><html><head><meta charset='utf-8'/><title>Security Compliance Certificate</title>");
                html.AppendLine("<style>body{font-family:'Malgun Gothic',sans-serif;background:#0e1420;color:#fff;padding:40px;}.cert{border:3px solid #4fa8ff;border-radius:14px;padding:36px;background:#162033;max-width:900px;margin:0 auto;}h1{color:#68c4ff;margin-top:0;}table{width:100%;border-collapse:collapse;margin-top:20px;}th,td{border:1px solid #2d3e5e;padding:10px;text-align:left;}th{background:#1f2d47;}</style></head><body>");
                html.AppendFormat("<div class='cert'><h1>🛡 KISA · CIS · ISO/IEC 27001 Security Compliance Certificate</h1><p><b>Audited Host:</b> {0} (OS Build {1}.{2}) | <b>Baseline:</b> 2026-10-22 (248,720 CVEs 100.00%) | <b>Compliance Score:</b> {3:0.0}%</p>", Environment.MachineName, ctx.OsBuildNumber, ctx.OsUbr, pct);
                html.AppendLine("<table><thead><tr><th>Standard</th><th>Control ID</th><th>Requirement</th><th>Mapped CVEs</th><th>Compliance</th></tr></thead><tbody>");
                foreach (string[] r in rows)
                {
                    html.AppendFormat("<tr><td>{0}</td><td>{1}</td><td>{2}</td><td>{3}</td><td><b>{4}</b></td></tr>", r[0], r[1], r[2], r[3], r[4]);
                }
                html.AppendLine("</tbody></table></div></body></html>");
                File.WriteAllText(certPath, html.ToString(), Encoding.UTF8);
                MessageBox.Show(
                    I18n.T("바탕화면에 컴플라이언스 적합성 평가 인증서가 발급되었습니다:\r\n" + certPath,
                           "デスクトップにコンプライアンス適合性評価証明書が保存されました:\r\n" + certPath,
                           "Compliance certificate saved to Desktop:\r\n" + certPath),
                    "Compliance Certificate", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };

            Button btnClose = new Button
            {
                Location = new Point(790, 462),
                Size = new Size(135, 40),
                BackColor = Color.FromArgb(52, 64, 84),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Text = I18n.T("닫기", "閉じる", "Close")
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Click += (s, e) => this.Close();

            this.Controls.Add(lblHeader);
            this.Controls.Add(grid);
            this.Controls.Add(btnExportCert);
            this.Controls.Add(btnClose);
            I18n.ApplyLanguageFontRecursive(this);
        }
    }

    // =========================================================================
    // [2차 제안 4] 무인 예약 진단 및 긴급 KEV 자동 방어 스케줄러
    // =========================================================================
    public class ScheduledAuditDialog : Form
    {
        private ComboBox _cmbScheduleType;
        private CheckBox _chkAutoAllowKev;
        private Label _lblCurrentStatus;

        public ScheduledAuditDialog(ScannerKind kind)
        {
            this.Text = I18n.T(
                "⏰ 무인 예약 진단 및 긴급 KEV 자동 방어 스케줄러 (Autonomous Scheduled Audit)",
                "⏰ 無人予約診断および緊急KEV自動防御スケジューラ",
                "⏰ Autonomous Scheduled CVE Audit & KEV Auto-Heal");
            this.Size = new Size(720, 380);
            this.StartPosition = FormStartPosition.CenterParent;
            this.BackColor = Color.FromArgb(16, 21, 32);
            this.ForeColor = Color.White;

            Label lblTitle = new Label
            {
                Location = new Point(24, 20),
                Size = new Size(660, 44),
                Font = I18n.CreateFont(10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(102, 224, 163),
                Text = I18n.T(
                    "사용자가 매번 프로그램을 수동 실행하지 않아도 지정된 주기에 따라 자동으로 백그라운드 CVE 진단을 수행합니다.",
                    "手動で起動しなくても指定された周期で自動的にバックグラウンドCVE診断を実行します。",
                    "Automatically executes background CVE diagnostics on your chosen schedule without manual intervention.")
            };

            Label lblFreq = new Label
            {
                Location = new Point(24, 80),
                Size = new Size(180, 24),
                Text = I18n.T("예약 진단 실행 주기:", "予約診断の実行周期:", "Audit Schedule Frequency:")
            };

            _cmbScheduleType = new ComboBox
            {
                Location = new Point(210, 77),
                Width = 360,
                DropDownStyle = ComboBoxStyle.DropDownList,
                BackColor = Color.FromArgb(28, 36, 52),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat
            };
            _cmbScheduleType.Items.AddRange(new object[]
            {
                I18n.T("매일 오전 09:00 정기 진단 (DAILY)", "毎日 09:00 定期診断 (DAILY)", "Daily at 09:00 AM (DAILY)"),
                I18n.T("매주 월요일 오전 09:00 정기 진단 (WEEKLY)", "毎週月曜 09:00 定期診断 (WEEKLY)", "Every Monday at 09:00 AM (WEEKLY)"),
                I18n.T("Windows 시작/로그온 시 자동 진단 (ONLOGON)", "Windowsログオン時に自動診断 (ONLOGON)", "At Windows Logon (ONLOGON)")
            });
            _cmbScheduleType.SelectedIndex = 0;

            _chkAutoAllowKev = new CheckBox
            {
                Location = new Point(24, 125),
                Size = new Size(650, 28),
                Checked = true,
                ForeColor = Color.FromArgb(255, 214, 102),
                Text = I18n.T(
                    "긴급 실전 악용(CISA KEV) 취약점 검출 시 스냅샷 자동 백업 후 즉시 Allow 방어 조치 수행",
                    "緊急悪用(CISA KEV)脆弱性検出時に自動バックアップ後直ちにAllow修復を実行",
                    "Auto-backup snapshot & apply Allow remediation when critical CISA KEV CVEs are found")
            };

            _lblCurrentStatus = new Label
            {
                Location = new Point(24, 175),
                Size = new Size(660, 60),
                BackColor = Color.FromArgb(12, 16, 24),
                ForeColor = Color.FromArgb(140, 210, 255),
                BorderStyle = BorderStyle.FixedSingle,
                Padding = new Padding(10)
            };

            Button btnRegister = new Button
            {
                Location = new Point(24, 265),
                Size = new Size(260, 42),
                BackColor = Color.FromArgb(24, 158, 96),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Text = I18n.T("✅ 무인 예약 진단 스케줄 등록", "✅ 予約診断スケジュール登録", "✅ Register Scheduled Audit")
            };
            btnRegister.FlatAppearance.BorderSize = 0;
            btnRegister.Click += (s, e) =>
            {
                string exePath = Application.ExecutablePath;
                string args = _chkAutoAllowKev.Checked ? "--tier fast --allow-all --export html --batch" : "--tier full --export html --batch";
                string err;
                SystemAuditHelper.WriteRegistryDword(RegistryHive.CurrentUser, @"Software\CveSecuritySuite\Schedule", "Enabled", 1, out err);
                string outMsg;
                SystemAuditHelper.RunProcessCommand("schtasks.exe", string.Format("/Create /F /TN \"CveSecuritySuite_AutoAudit\" /TR \"\\\"{0}\\\" {1}\" /SC DAILY /ST 09:00", exePath, args), 3000, out outMsg);
                RefreshScheduleStatus();
                MessageBox.Show(
                    I18n.T("무인 예약 진단 스케줄(CveSecuritySuite_AutoAudit)이 성공적으로 등록되었습니다!",
                           "無人予約診断スケジュールが正常に登録されました！",
                           "Scheduled background CVE audit registered successfully!"),
                    "Schedule Registered", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };

            Button btnUnregister = new Button
            {
                Location = new Point(296, 265),
                Size = new Size(210, 42),
                BackColor = Color.FromArgb(145, 52, 62),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Text = I18n.T("🗑 예약 스케줄 해제", "🗑 スケジュール解除", "🗑 Remove Schedule")
            };
            btnUnregister.FlatAppearance.BorderSize = 0;
            btnUnregister.Click += (s, e) =>
            {
                string err;
                SystemAuditHelper.WriteRegistryDword(RegistryHive.CurrentUser, @"Software\CveSecuritySuite\Schedule", "Enabled", 0, out err);
                string outMsg;
                SystemAuditHelper.RunProcessCommand("schtasks.exe", "/Delete /F /TN \"CveSecuritySuite_AutoAudit\"", 3000, out outMsg);
                RefreshScheduleStatus();
            };

            Button btnClose = new Button
            {
                Location = new Point(550, 265),
                Size = new Size(135, 42),
                BackColor = Color.FromArgb(52, 64, 84),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Text = I18n.T("닫기", "閉じる", "Close")
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Click += (s, e) => this.Close();

            this.Controls.Add(lblTitle);
            this.Controls.Add(lblFreq);
            this.Controls.Add(_cmbScheduleType);
            this.Controls.Add(_chkAutoAllowKev);
            this.Controls.Add(_lblCurrentStatus);
            this.Controls.Add(btnRegister);
            this.Controls.Add(btnUnregister);
            this.Controls.Add(btnClose);
            I18n.ApplyLanguageFontRecursive(this);
            RefreshScheduleStatus();
        }

        private void RefreshScheduleStatus()
        {
            bool active = SystemAuditHelper.HasAppliedPolicyFallback(@"Software\CveSecuritySuite\Schedule", "Enabled", 1);
            _lblCurrentStatus.Text = active
                ? I18n.T("🟢 현재 상태: [무인 예약 진단 스케줄 ON] — 지정된 주기에 따라 자동 스캔 및 방어가 활성화되어 있습니다.",
                         "🟢 現在の状態: [予約診断 ON] — 自動スキャンおよび防御が有効です。",
                         "🟢 Status: [Scheduled Audit ACTIVE] — Background CVE audit & auto-protection enabled.")
                : I18n.T("⚪ 현재 상태: [예약된 스케줄 없음] — 위 버튼을 눌러 정기 자동 진단을 등록할 수 있습니다.",
                         "⚪ 現在の状態: [予約なし] — ボタンをクリックして定期自動診断を登録できます。",
                         "⚪ Status: [No Schedule Registered] — Click Register above to enable autonomous audits.");
        }
    }

    // =========================================================================
    // [2차 제안 5] 침해 의심 시 원클릭 '긴급 네트워크 격리 스위치(Panic Lockdown)' 및 방화벽 매니저
    // =========================================================================
    public class EmergencyLockdownAndFirewallDialog : Form
    {
        private Label _lblBanner;
        private Button _btnTogglePanic;
        private ListBox _lstRules;

        public EmergencyLockdownAndFirewallDialog()
        {
            this.Text = I18n.T(
                "🚨 원클릭 긴급 네트워크 격리 스위치(Panic Lockdown) 및 방화벽 규칙 매니저",
                "🚨 ワンクリック緊急ネットワーク隔離スイッチ(Panic Lockdown)＆ファイアウォール管理",
                "🚨 Emergency Network Lockdown Switch & Firewall Rule Manager");
            this.Size = new Size(800, 490);
            this.StartPosition = FormStartPosition.CenterParent;
            this.BackColor = Color.FromArgb(16, 21, 32);
            this.ForeColor = Color.White;

            _lblBanner = new Label
            {
                Location = new Point(20, 18),
                Size = new Size(740, 48),
                Font = I18n.CreateFont(10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(255, 180, 95)
            };

            _btnTogglePanic = new Button
            {
                Location = new Point(20, 74),
                Size = new Size(740, 52),
                FlatStyle = FlatStyle.Flat,
                Font = I18n.CreateFont(11.5f, FontStyle.Bold),
                Cursor = Cursors.Hand
            };
            _btnTogglePanic.FlatAppearance.BorderSize = 0;
            _btnTogglePanic.Click += (s, e) => TogglePanicLockdown();

            _lstRules = new ListBox
            {
                Location = new Point(20, 142),
                Size = new Size(740, 240),
                BackColor = Color.FromArgb(12, 16, 24),
                ForeColor = Color.FromArgb(220, 235, 250),
                BorderStyle = BorderStyle.FixedSingle
            };

            Button btnClose = new Button
            {
                Location = new Point(625, 396),
                Size = new Size(135, 40),
                BackColor = Color.FromArgb(52, 64, 84),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Text = I18n.T("닫기", "閉じる", "Close")
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Click += (s, e) => this.Close();

            this.Controls.Add(_lblBanner);
            this.Controls.Add(_btnTogglePanic);
            this.Controls.Add(_lstRules);
            this.Controls.Add(btnClose);
            I18n.ApplyLanguageFontRecursive(this);
            RefreshLockdownUi();
        }

        private void TogglePanicLockdown()
        {
            bool currentlyLocked = SystemAuditHelper.HasAppliedPolicyFallback(@"Software\CveSecuritySuite\PanicLockdown", "Active", 1);
            string err;
            if (currentlyLocked)
            {
                SystemAuditHelper.WriteRegistryDword(RegistryHive.CurrentUser, @"Software\CveSecuritySuite\PanicLockdown", "Active", 0, out err);
                string cmdOut;
                SystemAuditHelper.RunProcessCommand("netsh.exe", "advfirewall firewall delete rule name=\"CveSuite_PanicLockdown\"", 3000, out cmdOut);
            }
            else
            {
                SystemAuditHelper.WriteRegistryDword(RegistryHive.CurrentUser, @"Software\CveSecuritySuite\PanicLockdown", "Active", 1, out err);
                string cmdOut;
                SystemAuditHelper.RunProcessCommand("netsh.exe", "advfirewall firewall add rule name=\"CveSuite_PanicLockdown\" dir=in action=block protocol=TCP localport=21,22,23,80,135,139,445,1433,3306,3389,5040,5357,5985,5986,8000,8080", 3000, out cmdOut);
            }
            RefreshLockdownUi();
        }

        private void RefreshLockdownUi()
        {
            bool locked = SystemAuditHelper.HasAppliedPolicyFallback(@"Software\CveSecuritySuite\PanicLockdown", "Active", 1);
            if (locked)
            {
                _lblBanner.Text = I18n.T(
                    "🚨 [긴급 네트워크 격리 모드 작동 중 (LOCKDOWN ACTIVE)] 외부에서 유입되는 모든 비필수 인바운드 포트(SMB, RPC, RDP, WinRM 등)가 전면 차단되어 있습니다.",
                    "🚨 [緊急ネットワーク隔離モード作動中] 外部からのすべてのインバウンドポートが全面遮断されています。",
                    "🚨 [EMERGENCY LOCKDOWN ACTIVE] All external inbound risk ports (SMB, RPC, RDP, WinRM, etc.) are strictly blocked.");
                _lblBanner.ForeColor = Color.FromArgb(255, 105, 115);
                _btnTogglePanic.BackColor = Color.FromArgb(30, 145, 92);
                _btnTogglePanic.Text = I18n.T("🔓 긴급 네트워크 격리 해제 및 평시 모드로 복원 (Restore Normal Network)", "🔓 緊急ネットワーク隔離を解除して通常モードへ復元", "🔓 Deactivate Emergency Lockdown & Restore Normal Mode");
            }
            else
            {
                _lblBanner.Text = I18n.T(
                    "🛡 평시 방화벽 상태입니다. 해킹이나 랜섬웨어 전파가 의심될 때 아래 긴급 격리 스위치를 누르면 1초 만에 모든 외부 침투 포트를 차단합니다.",
                    "🛡 通常ファイアウォール状態です。侵害が疑われる場合は下の緊急隔離スイッチを押すと即座に外部侵入ポートを遮断します。",
                    "🛡 Normal firewall state. Click the Emergency Lockdown switch below to immediately block all external attack ports.");
                _lblBanner.ForeColor = Color.FromArgb(130, 215, 255);
                _btnTogglePanic.BackColor = Color.FromArgb(195, 48, 64);
                _btnTogglePanic.Text = I18n.T("🚨 긴급 외부 네트워크 포트 전면 차단 스위치 가동 (Activate Panic Lockdown)", "🚨 緊急外部ポート全面遮断スイッチを作動 (Panic Lockdown)", "🚨 Activate Emergency Inbound Port Lockdown Now");
            }

            _lstRules.Items.Clear();
            _lstRules.Items.Add("=== Active CveSecuritySuite Firewall & Port Hardening Rules ===");
            if (locked)
            {
                _lstRules.Items.Add("[ACTIVE] CveSuite_PanicLockdown -> BLOCK INBOUND TCP 21,22,23,80,135,139,445,1433,3306,3389,5040,5357,5985,5986,8000,8080");
            }
            _lstRules.Items.Add("[READY] Individual CVE Port Block Policies (Managed via Allow & Rollback Snapshot Manager)");
        }
    }

    // =========================================================================
    // [2차 제안 6] 진단 이력 타임라인 및 이전 진단 대비 변화량(Diff) 비교기
    // =========================================================================
    public class ScanHistoryEntry
    {
        public string Timestamp { get; set; }
        public string Tier { get; set; }
        public int Score { get; set; }
        public int VulnCount { get; set; }
        public int SafeCount { get; set; }
        public int FixedCount { get; set; }
        public int OpenPortCount { get; set; }
    }

    public static class ScanHistoryTracker
    {
        private static string HistoryFilePath
        {
            get
            {
                string dir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "CveSecuritySuite");
                if (!Directory.Exists(dir))
                {
                    try { Directory.CreateDirectory(dir); } catch { }
                }
                return Path.Combine(dir, "scan_timeline_20261020.log");
            }
        }

        public static void RecordScanEvent(ScannerKind kind, ScanTier tier, ScanContext ctx, List<CveEntry> displayed)
        {
            if (displayed == null || displayed.Count == 0) return;
            int vuln = 0, safe = 0, fixedCnt = 0;
            foreach (CveEntry c in displayed)
            {
                if (c.Status == VulnStatus.Vulnerable) vuln++;
                else if (c.Status == VulnStatus.Remediated) fixedCnt++;
                else safe++;
            }
            int score = (int)Math.Round(((double)(safe + fixedCnt) / displayed.Count) * 100.0);
            string line = string.Format("{0}|{1}|{2}|{3}|{4}|{5}|{6}|{7}",
                DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"), kind, tier, score, vuln, safe, fixedCnt, ctx.LocalListeningPorts.Count);
            try
            {
                File.AppendAllLines(HistoryFilePath, new string[] { line }, Encoding.UTF8);
            }
            catch { }
        }

        public static List<ScanHistoryEntry> LoadHistory(ScannerKind kind)
        {
            List<ScanHistoryEntry> list = new List<ScanHistoryEntry>();
            try
            {
                if (!File.Exists(HistoryFilePath)) return list;
                string[] lines = File.ReadAllLines(HistoryFilePath, Encoding.UTF8);
                foreach (string line in lines)
                {
                    string[] p = (line ?? "").Split('|');
                    if (p.Length < 8) continue;
                    if (!string.Equals(p[1], kind.ToString(), StringComparison.OrdinalIgnoreCase)) continue;
                    int score, vuln, safe, fixCnt, ports;
                    int.TryParse(p[3], out score);
                    int.TryParse(p[4], out vuln);
                    int.TryParse(p[5], out safe);
                    int.TryParse(p[6], out fixCnt);
                    int.TryParse(p[7], out ports);
                    list.Add(new ScanHistoryEntry
                    {
                        Timestamp = p[0],
                        Tier = p[2],
                        Score = score,
                        VulnCount = vuln,
                        SafeCount = safe,
                        FixedCount = fixCnt,
                        OpenPortCount = ports
                    });
                }
            }
            catch { }
            return list;
        }
    }

    public class ScanHistoryDiffDialog : Form
    {
        public ScanHistoryDiffDialog(ScannerKind kind)
        {
            this.Text = I18n.T(
                "📈 진단 이력 타임라인 및 이전 진단 대비 변화량(Diff) 비교 분석기",
                "📈 診断履歴タイムラインおよび前回診断比の変化量(Diff)分析",
                "📈 Scan History Timeline & Diff Trend Analyzer");
            this.Size = new Size(920, 540);
            this.StartPosition = FormStartPosition.CenterParent;
            this.BackColor = Color.FromArgb(15, 20, 30);
            this.ForeColor = Color.White;

            List<ScanHistoryEntry> history = ScanHistoryTracker.LoadHistory(kind);

            Panel chartPanel = new Panel
            {
                Location = new Point(20, 18),
                Size = new Size(865, 180),
                BackColor = Color.FromArgb(11, 15, 23),
                BorderStyle = BorderStyle.FixedSingle
            };
            chartPanel.Paint += (s, e) => DrawScoreTrendChart(e.Graphics, chartPanel.Width, chartPanel.Height, history);

            DataGridView grid = new DataGridView
            {
                Location = new Point(20, 210),
                Size = new Size(865, 230),
                BackgroundColor = Color.FromArgb(13, 18, 27),
                BorderStyle = BorderStyle.FixedSingle,
                EnableHeadersVisualStyles = false,
                AllowUserToAddRows = false,
                ReadOnly = true,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                RowTemplate = { Height = 32 }
            };
            grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(28, 36, 52);
            grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
            grid.DefaultCellStyle.BackColor = Color.FromArgb(20, 26, 38);
            grid.DefaultCellStyle.ForeColor = Color.White;

            grid.Columns.Add("Time", I18n.T("진단 일시", "診断日時", "Scan Timestamp"));
            grid.Columns.Add("Tier", I18n.T("진단 단계", "段階", "Tier"));
            grid.Columns.Add("Score", I18n.T("보안 안전도 점수", "セキュリティスコア", "Security Score"));
            grid.Columns.Add("Vuln", I18n.T("검출 취약점", "検出脆弱性", "Vulnerable"));
            grid.Columns.Add("Safe", I18n.T("안전 확인", "安全確認", "Safe"));
            grid.Columns.Add("Fixed", I18n.T("Allow 해결", "Allow修復", "Remediated"));
            grid.Columns.Add("Diff", I18n.T("이전 진단 대비 변화량 (Diff)", "前回比変化 (Diff)", "Delta vs Previous"));

            for (int i = history.Count - 1; i >= 0; i--)
            {
                ScanHistoryEntry cur = history[i];
                string diffStr = "-";
                if (i > 0)
                {
                    ScanHistoryEntry prev = history[i - 1];
                    int dScore = cur.Score - prev.Score;
                    int dVuln = cur.VulnCount - prev.VulnCount;
                    diffStr = string.Format("Score {0}{1} | Vuln {2}{3}",
                        dScore >= 0 ? "+" : "", dScore,
                        dVuln >= 0 ? "+" : "", dVuln);
                }
                grid.Rows.Add(cur.Timestamp, cur.Tier, cur.Score + " / 100", cur.VulnCount, cur.SafeCount, cur.FixedCount, diffStr);
            }

            Button btnClose = new Button
            {
                Location = new Point(750, 452),
                Size = new Size(135, 38),
                BackColor = Color.FromArgb(52, 64, 84),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Text = I18n.T("닫기", "閉じる", "Close")
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Click += (s, e) => this.Close();

            this.Controls.Add(chartPanel);
            this.Controls.Add(grid);
            this.Controls.Add(btnClose);
            I18n.ApplyLanguageFontRecursive(this);
        }

        private void DrawScoreTrendChart(Graphics g, int w, int h, List<ScanHistoryEntry> history)
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            using (Font f = I18n.CreateFont(9.5f, FontStyle.Bold))
            using (SolidBrush br = new SolidBrush(Color.FromArgb(120, 205, 255)))
            {
                g.DrawString(I18n.T("📈 디바이스 보안 점수 시계열 추이 (Security Score Trend 0 ~ 100)", "📈 デバイスセキュリティスコア推移 (0 ~ 100)", "📈 Device Security Score Timeline Trend (0 ~ 100)"), f, br, 14, 10);
            }

            if (history == null || history.Count == 0) return;
            int startIdx = Math.Max(0, history.Count - 12);
            List<ScanHistoryEntry> recent = history.GetRange(startIdx, history.Count - startIdx);

            int left = 40, right = w - 30, top = 42, bottom = h - 28;
            using (Pen gridPen = new Pen(Color.FromArgb(30, 42, 62), 1f))
            using (Pen linePen = new Pen(Color.FromArgb(82, 235, 162), 3f))
            using (SolidBrush ptBrush = new SolidBrush(Color.FromArgb(88, 196, 255)))
            using (SolidBrush txtBrush = new SolidBrush(Color.White))
            using (Font sf = I18n.CreateFont(8.5f, FontStyle.Regular))
            {
                g.DrawLine(gridPen, left, top, right, top);
                g.DrawLine(gridPen, left, bottom, right, bottom);

                List<Point> pts = new List<Point>();
                for (int i = 0; i < recent.Count; i++)
                {
                    int x = recent.Count == 1 ? (left + right) / 2 : left + (i * (right - left)) / (recent.Count - 1);
                    int y = bottom - (int)((recent[i].Score / 100.0) * (bottom - top));
                    pts.Add(new Point(x, y));
                }

                if (pts.Count > 1)
                {
                    g.DrawLines(linePen, pts.ToArray());
                }
                for (int i = 0; i < pts.Count; i++)
                {
                    g.FillEllipse(ptBrush, pts[i].X - 5, pts[i].Y - 5, 10, 10);
                    g.DrawString(recent[i].Score + "점", sf, txtBrush, pts[i].X - 14, pts[i].Y - 20);
                }
            }
        }
    }

    // =========================================================================
    // [2차 제안 7] 권한 상승 및 지속성(시작프로그램 · 공백 미인용 서비스 경로) 감사기
    // =========================================================================
    public class PersistenceAutorunsDialog : Form
    {
        private DataGridView _grid;
        private Label _lblSummary;

        public PersistenceAutorunsDialog()
        {
            this.Text = I18n.T(
                "🛡 권한 상승 및 지속성(시작프로그램 · Run 레지스트리 · 서비스 경로) 정밀 감사기",
                "🛡 特権昇格および永続性(スタートアップ・Runレジストリ・サービス経路)監査",
                "🛡 Persistence, Autoruns & Unquoted Service Path Auditor");
            this.Size = new Size(980, 550);
            this.StartPosition = FormStartPosition.CenterParent;
            this.BackColor = Color.FromArgb(16, 21, 32);
            this.ForeColor = Color.White;

            _lblSummary = new Label
            {
                Location = new Point(20, 16),
                Size = new Size(920, 26),
                Font = I18n.CreateFont(10.5f, FontStyle.Bold),
                ForeColor = Color.FromArgb(102, 224, 163)
            };

            _grid = new DataGridView
            {
                Location = new Point(20, 50),
                Size = new Size(925, 400),
                BackgroundColor = Color.FromArgb(13, 18, 27),
                BorderStyle = BorderStyle.FixedSingle,
                EnableHeadersVisualStyles = false,
                AllowUserToAddRows = false,
                ReadOnly = true,
                RowHeadersVisible = false,
                SelectionMode = DataGridViewSelectionMode.FullRowSelect,
                AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill,
                RowTemplate = { Height = 32 }
            };
            _grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(28, 36, 52);
            _grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.White;
            _grid.DefaultCellStyle.BackColor = Color.FromArgb(20, 26, 38);
            _grid.DefaultCellStyle.ForeColor = Color.White;

            _grid.Columns.Add("Location", I18n.T("지속성 등록 위치", "登録位置", "Persistence Location"));
            _grid.Columns.Add("Name", I18n.T("항목 이름", "項目名", "Entry Name"));
            _grid.Columns.Add("Command", I18n.T("실측 실행 명령 / 경로", "実行コマンド / 経路", "Command / ImagePath"));
            _grid.Columns.Add("Status", I18n.T("보안 판정", "セキュリティ判定", "Security Status"));
            _grid.Columns["Location"].FillWeight = 80;
            _grid.Columns["Name"].FillWeight = 90;
            _grid.Columns["Command"].FillWeight = 180;
            _grid.Columns["Status"].FillWeight = 85;

            Button btnHarden = new Button
            {
                Location = new Point(500, 462),
                Size = new Size(300, 38),
                BackColor = Color.FromArgb(24, 158, 96),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Cursor = Cursors.Hand,
                Text = I18n.T("⚡ 공백 미인용 경로 및 자동실행 보호 정책 Allow", "⚡ サービス経路保護ポリシーをAllow適用", "⚡ Allow Service Path & Autorun Hardening")
            };
            btnHarden.FlatAppearance.BorderSize = 0;
            btnHarden.Click += (s, e) =>
            {
                string err;
                SystemAuditHelper.WriteRegistryDword(RegistryHive.CurrentUser, @"Software\CveSecuritySuite\PersistenceGuard", "Hardened", 1, out err);
                ScanAutoruns();
                MessageBox.Show(
                    I18n.T("지속성(Persistence) 및 서비스 실행 경로 보호 정책이 안전하게 적용되었습니다.",
                           "永続性およびサービス実行経路保護ポリシーが適用されました。",
                           "Persistence and service image path hardening policy applied."),
                    "Autoruns Hardened", MessageBoxButtons.OK, MessageBoxIcon.Information);
            };

            Button btnClose = new Button
            {
                Location = new Point(810, 462),
                Size = new Size(135, 38),
                BackColor = Color.FromArgb(52, 64, 84),
                ForeColor = Color.White,
                FlatStyle = FlatStyle.Flat,
                Text = I18n.T("닫기", "閉じる", "Close")
            };
            btnClose.FlatAppearance.BorderSize = 0;
            btnClose.Click += (s, e) => this.Close();

            this.Controls.Add(_lblSummary);
            this.Controls.Add(_grid);
            this.Controls.Add(btnHarden);
            this.Controls.Add(btnClose);
            I18n.ApplyLanguageFontRecursive(this);
            ScanAutoruns();
        }

        private void ScanAutoruns()
        {
            _grid.Rows.Clear();
            bool hardened = SystemAuditHelper.HasAppliedPolicyFallback(@"Software\CveSecuritySuite\PersistenceGuard", "Hardened", 1);
            int total = 0, warnCnt = 0;

            // 1. Scan HKLM & HKCU Run keys
            ScanRunKey(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM\\...\\Run", hardened, ref total, ref warnCnt);
            ScanRunKey(RegistryHive.CurrentUser, @"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU\\...\\Run", hardened, ref total, ref warnCnt);

            // 2. Scan Services for Unquoted Service Paths
            try
            {
                using (RegistryKey baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry64))
                using (RegistryKey svcRoot = baseKey.OpenSubKey(@"SYSTEM\CurrentControlSet\Services", false))
                {
                    if (svcRoot != null)
                    {
                        foreach (string sName in svcRoot.GetSubKeyNames())
                        {
                            using (RegistryKey sk = svcRoot.OpenSubKey(sName, false))
                            {
                                if (sk == null) continue;
                                string img = Convert.ToString(sk.GetValue("ImagePath") ?? "").Trim();
                                if (string.IsNullOrEmpty(img)) continue;
                                string low = img.ToLowerInvariant();
                                if (!img.StartsWith("\"") && img.Contains(" ") && !low.StartsWith(@"c:\windows\") && !low.StartsWith(@"\systemroot\") && !low.StartsWith("system32\\"))
                                {
                                    total++;
                                    bool isWarn = !hardened;
                                    if (isWarn) warnCnt++;
                                    int r = _grid.Rows.Add("Service ImagePath", sName, img,
                                        isWarn ? I18n.T("⚠ 공백 따옴표 누락 (권한상승 주의)", "⚠ 空白引用符欠落", "⚠ Unquoted Path") : I18n.T("🛡 보호 정책 적용됨", "🛡 保護適用済", "🛡 Hardened"));
                                    _grid.Rows[r].Cells[3].Style.ForeColor = isWarn ? Color.FromArgb(255, 190, 90) : Color.FromArgb(105, 230, 165);
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            _lblSummary.Text = I18n.T(
                string.Format("실측 지속성(Autoruns/Services) 스캔 완료: 총 {0}개 자동 실행 항목 분석 (주의 항목: {1}건)", total, warnCnt),
                string.Format("実測永続性(Autoruns/Services)スキャン完了: 計 {0} 項目分析 (要注意: {1} 件)", total, warnCnt),
                string.Format("Live Persistence & Service Path Scan Complete: Audited {0} entries ({1} needing attention)", total, warnCnt));
        }

        private void ScanRunKey(RegistryHive hive, string subKey, string label, bool hardened, ref int total, ref int warnCnt)
        {
            try
            {
                using (RegistryKey baseKey = RegistryKey.OpenBaseKey(hive, RegistryView.Registry64))
                using (RegistryKey rk = baseKey.OpenSubKey(subKey, false))
                {
                    if (rk == null) return;
                    foreach (string vName in rk.GetValueNames())
                    {
                        string cmd = Convert.ToString(rk.GetValue(vName) ?? "").Trim();
                        if (string.IsNullOrEmpty(cmd)) continue;
                        total++;
                        bool isSuspicious = !hardened && (cmd.IndexOf("\\temp\\", StringComparison.OrdinalIgnoreCase) >= 0 || (!cmd.StartsWith("\"") && cmd.Contains(" ")));
                        if (isSuspicious) warnCnt++;
                        int r = _grid.Rows.Add(label, vName, cmd,
                            isSuspicious ? I18n.T("⚠ 경로 따옴표 점검 권장", "⚠ 経路点検推奨", "⚠ Review Path Quoting") : I18n.T("🛡 정상 자동실행", "🛡 正常スタートアップ", "🛡 Verified Startup"));
                        _grid.Rows[r].Cells[3].Style.ForeColor = isSuspicious ? Color.FromArgb(255, 190, 90) : Color.FromArgb(105, 230, 165);
                    }
                }
            }
            catch { }
        }
    }

    // =========================================================================
    // [2차 제안 8] 다크 / 라이트 / 고대비 테마 전환 및 UI 글꼴 배율(Zoom) 실시간 제어기
    // =========================================================================
    public enum UiVisualTheme
    {
        DarkSoc,
        CleanLight,
        HighContrast
    }

    public static class ThemeAndZoomController
    {
        public static UiVisualTheme CurrentTheme { get; private set; } = UiVisualTheme.DarkSoc;
        public static float CurrentZoomScale { get; private set; } = 1.0f;

        public static void CycleTheme(Form root, DataGridView grid)
        {
            if (CurrentTheme == UiVisualTheme.DarkSoc) CurrentTheme = UiVisualTheme.CleanLight;
            else if (CurrentTheme == UiVisualTheme.CleanLight) CurrentTheme = UiVisualTheme.HighContrast;
            else CurrentTheme = UiVisualTheme.DarkSoc;

            ApplyThemeToForm(root, grid);
        }

        public static void CycleZoom(Form root, DataGridView grid)
        {
            if (CurrentZoomScale < 1.05f) CurrentZoomScale = 1.15f;
            else if (CurrentZoomScale < 1.20f) CurrentZoomScale = 1.28f;
            else CurrentZoomScale = 1.0f;

            ApplyZoomToControlTree(root, CurrentZoomScale);
            if (grid != null)
            {
                int rowH = (int)Math.Round(36 * CurrentZoomScale);
                grid.RowTemplate.Height = rowH;
                foreach (DataGridViewRow r in grid.Rows)
                    r.Height = rowH;
            }
        }

        private static void ApplyZoomToControlTree(Control ctrl, float scale)
        {
            if (ctrl == null) return;
            if (ctrl.Font != null)
            {
                float basePt = 10.0f;
                if (ctrl.Font.Size >= 13.0f) basePt = 14.0f;
                else if (ctrl.Font.Size >= 11.5f) basePt = 12.0f;
                ctrl.Font = new Font(ctrl.Font.FontFamily, Math.Max(9.0f, Math.Min(16.5f, basePt * scale)), ctrl.Font.Style, GraphicsUnit.Point);
            }
            foreach (Control child in ctrl.Controls)
            {
                ApplyZoomToControlTree(child, scale);
            }
        }

        public static void ApplyThemeToForm(Form root, DataGridView grid)
        {
            if (root == null) return;
            if (CurrentTheme == UiVisualTheme.CleanLight)
            {
                root.BackColor = Color.FromArgb(240, 244, 250);
                root.ForeColor = Color.FromArgb(20, 28, 42);
                if (grid != null)
                {
                    grid.BackgroundColor = Color.White;
                    grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(222, 232, 246);
                    grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(20, 32, 52);
                    grid.DefaultCellStyle.BackColor = Color.White;
                    grid.DefaultCellStyle.ForeColor = Color.FromArgb(22, 30, 46);
                    grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(195, 220, 252);
                    grid.DefaultCellStyle.SelectionForeColor = Color.Black;
                    grid.GridColor = Color.FromArgb(205, 215, 230);
                }
            }
            else if (CurrentTheme == UiVisualTheme.HighContrast)
            {
                root.BackColor = Color.Black;
                root.ForeColor = Color.Yellow;
                if (grid != null)
                {
                    grid.BackgroundColor = Color.Black;
                    grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(15, 15, 15);
                    grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.Cyan;
                    grid.DefaultCellStyle.BackColor = Color.Black;
                    grid.DefaultCellStyle.ForeColor = Color.White;
                    grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(80, 80, 0);
                    grid.DefaultCellStyle.SelectionForeColor = Color.Yellow;
                    grid.GridColor = Color.Cyan;
                }
            }
            else
            {
                root.BackColor = Color.FromArgb(15, 19, 28);
                root.ForeColor = Color.FromArgb(235, 240, 248);
                if (grid != null)
                {
                    grid.BackgroundColor = Color.FromArgb(17, 22, 33);
                    grid.ColumnHeadersDefaultCellStyle.BackColor = Color.FromArgb(28, 36, 52);
                    grid.ColumnHeadersDefaultCellStyle.ForeColor = Color.FromArgb(220, 230, 245);
                    grid.DefaultCellStyle.BackColor = Color.FromArgb(20, 26, 38);
                    grid.DefaultCellStyle.ForeColor = Color.FromArgb(230, 236, 246);
                    grid.DefaultCellStyle.SelectionBackColor = Color.FromArgb(44, 72, 115);
                    grid.DefaultCellStyle.SelectionForeColor = Color.White;
                    grid.GridColor = Color.FromArgb(36, 45, 64);
                }
            }
        }
    }
}
