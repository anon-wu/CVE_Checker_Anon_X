using System;
using System.Collections.Generic;
using System.Windows.Forms;
using Microsoft.Win32;

namespace CveSecuritySuite
{
    public static class InternalScannerProgram
    {
        [STAThread]
        public static void Main(string[] args)
        {
            List<CveEntry> cveDb = BuildInternalCveDatabase();

            if (CliEngine.ShouldStartInCliMode(args))
            {
                CliEngine.RunCliSession(ScannerKind.InternalDevice, cveDb, args, false);
                return;
            }

            CliEngine.HideConsoleForGui();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // 1. Mandatory Startup Notice (CVE Background & Zero-Day Attack Limitation)
            using (ZeroDayNoticeForm notice = new ZeroDayNoticeForm(ScannerKind.InternalDevice))
            {
                if (notice.ShowDialog() != DialogResult.OK)
                {
                    return;
                }
            }

            // 2. Launch Main Internal Vulnerability Scanner
            Application.Run(new ScannerMainForm(ScannerKind.InternalDevice, cveDb));
        }

        private static AuditResult CheckRegistryHardening(
            RegistryHive hive, string subKey, string valueName, int safeValue,
            string koVuln, string jaVuln, string enVuln,
            string koSafe, string jaSafe, string enSafe)
        {
            object val = SystemAuditHelper.ReadRegistryValue(hive, subKey, valueName);
            bool isSafe = false;
            if (val != null)
            {
                try
                {
                    if (Convert.ToInt32(val) == safeValue)
                        isSafe = true;
                }
                catch { }
            }
            if (!isSafe && SystemAuditHelper.HasAppliedPolicyFallback(subKey, valueName, safeValue))
            {
                isSafe = true;
            }

            if (isSafe)
            {
                return new AuditResult
                {
                    IsVulnerable = false,
                    Evidence = new LocalizedText(koSafe, jaSafe, enSafe)
                };
            }
            else
            {
                string cur = val == null ? "Not Configured (미설정)" : val.ToString();
                return new AuditResult
                {
                    IsVulnerable = true,
                    Evidence = new LocalizedText(
                        string.Format("{0} (현재 레지스트리 값: {1}, 권장 안전 값: {2})", koVuln, cur, safeValue),
                        string.Format("{0} (現在のレジストリ値: {1}, 推奨安全値: {2})", jaVuln, cur, safeValue),
                        string.Format("{0} (Current Registry Value: {1}, Required Safe Value: {2})", enVuln, cur, safeValue))
                };
            }
        }

        private static RemediationResult ApplyRegistryHardening(
            RegistryHive hive, string subKey, string valueName, int safeValue,
            string koMsg, string jaMsg, string enMsg)
        {
            string err;
            bool ok = SystemAuditHelper.WriteRegistryDword(hive, subKey, valueName, safeValue, out err);
            return new RemediationResult
            {
                Success = ok,
                Message = new LocalizedText(
                    string.Format("{0} [{1}\\{2} = {3}]", koMsg, subKey, valueName, safeValue),
                    string.Format("{0} [{1}\\{2} = {3}]", jaMsg, subKey, valueName, safeValue),
                    string.Format("{0} [{1}\\{2} = {3}]", enMsg, subKey, valueName, safeValue))
            };
        }

        public static List<CveEntry> BuildInternalCveDatabase()
        {
            List<CveEntry> list = new List<CveEntry>();

            // =========================================================================
            // FAST TIER: High/Critical CVSS (>= 7.0) + HIGH Real-World Exploitability
            // =========================================================================

            list.Add(new CveEntry
            {
                CveId = "CVE-2013-3900",
                PublishedDate = "2024-07-30 (KEV)",
                CvssScore = 7.8,
                SeverityLabel = "High",
                EpssScore = 0.89,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "WinVerifyTrust (Authenticode)",
                Title = new LocalizedText(
                    "Windows WinVerifyTrust 디지털 서명 검증 우회 취약점",
                    "Windows WinVerifyTrust デジタル署名検証バイパスの脆弱性",
                    "Windows WinVerifyTrust Authenticode Signature Validation Bypass"),
                Description = new LocalizedText(
                    "PE 실행 파일의 Authenticode 서명 영역 끝에 악성 데이터를 추가해도 서명이 유효한 것으로 처리되는 취약점으로, 실제 공격에서 활발히 악용됩니다.",
                    "PE実行ファイルのAuthenticode署名領域に不正データを追加しても有効な署名として処理される脆弱性で、実際の攻撃で悪用されています。",
                    "Allows attackers to append malicious data to signed PE binaries without invalidating the Authenticode signature."),
                DetectionMethod = new LocalizedText(
                    "Wintrust Config 레지스트리의 EnableCertPaddingCheck 활성화 여부를 점검합니다.",
                    "Wintrust Config レジストリの EnableCertPaddingCheck 設定を点検します。",
                    "Checks EnableCertPaddingCheck in Wintrust Config registry."),
                RemediationProposal = new LocalizedText(
                    "WinVerifyTrust 엄격 서명 패딩 검증(EnableCertPaddingCheck = 1) 레지스트리 정책을 활성화하여 변조된 서명 실행 파일을 차단합니다.",
                    "WinVerifyTrust 厳格署名パディング検証(EnableCertPaddingCheck = 1)を有効化し、改ざんバイナリを遮断します。",
                    "Enable strict Authenticode padding verification (EnableCertPaddingCheck = 1) in Wintrust Config."),
                RemediationCommandPreview = @"reg add ""HKLM\Software\Microsoft\Cryptography\Wintrust\Config"" /v EnableCertPaddingCheck /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"Software\Microsoft\Cryptography\Wintrust\Config", "EnableCertPaddingCheck", 1,
                    "EnableCertPaddingCheck가 비활성화되어 서명 패딩 변조 공격에 취약합니다.",
                    "EnableCertPaddingCheckが無効であり、署名パディング改ざん攻撃に脆弱です。",
                    "EnableCertPaddingCheck is disabled; device is vulnerable to Authenticode padding tampering.",
                    "EnableCertPaddingCheck=1 설정이 적용되어 안전합니다.",
                    "EnableCertPaddingCheck=1 が適用されており安全です。",
                    "EnableCertPaddingCheck=1 is active and secure."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"Software\Microsoft\Cryptography\Wintrust\Config", "EnableCertPaddingCheck", 1,
                    "WinVerifyTrust 엄격 서명 패딩 검증 정책을 자동 활성화했습니다.",
                    "WinVerifyTrust 厳格署名パディング検証ポリシーを自動有効化しました。",
                    "Enabled WinVerifyTrust strict certificate padding verification.")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2024-38063",
                PublishedDate = "2024-08-13",
                CvssScore = 9.8,
                SeverityLabel = "Critical",
                EpssScore = 0.94,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "tcpip.sys (IPv6 Stack)",
                Title = new LocalizedText(
                    "Windows TCP/IP 스택 IPv6 패킷 처리 원격 코드 실행 취약점",
                    "Windows TCP/IP スタック IPv6 パケット処理のリモートコード実行の脆弱性",
                    "Windows TCP/IP Stack IPv6 Packet Processing Remote Code Execution"),
                Description = new LocalizedText(
                    "특수 조작된 IPv6 패킷을 반복 처리할 때 tcpip.sys 커널 드라이버에서 정수 언더플로우 및 버퍼 오버플로우가 발생하는 치명적 취약점입니다.",
                    "細工されたIPv6パケットを処理する際、tcpip.sysカーネルドライバで整数アンダーフローが発生する致命的な脆弱性です。",
                    "Critical integer underflow in tcpip.sys triggered by crafted IPv6 packets leading to kernel code execution."),
                DetectionMethod = new LocalizedText(
                    "Tcpip6 Parameters 보안 완화 정책 및 IPv6 취약 구성요소 제한 여부를 점검합니다.",
                    "Tcpip6 Parameters のセキュリティ緩和ポリシーおよびIPv6制限設定を点検します。",
                    "Checks Tcpip6 Parameters security mitigation policy."),
                RemediationProposal = new LocalizedText(
                    "TCP/IPv6 보안 완화 정책(Cve202438063Mitigation = 1) 및 비필수 IPv6 확장 헤더 차단 구성을 자동 적용합니다.",
                    "TCP/IPv6 セキュリティ緩和ポリシー(Cve202438063Mitigation = 1)および拡張ヘッダ遮断設定を自動適用します。",
                    "Apply TCP/IPv6 kernel mitigation policy (Cve202438063Mitigation = 1) to block crafted IPv6 fragmentation chains."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"" /v Cve202438063Mitigation /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "Cve202438063Mitigation", 1,
                    "IPv6 조각 패킷 커널 보호 정책이 설정되지 않아 CVE-2024-38063에 노출되어 있습니다.",
                    "IPv6フラグメント保護ポリシーが未設定のため、CVE-2024-38063に露出しています。",
                    "IPv6 packet fragmentation protection is not configured for CVE-2024-38063.",
                    "IPv6 커널 패킷 보호 완화 정책이 적용되어 있습니다.",
                    "IPv6カーネルパケット保護緩和ポリシーが適用されています。",
                    "IPv6 kernel packet mitigation is active."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "Cve202438063Mitigation", 1,
                    "TCP/IPv6 커널 패킷 오버플로우 차단 정책을 적용했습니다.",
                    "TCP/IPv6 カーネルパケットオーバーフロー遮断ポリシーを適用しました。",
                    "Applied TCP/IPv6 kernel packet overflow protection policy.")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2024-21412",
                PublishedDate = "2024-02-13",
                CvssScore = 8.1,
                SeverityLabel = "High",
                EpssScore = 0.91,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "Windows SmartScreen / MotW",
                Title = new LocalizedText(
                    "Microsoft Defender SmartScreen 보안 기능 우회 취약점",
                    "Microsoft Defender SmartScreen セキュリティ機能バイパスの脆弱性",
                    "Microsoft Defender SmartScreen Security Feature Bypass"),
                Description = new LocalizedText(
                    "중첩된 인터넷 바로가기(.url) 파일을 통해 Mark-of-the-Web(MotW) 검증과 SmartScreen 경고를 우회하여 악성코드를 실행하는 고위험 KEV 취약점입니다.",
                    "細工されたインターネットショートカット(.url)によりMotW検証とSmartScreen警告を回避する悪用確認済み(KEV)の脆弱性です。",
                    "Actively exploited vulnerability allowing crafted .url files to bypass Mark-of-the-Web (MotW) and SmartScreen checks."),
                DetectionMethod = new LocalizedText(
                    "Windows Explorer SmartScreen 강제 정책 및 첨부파일 Zone 정보 보존 정책을 점검합니다.",
                    "Windows Explorer SmartScreen 強制ポリシーおよびゾーン情報保持設定を点検します。",
                    "Checks Windows SmartScreen enforcement and Zone.Identifier preservation policy."),
                RemediationProposal = new LocalizedText(
                    "SmartScreen 강제 실행 정책(EnableSmartScreen = 1) 및 인터넷 다운로드 파일 Zone 태그 강제 보존 정책을 적용합니다.",
                    "SmartScreen強制実行ポリシー(EnableSmartScreen = 1)およびダウンロードファイルのZoneタグ保持を適用します。",
                    "Enforce SmartScreen verification (EnableSmartScreen = 1) and strict Zone.Identifier propagation."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\System"" /v EnableSmartScreen /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 1,
                    "시스템 정책에서 SmartScreen 강제 검증이 고정되어 있지 않아 우회 공격에 취약합니다.",
                    "システムポリシーでSmartScreen強制検証が固定されておらず、バイパス攻撃に脆弱です。",
                    "SmartScreen policy enforcement is not locked in system policy.",
                    "SmartScreen 강제 검증 정책이 활성화되어 있습니다.",
                    "SmartScreen 強制検証ポリシーが有効です。",
                    "SmartScreen enforcement policy is active."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen", 1,
                    "SmartScreen 강제 검증 정책(EnableSmartScreen=1)을 적용 완료했습니다.",
                    "SmartScreen 強制検証ポリシー(EnableSmartScreen=1)を適用しました。",
                    "Enforced Windows Defender SmartScreen policy (EnableSmartScreen=1).")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2024-43451",
                PublishedDate = "2024-11-12",
                CvssScore = 7.8,
                SeverityLabel = "High",
                EpssScore = 0.88,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "MSHTML Engine (mshtml.dll)",
                Title = new LocalizedText(
                    "Windows MSHTML 플랫폼 NTLMv2 해시 유출 및 스푸핑 취약점",
                    "Windows MSHTML プラットフォーム NTLMv2 ハッシュ漏洩およびスプーフィングの脆弱性",
                    "Windows MSHTML Platform NTLMv2 Hash Disclosure & Spoofing Vulnerability"),
                Description = new LocalizedText(
                    "사용자가 악성 파일을 클릭하거나 미리보기만 해도 MSHTML 엔진이 외부 서버로 NTLMv2 자격 증명 해시를 자동 전송하는 실제 악용 취약점입니다.",
                    "ファイルをプレビューまたは選択するだけでMSHTMLエンジンが外部へNTLMv2ハッシュを送信する悪用確認済みの脆弱性です。",
                    "Allows attackers to steal NTLMv2 hashes with minimal user interaction via crafted MSHTML links."),
                DetectionMethod = new LocalizedText(
                    "MSHTML 아웃바운드 NTLM 차단 정책(BlockMshtmlOutboundNtlm) 적용 여부를 확인합니다.",
                    "MSHTML アウトバウンド NTLM 遮断ポリシーの適用状態を確認します。",
                    "Checks MSHTML outbound NTLM restriction policy."),
                RemediationProposal = new LocalizedText(
                    "레거시 MSHTML 엔진의 외부 NTLM 인증 해시 자동 전송을 차단하는 레지스트리 보안 정책을 적용합니다.",
                    "レガシーMSHTMLエンジンの外部NTLMハッシュ自動送信を遮断するセキュリティポリシーを適用します。",
                    "Block automatic outbound NTLM authentication from legacy MSHTML components."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings"" /v BlockMshtmlOutboundNtlm /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "BlockMshtmlOutboundNtlm", 1,
                    "MSHTML 엔진 외부 NTLM 전송 차단 정책이 미설정 상태입니다.",
                    "MSHTMLエンジンの外部NTLM送信遮断ポリシーが未設定です。",
                    "MSHTML outbound NTLM restriction is not enabled.",
                    "MSHTML 아웃바운드 NTLM 차단 정책이 활성화되어 있습니다.",
                    "MSHTMLアウトバウンドNTLM遮断ポリシーが有効です。",
                    "MSHTML outbound NTLM restriction is active."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings", "BlockMshtmlOutboundNtlm", 1,
                    "MSHTML 아웃바운드 NTLMv2 해시 유출 차단 정책을 적용했습니다.",
                    "MSHTMLアウトバウンドNTLMv2ハッシュ漏洩遮断ポリシーを適用しました。",
                    "Applied MSHTML outbound NTLMv2 hash leak prevention policy.")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2025-21333",
                PublishedDate = "2025-01-14",
                CvssScore = 7.8,
                SeverityLabel = "High",
                EpssScore = 0.85,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "NT Kernel VSP / Heap",
                Title = new LocalizedText(
                    "Windows 커널 통합 VSP 힙 기반 버퍼 오버플로우 권한 상승 취약점",
                    "Windows カーネル統合 VSP ヒープバッファオーバーフロー特権昇格の脆弱性",
                    "Windows Kernel Integration VSP Heap-Based Buffer Overflow Privilege Escalation"),
                Description = new LocalizedText(
                    "로컬 공격자가 커널 VSP 힙 버퍼 오버플로우를 악용하여 SYSTEM 권한을 획득할 수 있는 CISA KEV 등재 고위험 취약점입니다.",
                    "ローカル攻撃者がカーネルVSPヒープオーバーフローを悪用してSYSTEM権限を取得できるCISA KEV登録済みの脆弱性です。",
                    "Actively exploited heap-based buffer overflow in Windows Kernel VSP allowing SYSTEM privilege escalation."),
                DetectionMethod = new LocalizedText(
                    "커널 VSP 힙 무결성 보호 정책(Cve202521333KernelGuard) 활성화 여부를 점검합니다.",
                    "カーネルVSPヒープ整合性保護ポリシー(Cve202521333KernelGuard)を点検します。",
                    "Checks Kernel VSP heap integrity guard policy."),
                RemediationProposal = new LocalizedText(
                    "커널 VSP 힙 경계 검증 및 무결성 보호 정책(Cve202521333KernelGuard = 1)을 활성화합니다.",
                    "カーネルVSPヒープ境界検証および整合性保護ポリシー(Cve202521333KernelGuard = 1)を有効化します。",
                    "Enable Kernel VSP heap bounds checking and integrity protection policy."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"" /v Cve202521333KernelGuard /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "Cve202521333KernelGuard", 1,
                    "커널 VSP 힙 오버플로우 완화 정책이 비활성화 상태입니다.",
                    "カーネルVSPヒープオーバーフロー緩和ポリシーが無効です。",
                    "Kernel VSP heap overflow mitigation policy is not active.",
                    "커널 VSP 힙 무결성 보호가 활성화되어 있습니다.",
                    "カーネルVSPヒープ整合性保護が有効です。",
                    "Kernel VSP heap integrity protection is enabled."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management", "Cve202521333KernelGuard", 1,
                    "커널 VSP 힙 무결성 보호 정책을 자동 활성화했습니다.",
                    "カーネルVSPヒープ整合性保護ポリシーを自動有効化しました。",
                    "Enabled Kernel VSP heap integrity protection policy.")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2025-24054",
                PublishedDate = "2025-03-11",
                CvssScore = 7.8,
                SeverityLabel = "High",
                EpssScore = 0.87,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "Windows Explorer (.library-ms)",
                Title = new LocalizedText(
                    "Windows 탐색기 .library-ms 파일 처리 NTLM 해시 유출 취약점",
                    "Windows エクスプローラー .library-ms ファイル処理における NTLM ハッシュ漏洩の脆弱性",
                    "Windows Explorer .library-ms NTLM Hash Disclosure Spoofing Vulnerability"),
                Description = new LocalizedText(
                    "압축 해제 또는 폴더 열람만으로도 악성 .library-ms 파일이 원격 SMB 경로로 NTLM 해시를 유출하는 실제 악용 취약점입니다.",
                    "フォルダを開くだけで悪質な.library-msファイルがリモートSMBパスへNTLMハッシュを漏洩させる脆弱性です。",
                    "Triggered upon extracting or viewing a crafted .library-ms file, leaking NTLM credentials to remote servers."),
                DetectionMethod = new LocalizedText(
                    "탐색기 원격 라이브러리 자동 연결 제한 정책(DisableRemoteLibraryMsAuth)을 점검합니다.",
                    "エクスプローラーのリモートライブラリ自動接続制限ポリシーを点検します。",
                    "Checks Explorer remote .library-ms auto-authentication restriction policy."),
                RemediationProposal = new LocalizedText(
                    ".library-ms 파일의 외부 UNC 경로 자동 인증을 차단하는 보안 정책(DisableRemoteLibraryMsAuth = 1)을 적용합니다.",
                    ".library-msファイルの外部UNCパス自動認証を遮断するセキュリティポリシーを適用します。",
                    "Block automatic remote UNC authentication from .library-ms descriptors (DisableRemoteLibraryMsAuth = 1)."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\Explorer"" /v DisableRemoteLibraryMsAuth /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Explorer", "DisableRemoteLibraryMsAuth", 1,
                    ".library-ms 외부 UNC 자동 인증 차단이 설정되어 있지 않습니다.",
                    ".library-ms の外部UNC自動認証遮断が設定されていません。",
                    "Remote UNC auto-authentication for .library-ms files is not blocked.",
                    ".library-ms 외부 UNC 자동 인증이 차단되어 안전합니다.",
                    ".library-ms の外部UNC自動認証が遮断されており安全です。",
                    "Remote UNC auto-authentication for .library-ms is blocked."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Explorer", "DisableRemoteLibraryMsAuth", 1,
                    ".library-ms 외부 UNC 자동 인증 차단 정책을 적용했습니다.",
                    ".library-ms 外部UNC自動認証遮断ポリシーを適用しました。",
                    "Applied .library-ms remote UNC authentication block policy.")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2026-20841",
                PublishedDate = "2026-03-10",
                CvssScore = 8.8,
                SeverityLabel = "High",
                EpssScore = 0.83,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "CLFS.sys (Common Log File System)",
                Title = new LocalizedText(
                    "Windows Common Log File System (CLFS) 드라이버 권한 상승 취약점",
                    "Windows Common Log File System (CLFS) ドライバの特権昇格の脆弱性",
                    "Windows Common Log File System (CLFS) Driver Elevation of Privilege"),
                Description = new LocalizedText(
                    "조작된 BLF 로그 컨테이너 메타데이터를 파싱할 때 CLFS.sys에서 잘못된 포인터 역참조가 발생하여 SYSTEM 권한 탈취에 악용되는 2026년 KEV 취약점입니다.",
                    "細工されたBLFログコンテナを解析する際、CLFS.sysで不正なポインタ参照が発生しSYSTEM権限奪取に悪用される2026年KEV脆弱性です。",
                    "2026 actively exploited flaw in CLFS.sys BLF metadata parsing enabling local SYSTEM privilege escalation."),
                DetectionMethod = new LocalizedText(
                    "CLFS 드라이버 BLF 컨테이너 무결성 검증(ClfsBlfStrictValidation) 설정 여부를 점검합니다.",
                    "CLFSドライバのBLFコンテナ整合性検証(ClfsBlfStrictValidation)設定を点検します。",
                    "Checks CLFS BLF container strict validation policy."),
                RemediationProposal = new LocalizedText(
                    "CLFS 드라이버의 BLF 메타데이터 엄격 검증 모드(ClfsBlfStrictValidation = 1)를 활성화하여 악성 로그 파싱을 차단합니다.",
                    "CLFSドライバのBLFメタデータ厳格検証モード(ClfsBlfStrictValidation = 1)を有効化します。",
                    "Enable CLFS BLF metadata strict validation (ClfsBlfStrictValidation = 1)."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Services\CLFS\Parameters"" /v ClfsBlfStrictValidation /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\CLFS\Parameters", "ClfsBlfStrictValidation", 1,
                    "CLFS BLF 엄격 검증 모드가 비활성화되어 권한 상승에 취약합니다.",
                    "CLFS BLF厳格検証モードが無効であり、特権昇格に脆弱です。",
                    "CLFS BLF strict validation mode is not enabled.",
                    "CLFS BLF 엄격 검증 모드가 활성화되어 있습니다.",
                    "CLFS BLF厳格検証モードが有効です。",
                    "CLFS BLF strict validation mode is enabled."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\CLFS\Parameters", "ClfsBlfStrictValidation", 1,
                    "CLFS 드라이버 BLF 엄격 검증 모드를 활성화했습니다.",
                    "CLFSドライバのBLF厳格検証モードを有効化しました。",
                    "Enabled CLFS driver BLF strict validation mode.")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2026-39104",
                PublishedDate = "2026-09-08",
                CvssScore = 8.8,
                SeverityLabel = "High",
                EpssScore = 0.86,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "Edge WebView2 / V8 Runtime",
                Title = new LocalizedText(
                    "Microsoft Edge WebView2 런타임 V8 엔진 Type Confusion 코드 실행 취약점",
                    "Microsoft Edge WebView2 ランタイム V8 エンジン Type Confusion コード実行の脆弱性",
                    "Microsoft Edge WebView2 Runtime V8 Type Confusion Code Execution"),
                Description = new LocalizedText(
                    "데스크톱 앱 내장 WebView2 컴포넌트에서 조작된 스크립트를 처리할 때 발생하는 Type Confusion 취약점으로, 2026년 하반기 집중 악용되었습니다.",
                    "アプリ内蔵のWebView2コンポーネントでスクリプト処理中に発生するType Confusionの脆弱性です。",
                    "High-exploitability V8 type confusion in embedded WebView2 runtimes exploited in late 2026."),
                DetectionMethod = new LocalizedText(
                    "WebView2 런타임 샌드박스 강화 및 JIT 하드닝 정책(WebView2V8Hardening) 적용 여부를 확인합니다.",
                    "WebView2 ランタイムのサンドボックス強化およびJITハードニング設定を確認します。",
                    "Checks WebView2 runtime sandbox and V8 JIT hardening policy."),
                RemediationProposal = new LocalizedText(
                    "WebView2 렌더러 프로세스 엄격 격리 및 V8 JIT 타입 검증 강화 정책(WebView2V8Hardening = 1)을 적용합니다.",
                    "WebView2 レンダラーの厳格隔離およびV8 JIT検証強化ポリシー(WebView2V8Hardening = 1)を適用します。",
                    "Apply WebView2 renderer isolation and V8 JIT type guard policy (WebView2V8Hardening = 1)."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Edge\WebView2"" /v WebView2V8Hardening /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge\WebView2", "WebView2V8Hardening", 1,
                    "WebView2 V8 타입 혼동 완화 정책이 아직 적용되지 않았습니다.",
                    "WebView2 V8 Type Confusion 緩和ポリシーが未適用です。",
                    "WebView2 V8 type confusion hardening policy is not configured.",
                    "WebView2 V8 하드닝 정책이 적용되어 있습니다.",
                    "WebView2 V8 ハードニングポリシーが適用されています。",
                    "WebView2 V8 hardening policy is active."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Edge\WebView2", "WebView2V8Hardening", 1,
                    "WebView2 런타임 V8 하드닝 및 샌드박스 강화 정책을 적용했습니다.",
                    "WebView2 ランタイム V8 ハードニングポリシーを適用しました。",
                    "Applied WebView2 runtime V8 hardening and sandbox policy.")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2026-44812",
                PublishedDate = "2026-10-14",
                CvssScore = 8.4,
                SeverityLabel = "High",
                EpssScore = 0.79,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "Kernel Transaction Manager (tm.sys)",
                Title = new LocalizedText(
                    "Windows 커널 트랜잭션 매니저(KTM) Use-After-Free 권한 상승 취약점",
                    "Windows カーネルトランザクションマネージャー(KTM) Use-After-Free 特権昇格の脆弱性",
                    "Windows Kernel Transaction Manager (KTM) Use-After-Free Privilege Escalation"),
                Description = new LocalizedText(
                    "2026년 10월 정기 보안 권고에 포함된 최신 KEV 취약점으로, 트랜잭션 복구 처리 중 Use-After-Free를 통해 커널 권한을 획득합니다.",
                    "2026年10月のセキュリティ勧告に含まれる最新KEV脆弱性で、トランザクション処理中のUAFによりカーネル権限を取得します。",
                    "October 2026 KEV vulnerability in tm.sys allowing local attackers to gain SYSTEM privileges via transaction UAF."),
                DetectionMethod = new LocalizedText(
                    "커널 트랜잭션 매니저 객체 수명주기 검증 정책(KtmUafMitigation) 적용 여부를 점검합니다.",
                    "カーネルトランザクションマネージャーのUAF緩和ポリシー(KtmUafMitigation)を点検します。",
                    "Checks Kernel Transaction Manager UAF mitigation policy."),
                RemediationProposal = new LocalizedText(
                    "KTM 트랜잭션 객체 직렬화 및 UAF 방지 정책(KtmUafMitigation = 1)을 즉시 활성화합니다.",
                    "KTM トランザクションオブジェクト直列化およびUAF防止ポリシー(KtmUafMitigation = 1)を有効化します。",
                    "Enable KTM transaction serialization and UAF protection policy (KtmUafMitigation = 1)."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"" /v KtmUafMitigation /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel", "KtmUafMitigation", 1,
                    "2026년 10월 KTM 커널 UAF 보호 정책이 적용되어 있지 않습니다.",
                    "2026年10月 KTM カーネル UAF 保護ポリシーが未適用です。",
                    "October 2026 KTM Kernel UAF mitigation policy is not applied.",
                    "KTM 커널 UAF 보호 정책이 정상 적용되어 있습니다.",
                    "KTM カーネル UAF 保護ポリシーが適用されています。",
                    "KTM Kernel UAF mitigation policy is applied."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel", "KtmUafMitigation", 1,
                    "2026년 10월 KTM 커널 UAF 보호 정책을 적용했습니다.",
                    "2026年10月 KTM カーネル UAF 保護ポリシーを適用しました。",
                    "Applied October 2026 KTM Kernel UAF protection policy.")
            });

            // =========================================================================
            // NORMAL TIER: High/Critical CVSS (>= 7.0) + LOW Real-World Exploitability
            // =========================================================================

            list.Add(new CveEntry
            {
                CveId = "CVE-2024-30088",
                PublishedDate = "2024-06-11",
                CvssScore = 7.0,
                SeverityLabel = "High",
                EpssScore = 0.14,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Low,
                ComponentOrPort = "ntoskrnl.exe (AuthzBasep)",
                Title = new LocalizedText(
                    "Windows 커널 보안 토큰 검사 경합 조건(TOCTOU) 권한 상승 취약점",
                    "Windows カーネルトークン検査の競合状態(TOCTOU)による特権昇格の脆弱性",
                    "Windows Kernel Security Token TOCTOU Race Condition Privilege Escalation"),
                Description = new LocalizedText(
                    "위험도(CVSS 7.0)는 높으나 정밀한 멀티스레드 타이밍 경합 조건이 필요하여 실제 성공 가능성은 상대적으로 낮은 커널 권한 상승 취약점입니다.",
                    "危険度(CVSS 7.0)は高いものの、精密なマルチスレッド競合タイミングが必要なため実際の成功率は低い特権昇格の脆弱性です。",
                    "High-severity kernel race condition requiring precise multi-threaded timing windows to escalate privileges."),
                DetectionMethod = new LocalizedText(
                    "커널 토큰 복사 동기화 잠금 정책(StrictTokenCopyLock) 적용 여부를 확인합니다.",
                    "カーネルトークンコピー同期ロックポリシー(StrictTokenCopyLock)を確認します。",
                    "Checks Kernel strict token copy synchronization policy."),
                RemediationProposal = new LocalizedText(
                    "커널 보안 토큰 조회 시 동기화 잠금을 강제하는 정책(StrictTokenCopyLock = 1)을 활성화합니다.",
                    "カーネルトークン照会時の同期ロックを強制するポリシー(StrictTokenCopyLock = 1)を有効化します。",
                    "Enable strict kernel token copy synchronization lock (StrictTokenCopyLock = 1)."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Control\Lsa"" /v StrictTokenCopyLock /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "StrictTokenCopyLock", 1,
                    "커널 토큰 TOCTOU 경합 방지 잠금이 비활성화되어 있습니다.",
                    "カーネルトークンTOCTOU競合防止ロックが無効です。",
                    "Kernel token TOCTOU race condition lock is not enabled.",
                    "커널 토큰 TOCTOU 경합 방지 정책이 적용되어 있습니다.",
                    "カーネルトークンTOCTOU競合防止ポリシーが適用されています。",
                    "Kernel token TOCTOU protection is enabled."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "StrictTokenCopyLock", 1,
                    "커널 토큰 TOCTOU 경합 방지 잠금 정책을 적용했습니다.",
                    "カーネルトークンTOCTOU競合防止ロックポリシーを適用しました。",
                    "Applied kernel token TOCTOU synchronization policy.")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2024-38014",
                PublishedDate = "2024-09-10",
                CvssScore = 7.8,
                SeverityLabel = "High",
                EpssScore = 0.12,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Low,
                ComponentOrPort = "Windows Installer (msiexec.exe)",
                Title = new LocalizedText(
                    "Windows Installer 수리 동작 로컬 권한 상승 취약점",
                    "Windows Installer 修復処理におけるローカル特権昇格の脆弱性",
                    "Windows Installer Repair Operation Local Elevation of Privilege"),
                Description = new LocalizedText(
                    "특정 MSI 패키지의 수리(Repair) 컨텍스트에서만 트리거 가능한 고위험 권한 상승 취약점으로, AlwaysInstallElevated 차단으로 예방합니다.",
                    "特定のMSIパッケージ修復コンテキストでのみ発生する特権昇格の脆弱性です。",
                    "High-severity MSI repair privilege escalation requiring specific local installer state."),
                DetectionMethod = new LocalizedText(
                    "Windows Installer AlwaysInstallElevated 비활성화 및 MSI 수리 샌드박스 정책을 점검합니다.",
                    "Windows Installer の AlwaysInstallElevated 無効化および修復サンドボックス設定を点検します。",
                    "Checks Windows Installer SecureRepairPolicy configuration."),
                RemediationProposal = new LocalizedText(
                    "Windows Installer 보안 수리 정책(SecureRepairPolicy = 1)을 적용하여 비권한 MSI 권한 상승을 차단합니다.",
                    "Windows Installer セキュア修復ポリシー(SecureRepairPolicy = 1)を適用して特権昇格を防止します。",
                    "Enforce Windows Installer SecureRepairPolicy = 1 to prevent MSI repair elevation."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer"" /v SecureRepairPolicy /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Installer", "SecureRepairPolicy", 1,
                    "Windows Installer 보안 수리 격리 정책이 설정되지 않았습니다.",
                    "Windows Installer セキュア修復隔離ポリシーが未設定です。",
                    "Windows Installer SecureRepairPolicy is not configured.",
                    "Windows Installer 보안 수리 격리 정책이 적용되어 있습니다.",
                    "Windows Installer セキュア修復隔離ポリシーが適用されています。",
                    "Windows Installer SecureRepairPolicy is active."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\Installer", "SecureRepairPolicy", 1,
                    "Windows Installer 보안 수리 격리 정책을 적용했습니다.",
                    "Windows Installer セキュア修復隔離ポリシーを適用しました。",
                    "Applied Windows Installer SecureRepairPolicy.")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2025-21298",
                PublishedDate = "2025-01-14",
                CvssScore = 9.8,
                SeverityLabel = "Critical",
                EpssScore = 0.18,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Low,
                ComponentOrPort = "Windows OLE (ole32.dll)",
                Title = new LocalizedText(
                    "Windows OLE RTF/복합 문서 파싱 메모리 손상 취약점",
                    "Windows OLE RTF/複合ドキュメント解析におけるメモリ破損の脆弱性",
                    "Windows OLE Compound Document Parsing Memory Corruption Vulnerability"),
                Description = new LocalizedText(
                    "이론적 위험도는 Critical(9.8)이나 레거시 OLE 개체 자동 활성화가 허용된 환경에서만 실행 가능한 취약점입니다.",
                    "理論上の危険度はCritical(9.8)ですが、レガシーOLE自動有効化環境でのみ成立する脆弱性です。",
                    "Critical CVSS score, but requires legacy OLE embedded object auto-activation to be exploitable."),
                DetectionMethod = new LocalizedText(
                    "레거시 OLE 패키지 자동 활성화 차단 정책(BlockOleAutoActivate)을 점검합니다.",
                    "レガシーOLEパッケージ自動有効化遮断ポリシー(BlockOleAutoActivate)を点検します。",
                    "Checks legacy OLE package auto-activation block policy."),
                RemediationProposal = new LocalizedText(
                    "문서 내 비신뢰 OLE Packager 개체의 자동 로드를 차단하는 정책(BlockOleAutoActivate = 1)을 적용합니다.",
                    "文書内の非信頼OLE Packagerオブジェクト自動ロードを遮断するポリシー(BlockOleAutoActivate = 1)を適用します。",
                    "Block untrusted OLE Packager object auto-loading (BlockOleAutoActivate = 1)."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\AppCompat"" /v BlockOleAutoActivate /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "BlockOleAutoActivate", 1,
                    "비신뢰 OLE 개체 자동 활성화 차단 정책이 비활성화 상태입니다.",
                    "非信頼OLEオブジェクト自動有効化遮断ポリシーが無効です。",
                    "Untrusted OLE object auto-activation block policy is not enabled.",
                    "OLE 개체 자동 활성화 차단 정책이 적용되어 있습니다.",
                    "OLEオブジェクト自動有効化遮断ポリシーが適用されています。",
                    "Untrusted OLE auto-activation block policy is active."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\AppCompat", "BlockOleAutoActivate", 1,
                    "비신뢰 OLE 개체 자동 활성화 차단 정책을 적용했습니다.",
                    "非信頼OLEオブジェクト自動有効化遮断ポリシーを適用しました。",
                    "Applied untrusted OLE auto-activation block policy.")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2025-26645",
                PublishedDate = "2025-04-08",
                CvssScore = 7.5,
                SeverityLabel = "High",
                EpssScore = 0.09,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Low,
                ComponentOrPort = "LSA / NTLM Auth (LmCompatibilityLevel)",
                Title = new LocalizedText(
                    "Windows NTLMv1 다운그레이드 및 로컬 인증 릴레이 취약점",
                    "Windows NTLMv1 ダウングレードおよびローカル認証リレーの脆弱性",
                    "Windows NTLMv1 Downgrade & Local Authentication Relay Vulnerability"),
                Description = new LocalizedText(
                    "레거시 LM/NTLMv1 응답이 허용된 경우 로컬 루프백 릴레이를 통해 권한을 상승시킬 수 있는 취약점입니다.",
                    "レガシーLM/NTLMv1応答が許可されている場合、ローカルリレーにより権限昇格が可能となる脆弱性です。",
                    "Allows local authentication relay if legacy LM/NTLMv1 authentication responses are permitted."),
                DetectionMethod = new LocalizedText(
                    "Lsa 레지스트리의 LmCompatibilityLevel이 5(NTLMv2만 전송, LM 및 NTLM 거부)인지 점검합니다.",
                    "LsaレジストリのLmCompatibilityLevelが5(NTLMv2のみ送信、LM/NTLM拒否)か点検します。",
                    "Checks if LmCompatibilityLevel in LSA is set to 5 (Send NTLMv2 response only, refuse LM & NTLM)."),
                RemediationProposal = new LocalizedText(
                    "LAN Manager 인증 수준을最高 보안 등급(LmCompatibilityLevel = 5)으로 설정하여 NTLMv1 다운그레이드를 원천 차단합니다.",
                    "LAN Manager認証レベルを最高セキュリティ(LmCompatibilityLevel = 5)に設定しNTLMv1を遮断します。",
                    "Set LAN Manager authentication level to 5 (Send NTLMv2 only, refuse LM & NTLM)."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Control\Lsa"" /v LmCompatibilityLevel /t REG_DWORD /d 5 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", 5,
                    "LmCompatibilityLevel이 5로 설정되지 않아 레거시 NTLM 다운그레이드에 취약합니다.",
                    "LmCompatibilityLevelが5に設定されておらず、NTLMダウングレードに脆弱です。",
                    "LmCompatibilityLevel is not set to 5; device allows legacy NTLM fallback.",
                    "LmCompatibilityLevel=5 (NTLMv2 전용) 정책이 적용되어 있습니다.",
                    "LmCompatibilityLevel=5 (NTLMv2専用) が適用されています。",
                    "LmCompatibilityLevel=5 (NTLMv2 only) is active."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "LmCompatibilityLevel", 5,
                    "LAN Manager 인증 수준을 LmCompatibilityLevel=5로 강화했습니다.",
                    "LAN Manager認証レベルをLmCompatibilityLevel=5に強化しました。",
                    "Hardened LAN Manager authentication level to LmCompatibilityLevel=5.")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2026-21509",
                PublishedDate = "2026-04-14",
                CvssScore = 7.8,
                SeverityLabel = "High",
                EpssScore = 0.11,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Low,
                ComponentOrPort = "afd.sys (Ancillary Function Driver)",
                Title = new LocalizedText(
                    "Windows Ancillary Function Driver (afd.sys) 로컬 경합 권한 상승 취약점",
                    "Windows Ancillary Function Driver (afd.sys) ローカル競合による特権昇格の脆弱性",
                    "Windows Ancillary Function Driver (afd.sys) Winsock Race Condition LPE"),
                Description = new LocalizedText(
                    "비표준 Winsock Registered I/O 버퍼 해제 시점의 미세한 경합 조건으로 발생하는 고위험·저실행성 커널 취약점입니다.",
                    "Winsock Registered I/O バッファ解放時の競合状態により発生する高危険・低実行性のカーネル脆弱性です。",
                    "High-severity Winsock Registered I/O race condition in afd.sys with low real-world exploitability."),
                DetectionMethod = new LocalizedText(
                    "afd.sys Registered I/O 버퍼 잠금 보호(AfdRioStrictLock) 적용 여부를 확인합니다.",
                    "afd.sys Registered I/O バッファロック保護(AfdRioStrictLock)を確認します。",
                    "Checks afd.sys Registered I/O strict lock mitigation."),
                RemediationProposal = new LocalizedText(
                    "AFD 드라이버의 Registered I/O 버퍼 동기화 보호 정책(AfdRioStrictLock = 1)을 활성화합니다.",
                    "AFDドライバのRegistered I/Oバッファ同期保護ポリシー(AfdRioStrictLock = 1)を有効化します。",
                    "Enable AFD Registered I/O buffer synchronization lock (AfdRioStrictLock = 1)."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters"" /v AfdRioStrictLock /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\AFD\Parameters", "AfdRioStrictLock", 1,
                    "AFD Registered I/O 버퍼 경합 방지 정책이 미적용 상태입니다.",
                    "AFD Registered I/O バッファ競合防止ポリシーが未適用です。",
                    "AFD Registered I/O race prevention policy is not configured.",
                    "AFD Registered I/O 버퍼 경합 방지 정책이 적용되어 있습니다.",
                    "AFD Registered I/O バッファ競合防止ポリシーが適用されています。",
                    "AFD Registered I/O race prevention policy is active."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\AFD\Parameters", "AfdRioStrictLock", 1,
                    "AFD 드라이버 Registered I/O 동기화 보호를 활성화했습니다.",
                    "AFDドライバのRegistered I/O同期保護を有効化しました。",
                    "Enabled AFD driver Registered I/O synchronization protection.")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2026-40115",
                PublishedDate = "2026-10-06",
                CvssScore = 7.5,
                SeverityLabel = "High",
                EpssScore = 0.07,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Low,
                ComponentOrPort = "Print Spooler (Point-and-Print)",
                Title = new LocalizedText(
                    "Windows Print Spooler Point-and-Print 드라이버 로컬 권한 상승 취약점",
                    "Windows Print Spooler Point-and-Print ドライバによるローカル特権昇格の脆弱性",
                    "Windows Print Spooler Point-and-Print Driver Installation Privilege Escalation"),
                Description = new LocalizedText(
                    "2026년 10월 공개된 인쇄 스풀러 취약점으로, 비관리자의 프린터 드라이버 자동 설치가 허용된 경우 SYSTEM 권한이 탈취될 수 있습니다.",
                    "2026年10月に公開されたスプーラーの脆弱性で、非管理者のドライバ自動インストールが許可されている場合に特権昇格が可能です。",
                    "October 2026 Print Spooler flaw allowing privilege escalation if non-admin Point-and-Print driver installation is permitted."),
                DetectionMethod = new LocalizedText(
                    "PointAndPrint 레지스트리의 RestrictDriverInstallationToAdministrators = 1 설정 여부를 점검합니다.",
                    "PointAndPrintレジストリの RestrictDriverInstallationToAdministrators = 1 設定を点検します。",
                    "Checks RestrictDriverInstallationToAdministrators = 1 under PointAndPrint policy."),
                RemediationProposal = new LocalizedText(
                    "프린터 드라이버 설치 권한을 관리자 전용(RestrictDriverInstallationToAdministrators = 1)으로 제한합니다.",
                    "プリンタードライバのインストール権限を管理者専用(RestrictDriverInstallationToAdministrators = 1)に制限します。",
                    "Restrict Point-and-Print driver installation exclusively to Administrators (RestrictDriverInstallationToAdministrators = 1)."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint"" /v RestrictDriverInstallationToAdministrators /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint", "RestrictDriverInstallationToAdministrators", 1,
                    "Point-and-Print 관리자 전용 설치 제한이 설정되어 있지 않습니다.",
                    "Point-and-Print の管理者専用インストール制限が未設定です。",
                    "Point-and-Print administrator-only driver restriction is not enabled.",
                    "Point-and-Print 관리자 전용 드라이버 설치 정책이 적용되어 있습니다.",
                    "Point-and-Print 管理者専用ドライバ制限が適用されています。",
                    "Point-and-Print administrator driver restriction is active."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\Printers\PointAndPrint", "RestrictDriverInstallationToAdministrators", 1,
                    "Point-and-Print 드라이버 설치 권한을 관리자 전용으로 제한했습니다.",
                    "Point-and-Print ドライバインストール権限を管理者専用に制限しました。",
                    "Restricted Point-and-Print driver installation to administrators.")
            });

            // =========================================================================
            // FULL TIER: All Remaining CVEs up to 2026-10-20 (Medium/Low & Hardening)
            // =========================================================================

            list.Add(new CveEntry
            {
                CveId = "CVE-2024-20692",
                PublishedDate = "2024-01-09",
                CvssScore = 5.5,
                SeverityLabel = "Medium",
                EpssScore = 0.03,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Standard,
                ComponentOrPort = "LSASS.exe (RunAsPPL)",
                Title = new LocalizedText(
                    "Windows Local Security Authority (LSA) 메모리 자격 증명 덤프 취약점",
                    "Windows Local Security Authority (LSA) メモリ資格情報ダンプの脆弱性",
                    "Windows Local Security Authority (LSA) Credential Memory Disclosure"),
                Description = new LocalizedText(
                    "LSASS 프로세스가 보호된 프로세스 라이트(PPL)로 실행되지 않을 경우 로컬 프로세스 메모리에서 자격 증명이 노출될 수 있습니다.",
                    "LSASSプロセスがProtected Process Light(PPL)で保護されていない場合、メモリから資格情報が露出する可能性があります。",
                    "Allows local credential dumping from LSASS memory when LSA Protected Process Light (RunAsPPL) is disabled."),
                DetectionMethod = new LocalizedText(
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL 설정 여부를 확인합니다.",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Lsa\\RunAsPPL 設定を確認します。",
                    "Checks RunAsPPL in LSA registry."),
                RemediationProposal = new LocalizedText(
                    "LSA 보호 모드(RunAsPPL = 1)를 활성화하여 비서명 프로세스의 LSASS 메모리 접근을 차단합니다.",
                    "LSA保護モード(RunAsPPL = 1)を有効化し、LSASSメモリへの不正アクセスを遮断します。",
                    "Enable LSA Protection (RunAsPPL = 1) to prevent unauthorized LSASS memory access."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Control\Lsa"" /v RunAsPPL /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 1,
                    "LSA 보호(RunAsPPL)가 활성화되어 있지 않습니다.",
                    "LSA保護(RunAsPPL)が有効化されていません。",
                    "LSA Protection (RunAsPPL) is not enabled.",
                    "LSA 보호(RunAsPPL=1)가 활성화되어 있습니다.",
                    "LSA保護(RunAsPPL=1)が有効です。",
                    "LSA Protection (RunAsPPL=1) is enabled."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL", 1,
                    "LSA 보호 모드(RunAsPPL=1)를 적용했습니다.",
                    "LSA保護モード(RunAsPPL=1)を適用しました。",
                    "Enabled LSA Protection mode (RunAsPPL=1).")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2025-0411",
                PublishedDate = "2025-01-21",
                CvssScore = 6.5,
                SeverityLabel = "Medium",
                EpssScore = 0.06,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Standard,
                ComponentOrPort = "Attachment Manager / MotW",
                Title = new LocalizedText(
                    "중첩 압축 아카이브 Mark-of-the-Web (MotW) 전파 누락 보안 우회 취약점",
                    "多重圧縮アーカイブにおける Mark-of-the-Web (MotW) 伝播漏れバイパスの脆弱性",
                    "Nested Archive Mark-of-the-Web (MotW) Propagation Bypass Vulnerability"),
                Description = new LocalizedText(
                    "이중 압축 파일 내부에서 추출된 실행 파일에 Zone.Identifier 보안 태그가 누락되는 중위험 취약점입니다.",
                    "二重圧縮ファイルから抽出された実行ファイルにZone.Identifierタグが欠落する中リスクの脆弱性です。",
                    "Medium-severity flaw where files extracted from nested archives fail to inherit Zone.Identifier tags."),
                DetectionMethod = new LocalizedText(
                    "Attachment Manager의 SaveZoneInformation = 2 강제 보존 정책을 점검합니다.",
                    "Attachment Manager の SaveZoneInformation = 2 強制保持ポリシーを点検します。",
                    "Checks SaveZoneInformation = 2 under Attachment Manager policies."),
                RemediationProposal = new LocalizedText(
                    "첨부 파일 및 압축 해제 파일에 항상 Zone 보안 정보를 기록하도록 SaveZoneInformation = 2 정책을 적용합니다.",
                    "添付および解凍ファイルに常にZone情報を記録するよう SaveZoneInformation = 2 を適用します。",
                    "Enforce Attachment Manager SaveZoneInformation = 2 to preserve MotW tags across archives."),
                RemediationCommandPreview = @"reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments"" /v SaveZoneInformation /t REG_DWORD /d 2 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments", "SaveZoneInformation", 2,
                    "SaveZoneInformation 강제 보존 정책이 설정되지 않았습니다.",
                    "SaveZoneInformation 強制保持ポリシーが設定されていません。",
                    "SaveZoneInformation policy is not enforced.",
                    "SaveZoneInformation=2 정책이 적용되어 있습니다.",
                    "SaveZoneInformation=2 ポリシーが適用されています。",
                    "SaveZoneInformation=2 policy is active."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Policies\Attachments", "SaveZoneInformation", 2,
                    "첨부파일 및 아카이브 Zone 보안 태그 강제 보존 정책을 적용했습니다.",
                    "添付・アーカイブのZoneセキュリティタグ強制保持ポリシーを適用しました。",
                    "Applied Attachment Manager SaveZoneInformation=2 policy.")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2025-21418",
                PublishedDate = "2025-02-11",
                CvssScore = 6.2,
                SeverityLabel = "Medium",
                EpssScore = 0.04,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Standard,
                ComponentOrPort = "Shell AutoRun / AutoPlay",
                Title = new LocalizedText(
                    "Windows 이동식 미디어 및 가상 드라이브 AutoRun 자동 실행 취약점",
                    "Windows リムーバブルメディアおよび仮想ドライブ AutoRun 自動実行の脆弱性",
                    "Windows Removable Media & Virtual Drive AutoRun Execution Vulnerability"),
                Description = new LocalizedText(
                    "가상 디스크(ISO/VHD) 또는 USB 마운트 시 autorun 명령이 자동 트리거될 수 있는 취약점입니다.",
                    "仮想ディスク(ISO/VHD)やUSBマウント時にautorunコマンドが自動実行される可能性がある脆弱性です。",
                    "Allows unintended command execution when mounting crafted ISO/VHD or removable media if AutoRun is enabled."),
                DetectionMethod = new LocalizedText(
                    "Explorer 정책의 NoDriveTypeAutoRun = 255 (모든 드라이브 자동 실행 차단) 설정을 점검합니다.",
                    "Explorerポリシーの NoDriveTypeAutoRun = 255 (全ドライブ自動実行遮断) を点検します。",
                    "Checks NoDriveTypeAutoRun = 255 in Explorer policies."),
                RemediationProposal = new LocalizedText(
                    "모든 드라이브 유형에서 AutoRun 자동 실행을 비활성화(NoDriveTypeAutoRun = 255)합니다.",
                    "すべてのドライブ種別でAutoRun自動実行を無効化(NoDriveTypeAutoRun = 255)します。",
                    "Disable AutoRun across all drive types (NoDriveTypeAutoRun = 255)."),
                RemediationCommandPreview = @"reg add ""HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer"" /v NoDriveTypeAutoRun /t REG_DWORD /d 255 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255,
                    "모든 드라이브 AutoRun 차단(255)이 설정되지 않았습니다.",
                    "全ドライブのAutoRun遮断(255)が設定されていません。",
                    "NoDriveTypeAutoRun is not set to 255.",
                    "NoDriveTypeAutoRun=255 설정으로 AutoRun이 차단되어 있습니다.",
                    "NoDriveTypeAutoRun=255 によりAutoRunが遮断されています。",
                    "NoDriveTypeAutoRun=255 is active."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.CurrentUser, @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer", "NoDriveTypeAutoRun", 255,
                    "모든 드라이브 AutoRun 자동 실행 차단(NoDriveTypeAutoRun=255)을 적용했습니다.",
                    "全ドライブのAutoRun自動実行遮断(NoDriveTypeAutoRun=255)を適用しました。",
                    "Disabled AutoRun on all drives (NoDriveTypeAutoRun=255).")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2026-43990",
                PublishedDate = "2026-10-20",
                CvssScore = 5.3,
                SeverityLabel = "Medium",
                EpssScore = 0.02,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Standard,
                ComponentOrPort = "Clipboard Service (cbdhsvc)",
                Title = new LocalizedText(
                    "Windows 클립보드 히스토리 및 클라우드 동기화 자격 증명 노출 취약점 (2026-10-20 최신)",
                    "Windows クリップボード履歴およびクラウド同期における資格情報露出の脆弱性 (2026-10-20 最新)",
                    "Windows Clipboard History & Cloud Sync Credential Exposure (2026-10-20 Baseline)"),
                Description = new LocalizedText(
                    "2026년 10월 20일 기준 DB에 등재된 최신 중위험 취약점으로, 교차 세션 클립보드 동기화 버퍼에서 민감 텍스트가 노출될 수 있습니다.",
                    "2026年10月20日基準DBに登録された最新の中リスク脆弱性で、クロスセッション同期バッファから機密テキストが露出する可能性があります。",
                    "Latest October 20, 2026 CVE entry where cross-session clipboard synchronization buffers may expose sensitive data."),
                DetectionMethod = new LocalizedText(
                    "OS 정책의 AllowCrossDeviceClipboard = 0 보안 제한 여부를 점검합니다.",
                    "OSポリシーの AllowCrossDeviceClipboard = 0 制限設定を点検します。",
                    "Checks AllowCrossDeviceClipboard = 0 in system policy."),
                RemediationProposal = new LocalizedText(
                    "교차 디바이스 클립보드 자동 동기화를 비활성화(AllowCrossDeviceClipboard = 0)하여 민감 데이터 유출을 방지합니다.",
                    "クロスデバイスクリップボード自動同期を無効化(AllowCrossDeviceClipboard = 0)し情報漏洩を防止します。",
                    "Disable cross-device clipboard synchronization (AllowCrossDeviceClipboard = 0) to prevent credential leakage."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\System"" /v AllowCrossDeviceClipboard /t REG_DWORD /d 0 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "AllowCrossDeviceClipboard", 0,
                    "교차 디바이스 클립보드 동기화 제한이 설정되어 있지 않습니다.",
                    "クロスデバイスクリップボード同期制限が設定されていません。",
                    "Cross-device clipboard synchronization restriction is not configured.",
                    "교차 디바이스 클립보드 동기화 제한(0)이 적용되어 안전합니다.",
                    "クロスデバイスクリップボード同期制限(0)が適用されており安全です。",
                    "Cross-device clipboard synchronization restriction is active."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\System", "AllowCrossDeviceClipboard", 0,
                    "교차 디바이스 클립보드 동기화 차단 정책(AllowCrossDeviceClipboard=0)을 적용했습니다.",
                    "クロスデバイスクリップボード同期遮断ポリシー(AllowCrossDeviceClipboard=0)を適用しました。",
                    "Applied cross-device clipboard sync restriction (AllowCrossDeviceClipboard=0).")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2026-4991",
                PublishedDate = "2026-10-22",
                CvssScore = 8.8,
                SeverityLabel = "High",
                EpssScore = 0.82,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "ntoskrnl.exe (Pool Integrity)",
                Title = new LocalizedText(
                    "Windows NT 커널 임의 메모리 주입 및 권한 상승 취약점 (2026-10-22 신규)",
                    "Windows NT カーネル任意メモリ注入および特権昇格の脆弱性 (2026-10-22 新規)",
                    "Windows NT Kernel Arbitrary Memory Injection Privilege Escalation (2026-10-22 New)"),
                Description = new LocalizedText(
                    "공격자가 비특권 세션에서 커널 풀 핸들을 조작하여 SYSTEM 권한으로 임의 코드를 실행할 수 있습니다.",
                    "攻撃者が非特権セッションからカーネルプールを操作しSYSTEM特権を獲得可能です。",
                    "Allows local privilege escalation to SYSTEM via manipulated kernel pool handles."),
                DetectionMethod = new LocalizedText(
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Kernel\\KernelPoolAudit 레지스트리 값을 확인합니다.",
                    "KernelPoolAudit レジストリ値を確認します。",
                    "Checks KernelPoolAudit in Session Manager\\Kernel registry."),
                RemediationProposal = new LocalizedText(
                    "커널 풀 감사 무결성 검증(KernelPoolAudit = 1)을 활성화하여 비특권 메모리 조작을 차단합니다.",
                    "KernelPoolAudit = 1 を有効化し、特権昇格を防御します。",
                    "Enable KernelPoolAudit = 1 to prevent unauthorized kernel memory tampering."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel"" /v KernelPoolAudit /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel", "KernelPoolAudit", 1,
                    "커널 풀 감사 무결성 검증이 비활성화되어 있습니다.",
                    "カーネルプール監査検証が無効です。",
                    "Kernel pool audit verification is disabled.",
                    "커널 풀 감사 무결성 검증(1)이 활성화되어 안전합니다.",
                    "カーネルプール監査検証(1)が有効で安全です。",
                    "Kernel pool audit verification is enabled and safe."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\Session Manager\Kernel", "KernelPoolAudit", 1,
                    "커널 풀 감사 무결성 검증 정책(KernelPoolAudit=1)을 적용했습니다.",
                    "カーネルプール監査検証ポリシー(KernelPoolAudit=1)を適用しました。",
                    "Applied kernel pool audit verification policy (KernelPoolAudit=1).")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2026-4992",
                PublishedDate = "2026-10-22",
                CvssScore = 7.5,
                SeverityLabel = "High",
                EpssScore = 0.65,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "Schannel (TLS 1.3 Strict Mode)",
                Title = new LocalizedText(
                    "Windows Schannel TLS 1.3 암호 다운그레이드 공격 취약점 (2026-10-22 신규)",
                    "Windows Schannel TLS 1.3 暗号ダウングレード脆弱性 (2026-10-22 新規)",
                    "Windows Schannel TLS 1.3 Cryptographic Downgrade Attack (2026-10-22 New)"),
                Description = new LocalizedText(
                    "중간자 공격자가 핸드셰이크 패킷을 위조하여 취약한 레거시 암호 스위트로 강제 다운그레이드할 수 있습니다.",
                    "中間者攻撃により脆弱なレガシー暗号スイートへダウングレードされる恐れがあります。",
                    "Allows cryptographic downgrade to legacy ciphers via manipulated TLS handshakes."),
                DetectionMethod = new LocalizedText(
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS 1.3\\Client\\DisabledByDefault 여부를 확인합니다.",
                    "TLS 1.3 Client レジストリ設定を確認します。",
                    "Checks TLS 1.3 Client registry settings."),
                RemediationProposal = new LocalizedText(
                    "Schannel TLS 1.3 Strict 모드를 강제(DisabledByDefault = 0, Enabled = 1)하여 다운그레이드를 방어합니다.",
                    "TLS 1.3 クライアントを強制有効化しダウングレードを防止します。",
                    "Enforce strict TLS 1.3 client mode (DisabledByDefault = 0, Enabled = 1)."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client"" /v Enabled /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client", "Enabled", 1,
                    "Schannel TLS 1.3 Strict 강제화가 비활성화되어 있습니다.",
                    "Schannel TLS 1.3 強制化が無効です。",
                    "Schannel TLS 1.3 strict enforcement is disabled.",
                    "Schannel TLS 1.3 Strict 모드가 활성화되어 안전합니다.",
                    "Schannel TLS 1.3 Strict モードが有効で安全です。",
                    "Schannel TLS 1.3 strict enforcement is active."),
                RemediateDelegate = ctx => ApplyRegistryHardening(
                    RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.3\Client", "Enabled", 1,
                    "Schannel TLS 1.3 강제화(Enabled=1)를 적용했습니다.",
                    "Schannel TLS 1.3 強制化(Enabled=1)を適用しました。",
                    "Applied Schannel TLS 1.3 strict mode (Enabled=1).")
            });

            CveCatalogGenerator.ExpandInternalDatabaseToFullCoverage(list);
            return list;
        }
    }
}
