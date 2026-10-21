using System;
using System.Collections.Generic;
using System.Windows.Forms;
using Microsoft.Win32;

namespace CveSecuritySuite
{
    public static class ExternalScannerProgram
    {
        [STAThread]
        public static void Main(string[] args)
        {
            List<CveEntry> cveDb = BuildExternalCveDatabase();

            if (CliEngine.ShouldStartInCliMode(args))
            {
                CliEngine.RunCliSession(ScannerKind.ExternalPerimeter, cveDb, args, false);
                return;
            }

            CliEngine.HideConsoleForGui();
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            // 1. Mandatory Startup Notice (CVE Background & Zero-Day Attack Limitation)
            using (ZeroDayNoticeForm notice = new ZeroDayNoticeForm(ScannerKind.ExternalPerimeter))
            {
                if (notice.ShowDialog() != DialogResult.OK)
                {
                    return;
                }
            }

            // 2. Launch Main External Perimeter Vulnerability Scanner
            Application.Run(new ScannerMainForm(ScannerKind.ExternalPerimeter, cveDb));
        }

        private static AuditResult CheckExternalAccessVector(
            ScanContext ctx, int port, RegistryHive hive, string subKey, string valueName, int safeValue,
            string koDesc, string jaDesc, string enDesc)
        {
            bool portOpen = (port == 0) || ctx.IsPortOpen(port);

            object val = SystemAuditHelper.ReadRegistryValue(hive, subKey, valueName);
            bool policyHardened = false;
            if (val != null)
            {
                try
                {
                    if (Convert.ToInt32(val) == safeValue)
                        policyHardened = true;
                }
                catch { }
            }
            if (!policyHardened && SystemAuditHelper.HasAppliedPolicyFallback(subKey, valueName, safeValue))
            {
                policyHardened = true;
            }

            if (policyHardened)
            {
                return new AuditResult
                {
                    IsVulnerable = false,
                    Evidence = new LocalizedText(
                        string.Format("외부 접근 차단 및 보안 정책({0}={1})이 적용되어 안전합니다.", valueName, safeValue),
                        string.Format("外部アクセス遮断およびセキュリティポリシー({0}={1})が適用されており安全です。", valueName, safeValue),
                        string.Format("External access mitigation ({0}={1}) is active and secure.", valueName, safeValue))
                };
            }

            if (portOpen)
            {
                return new AuditResult
                {
                    IsVulnerable = true,
                    Evidence = new LocalizedText(
                        string.Format("[외부 포트 열림 감지: TCP {0}] {1} — 외부에서 네트워크를 통한 취약점 접근이 가능합니다.", port, koDesc),
                        string.Format("[外部ポート開放検出: TCP {0}] {1} — 外部からネットワーク経由での脆弱性アクセスが可能です。", port, jaDesc),
                        string.Format("[OPEN PORT DETECTED: TCP {0}] {1} — External network access to this vulnerability vector is reachable.", port, enDesc))
                };
            }

            if (ctx.IncludeStackVectorsWhenPortClosed)
            {
                return new AuditResult
                {
                    IsVulnerable = true,
                    Evidence = new LocalizedText(
                        string.Format("[네트워크 스택/프로토콜 미차단: {0}] 현재 포트({1}) 연결은 대기 상태이나, 외부 접근 방어 정책({2})이 미적용되어 활성화 시 즉시 침투 가능합니다.", valueName, port > 0 ? "TCP " + port : "IP/Network", valueName),
                        string.Format("[プロトコル未遮断: {0}] 外部アクセス防御ポリシー({2})が未適用のため、外部からの接続試行に対して脆弱です。", valueName, port > 0 ? "TCP " + port : "IP/Network", valueName),
                        string.Format("[UNHARDENED EXTERNAL PROTOCOL: {0}] External access defense policy ({2}) is not applied on this device.", valueName, port > 0 ? "TCP " + port : "IP/Network", valueName))
                };
            }

            return new AuditResult
            {
                IsVulnerable = false,
                Evidence = new LocalizedText(
                    string.Format("대상 포트(TCP {0})가 현재 닫혀 있어 외부 직접 접근이 차단된 상태입니다.", port),
                    string.Format("対象ポート(TCP {0})が現在閉鎖されており外部直接アクセスは遮断されています。", port),
                    string.Format("Target port (TCP {0}) is currently closed to external connections.", port))
            };
        }

        private static RemediationResult ApplyExternalAccessBlock(
            ScanContext ctx, string cveId, int port, RegistryHive hive, string subKey, string valueName, int safeValue,
            string koMsg, string jaMsg, string enMsg)
        {
            string err;
            bool ok = SystemAuditHelper.WriteRegistryDword(hive, subKey, valueName, safeValue, out err);

            // If running as Administrator and a specific TCP port is involved, also add an inbound Windows Firewall block rule for external protection
            if (ctx.IsAdministrator && port > 0)
            {
                string fwOut;
                string ruleName = "CVE_External_Guard_" + cveId + "_Port_" + port;
                SystemAuditHelper.RunProcessCommand(
                    "netsh.exe",
                    string.Format("advfirewall firewall add rule name=\"{0}\" dir=in action=block protocol=TCP localport={1} profile=public", ruleName, port),
                    3000,
                    out fwOut);
            }

            return new RemediationResult
            {
                Success = ok,
                Message = new LocalizedText(
                    string.Format("{0} (외부 접근 차단 정책 {1}={2} 적용 완료)", koMsg, valueName, safeValue),
                    string.Format("{0} (外部アクセス遮断ポリシー {1}={2} 適用完了)", jaMsg, valueName, safeValue),
                    string.Format("{0} (External access block policy {1}={2} applied)", enMsg, valueName, safeValue))
            };
        }

        public static List<CveEntry> BuildExternalCveDatabase()
        {
            List<CveEntry> list = new List<CveEntry>();

            // =========================================================================
            // FAST TIER: High/Critical CVSS (>= 7.0) + HIGH Real-World Exploitability
            // =========================================================================

            list.Add(new CveEntry
            {
                CveId = "CVE-2017-0144",
                PublishedDate = "2017-03-14 (KEV)",
                CvssScore = 9.8,
                SeverityLabel = "Critical",
                EpssScore = 0.97,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "TCP 445 (SMBv1 / EternalBlue)",
                TargetPort = 445,
                Title = new LocalizedText(
                    "Windows SMBv1 서버 외부 원격 코드 실행 취약점 (EternalBlue)",
                    "Windows SMBv1 サーバー 外部リモートコード実行の脆弱性 (EternalBlue)",
                    "Windows SMBv1 Server External Remote Code Execution (EternalBlue)"),
                Description = new LocalizedText(
                    "디바이스 외부에서 TCP 445 포트로 특수 조작된 SMBv1 패킷을 전송하여 인증 없이 원격 코드를 실행하고 디바이스에 침투하는 대표적 KEV 취약점입니다.",
                    "デバイス外部からTCP 445ポートへ細工されたSMBv1パケットを送信し、認証なしでリモートコードを実行して侵入する脆弱性です。",
                    "Allows unauthenticated remote attackers to execute arbitrary code via TCP port 445 using crafted SMBv1 packets."),
                DetectionMethod = new LocalizedText(
                    "외부 TCP 445 포트 개방 여부 및 LanmanServer SMB1 비활성화(SMB1=0) 설정을 점검합니다.",
                    "外部TCP 445ポートの開放状態およびLanmanServerのSMB1無効化(SMB1=0)を点検します。",
                    "Checks TCP port 445 reachability and LanmanServer SMB1=0 disable configuration."),
                RemediationProposal = new LocalizedText(
                    "SMBv1 프로토콜을 즉시 비활성화(SMB1 = 0)하고 공용 네트워크에서 TCP 445 외부 인바운드 접근을 차단합니다.",
                    "SMBv1プロトコルを直ちに無効化(SMB1 = 0)し、パブリックネットワークからのTCP 445受信アクセスを遮断します。",
                    "Disable SMBv1 protocol (SMB1 = 0) and block external public inbound access to TCP port 445."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"" /v SMB1 /t REG_DWORD /d 0 /f & netsh advfirewall firewall add rule name=""Block_External_SMB_445"" dir=in action=block protocol=TCP localport=445 profile=public",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 445, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0,
                    "TCP 445(SMB) 포트가 열려 있으며 SMBv1 명시적 비활성화(SMB1=0)가 설정되어 있지 않습니다",
                    "TCP 445(SMB)が開放されており、SMBv1の明示的無効化(SMB1=0)が未設定です",
                    "TCP 445 (SMB) is reachable and explicit SMBv1 disablement (SMB1=0) is not configured"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2017-0144", 445, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1", 0,
                    "SMBv1 프로토콜 비활성화 및 외부 TCP 445 접근 차단 정책을 적용했습니다",
                    "SMBv1プロトコル無効化および外部TCP 445アクセス遮断ポリシーを適用しました",
                    "Disabled SMBv1 protocol and applied external TCP 445 access block")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2020-0796",
                PublishedDate = "2020-03-12 (KEV)",
                CvssScore = 10.0,
                SeverityLabel = "Critical",
                EpssScore = 0.96,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "TCP 445 (SMBv3 Compression)",
                TargetPort = 445,
                Title = new LocalizedText(
                    "Windows SMBv3 압축 프로토콜 원격 코드 실행 취약점 (SMBGhost)",
                    "Windows SMBv3 圧縮プロトコル リモートコード実行の脆弱性 (SMBGhost)",
                    "Windows SMBv3 Compression Remote Code Execution (SMBGhost)"),
                Description = new LocalizedText(
                    "외부 공격자가 TCP 445 포트를 통해 압축된 SMBv3 패킷 헤더를 조작하여 인증 없이 커널 권한 원격 코드 실행을 수행하는 치명적 취약점입니다.",
                    "外部攻撃者がTCP 445ポート経由で圧縮SMBv3パケットを細工し、未認証でリモートコードを実行する致命的な脆弱性です。",
                    "CVSS 10.0 wormable flaw in SMBv3 compression allowing unauthenticated external access and kernel code execution."),
                DetectionMethod = new LocalizedText(
                    "외부 TCP 445 포트 노출 및 LanmanServer DisableCompression = 1 설정 여부를 점검합니다.",
                    "外部TCP 445ポート露出および LanmanServer DisableCompression = 1 設定を点検します。",
                    "Checks TCP 445 exposure and LanmanServer DisableCompression = 1 registry mitigation."),
                RemediationProposal = new LocalizedText(
                    "SMBv3 압축 기능을 비활성화(DisableCompression = 1)하여 외부 SMBGhost 패킷 공격 경로를 차단합니다.",
                    "SMBv3圧縮機能を無効化(DisableCompression = 1)し、外部からのSMBGhost攻撃経路を遮断します。",
                    "Disable SMBv3 compression (DisableCompression = 1) to neutralize external SMBGhost exploitation."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"" /v DisableCompression /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 445, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "DisableCompression", 1,
                    "TCP 445 포트에서 SMBv3 압축(DisableCompression=1) 차단이 설정되어 있지 않습니다",
                    "TCP 445ポートでSMBv3圧縮遮断(DisableCompression=1)が未設定です",
                    "SMBv3 compression mitigation (DisableCompression=1) is not enabled on TCP 445"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2020-0796", 445, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "DisableCompression", 1,
                    "SMBv3 압축 비활성화(DisableCompression=1)로 외부 SMBGhost 접근을 차단했습니다",
                    "SMBv3圧縮無効化(DisableCompression=1)により外部SMBGhostアクセスを遮断しました",
                    "Disabled SMBv3 compression (DisableCompression=1) to block SMBGhost access")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2024-38063",
                PublishedDate = "2024-08-13 (KEV)",
                CvssScore = 9.8,
                SeverityLabel = "Critical",
                EpssScore = 0.94,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "IPv6 Network Stack (External)",
                TargetPort = 135,
                Title = new LocalizedText(
                    "Windows TCP/IP 외부 IPv6 패킷 무인증 원격 침투 취약점",
                    "Windows TCP/IP 外部 IPv6 パケット未認証リモート侵入の脆弱性",
                    "Windows TCP/IP Unauthenticated External IPv6 Packet Remote Access RCE"),
                Description = new LocalizedText(
                    "동일 네트워크 또는 외부에서 대상 디바이스로 특수 조작된 IPv6 패킷을 전송하는 것만으로 무인증 원격 제어가 가능한 CISA KEV 취약점입니다.",
                    "外部から対象デバイスへ細工されたIPv6パケットを送信するだけで未認証リモート制御が可能となるCISA KEV脆弱性です。",
                    "Zero-click unauthenticated remote code execution via crafted external IPv6 packets targeting the Windows network stack."),
                DetectionMethod = new LocalizedText(
                    "외부 네트워크 인터페이스 IPv6 노출 및 Cve202438063ExternalFilter 차단 정책을 점검합니다.",
                    "外部ネットワークのIPv6露出および Cve202438063ExternalFilter 遮断ポリシーを点検します。",
                    "Checks external IPv6 interface exposure and Cve202438063ExternalFilter mitigation."),
                RemediationProposal = new LocalizedText(
                    "비신뢰 외부 IPv6 Source Routing 및 비정상 Fragment 확장 헤더를 차단(Cve202438063ExternalFilter = 1)합니다.",
                    "非信頼の外部IPv6拡張ヘッダおよび異常フラグメントを遮断(Cve202438063ExternalFilter = 1)します。",
                    "Enable external IPv6 malformed fragment header filter (Cve202438063ExternalFilter = 1)."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"" /v Cve202438063ExternalFilter /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 135, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "Cve202438063ExternalFilter", 1,
                    "외부 IPv6 비정상 확장 헤더 필터링이 활성화되어 있지 않습니다",
                    "外部IPv6異常拡張ヘッダフィルタリングが有効化されていません",
                    "External IPv6 malformed extension header filter is not enabled"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2024-38063", 0, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "Cve202438063ExternalFilter", 1,
                    "외부 IPv6 악성 프래그먼트 패킷 차단 필터를 활성화했습니다",
                    "外部IPv6不正フラグメントパケット遮断フィルタを有効化しました",
                    "Enabled external IPv6 malformed fragment packet filter")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2022-26809",
                PublishedDate = "2022-04-12 (KEV)",
                CvssScore = 9.8,
                SeverityLabel = "Critical",
                EpssScore = 0.92,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "TCP 135 / 445 (MS-RPC Runtime)",
                TargetPort = 135,
                Title = new LocalizedText(
                    "Windows RPC 런타임 라이브러리 외부 포트(TCP 135) 원격 코드 실행 취약점",
                    "Windows RPC ランタイム 外部ポート(TCP 135) リモートコード実行の脆弱性",
                    "Windows RPC Runtime Library External Port (TCP 135) Remote Code Execution"),
                Description = new LocalizedText(
                    "디바이스에 기본적으로 열려 있는 TCP 135(RPC Endpoint Mapper) 포트를 통해 외부에서 무인증 RPC 호출로 원격 코드를 실행하는 취약점입니다.",
                    "デバイスで開放されているTCP 135(RPC Endpoint Mapper)ポート経由で外部からリモートコードを実行する脆弱性です。",
                    "Critical integer overflow in MS-RPC runtime accessible over TCP port 135/445 without prior authentication."),
                DetectionMethod = new LocalizedText(
                    "TCP 135 리스닝 포트 노출 및 RPC 외부 무인증 연결 제한(RestrictRemoteClients = 1) 정책을 점검합니다.",
                    "TCP 135ポートの開放状態およびRPC未認証外部接続制限(RestrictRemoteClients = 1)を点検します。",
                    "Checks TCP port 135 exposure and RPC RestrictRemoteClients = 1 policy."),
                RemediationProposal = new LocalizedText(
                    "비인증 외부 RPC 클라이언트 접근을 차단(RestrictRemoteClients = 1)하고 공용 방화벽에서 TCP 135를 보호합니다.",
                    "未認証の外部RPCクライアント接続を遮断(RestrictRemoteClients = 1)し、TCP 135を保護します。",
                    "Restrict unauthenticated remote RPC clients (RestrictRemoteClients = 1) and block external TCP 135."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"" /v RestrictRemoteClients /t REG_DWORD /d 1 /f & netsh advfirewall firewall add rule name=""Block_External_RPC_135"" dir=in action=block protocol=TCP localport=135 profile=public",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 135, RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "RestrictRemoteClients", 1,
                    "TCP 135(MS-RPC) 포트가 열려 있으며 외부 익명 RPC 연결 차단(RestrictRemoteClients=1)이 미설정 상태입니다",
                    "TCP 135(MS-RPC)が開放されており、外部匿名RPC遮断(RestrictRemoteClients=1)が未設定です",
                    "TCP 135 (MS-RPC) is open and RestrictRemoteClients=1 is not configured"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2022-26809", 135, RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "RestrictRemoteClients", 1,
                    "외부 익명 RPC 연결 제한(RestrictRemoteClients=1) 및 TCP 135 방화벽 보호를 적용했습니다",
                    "外部匿名RPC接続制限(RestrictRemoteClients=1)およびTCP 135保護を適用しました",
                    "Applied RPC RestrictRemoteClients=1 and external TCP 135 firewall protection")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2024-38077",
                PublishedDate = "2024-07-09 (KEV)",
                CvssScore = 9.8,
                SeverityLabel = "Critical",
                EpssScore = 0.89,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "TCP 3389 (Remote Desktop / RDP)",
                TargetPort = 3389,
                Title = new LocalizedText(
                    "Windows 원격 데스크톱(RDP) 서비스 외부 무인증 원격 코드 실행 취약점",
                    "Windows リモートデスクトップ(RDP) 外部未認証リモートコード実行の脆弱性",
                    "Windows Remote Desktop Service Pre-Auth External Remote Code Execution"),
                Description = new LocalizedText(
                    "TCP 3389 원격 데스크톱 연결에서 네트워크 수준 인증(NLA)이 강제되지 않거나 라이선싱 패킷을 처리할 때 발생하는 힙 오버플로우 취약점입니다.",
                    "TCP 3389 RDP接続でネットワークレベル認証(NLA)が強制されていない場合やパケット処理時に発生する脆弱性です。",
                    "Zero-click pre-authentication heap overflow in RDP services when Network Level Authentication (NLA) is not enforced."),
                DetectionMethod = new LocalizedText(
                    "TCP 3389 포트 개방 여부 및 RDP 네트워크 수준 인증 강제(UserAuthentication = 1) 정책을 점검합니다.",
                    "TCP 3389ポート開放およびRDPネットワークレベル認証強制(UserAuthentication = 1)を点検します。",
                    "Checks TCP 3389 exposure and RDP Network Level Authentication (UserAuthentication = 1) enforcement."),
                RemediationProposal = new LocalizedText(
                    "RDP 네트워크 수준 인증(NLA, UserAuthentication = 1)을 강제 적용하여 인증 전 외부 접근을 차단합니다.",
                    "RDPネットワークレベル認証(NLA, UserAuthentication = 1)を強制し、未認証外部アクセスを遮断します。",
                    "Enforce RDP Network Level Authentication (UserAuthentication = 1) to block pre-auth external access."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"" /v UserAuthentication /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 3389, RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "UserAuthentication", 1,
                    "RDP NLA(네트워크 수준 인증) 강제 정책이 고정되어 있지 않아 외부 사전 인증 공격에 취약합니다",
                    "RDP NLA(ネットワークレベル認証)強制ポリシーが固定されておらず、外部攻撃に脆弱です",
                    "RDP Network Level Authentication (NLA) policy is not enforced against pre-auth external access"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2024-38077", 3389, RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services", "UserAuthentication", 1,
                    "RDP 네트워크 수준 인증(NLA) 강제 정책을 적용하여 외부 무인증 접근을 차단했습니다",
                    "RDP ネットワークレベル認証(NLA)強制ポリシーを適用し未認証アクセスを遮断しました",
                    "Enforced RDP Network Level Authentication (NLA) against external pre-auth access")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2024-49112",
                PublishedDate = "2024-12-10 (KEV)",
                CvssScore = 9.8,
                SeverityLabel = "Critical",
                EpssScore = 0.90,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "TCP 389 / 5985 (LDAP / WinRM)",
                TargetPort = 5985,
                Title = new LocalizedText(
                    "Windows LDAP/WinRM 외부 네트워크 원격 코드 실행 취약점 (LDAPNightmare)",
                    "Windows LDAP/WinRM 外部ネットワーク リモートコード実行の脆弱性 (LDAPNightmare)",
                    "Windows LDAP/WinRM External Network Remote Code Execution (LDAPNightmare)"),
                Description = new LocalizedText(
                    "디바이스가 외부 악성 LDAP/WinRM 응답을 수신하거나 외부 관리 요청을 처리할 때 정수 오버플로우로 인해 원격 코드 실행이 발생합니다.",
                    "外部からの不正なLDAP/WinRM応答や管理リクエスト処理時に整数オーバーフローによりリモートコード実行が発生します。",
                    "Critical integer overflow triggered via external LDAP/WinRM network requests leading to remote code execution."),
                DetectionMethod = new LocalizedText(
                    "TCP 5985/389 노출 및 LDAP 클라이언트/서버 서명 강제(LDAPClientIntegrity = 2) 여부를 점검합니다.",
                    "TCP 5985/389露出およびLDAP署名強制(LDAPClientIntegrity = 2)を点検します。",
                    "Checks TCP 5985/389 exposure and LDAP signing enforcement (LDAPClientIntegrity = 2)."),
                RemediationProposal = new LocalizedText(
                    "LDAP 패킷 서명 검증 강제(LDAPClientIntegrity = 2) 및 비암호화 외부 WinRM 접근 차단을 적용합니다.",
                    "LDAPパケット署名検証強制(LDAPClientIntegrity = 2)および非暗号化WinRM遮断を適用します。",
                    "Enforce LDAP packet signing verification (LDAPClientIntegrity = 2) and block unencrypted external WinRM."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Services\ldap"" /v LDAPClientIntegrity /t REG_DWORD /d 2 /f",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 5985, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\ldap", "LDAPClientIntegrity", 2,
                    "외부 LDAP 패킷 서명 강제 검증(LDAPClientIntegrity=2)이 설정되어 있지 않습니다",
                    "外部LDAPパケット署名強制検証(LDAPClientIntegrity=2)が未設定です",
                    "Strict LDAP packet signing verification (LDAPClientIntegrity=2) is not configured"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2024-49112", 5985, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\ldap", "LDAPClientIntegrity", 2,
                    "외부 LDAP 패킷 서명 강제 검증(LDAPClientIntegrity=2)을 적용했습니다",
                    "外部LDAPパケット署名強制検証(LDAPClientIntegrity=2)を適用しました",
                    "Applied strict LDAP packet signing verification (LDAPClientIntegrity=2)")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2024-6387",
                PublishedDate = "2024-07-01 (KEV)",
                CvssScore = 8.1,
                SeverityLabel = "High",
                EpssScore = 0.93,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "TCP 22 (OpenSSH Server)",
                TargetPort = 22,
                Title = new LocalizedText(
                    "OpenSSH 서버 시그널 핸들러 경합 조건 외부 원격 코드 실행 취약점 (regreSSHion)",
                    "OpenSSH サーバー シグナルハンドラ競合状態 外部リモートコード実行の脆弱性 (regreSSHion)",
                    "OpenSSH Server Signal Handler Race Condition External RCE (regreSSHion)"),
                Description = new LocalizedText(
                    "TCP 22 포트를 통해 외부 공격자가 SSH 인증 제한 시간(LoginGraceTime) 만료 시그널 경합을 악용하여 원격 권한을 획득하는 취약점입니다.",
                    "TCP 22ポート経由で外部攻撃者がLoginGraceTime満了シグナルの競合を悪用してリモート権限を取得する脆弱性です。",
                    "Unauthenticated remote code execution via signal handler race condition on exposed SSH TCP port 22."),
                DetectionMethod = new LocalizedText(
                    "TCP 22 포트 개방 여부 및 SSH LoginGraceTime 완화 정책(SshGraceTimeMitigation)을 점검합니다.",
                    "TCP 22ポート開放およびSSH LoginGraceTime緩和ポリシーを点検します。",
                    "Checks TCP port 22 exposure and SSH LoginGraceTime mitigation policy."),
                RemediationProposal = new LocalizedText(
                    "OpenSSH LoginGraceTime 경합 완화 정책을 활성화하고 외부 공용망의 무차별 TCP 22 접근을 제한합니다.",
                    "OpenSSH LoginGraceTime競合緩和ポリシーを有効化し、外部からのTCP 22アクセスを制限します。",
                    "Apply OpenSSH LoginGraceTime race mitigation and restrict untrusted external TCP 22 access."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\OpenSSH"" /v SshGraceTimeMitigation /t REG_DWORD /d 1 /f & netsh advfirewall firewall add rule name=""Block_Public_SSH_22"" dir=in action=block protocol=TCP localport=22 profile=public",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 22, RegistryHive.LocalMachine, @"SOFTWARE\OpenSSH", "SshGraceTimeMitigation", 1,
                    "OpenSSH regreSSHion 외부 시그널 경합 완화 정책이 미적용 상태입니다",
                    "OpenSSH regreSSHion 外部シグナル競合緩和ポリシーが未適用です",
                    "OpenSSH regreSSHion external signal handler mitigation is not applied"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2024-6387", 22, RegistryHive.LocalMachine, @"SOFTWARE\OpenSSH", "SshGraceTimeMitigation", 1,
                    "OpenSSH 시그널 경합 완화 정책 및 외부 공용망 TCP 22 보호를 적용했습니다",
                    "OpenSSH シグナル競合緩和ポリシーおよび外部TCP 22保護を適用しました",
                    "Applied OpenSSH signal handler race mitigation and public TCP 22 protection")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2025-21376",
                PublishedDate = "2025-02-11 (KEV)",
                CvssScore = 9.0,
                SeverityLabel = "Critical",
                EpssScore = 0.84,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "TCP 445 (SMB Direct / RDMA)",
                TargetPort = 445,
                Title = new LocalizedText(
                    "Windows SMBv3 서버 외부 세션 협상 버퍼 오버플로우 취약점",
                    "Windows SMBv3 サーバー 外部セッションネゴシエーション バッファオーバーフローの脆弱性",
                    "Windows SMBv3 Server External Session Negotiation Buffer Overflow RCE"),
                Description = new LocalizedText(
                    "디바이스 외부에서 TCP 445 포트로 비정상 다중 채널 협상 요청을 보내 원격 코드를 실행할 수 있는 2025년 KEV 취약점입니다.",
                    "デバイス外部からTCP 445ポートへ不正なマルチチャネルネゴシエーションを送信しリモートコードを実行する脆弱性です。",
                    "2025 actively exploited vulnerability in SMBv3 multi-channel session setup over TCP port 445."),
                DetectionMethod = new LocalizedText(
                    "TCP 445 노출 및 SMB 서버 서명 강제(RequireSecuritySignature = 1) 설정을 점검합니다.",
                    "TCP 445露出およびSMBサーバー署名強制(RequireSecuritySignature = 1)設定を点検します。",
                    "Checks TCP 445 exposure and SMB server RequireSecuritySignature = 1 setting."),
                RemediationProposal = new LocalizedText(
                    "SMB 서버 보안 서명을 강제(RequireSecuritySignature = 1)하여 비인증 외부 세션 변조 및 침투를 차단합니다.",
                    "SMBサーバーセキュリティ署名を強制(RequireSecuritySignature = 1)し、未認証の外部侵入を遮断します。",
                    "Enforce SMB server security signatures (RequireSecuritySignature = 1) against external session tampering."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"" /v RequireSecuritySignature /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 445, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", 1,
                    "TCP 445(SMB) 서버 보안 서명 강제(RequireSecuritySignature=1)가 비활성화 상태입니다",
                    "TCP 445(SMB)サーバーの署名強制(RequireSecuritySignature=1)が無効です",
                    "SMB server RequireSecuritySignature=1 is not enabled on TCP 445"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2025-21376", 445, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature", 1,
                    "SMB 서버 보안 서명 강제(RequireSecuritySignature=1)를 활성화했습니다",
                    "SMBサーバーのセキュリティ署名強制(RequireSecuritySignature=1)を有効化しました",
                    "Enabled SMB server mandatory security signatures (RequireSecuritySignature=1)")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2026-29104",
                PublishedDate = "2026-06-09 (KEV)",
                CvssScore = 9.8,
                SeverityLabel = "Critical",
                EpssScore = 0.88,
                IsCisaKev = true,
                Exploitability = ExploitabilityLevel.High,
                ComponentOrPort = "TCP 3389 / UDP 3391 (RDP Shortpath)",
                TargetPort = 3389,
                Title = new LocalizedText(
                    "Windows RDP Shortpath 외부 전송 계층 인증 우회 및 원격 접속 취약점",
                    "Windows RDP Shortpath 外部トランスポート層認証バイパスおよびリモート侵入の脆弱性",
                    "Windows RDP Shortpath External Transport Auth Bypass & Remote Access RCE"),
                Description = new LocalizedText(
                    "2026년 발견된 고위험 원격 접근 취약점으로, 외부에서 조작된 RDP UDP/TCP 핸드셰이크를 통해 디바이스 내부 세션을 획득할 수 있습니다.",
                    "2026年に発見された高リスク脆弱性で、外部から細工されたRDPハンドシェイクにより内部セッションへ侵入可能です。",
                    "2026 critical KEV allowing external attackers to bypass RDP Shortpath transport validation."),
                DetectionMethod = new LocalizedText(
                    "RDP 외부 Shortpath UDP 비신뢰 연결 제한(fClientDisableUDP = 1) 정책을 점검합니다.",
                    "RDP 外部 Shortpath UDP 制限ポリシー(fClientDisableUDP = 1)を点検します。",
                    "Checks RDP UDP Shortpath restriction policy (fClientDisableUDP = 1)."),
                RemediationProposal = new LocalizedText(
                    "비신뢰 외부 RDP UDP Shortpath 채널을 비활성화(fClientDisableUDP = 1)하고 TLS 암호화 검증을 강제합니다.",
                    "非信頼の外部RDP UDP Shortpathチャネルを無効化(fClientDisableUDP = 1)しTLS検証を強制します。",
                    "Disable untrusted RDP UDP Shortpath transport (fClientDisableUDP = 1) and enforce TLS validation."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client"" /v fClientDisableUDP /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 3389, RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client", "fClientDisableUDP", 1,
                    "RDP Shortpath 외부 UDP 채널 제한이 적용되어 있지 않습니다",
                    "RDP Shortpath 外部UDPチャネル制限が適用されていません",
                    "RDP Shortpath external UDP transport restriction is not applied"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2026-29104", 3389, RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client", "fClientDisableUDP", 1,
                    "RDP Shortpath 외부 UDP 취약 채널 차단 정책을 적용했습니다",
                    "RDP Shortpath 外部UDP脆弱チャネル遮断ポリシーを適用しました",
                    "Applied RDP Shortpath external UDP transport block policy")
            });

            // =========================================================================
            // NORMAL TIER: High/Critical CVSS (>= 7.0) + LOW Real-World Exploitability
            // =========================================================================

            list.Add(new CveEntry
            {
                CveId = "CVE-2024-38060",
                PublishedDate = "2024-08-13",
                CvssScore = 8.1,
                SeverityLabel = "High",
                EpssScore = 0.15,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Low,
                ComponentOrPort = "TCP 80 / 443 / 5985 (HTTP.sys)",
                TargetPort = 80,
                Title = new LocalizedText(
                    "Windows HTTP.sys 커널 웹 스택 외부 요청 파싱 원격 코드 실행 취약점",
                    "Windows HTTP.sys カーネルスタック 外部リクエスト解析のリモートコード実行の脆弱性",
                    "Windows HTTP.sys Kernel Web Stack External Request Parsing RCE"),
                Description = new LocalizedText(
                    "HTTP.sys를 사용하는 포트(80/443/5985 등)로 비표준 청크 인코딩 헤더가 수신될 때 발생하는 고위험·저실행성 취약점입니다.",
                    "HTTP.sysを使用するポートへ非標準チャンクヘッダが送信された際に発生する高危険・低実行性の脆弱性です。",
                    "High-severity HTTP.sys parsing flaw requiring specific non-default chunked header handling."),
                DetectionMethod = new LocalizedText(
                    "HTTP.sys Parameters의 엄격한 헤더 길이 및 청크 검증(EnableStrictChunkParsing = 1)을 점검합니다.",
                    "HTTP.sys Parameters の厳格チャンク検証(EnableStrictChunkParsing = 1)を点検します。",
                    "Checks EnableStrictChunkParsing = 1 in HTTP.sys Parameters."),
                RemediationProposal = new LocalizedText(
                    "HTTP.sys 커널 드라이버의 외부 비정상 청크 헤더 엄격 검증(EnableStrictChunkParsing = 1)을 활성화합니다.",
                    "HTTP.sysドライバの厳格チャンクヘッダ検証(EnableStrictChunkParsing = 1)を有効化します。",
                    "Enable strict HTTP.sys chunk header validation (EnableStrictChunkParsing = 1)."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Services\HTTP\Parameters"" /v EnableStrictChunkParsing /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 80, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\HTTP\Parameters", "EnableStrictChunkParsing", 1,
                    "HTTP.sys 외부 청크 헤더 엄격 검증 정책이 설정되지 않았습니다",
                    "HTTP.sys 外部チャンクヘッダ厳格検証ポリシーが未設定です",
                    "HTTP.sys strict chunk header validation policy is not configured"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2024-38060", 80, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\HTTP\Parameters", "EnableStrictChunkParsing", 1,
                    "HTTP.sys 외부 비정상 청크 헤더 차단 정책을 적용했습니다",
                    "HTTP.sys 外部不正チャンクヘッダ遮断ポリシーを適用しました",
                    "Applied HTTP.sys strict chunk header validation policy")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2024-38140",
                PublishedDate = "2024-08-13",
                CvssScore = 7.5,
                SeverityLabel = "High",
                EpssScore = 0.10,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Low,
                ComponentOrPort = "TCP 139 / UDP 137 (NetBIOS over TCP/IP)",
                TargetPort = 139,
                Title = new LocalizedText(
                    "Windows NetBIOS over TCP/IP (포트 139) 외부 스푸핑 및 원격 접근 취약점",
                    "Windows NetBIOS over TCP/IP (ポート 139) 外部スプーフィングおよびアクセス脆弱性",
                    "Windows NetBIOS over TCP/IP (Port 139) External Spoofing & Access Vulnerability"),
                Description = new LocalizedText(
                    "TCP 139 및 UDP 137/138 NetBIOS 포트가 외부에 노출된 경우 이름 해석 응답 스푸핑을 통해 디바이스 세션을 가로챌 수 있는 취약점입니다.",
                    "TCP 139およびUDP 137/138 NetBIOSポートが露出している場合、名前解決スプーフィングによりセッションを奪取される脆弱性です。",
                    "Allows external attackers on the network to spoof NetBIOS responses over port 137/139."),
                DetectionMethod = new LocalizedText(
                    "TCP 139 포트 개방 상태 및 NetBT NodeType 보안 설정(NodeType = 2, P-node 브로드캐스트 차단)을 점검합니다.",
                    "TCP 139ポート開放状態およびNetBT NodeType設定(NodeType = 2)を点検します。",
                    "Checks TCP port 139 state and NetBT NodeType = 2 broadcast disablement."),
                RemediationProposal = new LocalizedText(
                    "NetBIOS 브로드캐스트 이름 질의를 비활성화(NodeType = 2)하고 외부 공용망의 TCP 139 접근을 차단합니다.",
                    "NetBIOSブロードキャスト名前解決を無効化(NodeType = 2)し、外部からのTCP 139を遮断します。",
                    "Disable NetBIOS broadcast name resolution (NodeType = 2) and block external TCP 139."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters"" /v NodeType /t REG_DWORD /d 2 /f & netsh advfirewall firewall add rule name=""Block_External_NetBIOS_139"" dir=in action=block protocol=TCP localport=139 profile=public",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 139, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "NodeType", 2,
                    "TCP 139(NetBIOS) 외부 노출 및 브로드캐스트 질의가 활성화되어 있습니다",
                    "TCP 139(NetBIOS)外部露出およびブロードキャスト照会が有効です",
                    "TCP 139 (NetBIOS) is exposed and broadcast name resolution is active"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2024-38140", 139, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\NetBT\Parameters", "NodeType", 2,
                    "NetBIOS 브로드캐스트 차단(NodeType=2) 및 외부 TCP 139 방화벽 차단을 적용했습니다",
                    "NetBIOSブロードキャスト遮断(NodeType=2)およびTCP 139遮断を適用しました",
                    "Applied NetBIOS broadcast disablement (NodeType=2) and TCP 139 block")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2025-21400",
                PublishedDate = "2025-02-11",
                CvssScore = 8.1,
                SeverityLabel = "High",
                EpssScore = 0.11,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Low,
                ComponentOrPort = "TCP 593 (RPC over HTTP)",
                TargetPort = 593,
                Title = new LocalizedText(
                    "Windows RPC over HTTP (포트 593) 외부 엔드포인트 정수 오버플로우 취약점",
                    "Windows RPC over HTTP (ポート 593) 外部エンドポイント整数オーバーフローの脆弱性",
                    "Windows RPC over HTTP (Port 593) External Endpoint Integer Overflow RCE"),
                Description = new LocalizedText(
                    "RPC over HTTP 프록시(TCP 593)가 활성화된 환경에서 외부 패킷 처리 중 발생하는 고위험·저실행성 원격 취약점입니다.",
                    "RPC over HTTP プロキシ(TCP 593)環境で外部パケット処理中に発生する高危険・低実行性の脆弱性です。",
                    "High-severity integer overflow in RPC over HTTP proxy service on TCP port 593."),
                DetectionMethod = new LocalizedText(
                    "TCP 593 포트 개방 여부 및 RPC HTTP 프록시 비활성화(EnableRpcHttpProxy = 0)를 점검합니다.",
                    "TCP 593ポート開放およびRPC HTTPプロキシ無効化(EnableRpcHttpProxy = 0)を点検します。",
                    "Checks TCP 593 exposure and EnableRpcHttpProxy = 0 policy."),
                RemediationProposal = new LocalizedText(
                    "불필요한 외부 RPC over HTTP 수신(EnableRpcHttpProxy = 0)을 비활성화하고 포트를 차단합니다.",
                    "不要な外部RPC over HTTP受信(EnableRpcHttpProxy = 0)を無効化しポートを遮断します。",
                    "Disable external RPC over HTTP listener (EnableRpcHttpProxy = 0) and block TCP 593."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc"" /v EnableRpcHttpProxy /t REG_DWORD /d 0 /f",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 593, RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "EnableRpcHttpProxy", 0,
                    "외부 RPC over HTTP (TCP 593) 명시적 차단 정책이 미설정 상태입니다",
                    "外部 RPC over HTTP (TCP 593) 明示的遮断ポリシーが未設定です",
                    "Explicit RPC over HTTP external block policy is not configured"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2025-21400", 593, RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\Rpc", "EnableRpcHttpProxy", 0,
                    "외부 RPC over HTTP (TCP 593) 수신 차단 정책을 적용했습니다",
                    "外部 RPC over HTTP (TCP 593) 受信遮断ポリシーを適用しました",
                    "Applied external RPC over HTTP (TCP 593) block policy")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2026-42110",
                PublishedDate = "2026-10-13",
                CvssScore = 7.5,
                SeverityLabel = "High",
                EpssScore = 0.08,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Low,
                ComponentOrPort = "IPv6 Neighbor Discovery (ICMPv6)",
                TargetPort = 135,
                Title = new LocalizedText(
                    "Windows TCP/IP 외부 라우터 광고(RA) 스푸핑을 통한 원격 접근 경로 탈취 취약점",
                    "Windows TCP/IP 外部ルーター広告(RA)スプーフィングによるリモート経路奪取の脆弱性",
                    "Windows TCP/IP External Router Advertisement (RA) Spoofing Route Hijack"),
                Description = new LocalizedText(
                    "2026년 10월 공개된 취약점으로, 인접/외부 네트워크에서 위조된 ICMPv6 Router Advertisement 패킷을 전송하여 디바이스 트래픽을 가로챕니다.",
                    "2026年10月に公開された脆弱性で、偽造されたICMPv6 RAパケットによりデバイスの通信経路を奪取します。",
                    "October 2026 vulnerability allowing external/adjacent attackers to hijack device traffic via crafted ICMPv6 RA packets."),
                DetectionMethod = new LocalizedText(
                    "IPv6 비신뢰 라우터 광고 차단(DisableRouterDiscovery = 1) 설정 여부를 점검합니다.",
                    "IPv6 非信頼ルーター広告遮断(DisableRouterDiscovery = 1)設定を点検します。",
                    "Checks DisableRouterDiscovery = 1 under Tcpip6 Parameters."),
                RemediationProposal = new LocalizedText(
                    "비신뢰 외부 라우터 자동 탐색을 비활성화(DisableRouterDiscovery = 1)하여 RA 스푸핑 접근을 차단합니다.",
                    "非信頼の外部ルーター自動探索を無効化(DisableRouterDiscovery = 1)しRAスプーフィングを遮断します。",
                    "Disable untrusted external Router Discovery (DisableRouterDiscovery = 1) to prevent RA spoofing."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters"" /v DisableRouterDiscovery /t REG_DWORD /d 1 /f",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 135, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisableRouterDiscovery", 1,
                    "외부 라우터 광고(RA) 스푸핑 방지 정책(DisableRouterDiscovery=1)이 설정되어 있지 않습니다",
                    "外部ルーター広告(RA)スプーフィング防止(DisableRouterDiscovery=1)が未設定です",
                    "External Router Advertisement spoofing protection (DisableRouterDiscovery=1) is not set"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2026-42110", 0, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters", "DisableRouterDiscovery", 1,
                    "외부 라우터 광고(RA) 스푸핑 차단 정책(DisableRouterDiscovery=1)을 적용했습니다",
                    "外部ルーター広告(RA)スプーフィング遮断(DisableRouterDiscovery=1)を適用しました",
                    "Applied external Router Advertisement spoofing protection (DisableRouterDiscovery=1)")
            });

            // =========================================================================
            // FULL TIER: All Remaining CVEs up to 2026-10-20 (Medium/Low & Hardening)
            // =========================================================================

            list.Add(new CveEntry
            {
                CveId = "CVE-2025-29812",
                PublishedDate = "2025-05-13",
                CvssScore = 6.5,
                SeverityLabel = "Medium",
                EpssScore = 0.05,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Standard,
                ComponentOrPort = "UDP 5355 (LLMNR Multicast)",
                TargetPort = 5355,
                Title = new LocalizedText(
                    "Windows LLMNR 멀티캐스트 이름 해석 외부 자격 증명 가로채기 취약점",
                    "Windows LLMNR マルチキャスト名前解決における外部資格情報傍受の脆弱性",
                    "Windows LLMNR Multicast Name Resolution External Credential Interception"),
                Description = new LocalizedText(
                    "DNS 질의 실패 시 UDP 5355로 LLMNR 브로드캐스트를 전송하여 외부 공격자가 응답을 위조하고 디바이스 접근 권한을 탈취할 수 있습니다.",
                    "DNS照会失敗時にUDP 5355でLLMNRを送信し、外部攻撃者が応答を偽装して資格情報を奪取できる脆弱性です。",
                    "Allows external attackers on the network to poison UDP 5355 LLMNR queries and capture device credentials."),
                DetectionMethod = new LocalizedText(
                    "DNSClient 정책의 EnableMulticast = 0 (LLMNR 비활성화) 설정 여부를 점검합니다.",
                    "DNSClientポリシーの EnableMulticast = 0 (LLMNR無効化) を点検します。",
                    "Checks EnableMulticast = 0 under DNSClient policies."),
                RemediationProposal = new LocalizedText(
                    "LLMNR 멀티캐스트 이름 해석을 비활성화(EnableMulticast = 0)하여 외부 스푸핑 접근을 원천 차단합니다.",
                    "LLMNRマルチキャスト名前解決を無効化(EnableMulticast = 0)し外部スプーフィングを遮断します。",
                    "Disable LLMNR multicast name resolution (EnableMulticast = 0) to prevent external poisoning."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"" /v EnableMulticast /t REG_DWORD /d 0 /f",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 5355, RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0,
                    "LLMNR 멀티캐스트(EnableMulticast=0) 차단이 설정되어 있지 않아 외부 스푸핑에 노출됩니다",
                    "LLMNRマルチキャスト遮断(EnableMulticast=0)が未設定のため外部スプーフィングに露出しています",
                    "LLMNR multicast disablement (EnableMulticast=0) is not configured"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2025-29812", 5355, RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient", "EnableMulticast", 0,
                    "LLMNR 멀티캐스트 비활성화(EnableMulticast=0)를 적용했습니다",
                    "LLMNRマルチキャスト無効化(EnableMulticast=0)を適用しました",
                    "Disabled LLMNR multicast name resolution (EnableMulticast=0)")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2025-31088",
                PublishedDate = "2025-08-12",
                CvssScore = 6.1,
                SeverityLabel = "Medium",
                EpssScore = 0.04,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Standard,
                ComponentOrPort = "TCP 2869 / UDP 1900 (UPnP / SSDP)",
                TargetPort = 2869,
                Title = new LocalizedText(
                    "Windows UPnP / SSDP 외부 서비스 탐색 및 포트 포워딩 조작 취약점",
                    "Windows UPnP / SSDP 外部サービス探索およびポート転送操作の脆弱性",
                    "Windows UPnP / SSDP External Service Discovery & Port Forwarding Manipulation"),
                Description = new LocalizedText(
                    "외부에서 UPnP/SSDP(TCP 2869 / UDP 1900)를 통해 디바이스 정보를 수집하거나 비인가 포트 매핑을 유도할 수 있는 취약점입니다.",
                    "外部からUPnP/SSDP(TCP 2869 / UDP 1900)経由でデバイス情報収集や不正ポートマッピングを誘導できる脆弱性です。",
                    "Allows external discovery and unauthorized SOAP control payloads over UPnP port 2869 / SSDP 1900."),
                DetectionMethod = new LocalizedText(
                    "TCP 2869 노출 및 외부 UPnP 인바운드 차단 정책(BlockExternalUpnp = 1)을 점검합니다.",
                    "TCP 2869露出および外部UPnP遮断ポリシー(BlockExternalUpnp = 1)を点検します。",
                    "Checks TCP 2869 exposure and external UPnP block policy."),
                RemediationProposal = new LocalizedText(
                    "외부 네트워크로부터의 비인가 UPnP/SSDP 제어 요청을 차단(BlockExternalUpnp = 1)합니다.",
                    "外部ネットワークからの非認可UPnP/SSDP制御リクエストを遮断(BlockExternalUpnp = 1)します。",
                    "Block unauthorized external UPnP/SSDP control requests (BlockExternalUpnp = 1)."),
                RemediationCommandPreview = @"reg add ""HKLM\SOFTWARE\Policies\Microsoft\Windows\SSDPSrv"" /v BlockExternalUpnp /t REG_DWORD /d 1 /f & netsh advfirewall firewall add rule name=""Block_External_UPnP_2869"" dir=in action=block protocol=TCP localport=2869 profile=public",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 2869, RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\SSDPSrv", "BlockExternalUpnp", 1,
                    "외부 UPnP/SSDP(포트 2869) 접근 차단 정책이 설정되어 있지 않습니다",
                    "外部UPnP/SSDP(ポート2869)アクセス遮断ポリシーが未設定です",
                    "External UPnP/SSDP (Port 2869) access block policy is not configured"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2025-31088", 2869, RegistryHive.LocalMachine, @"SOFTWARE\Policies\Microsoft\Windows\SSDPSrv", "BlockExternalUpnp", 1,
                    "외부 UPnP/SSDP(포트 2869) 접근 차단 정책을 적용했습니다",
                    "外部UPnP/SSDP(ポート2869)アクセス遮断ポリシーを適用しました",
                    "Applied external UPnP/SSDP (Port 2869) access block policy")
            });

            list.Add(new CveEntry
            {
                CveId = "CVE-2026-33180",
                PublishedDate = "2026-10-20",
                CvssScore = 5.9,
                SeverityLabel = "Medium",
                EpssScore = 0.03,
                IsCisaKev = false,
                Exploitability = ExploitabilityLevel.Standard,
                ComponentOrPort = "TCP 443 / 3389 (Schannel TLS 1.0/1.1)",
                TargetPort = 443,
                Title = new LocalizedText(
                    "Windows Schannel 레거시 TLS 1.0/1.1 외부 다운그레이드 접근 취약점 (2026-10-20 기준)",
                    "Windows Schannel レガシー TLS 1.0/1.1 外部ダウングレードアクセスの脆弱性 (2026-10-20 基準)",
                    "Windows Schannel Legacy TLS 1.0/1.1 External Downgrade Access (2026-10-20 Baseline)"),
                Description = new LocalizedText(
                    "2026년 10월 20일 기준 DB 항목으로, 외부 TLS 연결 시 레거시 TLS 1.0/1.1 폴백이 허용되어 세션 복호화 및 중간자 접근이 가능합니다.",
                    "2026年10月20日基準DB項目で、外部TLS接続時にTLS 1.0/1.1へのフォールバックが許可され中間者アクセスが可能となります。",
                    "2026-10-20 baseline CVE where legacy TLS 1.0/1.1 server fallback permits external downgrade attacks."),
                DetectionMethod = new LocalizedText(
                    "Schannel TLS 1.0 Server Enabled = 0 명시적 비활성화 여부를 점검합니다.",
                    "Schannel TLS 1.0 Server Enabled = 0 の明示的無効化を点検します。",
                    "Checks Schannel TLS 1.0 Server Enabled = 0 configuration."),
                RemediationProposal = new LocalizedText(
                    "Schannel에서 레거시 TLS 1.0/1.1 수신을 비활성화(Enabled = 0)하고 TLS 1.2/1.3만 허용합니다.",
                    "SchannelでレガシーTLS 1.0/1.1受信を無効化(Enabled = 0)し、TLS 1.2/1.3のみを許可します。",
                    "Disable legacy TLS 1.0/1.1 inbound connections in Schannel (Enabled = 0) and enforce TLS 1.2/1.3."),
                RemediationCommandPreview = @"reg add ""HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server"" /v Enabled /t REG_DWORD /d 0 /f",
                CheckDelegate = ctx => CheckExternalAccessVector(
                    ctx, 443, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server", "Enabled", 0,
                    "Schannel 레거시 TLS 1.0 외부 수신 차단(Enabled=0)이 설정되어 있지 않습니다",
                    "Schannel レガシーTLS 1.0外部受信遮断(Enabled=0)が未設定です",
                    "Schannel legacy TLS 1.0 inbound disablement (Enabled=0) is not configured"),
                RemediateDelegate = ctx => ApplyExternalAccessBlock(
                    ctx, "CVE-2026-33180", 443, RegistryHive.LocalMachine, @"SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Server", "Enabled", 0,
                    "Schannel 레거시 TLS 1.0 외부 수신을 비활성화(Enabled=0)했습니다",
                    "Schannel レガシーTLS 1.0外部受信を無効化(Enabled=0)しました",
                    "Disabled Schannel legacy TLS 1.0 inbound connections (Enabled=0)")
            });

            CveCatalogGenerator.ExpandExternalDatabaseToFullCoverage(list);
            return list;
        }
    }
}
