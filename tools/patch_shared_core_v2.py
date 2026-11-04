# -*- coding: utf-8 -*-
import sys

sys.stdout.reconfigure(encoding='utf-8')

core_path = r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\src\SharedCore.cs'

with open(core_path, 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Update font families in GetPrimaryFontFamily and GetDetailFontFamily
old_primary_ko = '_cachedPrimaryKo = ResolveInstalledFont(new string[] { "맑은 고딕", "Malgun Gothic", "나눔바른고딕", "나눔고딕", "Segoe UI" }, "맑은 고딕");'
new_primary_ko = '_cachedPrimaryKo = ResolveInstalledFont(new string[] { "Segoe UI", "맑은 고딕", "Malgun Gothic", "나눔바른고딕", "나눔고딕" }, "Segoe UI");'

old_detail_ko = '_cachedDetailKo = ResolveInstalledFont(new string[] { "맑은 고딕", "Malgun Gothic", "나눔고딕" }, "맑은 고딕");'
new_detail_ko = '_cachedDetailKo = ResolveInstalledFont(new string[] { "Cascadia Mono", "Cascadia Code", "Consolas", "Segoe UI", "맑은 고딕", "Malgun Gothic" }, "Consolas");'

old_detail_ja = '_cachedDetailJa = ResolveInstalledFont(new string[] { "Yu Gothic", "Meiryo", "BIZ UDGothic", "MS Gothic" }, "Yu Gothic");'
new_detail_ja = '_cachedDetailJa = ResolveInstalledFont(new string[] { "Cascadia Mono", "Cascadia Code", "Consolas", "Yu Gothic UI", "Yu Gothic", "Meiryo" }, "Consolas");'

assert old_primary_ko in text, "old_primary_ko not found"
assert old_detail_ko in text, "old_detail_ko not found"
assert old_detail_ja in text, "old_detail_ja not found"

text = text.replace(old_primary_ko, new_primary_ko)
text = text.replace(old_detail_ko, new_detail_ko)
text = text.replace(old_detail_ja, new_detail_ja)

# 2. Add OsEnvironmentDetector class and PlatformScope enum before CveEntry
os_detector_code = '''
    public enum PlatformScope
    {
        UniversalPerimeter,
        WindowsKernel,
        WindowsEnterprise,
        CrossPlatformNetwork,
        LinuxWslSubsystem
    }

    public static class OsEnvironmentDetector
    {
        private static string _cachedHostSummary;
        private static string _cachedHostDetail;
        private static bool _cachedHasWsl;
        private static string _cachedWslDistros;

        public static string GetHostOsSummary()
        {
            if (_cachedHostSummary == null) DetectHostEnvironment();
            return _cachedHostSummary;
        }

        public static string GetHostOsDetail()
        {
            if (_cachedHostDetail == null) DetectHostEnvironment();
            return _cachedHostDetail;
        }

        public static bool HasWslLinuxSubsystem()
        {
            if (_cachedHostSummary == null) DetectHostEnvironment();
            return _cachedHasWsl;
        }

        public static string GetWslDistros()
        {
            if (_cachedHostSummary == null) DetectHostEnvironment();
            return _cachedWslDistros;
        }

        public static void DetectHostEnvironment()
        {
            try
            {
                string productName = "Windows";
                string displayVersion = "";
                int buildNumber = Environment.OSVersion.Version.Build;
                int ubr = 0;

                object prod = SystemAuditHelper.ReadRegistryValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName");
                if (prod != null) productName = prod.ToString();

                object dispVer = SystemAuditHelper.ReadRegistryValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion");
                if (dispVer != null) displayVersion = dispVer.ToString();

                object bldObj = SystemAuditHelper.ReadRegistryValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "CurrentBuildNumber");
                if (bldObj != null) int.TryParse(bldObj.ToString(), out buildNumber);

                object ubrObj = SystemAuditHelper.ReadRegistryValue(RegistryHive.LocalMachine, @"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "UBR");
                if (ubrObj != null) int.TryParse(ubrObj.ToString(), out ubr);

                string osName = productName;
                if (buildNumber >= 22000 && !osName.Contains("11"))
                {
                    osName = osName.Replace("10", "11");
                }
                string arch = Environment.Is64BitOperatingSystem ? "64-bit" : "32-bit";

                _cachedHasWsl = false;
                List<string> distros = new List<string>();
                try
                {
                    using (RegistryKey lxss = Registry.CurrentUser.OpenSubKey(@"Software\Microsoft\Windows\CurrentVersion\Lxss"))
                    {
                        if (lxss != null)
                        {
                            foreach (string sub in lxss.GetSubKeyNames())
                            {
                                using (RegistryKey distKey = lxss.OpenSubKey(sub))
                                {
                                    if (distKey != null)
                                    {
                                        object distName = distKey.GetValue("DistributionName");
                                        if (distName != null) distros.Add(distName.ToString());
                                    }
                                }
                            }
                        }
                    }
                }
                catch { }

                if (distros.Count > 0)
                {
                    _cachedHasWsl = true;
                    _cachedWslDistros = string.Join(", ", distros.ToArray());
                }
                else
                {
                    string wslPath = Path.Combine(Environment.SystemDirectory, "wsl.exe");
                    if (File.Exists(wslPath))
                    {
                        _cachedHasWsl = true;
                        _cachedWslDistros = "WSL2 Subsystem Enabled";
                    }
                    else
                    {
                        _cachedWslDistros = "None";
                    }
                }

                string wslSuffix = _cachedHasWsl ? (" + WSL2(" + _cachedWslDistros + ")") : "";
                string versionPart = !string.IsNullOrEmpty(displayVersion) ? (" " + displayVersion) : "";

                _cachedHostSummary = string.Format("{0}{1} {2} (Build {3}.{4}){5}", osName, versionPart, arch, buildNumber, ubr, wslSuffix);
                _cachedHostDetail = string.Format("OS: {0}{1} | Kernel: {2}.{3} | Arch: {4} | Subsystems: WSL2/Linux({5}), Hyper-V, .NET Runtime",
                    osName, versionPart, buildNumber, ubr, arch, _cachedWslDistros);
            }
            catch
            {
                _cachedHostSummary = Environment.OSVersion.VersionString + (Environment.Is64BitOperatingSystem ? " 64-bit" : "");
                _cachedHostDetail = _cachedHostSummary;
            }
        }

        public static string DetectRemoteTargetOs(string targetIp, int timeoutMs = 400)
        {
            if (string.IsNullOrEmpty(targetIp) || targetIp == "127.0.0.1" || targetIp.Equals("localhost", StringComparison.OrdinalIgnoreCase))
            {
                return GetHostOsSummary();
            }

            try
            {
                string sshBanner = ProbeBanner(targetIp, 22, timeoutMs);
                if (!string.IsNullOrEmpty(sshBanner))
                {
                    if (sshBanner.IndexOf("Ubuntu", StringComparison.OrdinalIgnoreCase) >= 0) return "Linux (Ubuntu / OpenSSH)";
                    if (sshBanner.IndexOf("Debian", StringComparison.OrdinalIgnoreCase) >= 0) return "Linux (Debian / OpenSSH)";
                    if (sshBanner.IndexOf("CentOS", StringComparison.OrdinalIgnoreCase) >= 0 || sshBanner.IndexOf("Red Hat", StringComparison.OrdinalIgnoreCase) >= 0) return "Linux (RHEL/CentOS / OpenSSH)";
                    if (sshBanner.IndexOf("FreeBSD", StringComparison.OrdinalIgnoreCase) >= 0) return "Unix (FreeBSD / OpenSSH)";
                    return "Linux/Unix (" + sshBanner.Trim() + ")";
                }

                string httpBanner = ProbeHttpServer(targetIp, 80, timeoutMs);
                if (string.IsNullOrEmpty(httpBanner)) httpBanner = ProbeHttpServer(targetIp, 443, timeoutMs);
                if (!string.IsNullOrEmpty(httpBanner))
                {
                    if (httpBanner.IndexOf("IIS", StringComparison.OrdinalIgnoreCase) >= 0) return "Windows Server (" + httpBanner + ")";
                    if (httpBanner.IndexOf("Apache", StringComparison.OrdinalIgnoreCase) >= 0) return "Linux/Unix Web (" + httpBanner + ")";
                    if (httpBanner.IndexOf("nginx", StringComparison.OrdinalIgnoreCase) >= 0) return "Linux/Unix Web (" + httpBanner + ")";
                    return "Web Stack (" + httpBanner + ")";
                }

                if (SystemAuditHelper.ProbeTcpPort(targetIp, 3389, timeoutMs)) return "Windows Host/Server (RDP Active)";
                if (SystemAuditHelper.ProbeTcpPort(targetIp, 445, timeoutMs)) return "Windows / Linux Samba (SMB Active)";

                return "Remote Network Boundary Host (Multi-OS Perimeter)";
            }
            catch
            {
                return "Remote Host (Multi-OS Perimeter)";
            }
        }

        private static string ProbeBanner(string host, int port, int timeoutMs)
        {
            try
            {
                using (var client = new System.Net.Sockets.TcpClient())
                {
                    var ar = client.BeginConnect(host, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) return null;
                    client.EndConnect(ar);
                    client.ReceiveTimeout = timeoutMs;
                    var stream = client.GetStream();
                    byte[] buf = new byte[256];
                    int read = stream.Read(buf, 0, buf.Length);
                    if (read > 0)
                    {
                        return System.Text.Encoding.ASCII.GetString(buf, 0, read).Trim();
                    }
                }
            }
            catch { }
            return null;
        }

        private static string ProbeHttpServer(string host, int port, int timeoutMs)
        {
            try
            {
                using (var client = new System.Net.Sockets.TcpClient())
                {
                    var ar = client.BeginConnect(host, port, null, null);
                    if (!ar.AsyncWaitHandle.WaitOne(timeoutMs)) return null;
                    client.EndConnect(ar);
                    client.ReceiveTimeout = timeoutMs;
                    client.SendTimeout = timeoutMs;
                    var stream = client.GetStream();
                    byte[] req = System.Text.Encoding.ASCII.GetBytes("HEAD / HTTP/1.0\\r\\nHost: " + host + "\\r\\n\\r\\n");
                    stream.Write(req, 0, req.Length);
                    byte[] buf = new byte[512];
                    int read = stream.Read(buf, 0, buf.Length);
                    if (read > 0)
                    {
                        string resp = System.Text.Encoding.ASCII.GetString(buf, 0, read);
                        foreach (string line in resp.Split('\\n'))
                        {
                            if (line.StartsWith("Server:", StringComparison.OrdinalIgnoreCase))
                            {
                                return line.Substring(7).Trim();
                            }
                        }
                    }
                }
            }
            catch { }
            return null;
        }
    }
'''

target_cve_entry = '    public class CveEntry\n    {'
assert target_cve_entry in text, "CveEntry not found"
text = text.replace(target_cve_entry, os_detector_code + '\n    public class CveEntry\n    {\n        public PlatformScope Scope { get; set; } = PlatformScope.WindowsEnterprise;')

# 3. Add properties to ScanContext
target_scan_context = '        public string OsProductName { get; set; } = "Windows 11";'
new_scan_context_props = '''        public string DetectedHostOs { get; set; }
        public string DetectedTargetOs { get; set; }
        public string OsProductName { get; set; } = "Windows 11";'''
assert target_scan_context in text, "target_scan_context not found"
text = text.replace(target_scan_context, new_scan_context_props)

# 4. In RefreshLiveSystemTelemetry, populate DetectedHostOs and DetectedTargetOs
target_refresh = '        public void RefreshLiveSystemTelemetry()\n        {'
new_refresh = '''        public void RefreshLiveSystemTelemetry()
        {
            try
            {
                DetectedHostOs = OsEnvironmentDetector.GetHostOsSummary();
                DetectedTargetOs = OsEnvironmentDetector.DetectRemoteTargetOs(TargetIp, PortTimeoutMs);
            }
            catch { }
'''
assert target_refresh in text, "target_refresh not found"
text = text.replace(target_refresh, new_refresh)

with open(core_path, 'w', encoding='utf-8') as f:
    f.write(text)

print('SharedCore.cs patched successfully with OsEnvironmentDetector and font improvements')
