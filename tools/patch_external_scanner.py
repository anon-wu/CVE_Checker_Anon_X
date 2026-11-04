# -*- coding: utf-8 -*-
import sys

sys.stdout.reconfigure(encoding='utf-8')

ext_path = r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\src\ExternalScannerProgram.cs'

with open(ext_path, 'r', encoding='utf-8') as f:
    text = f.read()

old_func_start = '''        private static AuditResult CheckExternalAccessVector(
            ScanContext ctx, int port, RegistryHive hive, string subKey, string valueName, int safeValue,
            string koDesc, string jaDesc, string enDesc)
        {
            bool portOpen = (port == 0) || ctx.IsPortOpen(port);

            object val = SystemAuditHelper.ReadRegistryValue(hive, subKey, valueName);'''

new_func = '''        private static AuditResult CheckExternalAccessVector(
            ScanContext ctx, int port, RegistryHive hive, string subKey, string valueName, int safeValue,
            string koDesc, string jaDesc, string enDesc)
        {
            bool isLocal = string.IsNullOrEmpty(ctx.TargetIp) || ctx.TargetIp == "127.0.0.1" || ctx.TargetIp.Equals("localhost", StringComparison.OrdinalIgnoreCase);
            bool portOpen = (port == 0) || ctx.IsPortOpen(port);

            if (!isLocal)
            {
                string remoteOs = ctx.DetectedTargetOs ?? OsEnvironmentDetector.DetectRemoteTargetOs(ctx.TargetIp, ctx.PortTimeoutMs);
                if (!portOpen)
                {
                    return new AuditResult
                    {
                        IsVulnerable = false,
                        Evidence = new LocalizedText(
                            string.Format("[포트 닫힘 - 안전] 대상({0}, OS: {1})에서 포트({2})가 닫혀(CLOSED) 있어 네트워크 침투가 불가능합니다.", ctx.TargetIp, remoteOs, port),
                            string.Format("[ポート閉鎖 - 安全] 対象({0}, OS: {1})でポート({2})が閉鎖(CLOSED)されており外部侵入は不可能です。", ctx.TargetIp, remoteOs, port),
                            string.Format("[SAFE - PORT CLOSED] Port {2} is CLOSED on remote target {0} (OS: {1}); unreachable from external network.", ctx.TargetIp, remoteOs, port))
                    };
                }
                else
                {
                    return new AuditResult
                    {
                        IsVulnerable = true,
                        Evidence = new LocalizedText(
                            string.Format("[경계면 노출 - 취약] 대상({0}, OS: {1})에서 외부 포트({2})가 열려(OPEN) 있어 네트워크 공격 벡터에 노출되어 있습니다.", ctx.TargetIp, remoteOs, port),
                            string.Format("[境界露出 - 脆弱] 対象({0}, OS: {1})で外部ポート({2})が開放(OPEN)されており攻撃ベクトルに露出しています。", ctx.TargetIp, remoteOs, port),
                            string.Format("[VULNERABLE - EXPOSED PERIMETER] Port {2} is OPEN on remote target {0} (OS: {1}); actively exposed to network attack vectors.", ctx.TargetIp, remoteOs, port))
                    };
                }
            }

            object val = SystemAuditHelper.ReadRegistryValue(hive, subKey, valueName);'''

assert old_func_start in text, "old_func_start not found in ExternalScannerProgram.cs"
text = text.replace(old_func_start, new_func)

with open(ext_path, 'w', encoding='utf-8') as f:
    f.write(text)

print('ExternalScannerProgram.cs patched successfully with remote OS awareness')
