# -*- coding: utf-8 -*-
import os

path = os.path.join(os.path.dirname(__file__), "..", "src", "SharedCore.cs")
with open(path, "r", encoding="utf-8") as f:
    text = f.read()

# 1. Update font families in I18n
old_fonts = '''        public static string GetPrimaryFontFamily()
        {
            switch (CurrentLanguage)
            {
                case AppLanguage.JA:
                    if (_cachedPrimaryJa == null)
                        _cachedPrimaryJa = ResolveInstalledFont(new string[] { "Noto Sans JP", "BIZ UDPGothic", "Yu Gothic UI", "Meiryo UI" }, "Noto Sans JP");
                    return _cachedPrimaryJa;
                case AppLanguage.KO:
                    if (_cachedPrimaryKo == null)
                        _cachedPrimaryKo = ResolveInstalledFont(new string[] { "맑은 고딕", "나눔바른고딕", "나눔고딕", "Noto Sans KR", "Malgun Gothic" }, "맑은 고딕");
                    return _cachedPrimaryKo;
                default:
                    if (_cachedPrimaryEn == null)
                        _cachedPrimaryEn = ResolveInstalledFont(new string[] { "Segoe UI", "Verdana", "Calibri" }, "Segoe UI");
                    return _cachedPrimaryEn;
            }
        }

        public static string GetDetailFontFamily()
        {
            switch (CurrentLanguage)
            {
                case AppLanguage.JA:
                    if (_cachedDetailJa == null)
                        _cachedDetailJa = ResolveInstalledFont(new string[] { "Noto Sans JP", "BIZ UDGothic", "Yu Gothic", "Meiryo" }, "Noto Sans JP");
                    return _cachedDetailJa;
                case AppLanguage.KO:
                    if (_cachedDetailKo == null)
                        _cachedDetailKo = ResolveInstalledFont(new string[] { "맑은 고딕", "나눔고딕", "Noto Sans KR" }, "맑은 고딕");
                    return _cachedDetailKo;
                default:
                    if (_cachedDetailEn == null)
                        _cachedDetailEn = ResolveInstalledFont(new string[] { "Cascadia Code", "Consolas", "Segoe UI" }, "Consolas");
                    return _cachedDetailEn;
            }
        }'''

new_fonts = '''        public static string GetPrimaryFontFamily()
        {
            switch (CurrentLanguage)
            {
                case AppLanguage.JA:
                    if (_cachedPrimaryJa == null)
                        _cachedPrimaryJa = ResolveInstalledFont(new string[] { "Yu Gothic UI", "Meiryo UI", "BIZ UDPGothic", "Yu Gothic", "Meiryo", "MS UI Gothic" }, "Yu Gothic UI");
                    return _cachedPrimaryJa;
                case AppLanguage.KO:
                    if (_cachedPrimaryKo == null)
                        _cachedPrimaryKo = ResolveInstalledFont(new string[] { "맑은 고딕", "Malgun Gothic", "나눔바른고딕", "나눔고딕", "Segoe UI" }, "맑은 고딕");
                    return _cachedPrimaryKo;
                default:
                    if (_cachedPrimaryEn == null)
                        _cachedPrimaryEn = ResolveInstalledFont(new string[] { "Segoe UI", "Calibri", "Arial" }, "Segoe UI");
                    return _cachedPrimaryEn;
            }
        }

        public static string GetDetailFontFamily()
        {
            switch (CurrentLanguage)
            {
                case AppLanguage.JA:
                    if (_cachedDetailJa == null)
                        _cachedDetailJa = ResolveInstalledFont(new string[] { "Yu Gothic", "Meiryo", "BIZ UDGothic", "MS Gothic" }, "Yu Gothic");
                    return _cachedDetailJa;
                case AppLanguage.KO:
                    if (_cachedDetailKo == null)
                        _cachedDetailKo = ResolveInstalledFont(new string[] { "맑은 고딕", "Malgun Gothic", "나눔고딕" }, "맑은 고딕");
                    return _cachedDetailKo;
                default:
                    if (_cachedDetailEn == null)
                        _cachedDetailEn = ResolveInstalledFont(new string[] { "Consolas", "Cascadia Code", "Segoe UI" }, "Consolas");
                    return _cachedDetailEn;
            }
        }'''

if old_fonts in text:
    text = text.replace(old_fonts, new_fonts)
    print("[+] Replaced font families in SharedCore.cs")
else:
    print("[-] Warning: old_fonts not found in SharedCore.cs")

# 2. Add Year property and update MatchesScanTier in CveEntry
old_matches = '''        public bool MatchesScanTier(ScanTier tier)
        {
            if (tier == ScanTier.Fast)
            {
                // Fast: Dangerous (CVSS >= 7.0) AND High real-world exploitability
                return CvssScore >= 7.0 && Exploitability == ExploitabilityLevel.High;
            }
            else if (tier == ScanTier.Normal)
            {
                // Normal: Dangerous CVEs with High OR Low real-world exploitability
                return CvssScore >= 7.0 && (Exploitability == ExploitabilityLevel.High || Exploitability == ExploitabilityLevel.Low);
            }
            else
            {
                // Full: All CVEs in DB
                return true;
            }
        }'''

new_matches = '''        public int Year
        {
            get
            {
                if (string.IsNullOrEmpty(CveId)) return 2024;
                string[] parts = CveId.Split('-');
                if (parts.Length >= 2 && int.TryParse(parts[1], out int y))
                    return y;
                return 2024;
            }
        }

        public bool MatchesScanTier(ScanTier tier)
        {
            if (tier == ScanTier.Fast)
            {
                // Fast: High-speed triage of top-tier active threats & critical RCEs
                // External: Critical ports/protocols (19 items)
                // Internal: Recent Critical CVSS 9.0+ RCEs & active modern threats (71 items)
                if (TargetPort > 0)
                {
                    return (CvssScore >= 9.8 && Year >= 2020) || CveId == "CVE-2019-0708" || CveId == "CVE-2017-0144";
                }
                return (CvssScore >= 9.0 && Year >= 2023) || (Year >= 2025 && CvssScore >= 8.0);
            }
            else if (tier == ScanTier.Normal)
            {
                // Normal: Operational Standard Audit for Modern Supported Systems (2020-2026)
                // External: Modern perimeter vectors (42 items)
                // Internal: Modern high-impact vectors (312 items)
                if (TargetPort > 0)
                {
                    return Year >= 2020 || CvssScore >= 9.0;
                }
                return CvssScore >= 9.0 || (Year >= 2020 && CvssScore >= 7.0);
            }
            else
            {
                // Full: All CVEs in database (Internal: 433 items, External: 48 items)
                return true;
            }
        }'''

if old_matches in text:
    text = text.replace(old_matches, new_matches)
    print("[+] Replaced MatchesScanTier and added Year property in SharedCore.cs")
else:
    print("[-] Warning: old_matches not found in SharedCore.cs")

with open(path, "w", encoding="utf-8") as f:
    f.write(text)
print("[+] Updated SharedCore.cs")
