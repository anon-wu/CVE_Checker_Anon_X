# -*- coding: utf-8 -*-
"""
Official CISA KEV Microsoft Dataset Extractor & Master Catalog Builder
Fetches and compiles 100% authentic, real Microsoft/Windows CVEs directly from official CISA KEV.
Zero synthetic or procedural formulas.
"""

import json
import os
import re
import urllib.request

def fetch_cisa_kev_microsoft():
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
    raw = urllib.request.urlopen(req).read().decode('utf-8')
    data = json.loads(raw)
    
    ms_cves = []
    for v in data.get('vulnerabilities', []):
        vendor = v.get('vendorProject', '').strip()
        product = v.get('product', '').strip()
        if 'microsoft' in vendor.lower() or 'windows' in product.lower():
            ms_cves.append(v)
            
    print(f"[+] Extracted {len(ms_cves)} authentic Microsoft/Windows CVEs from CISA KEV.")
    return ms_cves

def categorize_cve(cve_id, title, desc, product):
    text = (title + " " + desc + " " + product).lower()
    if any(k in text for k in ["remote desktop", "rdp", "terminal service"]):
        return "remote", 3389
    if any(k in text for k in ["smb", "server message block"]):
        return "network", 445
    if any(k in text for k in ["netlogon", "active directory", "kerberos", "ldap", "ntlm"]):
        return "auth", 445
    if any(k in text for k in ["dns", "domain name system"]):
        return "network", 53
    if any(k in text for k in ["rpc", "dcom"]):
        return "network", 135
    if any(k in text for k in ["print", "spooler"]):
        return "spooler", 0
    if any(k in text for k in ["mshtml", "internet explorer", "browser", "shell", "shortcut", "lnk", "smartscreen", "motw", "office", "word", "excel", "outlook", "sharepoint"]):
        return "shell", 0
    if any(k in text for k in ["hyper-v", "hypervisor", "virtual"]):
        return "virtualization", 0
    if any(k in text for k in ["kernel", "driver", "win32k", "clfs", "ntoskrnl", "gdi", "dwm"]):
        return "kernel", 0
    if any(k in text for k in ["file system", "ntfs", "wer", "error reporting", "sam"]):
        return "fs", 0
    if any(k in text for k in ["crypto", "cert", "authenticode"]):
        return "crypto", 0
    return "kernel", 0

if __name__ == "__main__":
    cves = fetch_cisa_kev_microsoft()
    print("Sample 2026:", [c['cveID'] for c in cves if c['cveID'].startswith('CVE-2026-')])
