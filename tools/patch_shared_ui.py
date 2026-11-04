# -*- coding: utf-8 -*-
import os

path = os.path.join(os.path.dirname(__file__), "..", "src", "SharedUi.cs")
with open(path, "r", encoding="utf-8") as f:
    text = f.read()

# 1. Update BuildScannerView radio button initialization
old_block1 = '''            _rbFast = UiKit.Radio(I18n.T("신속(Fast)", "迅速(Fast)", "Fast"), Color.FromArgb(102, 217, 255));
            _rbFast.Checked = true;
            _rbFast.CheckedChanged += async (s, e) => { if (_rbFast.Checked) { _selectedTier = ScanTier.Fast; await ExecuteScanAsync(); } };

            _rbNormal = UiKit.Radio(I18n.T("표준(Norm)", "標準(Norm)", "Normal"), Color.FromArgb(255, 214, 102));
            _rbNormal.CheckedChanged += async (s, e) => { if (_rbNormal.Checked) { _selectedTier = ScanTier.Normal; await ExecuteScanAsync(); } };

            _rbFull = UiKit.Radio(I18n.T("심층(Full)", "深層(Full)", "Full"), Color.FromArgb(255, 128, 128));'''

new_block1 = '''            int fastInitCount = _allCves != null ? _allCves.FindAll(c => c.MatchesScanTier(ScanTier.Fast)).Count : 0;
            int normInitCount = _allCves != null ? _allCves.FindAll(c => c.MatchesScanTier(ScanTier.Normal)).Count : 0;
            int fullInitCount = _allCves != null ? _allCves.Count : 0;

            _rbFast = UiKit.Radio(string.Format(I18n.T("신속({0})", "迅速({0})", "Fast ({0})"), fastInitCount), Color.FromArgb(102, 217, 255));
            _rbFast.Checked = true;
            _rbFast.CheckedChanged += async (s, e) => { if (_rbFast.Checked) { _selectedTier = ScanTier.Fast; await ExecuteScanAsync(); } };

            _rbNormal = UiKit.Radio(string.Format(I18n.T("표준({0})", "標準({0})", "Normal ({0})"), normInitCount), Color.FromArgb(255, 214, 102));
            _rbNormal.CheckedChanged += async (s, e) => { if (_rbNormal.Checked) { _selectedTier = ScanTier.Normal; await ExecuteScanAsync(); } };

            _rbFull = UiKit.Radio(string.Format(I18n.T("심층({0})", "深層({0})", "Full ({0})"), fullInitCount), Color.FromArgb(255, 128, 128));'''

if old_block1 in text:
    text = text.replace(old_block1, new_block1)
    print("[+] Replaced tier radio initialization in SharedUi.cs")
else:
    print("[-] Warning: old_block1 not found in SharedUi.cs")

# 2. Update UpdateControlTexts in SharedUi.cs
old_block2 = '''            if (_rbFast != null) _rbFast.Text = I18n.T("신속(Fast)", "迅速(Fast)", "Fast");
            if (_rbNormal != null) _rbNormal.Text = I18n.T("표준(Norm)", "標準(Norm)", "Normal");
            if (_rbFull != null) _rbFull.Text = I18n.T("심층(Full)", "深層(Full)", "Full");'''

new_block2 = '''            int fastUpCount = _allCves != null ? _allCves.FindAll(c => c.MatchesScanTier(ScanTier.Fast)).Count : 0;
            int normUpCount = _allCves != null ? _allCves.FindAll(c => c.MatchesScanTier(ScanTier.Normal)).Count : 0;
            int fullUpCount = _allCves != null ? _allCves.Count : 0;

            if (_rbFast != null) _rbFast.Text = string.Format(I18n.T("신속({0})", "迅速({0})", "Fast ({0})"), fastUpCount);
            if (_rbNormal != null) _rbNormal.Text = string.Format(I18n.T("표준({0})", "標準({0})", "Normal ({0})"), normUpCount);
            if (_rbFull != null) _rbFull.Text = string.Format(I18n.T("심층({0})", "深層({0})", "Full ({0})"), fullUpCount);'''

if old_block2 in text:
    text = text.replace(old_block2, new_block2)
    print("[+] Replaced tier radio language update in SharedUi.cs")
else:
    print("[-] Warning: old_block2 not found in SharedUi.cs")

with open(path, "w", encoding="utf-8") as f:
    f.write(text)
print("[+] Updated SharedUi.cs successfully!")
