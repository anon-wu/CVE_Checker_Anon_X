# -*- coding: utf-8 -*-
import os

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# 1. Update README.md
path_ko = os.path.join(base_dir, "README.md")
with open(path_ko, "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace("520 Deep Live Signatures per Scanner", "433 Verified Signatures (Fast: 71, Normal: 312, Full: 433)")
text = text.replace("520종 심층 실측 시그니처 클러스터", "433종 공식 실측 시그니처 (Fast: 71, Normal: 312, Full: 433)")
text = text.replace("`520`개 호스트 실측 시그니처", "`433`개 호스트 실측 시그니처")
text = text.replace("`520`개 경계면 실측 시그니처", "`48`개 경계면 실측 시그니처")
text = text.replace("`520`개 감사 시그니처", "`433`개 감사 시그니처")
text = text.replace("520종 핵심 시그니처 (`Fast` / `Normal` / `Full` 3단계 정밀 진단)", "433종 공식 시그니처 (`Fast: 71` / `Normal: 312` / `Full: 433` 3단계 정밀 진단)")
text = text.replace("520종 기본", "433종 기본")
text = text.replace("전수 520종", "전수 433종")

with open(path_ko, "w", encoding="utf-8") as f:
    f.write(text)
print("[+] Updated README.md")

# 2. Update README.en.md
path_en = os.path.join(base_dir, "README.en.md")
with open(path_en, "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace("520 Deep Live Signatures per Scanner", "433 Verified Signatures (Fast: 71, Normal: 312, Full: 433)")
text = text.replace("520 deep live signature clusters per scanner", "433 verified signatures (Fast: 71, Normal: 312, Full: 433)")
text = text.replace("`520` live host signatures", "`433` live host signatures")
text = text.replace("`520` live perimeter signatures", "`48` live perimeter signatures")
text = text.replace("`520` full signatures", "`433` full signatures")
text = text.replace("All 520 live signature clusters (`Fast` / `Normal` / `Full` scan tiers)", "433 verified signatures (`Fast: 71` / `Normal: 312` / `Full: 433` scan tiers)")
text = text.replace("All 520 clusters", "All 433 signatures")
text = text.replace("Full 520-cluster scan", "Full 433-signature scan")

with open(path_en, "w", encoding="utf-8") as f:
    f.write(text)
print("[+] Updated README.en.md")

# 3. Update README.ja.md
path_ja = os.path.join(base_dir, "README.ja.md")
with open(path_ja, "r", encoding="utf-8") as f:
    text = f.read()

text = text.replace("520 Deep Live Signatures per Scanner", "433 Verified Signatures (Fast: 71, Normal: 312, Full: 433)")
text = text.replace("520基", "433基")
text = text.replace("`520` 基", "`433` 基")
text = text.replace("`520`基", "`433`基")
text = text.replace("全520基", "全433基")
text = text.replace("520件", "433件")

with open(path_ja, "w", encoding="utf-8") as f:
    f.write(text)
print("[+] Updated README.ja.md")
