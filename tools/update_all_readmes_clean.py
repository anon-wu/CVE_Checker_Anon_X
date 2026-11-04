# -*- coding: utf-8 -*-
import sys

# 1. README.md
path_ko = r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\README.md'
with open(path_ko, 'r', encoding='utf-8') as f:
    ko = f.read()

ko = ko.replace(
    '스캐너당 `520`종 심층 실측 시그니처 클러스터 `100.00%` 매핑',
    '433종의 CISA KEV 및 Windows 심층 실측 시그니처 클러스터 `100.00%` 매핑'
)
ko = ko.replace(
    '| **내장 시그니처** | `520`종 호스트 실측 시그니처 (`249,280` CVE) | `520`종 경계 실측 시그니처 (`249,280` CVE) | `520`종 전수 시그니처 (`249,280` CVE, 조치 루틴 원천 비활성화) |',
    '| **내장 시그니처** | `433`종 호스트 실측 시그니처 (`249,280` CVE) | `48`종 경계 실측 시그니처 (`249,280` CVE) | `433`종 전수 시그니처 (`249,280` CVE, 조치 루틴 원천 비활성화) |'
)
ko = ko.replace(
    '| **내부/외부 CVE 진단 엔진** | 520종 핵심 시그니처 (`Fast` / `Normal` / `Full` 3단계 전수 지원) | 520종 전수 + 폐쇄망 커스텀 `.cvedb` 핫업데이트 & 전사 오케스트레이션 |',
    '| **내부/외부 CVE 진단 엔진** | 433종 실측 시그니처 (`Fast: 76` / `Normal: 314` / `Full: 433` 3단계 지원, 외부는 `Fast: 19` / `Normal: 42` / `Full: 48`) | 433종 전수 + 폐쇄망 커스텀 `.cvedb` 핫업데이트 & 전사 오케스트레이션 |'
)
with open(path_ko, 'w', encoding='utf-8') as f:
    f.write(ko)
print('Updated README.md')

# 2. README.en.md
path_en = r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\README.en.md'
with open(path_en, 'r', encoding='utf-8') as f:
    en = f.read()

en = en.replace(
    'mapped `100.00%` across `520` deep live signature clusters per scanner',
    'mapped `100.00%` across 433 verified CISA KEV & Windows live signature clusters'
)
en = en.replace(
    '433 verified signatures (`Fast: 71` / `Normal: 312` / `Full: 433` scan tiers)',
    '433 verified signatures (`Fast: 76` / `Normal: 314` / `Full: 433` scan tiers, perimeter: `Fast: 19` / `Normal: 42` / `Full: 48`)'
)
with open(path_en, 'w', encoding='utf-8') as f:
    f.write(en)
print('Updated README.en.md')

# 3. README.ja.md
path_ja = r'C:\Users\Anon\Desktop\CVE_Security_Suite_Archive_and_Versions\5_Source_Code_and_Build\CVE_Security_Scanner\README.ja.md'
with open(path_ja, 'r', encoding='utf-8') as f:
    ja = f.read()

ja = ja.replace(
    'スキャナあたり `520` 種の深層実測シグネチャへ `100.00%` マッピング',
    '433種のCISA KEV・Windows深層実測シグネチャへ `100.00%` マッピング'
)
ja = ja.replace(
    '| **内蔵シグネチャ数** | `520` 種のホスト実측シグネチャ（`249,280` CVE） | `520` 種の境界実測シグネチャ（`249,280` CVE） | `520` 種の全数シグネチャ（`249,280` CVE、修復ルーチンを完全遮断） |',
    '| **内蔵シグネチャ数** | `433` 種のホスト実測シグネチャ（`249,280` CVE） | `48` 種の境界実測シグネチャ（`249,280` CVE） | `433` 種の全数シグネチャ（`249,280` CVE、修復ルーチンを完全遮断） |'
)
ja = ja.replace(
    '| **内蔵シグネチャ数** | `520` 種のホスト実測シグネチャ（`249,280` CVE） | `520` 種の境界実測シグネチャ（`249,280` CVE） | `520` 種の全数シグネチャ（`249,280` CVE、修復ルーチンを完全遮断） |',
    '| **内蔵シグネチャ数** | `433` 種のホスト実測シグネチャ（`249,280` CVE） | `48` 種の境界実測シグネチャ（`249,280` CVE） | `433` 種の全数シグネチャ（`249,280` CVE、修復ルーチンを完全遮断） |'
)
ja = ja.replace(
    '| **内部・外部 CVE 診断エンジン** | 全520種シグネチャ対応（`Fast` / `Normal` / `Full` 全3段階対応） | 全520種 + 閉鎖網カスタム `.cvedb` ホット更新・全社オーケストレーション |',
    '| **内部・外部 CVE 診断エンジン** | 433種実測シグネチャ（`Fast: 76` / `Normal: 314` / `Full: 433`、境界スキャンは `Fast: 19` / `Normal: 42` / `Full: 48`） | 433種全数 + 閉鎖網カスタム `.cvedb` ホット更新・全社オーケストレーション |'
)
with open(path_ja, 'w', encoding='utf-8') as f:
    f.write(ja)
print('Updated README.ja.md')
