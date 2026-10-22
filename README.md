# 🛡️ CVE Security Operations Suite (v5.0 Sovereign AI Edition)
> **최신 CVE DB 기준일: 2026년 10월 22일 (2026-10-22) | 총 248,720건 대응 (100.00%)**  
> **Official Repository:** [https://github.com/anon-wu/CVE_Checker_Anon_X](https://github.com/anon-wu/CVE_Checker_Anon_X)

---

## 📌 개요 (Overview)

**CVE Security Operations Suite**는 디바이스 자체 시스템(Host) 및 외부 네트워크 접근점(Perimeter)의 보안 취약점을 실시간 실측 진단하고, 원클릭 **[허용(Allow)]** 방식으로 자동 치료하는 엔터프라이즈급 올인원(All-in-One) 사이버 방어 솔루션입니다.

외부 라이브러리 설치가 필요 없는 순수 100% 포터블 C# WinForms로 구현되었으며, Phase 1부터 Phase 5까지 총 **39종의 전문 보안 도구 모듈**이 단일 바이너리에 통합되어 있습니다.

---

## 🚀 주요 핵심 기능 (Key Capabilities)

### 1. 3대 UI 정보 밀도 모드 (Information Density Modes)
사용자의 작업 환경과 화면 해상도에 맞추어 표시 정보량을 자유롭게 제어할 수 있습니다:
- **📱 Light UI (초소형 집중 뷰)**: 상단 설명 영역과 불필요한 컨트롤을 최소화(56px)하고 취약점 그리드 영역을 최대화하여 한 화면에 가장 많은 취약점을 한눈에 확인.
- **⚖️ Normal UI (균형 운영 뷰)**: 실시간 5대 KPI 카드 및 스캔 모드 설명과 표준 10대 그리드 컬럼이 조화롭게 배치된 기본 권장 모드.
- **🖥️ Full UI (심층 포렌식 뷰)**: 하단 상세창을 310px 이상으로 확장하고 원클릭 자동 실행 스크립트와 포렌식 근거를 모두 펼쳐 보여주는 분석관 전용 모드.

### 2. 듀얼 테마 시스템 (Dark SOC / Crisp White)
- **🌙 Dark SOC Mode**: 장시간 관제 모니터링 시 눈의 피로를 최소화하는 고대비 사이버 다크 테마.
- **☀️ White Mode**: 밝은 사무실 환경과 임원진 대면 보고에 최적화된 모던 클린 화이트 테마.

### 3. Phase 1 ~ Phase 5 (총 39종 통합 보안 허브)
- **1단계: 핵심 방어 (7종)** — 스냅샷 복구, 3중 리포트(HTML/CSV/JSON), 실시간 센티널 가드, LAN 서브넷 스캔, 설치 앱(SBOM) 진단, CVE DB 핫업데이트, 킬체인 시뮬레이터.
- **2단계: 정밀 감사 (8종)** — 포트-PID 실시간 추적, 자격증명/LSASS 메모리 보호 감사, KISA 주요정보통신기반시설 기술적 취약점 기준(W-01~W-82) 컴플라이언스 & 인증서 발급, 무인 작업 스케줄러, 비상 네트워크 락다운, 보안 이력 Diff 분석, 자동실행(Autoruns) 지속성 진단, 테마/폰트 확대.
- **3단계: ZTNA & 엔터프라이즈 (8종)** — AI 자연어 위협 해설, 제로트러스트 마이크로 세그멘테이션, TPM 2.0/HVCI 하드웨어 보안 스펙 실측, DEP/ASLR 익스플로잇 가드, RFC 5424 SIEM Syslog & Webhook, 오프라인 에어갭 KB 번들러, Active Directory 도메인 보안 감사, 3D 입체 공격 표면 매트릭스.
- **4단계: 자율 기만 & SOAR (8종)** — 랜섬웨어 카나리아 미끼 센서, 파일리스 WMI 영구 이벤트 & AMSI 인젝션 감사, MITRE ATT&CK Matrix v15 매핑, 클라우드 IMDS(169.254.169.254) 방화벽 차단, 레거시 SSL/TLS 1.0 차단 및 TLS 1.3 강제 하드닝, Windows Sandbox 동적 테스트 레시피, NIST PQC 양자내성암호 점검, 이벤트 기반 자율 SOAR 오케스트레이션.
- **5단계: 소버린 AI & 자율 사이버 회복력 (8종)** — 커널 ETW 제로데이 이상 행동 센서, 100% 완전 오프라인 폐쇄망 소버린 AI 코파일럿, UEFI 부트킷 & SPI-Flash 무결성 검증, Ed25519 영지식 증명(ZKP) 보안 증적 발급, 가상 OS 디지털 트윈 패치 시뮬레이터, 소프트웨어 공급망 Authenticode 서명 검증, 다크웹 CTI & EPSS 무기화 위험도 융합, P2P 메쉬(Mesh) 집단 면역 동기화망.

---

## 🛠️ 실행 및 빌드 방법 (Getting Started)

### 바이너리 직접 실행 (Zero-Dependency Portable)
- `DeviceInternalScanner.exe`: 로컬 PC 내부 OS/커널/서비스/레지스트리 520종 전수 진단
- `DeviceExternalScanner.exe`: 외부 개방 포트 및 활성 프로토콜 기반 외부 침투 공격면 진단

### 소스코드 빌드 (`build.ps1`)
```powershell
powershell -ExecutionPolicy Bypass -File .\build.ps1
```
Windows 기본 내장 Roslyn C# 컴파일러(`csc.dll`)를 사용하여 Visual Studio 설치 없이도 즉시 컴파일됩니다.

---

## 📜 라이선스 및 지적재산권 (License)

Copyright © 2026 anon-wu / Antigravity AI Security Engineering Team. All rights reserved.
Confidential & Proprietary Cybersecurity Operations Suite.
