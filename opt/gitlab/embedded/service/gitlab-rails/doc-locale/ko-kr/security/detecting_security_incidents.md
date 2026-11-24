---
stage: Security
group: Security Operations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 보안 사건 탐지
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

보안 사건을 빨리 탐지할수록 그 영향을 더 잘 제한할 수 있습니다.

GitLab Security Operations 팀이 GitLab Self-Managed 인스턴스와 GitLab.com의 그룹의 관리자와 유지 관리자를 위해 이러한 권장사항을 작성했습니다. 이를 사용하여 GitLab의 보안 관련 활동에 대한 탐지 범위를 구축하고, 잠재적 보안 사건을 나타내는 신호를 인식할 수 있습니다. 이는 조직에서 정의한 탐지 및 모니터링 프로세스를 보완하지만, 그 프로세스를 대체하지는 않습니다.

사건을 확인했을 때 [보안 사건에 대응하기](responding_to_security_incidents.md)를 따라 사건을 포함하고 해결합니다.

> [!warning]
> 이러한 제안과 권장사항을 자신의 책임 하에 사용합니다. 탐지 범위는 구성, 구독 티어, 환경의 로깅 및 모니터링 도구에 따라 달라집니다.

## 탐지 기능 구축 {#build-a-detection-capability}

효과적인 탐지는 신뢰할 수 있는 데이터 소스, 이를 분석할 중앙 위치, 원본 활동을 실행 가능한 경고로 변환하는 조정된 규칙을 결합합니다.

### 탐지 데이터 소스 {#detection-data-sources}

GitLab은 의심스러운 활동을 탐지하는 데 사용할 수 있는 보안 관련 데이터의 여러 소스를 생성합니다:

| 데이터 소스 | 가용성 | 표시되는 내용 |
|-------------|--------------|---------------|
| [감사 이벤트](../administration/compliance/audit_event_reports.md) | Premium, Ultimate | 인증, 권한 변경, 프로젝트, 그룹, 설정 변경. GitLab에서 보안 사건을 탐지하기 위한 주요 소스입니다. 전체 목록은 [감사 이벤트 유형](../user/compliance/audit_event_types.md)을 참조하세요. |
| [로그인 감사 이벤트](../user/compliance/audit_events.md#sign-in-audit-events) | 모든 티어 | 사용자 프로필의 **인증 로그**에서 사용자를 위한 성공한 로그인. |
| [시스템 로그](../administration/logs/_index.md) | 모든 티어, GitLab Self-Managed만 해당 | 애플리케이션, API, 인증, Workhorse 로그. [상관관계 ID](../administration/logs/tracing_correlation_id.md)를 사용하여 단일 요청을 여러 로그에서 추적합니다. |
| [CI/CD 작업 로그](../ci/jobs/job_logs.md) | 모든 티어 | 노출된 시크릿, 예상치 못한 명령, 공격자가 시작한 파이프라인 활동. |
| [자격증명 인벤토리](../administration/credentials_inventory.md) | Ultimate | 인스턴스 또는 최상위 그룹에 존재하는 개인, 그룹, 프로젝트 액세스 토큰, SSH 키, GPG 키. |
| [시크릿 푸시 보호](../user/application_security/secret_detection/secret_push_protection/_index.md) 및 [시크릿 검색](../user/application_security/secret_detection/_index.md) | 시크릿 푸시 보호: Ultimate. 파이프라인 시크릿 검색: 모든 계층. | 사용자가 푸시하려고 하거나 리포지토리에 커밋된 시크릿. |

각 소스가 포함하는 내용과 각 제공 서비스 및 구독 티어에서 이를 수집하는 방법에 대한 자세한 내용은 [보안 원격 분석](security_telemetry.md)을 참조하세요.

예상치 못한 위치에서의 로그인이나 2단계 인증 변경과 같은 의심스러운 인증을 탐지하려면 [시스템 액세스 감사 이벤트](../user/compliance/audit_event_types.md#system-access)를 검토하세요.

### 이벤트를 SIEM으로 중앙화 및 스트리밍 {#centralize-and-stream-events-to-a-siem}

거의 실시간으로 사건을 탐지하고 조사를 위해 이벤트를 유지하려면 데이터를 보안 정보 및 이벤트 관리(SIEM) 시스템 또는 다른 로그 분석 플랫폼에 중앙화합니다:

- 감사 이벤트를 외부 대상으로 스트리밍합니다.
  - GitLab Self-Managed 및 GitLab Dedicated: [인스턴스의 감사 이벤트 스트리밍](../administration/compliance/audit_event_streaming.md) 
  - GitLab.com: [최상위 그룹을 위한 감사 이벤트 스트리밍](../user/compliance/audit_event_streaming.md)
- 이벤트를 스트리밍하지 않는 경우 [감사 이벤트 API](../api/audit_events.md)를 사용하여 일정에 따라 수집할 수 있습니다.
- 로그 및 이벤트를 독립적인 쓰기 전용(불변) 데이터 저장소로 라우팅하여 공격자가 이를 변경하거나 삭제할 수 없도록 합니다.
- 데이터가 필요하기 전에 조사 및 규정 준수 요구사항을 충족하는 보관 기간을 정의합니다.

### GitLab 탐지 규칙 사용 {#use-the-gitlab-detection-rules}

GitLab Security Operations 팀은 GitLab 환경을 위한 오픈 소스 탐지 프레임워크인 [TLDR](https://gitlab.com/gitlab-security-oss/tldr)(위협, 로그, 탐지, 대응)을 유지 관리합니다.

각 TLDR 탐지에는 다양한 정보가 포함됩니다:

- 위협 세부 정보: 위협의 설명 및 기술적, 비즈니스 영향.
- 로그: 탐지에 필요한 로그 소스(샘플 이벤트 포함).
- 탐지: 일반 [Sigma](https://github.com/SigmaHQ/sigma) 형식의 규칙 및 SIEM 없는 환경을 위한 원본 로그 쿼리.
- 원자적 테스트: 탐지가 발생하는지 확인할 수 있도록 활동을 재현하는 단계.
- 응답: 참 양성을 처리하는 방법에 대한 지침.

탐지는 두 가지 유형으로 분류됩니다:

- 위협 탐지: 감사 이벤트에 기록된 의심스럽거나 악의적인 활동(예: 2단계 인증 비활성화, 새 관리자 계정, 새 배포 키 또는 프로젝트 액세스 토큰, 머지 리퀘스트 승인 또는 보호된 브랜치 설정 변경).
- 취약성 탐지: GitLab Self-Managed의 알려진 취약성을 악용하려는 시도(애플리케이션 로그에 기록됨).

이러한 탐지를 사용하려면:

1. 각 탐지에 나열된 로그 소스를 SIEM으로 수집합니다.
1. Sigma 규칙을 SIEM의 쿼리 언어로 변환합니다. 공식 [Sigma CLI](https://github.com/SigmaHQ/sigma-cli) 또는 웹 기반 [sigconverter.io](https://sigconverter.io/)를 사용합니다.
1. 변환된 규칙을 모니터링 전용 모드로 먼저 배포하고 경고 볼륨을 검토합니다.
1. 경고를 대기 중인 응급 대응자에게 라우팅하기 전에 규칙을 환경에 맞게 조정합니다.

### 범위 매핑 및 탐지 조정 {#map-coverage-and-tune-detections}

탐지를 배포한 후 정기적으로 검토하여 정확성을 유지하고 조직에 중요한 위협을 포함하는지 확인합니다:

- [MITRE ATT&CK](https://attack.mitre.org/)와 같은 프레임워크에 탐지를 매핑하여 탐지할 수 있는 적 기법과 격차가 있는 부분을 파악합니다.
- 환경의 정상 활동을 기준으로 하여 경고가 의미 있는 편차에 중점을 두도록 합니다.
- 높은 심각도 경고가 신뢰할 수 있도록 잡음이 많은 규칙을 조정합니다.
- 각 탐지가 예상대로 발생하는지 테스트하고 각 규칙의 예상 동작을 문서화합니다. 각 TLDR 탐지에는 이를 위해 사용할 수 있는 원자적 테스트가 포함되어 있습니다.

## 시나리오별 탐지 항목 {#what-to-detect-by-scenario}

다음 시나리오의 대부분은 사건 대응을 위한 [일반적인 보안 사건 시나리오](responding_to_security_incidents.md#common-security-incident-scenarios)와 일치합니다. 각 시나리오에 대해 나열된 신호를 모니터링합니다. 탐지가 발생하고 사건을 확인했을 때 연결된 대응 단계를 따릅니다.

다음 표는 각 시나리오를 예제 MITRE ATT&CK 기법에 매핑합니다. 이러한 매핑을 시작점으로 사용하고 자신의 위협 모델에 맞게 조정합니다.

| 시나리오 | 주요 신호 | 예제 MITRE ATT&CK 기법 |
|----------|-------------|---------------------------------|
| [자격증명 노출 및 토큰 남용](#credential-exposure-and-token-abuse) | 새로운 토큰, 키, 사용자, CI/CD 변수 변경 | T1552 보안되지 않은 자격증명, T1078 유효한 계정, T1136 계정 생성 |
| [손상된 사용자 계정](#compromised-user-account) | 비정상적인 로그인, 2단계 인증 변경, 새 OAuth 애플리케이션 | T1078 유효한 계정, T1110 무차별 대입, T1098 계정 조작, T1556 인증 프로세스 수정 |
| [CI/CD 남용](#cicd-abuse) | 파이프라인 구성, 변수, 러너 변경 | T1195.002 소프트웨어 공급망 훼손, T1552 보안되지 않은 자격증명 |
| [손상된 인스턴스](#compromised-instance) | 새 관리자, 루트 사용자 활동, 호스트 지표 | T1078 유효한 계정, T1098 계정 조작, T1136 계정 생성 |
| [잘못 구성된 프로젝트 또는 그룹 설정](#misconfigured-project-or-group-settings) | 표시 여부, 승인, 보호된 브랜치 변경 | T1685 도구 비활성화 또는 수정, T1485 데이터 파괴 |
| [데이터 유출](#data-exfiltration) | 대량 클론, 프로젝트 내보내기, 새 배포 키 또는 토큰 | T1213.003 코드 리포지토리, T1567 웹 서비스 통한 유출 |
| [남용 및 리소스 오용](#abuse-and-resource-misuse) | 계산 스파이크, 새 계정의 폭증, 과도한 Git 작업 | T1496 리소스 하이재킹, T1136 계정 생성 |

### 자격증명 노출 및 토큰 남용 {#credential-exposure-and-token-abuse}

토큰, 키 또는 다른 자격증명이 노출되거나 오용되었음을 시사하는 활동을 감시합니다:

- 개인, 프로젝트 또는 그룹 액세스 토큰 생성(특히 예상치 못한 사용자).
- SSH 또는 GPG 키 생성.
- 지속성을 유지하기 위해 공격자가 사용할 수 있는 새 사용자 계정 생성.
- [CI/CD 변수](../ci/variables/_index.md) 또는 시크릿을 저장하는 다른 구성에 대한 변경. [지속적 통합 감사 이벤트](../user/compliance/audit_event_types.md#continuous-integration)에 중점을 두세요.
- 예상치 못한 사용자가 실행한 파이프라인. 세부 정보는 [작업 로그](../administration/cicd/job_logs.md)를 검토하세요.

대응하려면 [공개 인터넷으로의 자격증명 노출](responding_to_security_incidents.md#credential-exposure-to-public-internet)을 참조하세요.

### 손상된 사용자 계정 {#compromised-user-account}

계정이 소유자 이외의 다른 사람에 의해 사용되고 있음을 나타내는 신호를 감시합니다:

- 예상치 못한 IP 주소, 위치 또는 디바이스에서의 로그인과 같은 의심스러운 로그인 이벤트.
- 개인, 프로젝트 또는 그룹 액세스 토큰의 생성 또는 삭제.
- SSH 또는 GPG 키의 생성 또는 삭제.
- 2단계 인증 설정 변경.
- 이메일 주소 또는 알림 설정 변경.
- 인증된 OAuth 애플리케이션의 추가 또는 수정.
- 연결된 SAML 자격 증명 공급자에 대한 변경.

대응하려면 [손상된 사용자 계정 의심](responding_to_security_incidents.md#suspected-compromised-user-account)을 참조하세요.

### CI/CD 남용 {#cicd-abuse}

시크릿을 노출하거나 공격자가 파이프라인에서 코드를 실행할 수 있도록 하는 변경을 감시합니다:

- CI/CD 구성 파일 또는 파이프라인 정의에 대한 수정.
- [마스킹](../ci/variables/_index.md#mask-a-cicd-variable) 및 보호 설정을 포함한 CI/CD 변수 변경
- 파이프라인 또는 작업 아티팩트를 공개적으로 접근 가능하게 하는 변경.
- 새 러너 등록 또는 기존 러너 변경.
- [CI/CD 작업 토큰](../ci/jobs/ci_job_token.md#gitlab-cicd-job-token-security)의 예상치 못한 사용.

대응하려면 [CI/CD 관련 보안 사건](responding_to_security_incidents.md#cicd-related-security-incidents)을 참조하세요.

### 손상된 인스턴스 {#compromised-instance}

GitLab Self-Managed의 경우 인스턴스 수준 및 호스트 수준 신호를 감시합니다:

- 시스템 설정, 사용자 권한 또는 로그인 이벤트에 대한 변경을 보여주는 시스템 액세스 감사 이벤트.
- 새 관리자 계정 생성 또는 관리 루트 사용자의 활동.
- 인식할 수 없는 백그라운드 프로세스, 예상치 못한 열린 포트, 비정상적인 네트워크 트래픽 같은 호스트 수준 지표.

대응하려면 [손상된 인스턴스 의심](responding_to_security_incidents.md#suspected-compromised-instance)을 참조하세요.

### 잘못 구성된 프로젝트 또는 그룹 설정 {#misconfigured-project-or-group-settings}

데이터를 노출하거나 액세스 제어를 약화시킬 수 있는 변경을 감시합니다:

- 프로젝트 또는 그룹 표시 여부 변경.
- 머지 리퀘스트 승인 설정 수정.
- 프로젝트 삭제.
- 의심스러운 웹후크 또는 [서버 후크](../administration/server_hooks.md) 추가.
- 보호된 브랜치 설정 변경.

검색을 좁히기 위해 `target_type` 필드로 감사 이벤트를 필터링하고 [규정 준수 관리](../user/compliance/audit_event_types.md#compliance-management) 및 [그룹 및 프로젝트](../user/compliance/audit_event_types.md#groups-and-projects) 감사 이벤트를 검토합니다.

대응하려면 [잘못 구성된 프로젝트 또는 그룹 설정](responding_to_security_incidents.md#misconfigured-project-or-group-settings)을 참조하세요.

### 데이터 유출 {#data-exfiltration}

소스 코드 또는 다른 데이터가 GitLab 외부로 복사되고 있음을 나타내는 신호(종종 손상된 계정이나 토큰을 통해 공격자가 액세스를 얻은 후)를 감시합니다:

- 짧은 기간에 단일 사용자 또는 토큰에 의한 많은 리포지토리 다운로드 또는 클론.
- 프로젝트 또는 그룹 내보내기 및 내보내기 파일 다운로드(특히 일반적으로 수행하지 않는 사용자).
- 리포지토리에 대한 장기 액세스를 제공하는 새 배포 키 또는 배포 토큰.
- 예상치 못한 사용자의 작업 아티팩트 다운로드.
- 비공개 프로젝트 또는 그룹을 공개로 만드는 변경.
- 이전에 보지 못한 IP 주소에서 사용된 개인 액세스 토큰.

대응하려면 [공개 인터넷으로의 자격증명 노출](responding_to_security_incidents.md#credential-exposure-to-public-internet)을 따라 관련된 자격증명을 취소하고 조직에서 정의한 사건 대응 프로세스를 따릅니다.

### 남용 및 리소스 오용 {#abuse-and-resource-misuse}

CI/CD에서의 암호화폐 마이닝과 같은 자동화된 남용 및 예상치 못한 리소스 소비를 감시합니다:

- 파이프라인 활동, 계산 분 또는 새 러너 등록의 스파이크.
- 새 계정 생성의 폭증.
- 과도한 Git 작업. Ultimate에서는 [Git 남용 속도 제한](../user/group/reporting/git_abuse_rate_limit.md)을 구성하여 이러한 패턴의 일부를 자동으로 완화할 수 있습니다.

대응하려면 조직에서 정의한 사건 대응 프로세스를 따르고 [강화 권장사항](hardening.md)을 검토합니다.

## 탐지가 발생했을 때 {#when-a-detection-fires}

탐지가 경고를 트리거할 때 이를 분류하여 보안 사건이 진행 중인지 확인합니다:

1. 증거를 보존합니다. 관련 로그 및 감사 이벤트를 쓰기 전용 위치에 저장하여 나중에 조사할 수 있도록 합니다.
1. 영향을 받은 사용자, 프로젝트, 그룹, 토큰 또는 호스트와 같은 범위를 결정합니다.
1. 일치하는 시나리오에서 연결된 대응 단계를 따라 사건을 포함하고 해결합니다.
1. 조직에서 정의한 사건 대응 프로세스를 따릅니다.

## GitLab에 지원 요청 {#engaging-gitlab-for-assistance}

GitLab에 도움을 요청하기 전에 [GitLab 설명서](https://docs.gitlab.com)를 검색합니다. 예비 조사를 완료한 후에도 여전히 질문이 있거나 지원이 필요한 경우 GitLab Support에 문의합니다. GitLab Support로부터 지원을 받을 수 있는 자격은 [라이선스에 의해 결정됩니다](https://support.gitlab.com/hc/en-us/articles/11626483177756-GitLab-Support#gitlab-support-service-levels).

## 관련 항목 {#related-topics}

- [보안 사건](security_incidents.md)
- [보안 원격 분석](security_telemetry.md)
- [GitLab 보안](_index.md)
- [감사 이벤트 유형](../user/compliance/audit_event_types.md)
