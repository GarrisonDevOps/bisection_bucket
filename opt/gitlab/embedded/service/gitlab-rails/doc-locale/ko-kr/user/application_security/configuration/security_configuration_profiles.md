---
stage: Security Governance
group: Security Controls
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 보안 구성 프로필 관리
---

{{< details >}}

- 티어:  Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [도입됨](https://gitlab.com/groups/gitlab-org/-/work_items/19802) GitLab 18.9에서 [기능 플래그](../../../administration/feature_flags/_index.md) 함께 `security_scan_profiles_feature`로 지정됨. 기본적으로 활성화되어 있습니다.
- 시크릿 검색 프로필 [추가됨](https://gitlab.com/groups/gitlab-org/-/epics/19903) GitLab 18.10에서.
- SAST 프로필 [추가됨](https://gitlab.com/groups/gitlab-org/-/epics/19951) GitLab 18.11에서.
- 종속성 검사 프로필 [도입됨](https://gitlab.com/groups/gitlab-org/-/epics/19952) GitLab 19.0에서 [기능 플래그](../../../administration/feature_flags/_index.md) 함께 `security_scan_profiles_dependency_scanning`로 지정됨. 기본적으로 활성화되어 있습니다.
- 종속성 검사 자동 수정 프로필 [도입됨](https://gitlab.com/groups/gitlab-org/-/work_items/604588) GitLab 19.2에서 [기능 플래그](../../../administration/feature_flags/_index.md) 함께 `security_remediation_profiles`로 지정됨. 기본적으로 활성화되어 있습니다.
- 시크릿 검색 스캔 프로필 구성 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/606237) GitLab 19.3에서 [실험](../../../policy/development_stages_support.md) 중이며 GraphQL API를 통해서만 사용 가능합니다.
- 기능 플래그 `security_scan_profiles_feature` GitLab 19.4에서 제거됨.
- 기능 플래그 `security_remediation_profiles` GitLab 19.4에서 제거됨.
- SAST 스캔 프로필 구성 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/617070) GitLab 19.4에서 [실험](../../../policy/development_stages_support.md) 중이며 GraphQL API를 통해서만 사용 가능합니다.
- 종속성 검사 스캔 프로필 구성 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/629403) GitLab 19.5에서 [실험](../../../policy/development_stages_support.md#experiment) 중이며 GraphQL API를 통해서만 사용 가능합니다.
- UI의 커스텀 프로필 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/624191) GitLab 19.4에서 [기능 플래그](../../../administration/feature_flags/_index.md) 함께 `custom_scan_profiles_ui`로 지정됨. 기본적으로 비활성화되었습니다.
- [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/259962) GitLab 19.5에서.

{{< /history >}}

보안 구성 프로필은 프로젝트 전반에 걸쳐 보안 스캐너가 언제 어떻게 실행될지 정의하는 중앙 집중식 설정입니다. 보안 구성 프로필을 사용하여 조직 전반의 보안 스캐너를 효율적으로 관리할 수 있습니다. 프로필 기반 접근 방식은 최소한의 수동 설정으로 모범 사례를 적용합니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 개요는 [보안 구성 프로필 소개](https://www.youtube.com/watch?v=QbnLGzTEqGI)를 참조하세요.

그룹에 프로필을 적용하면 해당 그룹 내의 각 개별 프로젝트에도 적용됩니다. 프로필은 그룹 자체에 연결되지 않으며 프로필이나 하위 그룹 간에 상속되지 않습니다.

[기본 프로필](#default-profiles)을 사용하면 최소한의 구성만으로 몇 분 안에 사전 구성된 보안 스캐닝을 활성화할 수 있습니다.

## 보안 스캐너 구성 {#configure-security-scanners}

그룹의 [security inventory](../security_inventory/_index.md#view-the-security-inventory)를 중앙 대시보드로 사용하여 프로필을 평가하고 관리합니다.

### 테스트 범위 검토 {#review-test-coverage}

그룹의 SAST, 종속성 검사, 시크릿 검색 등 스캐너의 높은 수준의 상태(**활성화**, **활성화되지 않음** 또는 **실패함**)를 확인하려면:

1. 상단 바에서 **Search or go to**를 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **Secure** > **Security inventory**를 선택합니다.
1. Security inventory에서 **Test Coverage** 열을 검토합니다.

### 개별 프로젝트 범위 변경 {#change-individual-project-coverage}

특정 프로젝트를 구성하려면:

1. 상단 바에서 **Search or go to**를 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **Secure** > **Security inventory**를 선택합니다.
1. 프로젝트 옆에서 세로 줄임표({{< icon name="ellipsis_v" >}})를 선택하고 **도구 범위 관리**를 선택합니다.
1. 개별 스캐너를 켜거나 끕니다.

### 여러 프로젝트에 프로필 적용 {#apply-a-profile-to-multiple-projects}

시간을 절약하기 위해 여러 프로젝트에 보안 설정을 한 번에 적용할 수 있습니다.

1. 상단 바에서 **Search or go to**를 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **Secure** > **Security inventory**를 선택합니다.
1. 설정을 적용할 여러 프로젝트 또는 전체 하위 그룹을 선택합니다.
1. **Bulk Action** 드롭다운을 선택하고 **Manage security scanners**를 선택합니다.
1. **Apply default profile to all**을 선택하여 선택한 항목 전반의 보안 태세를 표준화합니다.

## 기본 프로필 {#default-profiles}

GitLab은 최소한의 구성으로 보안 스캐닝을 활성화할 수 있도록 사전 구성된 스캐너 설정인 기본 프로필을 제공합니다.

### 시크릿 검색 프로필 {#secret-detection-profile}

시크릿 검색 프로필을 적용하면 전체 개발 워크플로우 전반에 걸쳐 시크릿에 대한 권장 기준 보호 기능이 활성화됩니다. 이 프로필은 다음 스캔 트리거를 활성화합니다.

- **Push protection**: 모든 Git 푸시 이벤트를 스캔하고 시크릿이 탐지된 푸시를 차단하여, 시크릿이 코드베이스에 유입되는 것을 원천적으로 방지합니다.
- **Merge Request Pipelines**: 열려 있는 머지 리퀘스트가 있는 브랜치에 새 커밋이 푸시될 때마다 스캔을 자동으로 실행합니다. 스캔 결과는 해당 머지 리퀘스트에 의해 유입된 새로운 취약성으로 범위가 지정됩니다. 모든 브랜치를 대상으로 합니다.
- **Branch Pipelines (기본값 만)**:  변경 사항이 기본 브랜치에 병합되거나 푸시될 때 자동으로 실행되어, 기본 브랜치의 시크릿 검색 태세에 대한 전체적인 현황을 제공합니다. 모든 브랜치를 대상으로 합니다.

### SAST 프로필 {#sast-profile}

SAST 프로필을 적용하면 권장 구성을 사용하여 프로젝트 전반에서 정적 애플리케이션 보안 테스트(SAST)를 활성화하게 됩니다. 이 프로필은 다음 스캔 트리거를 활성화합니다.

- **Merge Request Pipelines**: 열려 있는 머지 리퀘스트가 있는 브랜치에 새 커밋이 푸시될 때마다 SAST 스캔을 자동으로 실행합니다. 스캔 결과에는 해당 머지 리퀘스트에 의해 유입된 새로운 취약성만 포함됩니다. 모든 브랜치를 대상으로 합니다.
- **Branch Pipelines (기본값 만)**:  변경 사항이 기본 브랜치에 병합되거나 푸시될 때 자동으로 실행되어, 기본 브랜치의 SAST 태세에 대한 전체적인 현황을 제공합니다. 기본 브랜치를 대상으로 합니다.

### 종속성 검사 프로필 {#dependency-scanning-profile}

종속성 검사 프로필을 활성화하면 권장 구성을 사용하여 프로젝트의 종속성을 알려진 취약성에 대해 검사합니다. 이 프로필은 다음 스캔 트리거를 활성화합니다.

- **Merge Request Pipelines**: 머지 리퀘스트가 열려 있는 브랜치에 새 커밋을 푸시할 때마다 종속성 검사를 자동으로 실행합니다. 스캔 결과에는 해당 머지 리퀘스트에 의해 유입된 새로운 취약성만 포함됩니다. 모든 브랜치를 대상으로 합니다.
- **Branch Pipelines (기본값 만)**:  변경 사항이 기본 브랜치에 병합되거나 푸시될 때 자동으로 실행되어 기본 브랜치의 종속성 취약성 상태를 전체적으로 파악할 수 있습니다. 기본 브랜치를 대상으로 합니다.

### 종속성 검사 자동 수정 프로필 {#dependency-scanning-auto-remediation-profile}

{{< history >}}

- 자동 수정을 위한 심사 및 수정 프로필 지원 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253780) GitLab 19.4에서 [기능 플래그](../../../administration/feature_flags/_index.md) 함께 `triage_and_remediation_profile`로 지정됨. 기본적으로 활성화되어 있습니다.

{{< /history >}}

종속성 검사 자동 수정 프로필을 활성화하면 GitLab은 취약한 종속성을 취약하지 않은 버전으로 업그레이드하는 머지 리퀘스트를 엽니다. 이 기능에 대한 자세한 정보는 [종속성 검사 자동 수정](../remediate/dependency_scanning_auto_remediation.md)을 참조하세요.

[GitLab CLI](../../../editor_extensions/gitlab_cli/_index.md)(`glab`)를 사용하여 프로젝트에 프로필을 연결합니다:

```shell
glab security config enable dependency_scanning_post_processing -R <project-path>
```

예를 들어, `my-group/my-project`에 대한 프로필을 활성화하려면:

```shell
glab security config enable dependency_scanning_post_processing -R my-group/my-project
```

> [!note]
> 프로젝트는 동시에 두 프로필을 모두 연결할 수 있습니다. 그 경우 GitLab은 먼저 적용된 프로필만 사용합니다. 다른 프로필의 구성은 무시됩니다.

### 자동화된 심사 및 수정 프로필 {#automated-triage-and-remediation-profile}

{{< history >}}

- 심사 및 수정 프로필 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/622469) GitLab 19.4에서 [기능 플래그](../../../administration/feature_flags/_index.md) 함께 `triage_and_remediation_profile`로 지정됨. 기본적으로 활성화되어 있습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

심사 및 수정 프로필을 사용하여 프로젝트 및 그룹 전체에서 GitLab Duo 심사 플로우 및 종속성 검사 자동 수정을 활성화합니다. GitLab Duo 플로우는 AI를 사용하여 결과를 평가하고 해결합니다. 프로필은 플로우를 자체적으로 활성화하거나 기존 프로젝트별 설정을 대체할 수 있습니다.

GitLab은 세 가지 사전 설정을 제공합니다: 보수적, 표준 및 사전 예방적. 각 사전 설정은 모든 플로우에 다른 구성을 적용하므로 플로우가 트리거되고 실행되는 방식과 빈도를 선택할 수 있습니다. 프로필을 직접 만들고 구성할 수도 있습니다.

전제 조건:

- [GitLab Duo Agent Platform 사전 요구 사항](../../duo_agent_platform/_index.md#prerequisites)을 충족합니다.
- **기본 플로우 허용**을 활성화하고 [최상위 그룹에 대해](../../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off) 사용하려는 각 플로우를 활성화합니다. 각 프로젝트가 아닌 최상위 그룹에 대해 한 번만 플로우를 활성화합니다.

> [!note]
> 이러한 플로우의 대부분은 AI 기반이며 [GitLab Credits](../../../subscriptions/gitlab_credits.md)를 소비합니다. 소비는 결과의 개수에 따라 증가합니다.

#### 사전 설정 {#presets}

| 플로우 | 보수적 | 표준 | 사전 예방적 |
| ---- | ------------ | -------- | --------- |
| SAST 거짓 양성 탐지 | `high` 이상, 온디맨드 | `medium` 이상, 자동 | `info` 이상, 자동 |
| SAST 취약성 해결 | `high` 이상, 온디맨드, 최대 5개의 열린 머지 리퀘스트 | `medium` 이상, 자동, 최대 15개의 열린 머지 리퀘스트 | `info` 이상, 자동, 머지 리퀘스트 제한 없음 |
| 시크릿 검색 거짓 양성 탐지 | `high` 이상, 온디맨드 | `medium` 이상, 자동 | `info` 이상, 자동 |
| 종속성 검사 자동 수정 | `high` 이상, 부 버전 업그레이드, 최대 5개의 열린 머지 리퀘스트, 지난 7일의 수정 버전 건너뛰기 | `high` 이상, 부 버전 업그레이드, 최대 10개의 열린 머지 리퀘스트, 지난 7일의 수정 버전 건너뛰기 | `info` 이상, 주 버전 업그레이드, 최대 10개의 열린 머지 리퀘스트, 지난 7일의 수정 버전 건너뛰기 |

사전 설정을 적용하려면 [GraphQL API](#apply-a-profile-with-the-graphql-api)를 사용합니다. 사전 설정의 이름은 `Triage and Remediation (Conservative)`, `Triage and Remediation (Standard)` 및 `Triage and Remediation (Proactive)`입니다.

#### 관련 항목 {#related-topics}

- [거짓 양성 자동 탐지](../vulnerabilities/false_positive_detection.md)
- [에이전틱 SAST 취약성 해결](../vulnerabilities/agentic_vulnerability_resolution.md)
- [시크릿 오탐 탐지](../vulnerabilities/secret_false_positive_detection.md)
- [종속성 검사 자동 수정](../remediate/dependency_scanning_auto_remediation.md)

### 비즈니스 로직 프로필 {#business-logic-profile}

{{< details >}}

- 상태:  실험

{{< /details >}}

{{< history >}}

- GitLab 19.5에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257199) [기능 플래그](../../../administration/feature_flags/_index.md) `bl_security_analyzer`. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

비즈니스 로직 프로필은 AI 에이전트를 사용하여 인증 누락, 손상된 객체 수준 액세스 및 대량 할당과 같은 비즈니스 로직 취약성을 찾습니다. 프로필을 프로젝트에 연결하면 해당 프로젝트에 대해 스캔이 활성화됩니다.

머지 리퀘스트의 헤드 파이프라인이 성공하면 스캔은 머지 리퀘스트가 추가하거나 수정하는 파일에서 실행됩니다. 기본 브랜치 파이프라인에서는 실행되지 않습니다. 기본 브랜치를 커버하려면 [GitLab Duo Chat에서 스캔 시작](../business_logic_scanning/_index.md#start-a-scan-from-gitlab-duo-chat)합니다. 프로젝트에 CI/CD 파이프라인이 없으면 머지 리퀘스트 스캔이 실행되지 않습니다.

**플로우 실행 허용**, **기본 플로우 허용** 및 **비즈니스 로직 보안 스캔** 플로우 [최상위 그룹에 대해](../../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off)를 활성화합니다.

필수 구성 요소 및 스캔이 발견하는 것에 대한 자세한 정보는 [비즈니스 로직 스캔](../business_logic_scanning/_index.md)을 참조하세요.

### 프로필 세부 정보 보기 {#view-details-about-a-profile}

시크릿 검색 프로필에 대한 기술 세부 정보를 보려면:

1. 상단 바에서 **Search or go to**를 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **Secure** > **Security inventory**를 선택합니다.
1. **Secret Detection** 프로필을 선택합니다.
1. 다음 정보를 검토합니다.
   - **Analyzer type**: 프로필의 유형(예: **시크릿 검색**, **SAST**, **종속성 검사**).
   - **Scan triggers**: 프로필이 지원하는 트리거(예: **Push Protection**, **Merge Request Pipelines**, **Branch Pipelines**)입니다.
   - **Status**: 커버리지 상태 표시기를 사용하여 현재 컨텍스트에 대해 프로필이 현재 **Active**인지 **Disabled**인지 표시합니다.

## 스캐너 활성화 마법사를 사용하여 스캐너 활성화 {#enable-scanners-with-the-scanner-enablement-wizard}

스캐너 적용 범위가 없는 프로젝트에 프로필을 적용하려면 [스캐너 활성화 마법사](scanner_enablement_wizard.md)를 사용합니다. 마법사는 적용 범위가 없는 프로젝트를 식별하고 그룹 전체에 기본 또는 커스텀 프로필을 적용할 수 있게 합니다.

## GraphQL API를 사용하여 프로필 적용 {#apply-a-profile-with-the-graphql-api}

GraphQL API를 사용하여 UI에서 아직 사용 가능하지 않은 프로필을 포함한 모든 보안 구성 프로필을 적용합니다. [대화형 GraphQL 탐색기](../../../api/graphql/_index.md#interactive-graphql-explorer)를 사용하거나 `/api/graphql` 엔드포인트로 직접 요청을 보낼 수 있습니다.

쿼리 실행, 인증 및 페이지 매김에 대한 자세한 정보는 [GraphQL API 쿼리 및 뮤테이션 실행](../../../api/graphql/getting_started.md)을 참조하세요.

전제 조건:

- 관련 프로젝트 또는 그룹에 대해 최소한 유지 관리자 역할 또는 보안 관리자 역할.

보안 구성 프로필을 적용하려면:

1. 그룹에서 사용 가능한 프로필 및 해당 ID를 가져옵니다:

```graphql
   query {
     group(fullPath: "my-group") {
       availableSecurityScanProfiles {
         id
         name
         scanType
       }
     }
   }
```

   아직 저장되지 않은 기본 프로필은 스캔 유형을 기반으로 가상 ID를 반환합니다. 예: `gid://gitlab/Security::ScanProfile/dependency_scanning_post_processing`.

   자세한 정보는 [`Group.availableSecurityScanProfiles` 필드](../../../api/graphql/reference/_index.md#groupavailablesecurityscanprofiles)를 참조하세요.

1. `securityScanProfileAttach` 뮤테이션을 사용하여 원하는 프로필의 가상 ID 또는 실제 ID를 사용하여 프로필을 적용합니다:

```graphql
   mutation {
     securityScanProfileAttach(input: {
       securityScanProfileId: "gid://gitlab/Security::ScanProfile/dependency_scanning_post_processing",
       projectIds: ["gid://gitlab/Project/123"]
     }) {
       errors
     }
   }
```

   자세한 정보는 [`securityScanProfileAttach` 뮤테이션](../../../api/graphql/reference/_index.md#mutationsecurityscanprofileattach)을 참조하세요.

1. 프로필을 적용할 위치를 선택하려면 다음 인수 중 하나 또는 둘 다를 설정합니다:
   - `projectIds`: 특정 프로젝트에 프로필을 적용합니다.
   - `groupIds`: 하나 이상의 그룹의 모든 프로젝트에 프로필을 적용합니다.

   지정된 모든 프로젝트 및 그룹은 동일한 최상위 그룹에 속해야 합니다. 단일 뮤테이션은 최대 100개의 ID(프로젝트 및 그룹 ID 합계)를 허용합니다.

1. 응답의 `errors` 필드를 확인하여 프로필이 적용되었는지 확인합니다.

## 시크릿 검색 프로필 커스터마이징 {#customize-a-secret-detection-profile}

{{< details >}}

- 상태:  실험

{{< /details >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

시크릿 검색 프로필을 커스터마이징하여 스캐너가 실행될 때 사용하는 구성을 재정의합니다. 각 설정은 기존 [시크릿 검색 CI/CD 변수](../secret_detection/_index.md)로 매핑됩니다.

UI 또는 GraphQL API를 사용하여 시크릿 검색 프로필을 커스터마이징할 수 있습니다.

전제 조건:

- 관련 그룹에 대한 유지 관리자 또는 보안 관리자 역할.

UI에서 시크릿 검색 프로필을 커스터마이징하려면:

1. 상단 바에서 **Search or go to**를 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **보안** > **보안 구성**을 선택합니다.
1. **스캐너** 탭을 선택합니다.
1. **시크릿 검색** 행에서 **프로필 관리**를 선택합니다.
1. **새 프로필 만들기**를 선택합니다.
1. **이름** 및 **설명**을 입력합니다.
1. **스캔 트리거** 아래에서 원하는 트리거를 활성화합니다.
1. 선택사항. **고급 구성** 아래에서 재정의할 설정을 추가합니다.
1. **프로필 만들기**를 선택합니다.

나중에 프로필을 변경하려면 선택한 후 세로 줄임표({{< icon name="ellipsis_v" >}}) > **편집**을 선택한 다음 **변경사항 저장**을 선택합니다. 변경 사항이 프로필을 사용하는 모든 프로젝트에 적용됩니다.

GraphQL API를 사용하여 시크릿 검색 프로필을 커스터마이징하려면 `securityScanProfileCreate` 또는 `securityScanProfileUpdate` 뮤테이션을 사용합니다. 커스터마이징하려는 트리거에서 `configuration.secretDetection` 객체를 설정합니다.

| 필드 | UI 설정 | 설명 | 동등한 CI/CD 변수 |
| ----- | ---------- | ----------- | ------------------------- |
| `secureAnalyzersPrefix` | **분석기 이미지 레지스트리** | 분석기 이미지를 가져올 수 있는 컨테이너 레지스트리의 접두사. | `SECURE_ANALYZERS_PREFIX` |
| `imageSuffix` | **이미지 변형** (기본값, FIPS) | 분석기 이미지 이름에 추가된 접미사. `DEFAULT` 또는 `FIPS`로 설정합니다. | `SECRET_DETECTION_IMAGE_SUFFIX` |
| `historicScan` | **이전 스캔** | 현재 상태만이 아닌 전체 Git 히스토리를 스캔할지 여부. | `SECRET_DETECTION_HISTORIC_SCAN` |
| `logOptions` | **로그 옵션** | `git log`에 전달되는 옵션으로 스캔된 커밋 범위를 제어합니다. | `SECRET_DETECTION_LOG_OPTIONS` |
| `excludedPaths` | **제외할 경로** | 스캔에서 제외된 글로브 경로. | `SECRET_DETECTION_EXCLUDED_PATHS` |
| `rulesetGitReference` | **규칙 집합 Git 참조** | 사용할 원격 규칙 집합 구성의 Git 참조. | `SECRET_DETECTION_RULESET_GIT_REFERENCE` |

예를 들어, 커스터마이징된 머지 리퀘스트 파이프라인 트리거로 시크릿 검색 프로필을 만들려면:

```graphql
mutation {
  securityScanProfileCreate(input: {
    namespaceId: "gid://gitlab/Group/123",
    scanType: SECRET_DETECTION,
    name: "Custom secret detection profile",
    description: "Secret detection profile with a historic scan and path exclusions",
    triggers: [
      {
        triggerType: MERGE_REQUEST_PIPELINE,
        configuration: {
          secretDetection: {
            historicScan: true,
            excludedPaths: ["spec/**/*", "test/**/*"]
          }
        }
      }
    ]
  }) {
    scanProfile {
      id
      name
    }
    errors
  }
}
```

기본적으로 `stripDefaults` 인수는 기본값과 일치하는 트리거 구성 값을 제거한 후 프로필을 저장하므로 재정의만 유지됩니다.

전체 인수 목록은 [`securityScanProfileCreate` 뮤테이션](../../../api/graphql/reference/_index.md#mutationsecurityscanprofilecreate)을 참조하세요.

## SAST 프로필 커스터마이징 {#customize-a-sast-profile}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

SAST 프로필을 커스터마이징하여 프로필이 실행될 때 사용되는 스캐너 구성을 재정의합니다. 각 설정은 기존 [SAST CI/CD 변수](../sast/_index.md)로 매핑됩니다.

이 기능은 [실험](../../../policy/development_stages_support.md) 중입니다. UI 또는 GraphQL API를 사용하여 SAST 프로필을 커스터마이징할 수 있습니다.

전제 조건:

- 관련 그룹에 대한 유지 관리자 또는 보안 관리자 역할.

UI에서 SAST 프로필을 커스터마이징하려면:

1. 상단 바에서 **Search or go to**를 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **보안** > **보안 구성**을 선택합니다.
1. **스캐너** 탭을 선택합니다.
1. **정적 애플리케이션 보안 테스트(SAST)** 행에서 **프로필 관리**를 선택합니다.
1. **새 프로필 만들기**를 선택합니다.
1. **이름** 및 **설명**을 입력합니다.
1. **스캔 트리거** 아래에서 원하는 트리거를 활성화합니다.
1. 선택사항. **고급 구성** 아래에서 재정의할 설정을 추가합니다.
1. **프로필 만들기**를 선택합니다.

나중에 프로필을 변경하려면 선택한 후 세로 줄임표({{< icon name="ellipsis_v" >}}) > **편집**을 선택한 다음 **변경사항 저장**을 선택합니다. 변경 사항이 프로필을 사용하는 모든 프로젝트에 적용됩니다.

GraphQL API를 사용하여 SAST 프로필을 커스터마이징하려면 `securityScanProfileCreate` 또는 `securityScanProfileUpdate` 뮤테이션을 사용합니다. 커스터마이징하려는 트리거에서 `configuration.sast` 객체를 설정합니다.

| 필드 | UI 설정 | 설명 | 동등한 CI/CD 변수 |
| ----- | ---------- | ----------- | ------------------------- |
| `secureAnalyzersPrefix` | **분석기 이미지 레지스트리** | 분석기 이미지를 가져올 수 있는 컨테이너 레지스트리의 접두사. | `SECURE_ANALYZERS_PREFIX` |
| `imageSuffix` | **이미지 변형** (기본값, FIPS) | 분석기 이미지 이름에 추가된 접미사. `DEFAULT` 또는 `FIPS`로 설정합니다. | `SAST_IMAGE_SUFFIX` |
| `analyzerImageTag` | **분석기 이미지 태그** | 사용할 분석기 이미지의 태그. 모든 SAST 분석기에 대해 고정된 이미지 태그를 재정의합니다. 이는 특정 버전이 필요한 경우 분석기 오류를 발생시킬 수 있습니다. | `SAST_ANALYZER_IMAGE_TAG` |
| `excludedAnalyzers` | **건너뛸 분석기** | 스캔에서 제외된 분석기. | `SAST_EXCLUDED_ANALYZERS` |
| `excludedPaths` | **제외할 경로** | 스캔에서 제외된 글로브 경로. | `SAST_EXCLUDED_PATHS` |
| `advancedSastPartialScan` | **Advanced SAST 부분 스캔** (활성화됨, 비활성화됨) | GitLab Advanced SAST에 대한 [diff 기반 스캔](../sast/gitlab_advanced_sast.md)을 제어합니다. `DIFFERENTIAL` 또는 `DISABLED`로 설정합니다. | `ADVANCED_SAST_PARTIAL_SCAN` |
| `gitlabAdvSastIncrScan` | **Advanced SAST 증분 스캔** | [증분 스캔](../sast/gitlab_advanced_sast.md)이 GitLab Advanced SAST에 대해 활성화되는지 여부. | `GITLAB_ADV_SAST_INCR_SCAN` |

예를 들어, 커스터마이징된 머지 리퀘스트 파이프라인 트리거로 SAST 프로필을 만들려면:

```graphql
mutation {
  securityScanProfileCreate(input: {
    namespaceId: "gid://gitlab/Group/123",
    scanType: SAST,
    name: "Custom SAST profile",
    description: "SAST profile with custom analyzer exclusions and Advanced SAST settings",
    triggers: [
      {
        triggerType: MERGE_REQUEST_PIPELINE,
        configuration: {
          sast: {
            excludedAnalyzers: ["eslint"],
            excludedPaths: ["spec/**/*", "test/**/*"],
            advancedSastPartialScan: DIFFERENTIAL,
            gitlabAdvSastIncrScan: true
          }
        }
      }
    ]
  }) {
    scanProfile {
      id
      name
    }
    errors
  }
}
```

트리거당 하나의 구성 멤버만 설정할 수 있으며 프로필의 스캔 유형과 일치해야 합니다. SAST 프로필의 경우 해당 멤버는 `sast`입니다.

기본적으로 `stripDefaults` 인수는 기본값과 일치하는 트리거 구성 값을 제거한 후 프로필을 저장하므로 재정의만 유지됩니다.

전체 인수 목록은 [`securityScanProfileCreate` 뮤테이션](../../../api/graphql/reference/_index.md#mutationsecurityscanprofilecreate)을 참조하세요.

## 종속성 검사 프로필 커스터마이징 {#customize-a-dependency-scanning-profile}

{{< details >}}

- 상태:  실험

{{< /details >}}

종속성 검사 프로필을 커스터마이징하여 스캐너가 실행될 때 사용하는 구성을 재정의합니다. 각 설정은 기존 [종속성 검사 CI/CD 변수](../dependency_scanning/dependency_scanning_sbom/_index.md)로 매핑됩니다.

이 기능은 GraphQL API를 통해서만 사용 가능합니다.

전제 조건:

- 최상위 그룹에 대한 보안 관리자, 유지 관리자 또는 소유자 역할.

종속성 검사 프로필을 커스터마이징하려면:

- `securityScanProfileCreate` 또는 `securityScanProfileUpdate` 뮤테이션에서 커스터마이징하려는 각 트리거에 `configuration.dependencyScanning` 객체를 설정합니다.

`dependencyScanning` 객체는 다음 필드를 지원합니다:

| 필드 | 설명 | 동등한 CI/CD 변수 |
| ----- | ----------- | ------------------------- |
| `secureAnalyzersPrefix` | 분석기 이미지를 가져올 수 있는 컨테이너 레지스트리의 접두사. | `SECURE_ANALYZERS_PREFIX` |
| `additionalCaCertBundle` | 신뢰할 수 있는 CA 인증서 번들입니다. 번들이 시스템의 인증서에 추가되고 스캔 중 다른 도구에서 사용됩니다. | `ADDITIONAL_CA_CERT_BUNDLE` |
| `secureLogLevel` | 분석기에서 사용하는 로깅 수준. `FATAL`, `ERROR`, `WARN`, `INFO` 또는 `DEBUG`로 설정합니다. | `SECURE_LOG_LEVEL` |
| `excludedPaths` | 스캔에서 제외된 글로브 경로. | `DS_EXCLUDED_PATHS` |
| `includeDevDependencies` | 지원되는 파일을 스캔할 때 개발 및 테스트 종속성을 포함할지 여부. | `DS_INCLUDE_DEV_DEPENDENCIES` |
| `maxDepth` | 분석기가 스캔하는 디렉토리 깊이. `-1`의 값은 모든 디렉토리를 스캔합니다. | `DS_MAX_DEPTH` |
| `pipDependencyPath` | 분석을 위해 Python 패키지를 설치하는 데 사용되는 경로. | `DS_PIP_DEPENDENCY_PATH` |
| `staticReachabilityEnabled` | [정적 도달성](../dependency_scanning/static_reachability.md)이 활성화되는지 여부. | `DS_STATIC_REACHABILITY_ENABLED` |
| `enableManifestFallback` | 잠금 파일 또는 종속성 그래프 내보내기를 사용할 수 없을 때 매니페스트 파일을 스캔할지 여부. 자세한 정보는 [매니페스트 폴백](../dependency_scanning/dependency_scanning_sbom/_index.md#manifest-fallback)을 참조하세요. | `DS_ENABLE_MANIFEST_FALLBACK` |
| `pipcompileLockfileFileNamePattern` | 처리할 pip-compile 잠금 파일을 선택하는 글로브 패턴. 패턴은 파일 이름만 일치하고 디렉토리 경로는 일치하지 않습니다. | `DS_PIPCOMPILE_LOCKFILE_FILE_NAME_PATTERN` |
| `pipManifestFileNamePattern` | 종속성 해결 및 매니페스트 스캔을 위해 처리할 pip 매니페스트 파일을 선택하는 글로브 패턴. 패턴은 파일 이름만 일치하고 디렉토리 경로는 일치하지 않습니다. | `DS_PIP_MANIFEST_FILE_NAME_PATTERN` |
| `enableVulnerabilityScan` | 생성된 SBOM의 취약성 분석이 활성화되는지 여부. | `DS_ENABLE_VULNERABILITY_SCAN` |
| `apiTimeout` | 취약성 스캔 API 요청 시간 초과(초 단위, 5~300). | `DS_API_TIMEOUT` |
| `apiScanDownloadDelay` | 스캔 결과를 다운로드하기 전 취약성 스캔 API 초기 지연(초 단위, 1~120). | `DS_API_SCAN_DOWNLOAD_DELAY` |
| `mavenDependencyPluginVersion` | 해결 중에 사용되는 `maven-dependency-plugin`의 버전. | `DS_MAVEN_DEPENDENCY_PLUGIN_VERSION` |
| `mavenArgs` | 종속성 해결 중에 Maven에 전달되는 추가 인수. | `MAVEN_ARGS` |
| `gradleCliOpts` | 종속성 해결 중에 Gradle에 전달되는 추가 명령줄 옵션. | `GRADLE_CLI_OPTS` |
| `disabledResolutionJobs` | 비활성화할 해결 작업 목록. 유효한 값은 `MAVEN`, `GRADLE` 및 `PYTHON`입니다. 기본적으로 사용 가능한 모든 해결 작업이 사용으로 설정됩니다. | `DS_DISABLED_RESOLUTION_JOBS` |
| `mavenResolutionImage` | Maven 종속성 해결 작업에서 사용하는 이미지. | `DS_MAVEN_RESOLUTION_IMAGE` |
| `gradleResolutionImage` | Gradle 종속성 해결 작업에서 사용하는 이미지. | `DS_GRADLE_RESOLUTION_IMAGE` |
| `pythonResolutionImage` | Python 종속성 해결 작업에서 사용하는 이미지. | `DS_PYTHON_RESOLUTION_IMAGE` |
| `pipIndexUrl` | Python Package Index의 기본 URL. | `PIP_INDEX_URL` |
| `pipExtraIndexUrl` | `pipIndexUrl`에 추가로 사용할 Python 패키지 인덱스의 추가 URL. | `PIP_EXTRA_INDEX_URL` |
| `searchIgnoreHiddenDirs` | 분석기가 지원되는 파일을 검색할 때 숨겨진 디렉토리를 무시할지 여부. | `SEARCH_IGNORE_HIDDEN_DIRS` |

예를 들어, 커스터마이징된 머지 리퀘스트 파이프라인 트리거로 종속성 검사 프로필을 만들려면:

```graphql
mutation {
  securityScanProfileCreate(input: {
    namespaceId: "gid://gitlab/Group/123",
    scanType: DEPENDENCY_SCANNING,
    name: "Custom dependency scanning profile",
    description: "Dependency scanning profile that excludes development dependencies and scans all directories",
    triggers: [
      {
        triggerType: MERGE_REQUEST_PIPELINE,
        configuration: {
          dependencyScanning: {
            includeDevDependencies: false,
            excludedPaths: ["spec/**/*", "test/**/*"],
            maxDepth: -1,
            staticReachabilityEnabled: true
          }
        }
      }
    ]
  }) {
    scanProfile {
      id
      name
    }
    errors
  }
}
```

트리거당 하나의 구성 멤버만 설정할 수 있으며 프로필의 스캔 유형과 일치해야 합니다. 종속성 검사 프로필의 경우 해당 멤버는 `dependencyScanning`입니다.

전체 인수 목록은 [`securityScanProfileCreate` 뮤테이션](../../../api/graphql/reference/_index.md#mutationsecurityscanprofilecreate)을 참조하세요.

## 범위 상태 표시기 {#coverage-status-indicators}

시스템은 인벤토리의 시각적 큐를 사용하여 프로젝트가 보호되고 있는지 여부를 표시합니다.

- **Solid green bar**:  스캐너가 완전히 활성화되어 활성 상태입니다.
- **Gray/empty bar**:  스캐너가 아직 구성되거나 활성화되지 않았습니다.
- **Partial bar**:  일부 보호 기능이 활성화되어 있습니다(예: 프로필에서 사용 가능한 일부 트리거는 활성화되어 있지만 다른 트리거는 활성화되지 않음).
- **Tooltips**:  포함된 범위의 마지막 스캔 날짜 및 특정 파이프라인 상태를 확인하려면 범위 표시기 위로 마우스를 올립니다.

파이프라인 기반 스캔과 달리 푸시 보호(push protection)는 푸시 프로세스 중에 실시간으로 실행되므로 최근 스캔 날짜가 없습니다.

## 문제 해결 {#troubleshooting}

보안 구성 프로필 작업 시 다음 이슈를 접할 수 있습니다.

### 푸시 보호에 대한 최근 스캔 날짜가 표시되지 않음 {#no-last-scan-date-appears-for-push-protection}

푸시 보호는 일정 기반이 아닌 이벤트 기반입니다. 이 기능은 `git push` 프로세스 중에 실시간으로 시크릿을 가로챕니다. `push` 명령 시점에 활성화되므로 파이프라인 기반 스캐너에서 예상할 수 있는 것과 같은 최근 스캔 날짜는 없습니다.

### 스캐너 상태가 대시보드에서는 활성이지만 인벤토리 툴팁에서는 활성화되지 않음으로 표시됨 {#scanner-status-is-active-in-the-dashboard-but-not-enabled-in-inventory-tooltip}

프로젝트가 레거시 설정을 사용하면서 동시에 새 프로필이 할당된 경우 이 문제가 발생할 수 있습니다.

이 이슈를 해결하려면:

1. **Security Configuration** 페이지를 확인하여 가장 정확한 현재 프로필 상태를 확인하세요.
1. 필요한 경우, 프로필 기반 구성만 사용하도록 `.gitlab-ci.yml` 파일에서 레거시 스캐너 구성을 제거하세요.

> [!note]
> 인벤토리 툴팁은 레거시 설정과 프로필 기반 설정 모두의 통합된 상태를 반영하도록 개선 중입니다.

### 레거시 및 프로필 기반 구성 비교 이해 {#understanding-legacy-versus-profile-based-configuration}

레거시 스캐너 구성에서 프로필 기반 구성으로 마이그레이션하는 경우 다음 차이점을 참고하세요.

- 레거시 구성:  스캐너를 활성화하려면 YAML 파일 또는 개별 프로젝트 설정을 수동으로 편집해야 합니다.
- 프로필 기반 구성:  중앙 집중식 시스템을 사용하여 코드를 수정하지 않고도 한 번에 여러 프로젝트에 기본 프로필을 적용할 수 있습니다.

프로젝트 전반에 걸친 더 쉬운 관리와 뛰어난 일관성을 위해 프로필 기반 구성을 사용하는 것이 권장됩니다.
