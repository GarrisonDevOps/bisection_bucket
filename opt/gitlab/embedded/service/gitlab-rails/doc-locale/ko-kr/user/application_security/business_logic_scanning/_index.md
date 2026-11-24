---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 비즈니스 로직 스캔은 AI 에이전트를 사용하여 소스 코드에서 권한 부여 및 접근 제어 취약성을 찾습니다.
title: 비즈니스 로직 스캔
---

{{< details >}}

- 티어:  Ultimate
- 제공 서비스:  GitLab.com, GitLab Self-Managed
- 상태:  베타

{{< /details >}}

{{< history >}}

- [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/257199) GitLab 19.5에서 [기능 플래그](../../../administration/feature_flags/_index.md)와 함께 `bl_security_analyzer`(`experiment` 타입) 및 `agentic_analyzer_security_ingestion`(`gitlab_com_derisk` 타입)이라는 이름으로. 기본적으로 비활성화되었습니다.
- GitLab Duo Chat에서 스캔을 시작하려면 [기능 플래그](../../../administration/feature_flags/_index.md)라는 `duo_chat_flow_commands`(`wip` 타입)도 필요합니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

비즈니스 로직 스캔은 AI 에이전트인 비즈니스 로직 보안 분석기(BLSA)를 사용하여 애플리케이션이 자신의 규칙을 어떻게 적용하는지에서 취약성을 찾습니다. [SAST](../sast/_index.md)와 같은 패턴 기반 분석기는 이러한 취약성을 놓치는 경우가 많습니다. 코드가 유효하지만 의도가 잘못되었기 때문입니다.

## 비즈니스 로직 스캔이 찾는 것 {#what-business-logic-scanning-finds}

비즈니스 로직 스캔은 다음과 같은 취약성을 찾습니다:

- 손상된 객체 수준 권한 부여(BOLA), 또는 안전하지 않은 직접 객체 참조(IDOR)라고도 합니다. 예를 들어, 엔드포인트가 URL의 ID로 청구서를 로드하지만 청구서가 인증된 사용자에게 속하는지 확인하지 않습니다.
- 누락된 권한 부여. 예를 들어, 관리 작업은 사용자가 인증되었는지 확인하지만 사용자가 관리자인지 확인하지 않습니다.
- 대량 할당. 예를 들어, 업데이트 엔드포인트가 모든 요청 매개변수를 모델로 전달하므로 사용자가 자신의 `role` 또는 `is_admin` 속성을 변경할 수 있습니다.

## 비즈니스 로직 스캔이 작동하는 방식 {#how-business-logic-scanning-works}

비즈니스 로직 스캔은 CI/CD 파이프라인의 작업이 아니라 [GitLab Duo Agent Platform](../../duo_agent_platform/_index.md) 기본 플로우로 실행됩니다. `.gitlab-ci.yml` 파일에 템플릿이나 작업을 추가하지 않습니다.

스캔은 다음 중 한 가지 방식으로 시작됩니다:

| 스캔이 시작되는 방식 | 스캔할 대상 | 켜는 방법 |
|---------------------|---------------|-------------------|
| [머지 리퀘스트에서 자동으로](#automatic-merge-request-scans) | 머지 리퀘스트가 추가하거나 수정하는 파일. 부분 스캔. | 비즈니스 로직 스캔 프로필을 프로젝트에 첨부합니다. |
| [GitLab Duo Chat에서](#start-a-scan-from-gitlab-duo-chat) | 기본 브랜치의 전체 리포지토리. 전체 리포지토리를 스캔하는 권장 방법. | GitLab Duo Chat에서 플로우 명령을 보냅니다. |
| [API 사용](#start-a-scan-with-the-api) | 기본 브랜치의 전체 리포지토리. | API 요청을 보냅니다. |
| [일정에 따라](#scheduled-default-branch-scans) | 아직 사용할 수 없습니다. | 아직 사용할 수 없습니다. |

## 비즈니스 로직 스캔 켜기 {#turn-on-business-logic-scanning}

비즈니스 로직 스캔은 비공개 베타 단계에 있습니다. GitLab.com에서는 GitLab이 참여하는 최상위 그룹의 기능 플래그를 활성화합니다. 액세스를 요청하려면 계정 담당자에게 문의하세요.

전제 조건:

- GitLab Ultimate 구독.
- 최상위 그룹에 대해 [GitLab Duo Agent Platform이 켜져 있음](../../duo_agent_platform/turn_on_off.md).
- `bl_security_analyzer` 및 `agentic_analyzer_security_ingestion` 기능 플래그가 최상위 그룹에 대해 활성화되었습니다. `agentic_analyzer_security_ingestion`이 없으면 스캔 결과가 취약성 보고서에 나타나지 않습니다. GitLab Self-Managed에서는 관리자가 이 기능 플래그를 활성화해야 합니다.

비즈니스 로직 스캔을 켜려면:

1. 최상위 그룹의 소유자 역할을 가진 사용자로서 **비즈니스 로직 보안 스캔** 플로우를 포함하여 [기본 플로우를 켭니다](../../duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off).
1. [비즈니스 로직 스캔 프로필을 첨부](../configuration/security_configuration_profiles.md#business-logic-profile)하여 스캔할 각 프로젝트에 첨부합니다. 스캔 프로필 UI를 사용할 수 있을 때까지 [GraphQL API로 프로필을 첨부](../configuration/security_configuration_profiles.md#apply-a-profile-with-the-graphql-api)하세요.

## 자동 머지 리퀘스트 스캔 {#automatic-merge-request-scans}

프로젝트에 비즈니스 로직 스캔 프로필이 첨부되어 있으면 각 머지 리퀘스트에서 스캔이 실행됩니다:

- 스캔은 머지 리퀘스트의 헤드 파이프라인(머지 리퀘스트 파이프라인 또는 열린 머지 리퀘스트의 브랜치 파이프라인)에서 실행됩니다.
- 스캔은 파이프라인이 성공한 후에 시작됩니다. 파이프라인이 실패하거나 프로젝트에 CI/CD 파이프라인이 없으면 스캔이 실행되지 않습니다.
- 스캔은 머지 리퀘스트가 추가하거나 수정하는 파일만 확인합니다.
- 파이프라인을 실행한 사용자는 개발자 역할 이상과 GitLab Duo Agent Platform에 대한 액세스 권한이 있는 실제 사용자여야 합니다.

이러한 머지 리퀘스트는 스캔되지 않습니다:

- 포크에서 가져온 머지 리퀘스트.
- 파일만 삭제하는 머지 리퀘스트.
- 프로젝트 액세스 토큰 또는 서비스 계정과 같은 봇이 실행한 머지 리퀘스트 파이프라인.
- 머지 트레인 파이프라인과 더 최신 커밋이 교체한 머지 리퀘스트 파이프라인.

머지 리퀘스트 스캔은 변경된 파일만 확인하므로 GitLab Advanced SAST [diff 기반 스캔](../sast/gitlab_advanced_sast.md#diff-based-scanning)과 같은 부분 스캔입니다. 스캔하지 않은 파일의 취약성은 해결된 것으로 보고되지 않습니다.

## 예약된 기본 브랜치 스캔 {#scheduled-default-branch-scans}

예약된 스캔은 아직 사용할 수 없습니다. 자동 스캔은 기본 브랜치에서 실행되지 않습니다. 기본 브랜치를 스캔하려면 [GitLab Duo Chat에서 스캔을 시작](#start-a-scan-from-gitlab-duo-chat)하거나 [API를 사용](#start-a-scan-with-the-api)하세요.

## GitLab Duo Chat에서 스캔 시작 {#start-a-scan-from-gitlab-duo-chat}

전체 리포지토리를 스캔하려면 GitLab Duo Chat에서 스캔을 시작하세요. 스캔은 기본 브랜치를 확인하고 따라갈 수 있는 GitLab Duo Agent Platform 세션으로 실행됩니다. 결과는 [취약성 보고서](../vulnerability_report/_index.md)에 나타납니다.

전제 조건:

- 프로젝트에 대해 개발자 역할 이상이 필요합니다.
- [GitLab Duo Agent Platform 필수 조건](../../duo_agent_platform/_index.md#prerequisites)을 충족해야 합니다.
- `bl_security_analyzer`, `agentic_analyzer_security_ingestion`, 및 `duo_chat_flow_commands` 기능 플래그를 활성화해야 하며 **비즈니스 로직 보안 스캔** 플로우를 켜야 합니다. 프로젝트는 비즈니스 로직 스캔 프로필이 필요하지 않습니다.

스캔을 시작하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. [GitLab Duo Chat](../../gitlab_duo_chat/agentic_chat.md#use-gitlab-duo-chat-in-the-gitlab-ui)을 열고 **에이전트 모드** 토글이 켜져 있는지 확인하세요.
1. 채팅 텍스트 상자에 `/flow:`을 입력하고 **비즈니스 로직 보안 스캔**을 선택하세요.
1. 다른 텍스트 없이 명령을 보냅니다.
1. 에이전트 세션에서 스캔을 따릅니다. 세션이 완료되면 결과가 취약성 보고서에 나타납니다.

스캔의 CI/CD 작업은 플로우의 서비스 계정으로 실행됩니다.

> [!warning]
> 명령 뒤에 머지 리퀘스트 번호 또는 다른 텍스트를 추가하지 마세요. GitLab Duo Chat의 스캔은 항상 기본 브랜치에서 실행되므로 머지 리퀘스트의 변경 사항이 아니라 전체 리포지토리를 스캔합니다.

## API로 스캔 시작 {#start-a-scan-with-the-api}

[GitLab Duo Agent Platform flows API](../../../api/duo_agent_platform_flows.md#trigger-a-flow)로 기본 브랜치의 전체 스캔을 시작할 수 있습니다. 스캔은 당신을 대신하여 당신의 권한 및 GitLab Duo Agent Platform 액세스로 실행되며 전체 리포지토리를 확인합니다. 결과는 취약성 보고서에 나타납니다.

전제 조건:

- 프로젝트에 대해 개발자 역할 이상이 필요합니다.
- `api` 범위를 가진 개인 액세스 토큰이 필요합니다.
- `bl_security_analyzer` 및 `agentic_analyzer_security_ingestion` 기능 플래그를 활성화해야 하며 **비즈니스 로직 보안 스캔** 플로우를 켜야 합니다. 프로젝트는 비즈니스 로직 스캔 프로필이 필요하지 않습니다.

스캔을 시작하려면 요청을 보냅니다:

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_access_token>" \
  --data "project_id=<project_id>" \
  --data "workflow_definition=bl_security/experimental" \
  --data "start_workflow=true" \
  --url "https://gitlab.example.com/api/v4/ai/duo_workflows/workflows"
```

`workflow_definition` 대신 프로젝트의 **비즈니스 로직 보안 스캔** 플로우 소비자 ID를 포함하는 `ai_catalog_item_consumer_id`를 전달할 수 있습니다. ID를 얻으려면 GraphQL `aiCatalogConfiguredItems` 쿼리를 사용하세요. [소비자 ID 조회](../../../api/duo_agent_platform_flows.md#look-up-the-consumer-id)에 설명되어 있습니다.

머지 리퀘스트가 변경하는 파일만 스캔하려면 머지 리퀘스트 IID를 `goal`로 전달하고 머지 리퀘스트의 소스 브랜치를 `source_branch`로 전달합니다. 머지 리퀘스트는 포크에서 가져오지 않아야 합니다. 기본 브랜치 이외의 다른 브랜치에서 [`BL_TARGET_FILES`](#configure-a-scan) CI/CD 변수를 설정하면 머지 리퀘스트의 변경된 파일을 바꿉니다. 그렇지 않으면 스캔은 전체 리포지토리를 확인합니다.

## 결과 보기 {#view-results}

비즈니스 로직 스캔은 다른 보안 스캐너와 같은 위치에서 취약성을 보고합니다:

- [머지 리퀘스트 보안 위젯](../detect/security_scanning_results.md#merge-request-reports)에서 머지 리퀘스트 스캔의 경우.
- 기본 브랜치 스캔의 경우 취약성 보고서에서.

## 스캔 구성 {#configure-a-scan}

비즈니스 로직 스캔 실행 방식을 변경하려면 [프로젝트 CI/CD 변수](../../../ci/variables/_index.md#for-a-project)를 추가하세요. 환경 범위를 **모두 (기본값)**으로 설정하세요. 다른 범위의 변수는 무시됩니다.

보호된 변수와 파일 형식 변수는 무시됩니다. `*` 환경 범위를 가진 일반적인 보호되지 않은 변수로 정의합니다.

| CI/CD 변수    | 설명 |
|-------------------|-------------|
| `BL_SCAN_EFFORT`  | 스캔의 노력 수준: `low`, `standard` 또는 `high`. 설정하지 않거나 비어 있거나 다른 값이면 수준은 `low`입니다. 더 높은 수준은 더 깊이 있게 스캔하고 더 많은 GitLab Duo Agent Platform 사용량을 사용합니다. |
| `BL_TARGET_FILES` | 스캔할 파일 경로의 줄 바꿈 또는 쉼표로 구분된 목록. 기본 브랜치 이외의 다른 브랜치의 스캔에 적용되며 머지 리퀘스트가 변경하는 파일을 바꿉니다. 기본 브랜치에서는 무시되므로 기본 브랜치의 스캔은 전체 리포지토리를 확인합니다. |

스캔은 시작할 때 프로젝트의 CI/CD 설정에서 이 변수를 읽습니다. `.gitlab-ci.yml`에 설정되거나 파이프라인을 실행할 때 설정된 변수는 적용되지 않습니다.

## 알려진 이슈 {#known-issues}

비즈니스 로직 스캔에는 다음과 같은 알려진 문제가 있습니다:

- 머지 리퀘스트가 400개 이상의 파일을 변경하거나 diff가 너무 커서 수집할 수 없으면 스캔이 변경된 파일로 제한되지 않습니다. 대신 리포지토리의 전체 스캔을 실행하며 결과는 부분 스캔이 아닙니다.
- 스캔은 고정된 양의 코드를 분석합니다. 이 제한에 도달하는 스캔도 전체 스캔으로 계산됩니다. 스캔이 건너뛴 코드의 취약성은 더 이상 감지되지 않는 것으로 표시될 수 있으며 나중의 스캔에서 다시 나타날 수 있습니다.
- 스캔은 필수 조건의 기능 플래그가 활성화될 때만 실행됩니다. 자동 스캔은 [자동 머지 리퀘스트 스캔](#automatic-merge-request-scans)에 설명된 사용자에 대해서만 실행됩니다.
- 예약된 스캔은 아직 사용할 수 없습니다. 자세한 내용은 [예약된 기본 브랜치 스캔](#scheduled-default-branch-scans)을 참조하세요.
- GitLab Duo Chat의 스캔은 항상 기본 브랜치에서 실행됩니다. 플로우 명령 뒤에 머지 리퀘스트 번호 또는 다른 텍스트를 추가하면 스캔은 여전히 전체 리포지토리를 확인합니다. 머지 리퀘스트의 변경 사항을 확인하지 않습니다. 다른 텍스트 없이 명령을 보냅니다. 머지 리퀘스트의 변경 사항을 스캔하려면 [API를 사용](#start-a-scan-with-the-api)하세요.

## 비용 {#cost}

각 스캔은 GitLab Duo Agent Platform 세션이며 [GitLab Credits](../../../subscriptions/gitlab_credits.md)를 소비합니다. 큰 머지 리퀘스트 또는 전체 리포지토리의 스캔은 작은 변경의 스캔보다 더 많이 사용합니다.
