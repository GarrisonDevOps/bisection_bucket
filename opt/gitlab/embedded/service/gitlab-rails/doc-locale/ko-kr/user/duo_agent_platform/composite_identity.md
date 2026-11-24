---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 복합 ID가 서비스 계정과 사용자를 하나의 토큰으로 결합하여 에이전트 작업의 보안과 추적성을 보장하는 방식을 알아봅니다.
title: 복합 ID
---

{{< history >}}

- [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/554156)됨: GitLab 18.3 [기능 플래그](../../administration/feature_flags/_index.md) `duo_workflow_use_composite_identity`를 사용하며, 기본값으로 비활성화되어 있습니다.
- GitLab 18.6에서 [기본값으로 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/212618)됨.
- GitLab 18.8에서 [정식 출시(GA)](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273)되었습니다.
- 복합 ID가 GitLab Duo Agent Platform에 자동으로 포함되고, 복합 ID를 켜거나 끄는 설정이 GitLab 18.9에서 [제거](https://gitlab.com/gitlab-org/gitlab/-/work_items/588629)되었습니다.
- 기능 플래그 `duo_workflow_use_composite_identity`이 GitLab 19.3에서 [제거](https://gitlab.com/gitlab-org/gitlab/-/issues/554199)되었습니다.

{{< /history >}}

복합 ID는 두 개의 ID를 하나의 토큰으로 결합하는 인증 및 권한 부여 메커니즘입니다:

- 서비스 계정: 실제 작업을 수행하는 에이전트입니다.
- 사용자: 요청을 시작한 사람입니다.

모든 서비스 계정은 사람이 시작한 모든 작업이 있으므로 복합 ID를 가집니다.

복합 ID는 GitLab Duo Agent Platform에 자동으로 포함됩니다.

이 이중 ID 접근 방식은 중요한 문제를 해결합니다. 에이전트는 이를 트리거한 사용자의 액세스 권한 이하이거나 서비스 계정에 부여된 액세스 권한 이하인 액세스 권한으로 작동해야 하며, 동시에 작업이 사람이 직접 수행한 것이 아니라 에이전트가 수행한 것임을 명확히 보여주는 고유한 ID를 유지해야 합니다.

## 복합 ID가 중요한 이유 {#why-composite-identity-matters}

복합 ID가 중요한 이유는 다음을 보장하기 때문입니다:

- 추적성: 모든 에이전트 활동이 서비스 계정에 명확히 귀속되므로 감사 로그 및 커밋 기록에서 자동화된 작업을 쉽게 식별할 수 있습니다.
- 보안: 에이전트는 서비스 계정과 트리거 사용자만 액세스할 수 있는 작업을 수행할 수 있습니다. 이 교차적 액세스는 권한 상향을 방지합니다.
- 책임 추적: 사용자의 ID가 토큰에 포함되어 있으므로 에이전트 작업을 이를 시작한 사람에게 다시 연결하는 감사 기록이 생성됩니다.

예를 들어, 에이전트에 코드에 대한 테스트를 만들도록 요청하면 결과 커밋은 서비스 계정에서 사용자를 대신하여 생성되었음을 보여줍니다.

## 복합 ID가 사용되는 위치 {#where-composite-identity-is-used}

복합 ID는 플로우와 에이전트가 러너에서 실행될 때 사용됩니다. 다음 목록에는 다음이 포함됩니다:

- 기본 플로우
- 사용자 지정 플로우
- 외부 에이전트
- 엔드포인트 `api/v4/ai/duo_workflows/workflows`을(를) 통해 시작된 모든 플로우

복합 ID는 UI 및 IDE의 GitLab Duo Agentic Chat에 적용되지 않습니다.

## 복합 ID의 작동 방식 {#how-composite-identity-works}

요청을 인증하는 토큰은 두 개의 ID로 이루어진 복합입니다:

- 기본 작성자: 에이전트 또는 플로우를 시작한 사용자입니다. 사용자의 `id`은(는) [동적 범위](https://github.com/doorkeeper-gem/doorkeeper/pull/1739)를 사용하여 토큰의 범위에 포함됩니다.
- 보조 작성자: [서비스 계정](../profile/service_accounts.md)으로, 토큰의 소유자이며 개발자 역할을 가집니다.

이 복합 ID는 GitLab Duo Agent Platform에서 생성한 모든 활동이 사용자에게 귀속되도록 하면서 사용자 또는 서비스 계정에 의한 [권한 상향](https://en.wikipedia.org/wiki/Privilege_escalation)을 방지합니다.

## 복합 ID 워크플로우 {#composite-identity-workflow}

복합 ID는 워크플로우의 일부입니다.

1. AI 카탈로그에서 플로우를 만듭니다.
   - 복합 ID 관련 변경 사항이 없습니다.
1. 프로젝트에 대한 플로우를 활성화합니다.
   - 최상위 그룹에 서비스 계정이 생성됩니다. (이름은 `ai-flowname-groupname`과(와) 유사합니다.)
   - 서비스 계정이 개발자 역할로 프로젝트에 추가됩니다.
1. 사용자가 플로우를 실행합니다.
   - 플로우는 일회용 복합 ID로 실행됩니다. 이 ID는 사용자의 역할과 서비스 계정의 개발자 역할의 조합을 가지며, 더 제한적인 것이 사용됩니다. 따라서 사용자가 유지보수자이지만 서비스 계정이 개발자인 경우, 개발자 역할이 사용됩니다.
   - 플로우는 다음 두 프로젝트에 모두 액세스할 수 있습니다:
     - 사용자가 액세스할 수 있는 프로젝트
     - 서비스 계정이 추가된 프로젝트

     예를 들어, 서비스 계정이 다른 프로젝트에 추가되었고 사용자가 해당 프로젝트에 액세스할 수 있다면, 사용자가 해당 프로젝트에서 플로우를 이전에 사용하지 않았더라도 플로우가 해당 프로젝트에 액세스할 수 있습니다.

## AI 카탈로그 플로우의 토큰 권한 {#token-permissions-for-ai-catalog-flows}

AI 카탈로그 플로우는 다양한 권한 범위를 가진 다양한 토큰 유형을 사용합니다:

- AI 워크플로우에서 복합 ID에 사용되는 OAuth 토큰은 `ai_workflows` 및 `mcp` 범위로 액세스가 제한됩니다. 이 OAuth 토큰이 AI Gateway에 전달되어 플로우를 실행합니다.
- 플로우의 일부로 트리거되는 CI 작업 토큰은 [사용 가능한 작업 토큰 권한](../../ci/jobs/ci_job_token.md#job-token-access)으로 권한이 추가로 제한됩니다.

이들은 다양한 범위를 가진 다양한 토큰 유형이므로 CI/CD 작업은 OAuth 토큰과 다른 권한을 가집니다.

## 머지 리퀘스트에 대한 규정 준수 고려 사항 {#compliance-considerations-for-merge-requests}

플로우가 머지 리퀘스트를 생성하면, 머지 리퀘스트는 서비스 계정 대신 플로우를 트리거한 사용자에게 귀속됩니다. 이는 다음을 포함하는 업무 분리를 요구하는 규정 준수 프레임워크를 준수하기 위해 수행됩니다:

- SOC 2(System and Organization Controls 2)
- SOX(Sarbanes-Oxley Act)
- ISO 27001(정보 보안 관리)
- FedRAMP(Federal Risk and Authorization Management Program)

이러한 프레임워크는 일반적으로 사용자가 코드 변경을 작성하고 프로덕션 배포를 위해 해당 변경을 승인할 수 없도록 요구합니다.

### 속성 모델 이해 {#understanding-the-attribution-model}

서비스 계정이 커밋을 생성하고 머지 리퀘스트를 열더라도, 사용자는 다음 이유로 작성자로 간주됩니다:

- 사용자가 서비스 계정에 변경을 만들도록 지시했습니다.
- 규정 준수 관점에서, AI 시스템에 코드를 작성하도록 지시하는 것은 코드를 직접 작성하는 것과 동일합니다.
- 서비스 계정은 사용자의 의도를 대리하는 역할을 합니다.
