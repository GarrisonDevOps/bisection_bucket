---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 프로젝트 설정
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

## 사전 요구 사항 {#prerequisites}

- 프로젝트에 대한 Maintainer 또는 Owner 역할.

## 프로젝트 기능 및 권한 구성 {#configure-project-features-and-permissions}

프로젝트의 기능 및 권한을 구성하려면 다음을 수행하세요:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한**을 확장합니다.
1. 사용자가 프로젝트에 액세스를 요청할 수 있도록 하려면 **사용자가 액세스를 요청할 수 있음** 확인란을 선택하세요.
1. 프로젝트의 기능을 켜거나 끄려면 기능 토글을 사용하세요.
1. **변경 사항 저장**을 선택합니다.

### 기능 의존성 {#feature-dependencies}

기능을 끄면 다음 추가 기능도 사용할 수 없습니다:

- **작업 항목** 기능을 끄면 프로젝트 사용자는 다음을 사용할 수 없습니다:
  - **이슈 보드**
  - **서비스 데스크**
  - 프로젝트 사용자는 머지 리퀘스트에서 **마일스톤**에 계속 액세스할 수 있습니다.
- **작업 항목**과 **머지 리퀘스트**를 끄면 프로젝트 사용자는 다음을 사용할 수 없습니다:
  - **레이블**
  - **마일스톤**
- **리포지토리**를 끄면 프로젝트 사용자는 다음에 액세스할 수 없습니다:
  - **머지 리퀘스트**
  - **CI/CD**
  - **Git Large File Storage**
  - **패키지**
- 메트릭 대시보드에는 프로젝트 환경 및 배포에 대한 읽기 액세스 권한이 필요합니다. 메트릭 대시보드에 액세스할 수 있는 사용자는 환경 및 배포에도 액세스할 수 있습니다.

## 프로젝트 기능 토글 {#toggle-project-features}

사용 가능한 프로젝트 기능은 프로젝트 멤버에게 표시되고 액세스 가능합니다. 특정 프로젝트 기능을 끌 수 있으므로 역할에 관계없이 프로젝트 멤버에게 표시되지 않고 액세스할 수 없습니다.

프로젝트의 개별 기능 가용성을 토글하려면 다음을 수행하세요:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한**을 확장합니다.
1. 기능의 가용성을 변경하려면 토글을 켜거나 끕니다.
1. **변경 사항 저장**을 선택합니다.

## 프로젝트 분석 끄기 {#turn-off-project-analytics}

> [!note]
> 프로젝트 분석을 끄면 **분석** 탐색 항목만 제거되지만 데이터는 계속 계산되며 각 API 엔드포인트를 통해 사용할 수 있습니다.

기본적으로 프로젝트 분석은 왼쪽 사이드바의 **분석** 항목 아래에 표시됩니다. 이 기능을 끄고 왼쪽 사이드바에서 **분석** 항목을 제거하려면 다음을 수행하세요:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한**을 확장합니다.
1. **분석** 토글을 끕니다.
1. **변경 사항 저장**을 선택합니다.

## 이슈에서 CVE 식별자 요청 끄기 {#turn-off-cve-identifier-request-in-issues}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

이 기능은 GitLab.com의 공개 프로젝트에서만 사용할 수 있습니다.

일부 환경에서는 사용자가 이슈에서 [CVE 식별자 요청](../../application_security/cve_id_request.md)을 제출할 수 있습니다.

프로젝트의 이슈에서 CVE 식별자 요청 옵션을 끄려면 다음을 수행하세요:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한**을 확장합니다.
1. **작업 항목** 아래에서 **이슈 사이드바의 CVE ID 요청** 토글을 끕니다.
1. **변경 사항 저장**을 선택합니다.

## 프로젝트 이메일 알림 끄기 {#turn-off-project-email-notifications}

사전 요구 사항:

- 프로젝트에 대해 Owner 역할이 필요합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한** 섹션을 확장합니다.
1. **이메일 알림 활성화** 확인란을 선택 해제합니다.

### 프로젝트 이메일 알림에서 diff 미리보기 끄기 {#turn-off-diff-previews-in-project-email-notifications}

{{< history >}}

- [GitLab 15.6에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/24733) [기능 플래그](../../../administration/feature_flags/_index.md) 포함(`diff_preview_in_email`). 기본적으로 비활성화되었습니다.
- GitLab 17.1에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/382055)합니다. `diff_preview_in_email` 기능 플래그가 제거되었습니다.

{{< /history >}}

머지 리퀘스트에서 코드를 검토하고 코드 라인에 댓글을 달면 GitLab은 이메일 알림에 diff의 몇 줄을 참여자에게 포함시킵니다. 일부 조직 정책은 이메일을 보안 수준이 낮은 시스템으로 취급하거나 이메일을 위한 자체 인프라를 제어하지 않을 수 있습니다. 이는 소스 코드의 IP 또는 액세스 제어에 위험을 야기할 수 있습니다.

사전 요구 사항:

- 프로젝트에 대해 Owner 역할이 필요합니다.

프로젝트에 대해 diff 미리보기를 끄려면 다음을 수행하세요:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한** 섹션을 확장합니다.
1. **diff 미리보기 포함**을 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

## 프로젝트의 머지 리퀘스트 설정 구성 {#configure-merge-request-settings-for-a-project}

프로젝트의 머지 리퀘스트 설정을 구성합니다:

- [머지 리퀘스트 방법](../merge_requests/methods/_index.md)을 설정합니다(머지 커밋, 빠른 전진 머지).
- 머지 리퀘스트 [설명 템플릿](../description_templates.md)을 추가합니다.
- 다음을 켭니다:
  - [머지 리퀘스트 승인](../merge_requests/approvals/_index.md).
  - [상태 확인](../merge_requests/status_checks.md).
  - [파이프라인이 성공한 경우에만 머지](../merge_requests/auto_merge.md).
  - [모든 스레드가 해결된 경우에만 머지](../merge_requests/_index.md#prevent-merge-unless-all-threads-are-resolved).
  - [Jira의 필수 관련 이슈](../../../integration/jira/issues.md#require-associated-jira-issue-for-merge-requests-to-be-merged).
  - [머지 리퀘스트 제목 유효성 검사](../merge_requests/title_validation.md).
  - 반선형 및 빠른 전진 머지 방법에 대한 [머지 전 자동 재베이스](../merge_requests/methods/_index.md#automatic-rebase-before-merge).
  - [**머지 리퀘스트가 수락될 때 소스 브랜치 삭제** 옵션(기본적으로)](#delete-the-source-branch-on-merge-by-default).
- 다음을 구성합니다:
  - [제안된 변경 사항 커밋 메시지](../merge_requests/reviews/suggestions.md#configure-the-commit-message-for-applied-suggestions).
  - [머지 및 스쿼시 커밋 메시지 템플릿](../merge_requests/commit_templates.md).
  - [머지 리퀘스트 제목 템플릿](../merge_requests/title_templates.md).
  - 포크에서 제출된 머지 리퀘스트에 대한 [기본 대상 프로젝트](../merge_requests/creating_merge_requests.md#set-the-default-target-project).

### 머지 시 기본적으로 소스 브랜치 삭제 {#delete-the-source-branch-on-merge-by-default}

머지 리퀘스트에서 **소스 브랜치 삭제** 확인란이 항상 선택되도록 기본 동작을 변경할 수 있습니다.

이 기본값을 설정하려면 다음을 수행하세요:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **병합 요청**을 선택합니다.
1. **"소스 브랜치 삭제"를 기본 옵션으로 활성화**를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

이 설정은 이 프로젝트의 소스 브랜치가 있는 머지 리퀘스트에 적용됩니다. 포크에서 제출된 머지 리퀘스트의 경우 기본값은 이 프로젝트의 설정이 아니라 포크의 설정에서 가져옵니다. 포크는 생성될 때 이 설정을 상속하지 않습니다.

## 프로젝트 액세스 토큰 만료에 대한 추가 웹후크 트리거 추가 {#add-additional-webhook-triggers-for-project-access-token-expiration}

{{< history >}}

- GitLab 17.9에서 프로젝트 및 그룹 액세스 토큰 웹후크에 60일 및 30일 트리거를 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/499732)했습니다. [기능 플래그](../../../administration/feature_flags/_index.md) 포함(`extended_expiry_webhook_execution_setting`). 기본적으로 비활성화되었습니다.
- GitLab 17.10에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/513684)합니다. `extended_expiry_webhook_execution_setting` 기능 플래그가 제거되었습니다.

{{< /history >}}

GitLab은 프로젝트 토큰이 만료되기 전에 여러 [만료 이메일](project_access_tokens.md#project-access-token-expiry-emails)을 보내고 관련 [웹후크](../integrations/webhook_events.md#project-and-group-access-token-events)를 트리거합니다. 기본적으로 이 웹후크는 토큰이 만료되기 7일 전에 트리거됩니다.

이 웹후크를 토큰이 만료되기 60일 및 30일 전에 트리거하도록 구성하려면 다음을 수행하세요:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한** 섹션을 확장합니다.
1. **프로젝트 액세스 토큰 만료에 대한 추가 웹후크 트리거 추가** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 프로젝트에 대해 CI/CD 끄기 {#turn-off-cicd-for-a-project}

프로젝트에서 CI/CD를 사용하지 않으면 이를 끌 수 있습니다. 이렇게 하면 머지 리퀘스트에서 CI/CD 배너가 제거됩니다.

CI/CD를 끄려면 다음을 수행하세요:

1. 왼쪽 사이드바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한**을 확장합니다.
1. **CI/CD** 토글을 끕니다.
1. **변경 사항 저장**을 선택합니다.
