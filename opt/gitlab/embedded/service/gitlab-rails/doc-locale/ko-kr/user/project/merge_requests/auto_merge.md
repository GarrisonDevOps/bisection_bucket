---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 병합 리퀘스트의 콘텐츠를 검토한 후 자동 병합으로 설정하면 모든 머지 점검이 통과할 때 개입 없이 병합할 수 있습니다.
title: 자동 병합
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 향상된 자동 병합:
  - GitLab 16.5에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/10874)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `merge_when_checks_pass` 및 `additional_merge_when_checks_ready`와 함께 제공됩니다. 기본적으로 비활성화되었습니다.
  - GitLab 17.1에서 [병합](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/154366)된 플래그 `additional_merge_when_checks_ready`와 플래그 `merge_when_checks_pass`입니다.
  - GitLab 17.7에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/412995)됩니다. `merge_when_checks_pass` 기능 플래그가 제거되었습니다.
- 머지 트레인을 위한 자동 병합:
  - `merge_when_checks_pass_merge_train`라는 이름의 [기능 플래그](../../../administration/feature_flags/_index.md)와 함께 GitLab 17.2에 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/10874)되었습니다. 기본적으로 비활성화되었습니다.
  - GitLab 17.7에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/174357)됩니다. `merge_when_checks_pass_merge_train` 기능 플래그가 제거되었습니다.

{{< /history >}}

병합 리퀘스트의 콘텐츠가 병합할 준비가 되면 **자동 병합으로 설정**을 선택할 수 있습니다. 모든 필수 점검이 완료되면 병합 리퀘스트가 자동으로 병합되므로 병합 리퀘스트를 수동으로 병합하는 것을 잊을 필요가 없습니다.

머지 점검을 통해 병합 리퀘스트의 내용을 검토하는 데 집중하고 프로젝트 설정을 사용하여 병합 가능성을 결정할 수 있습니다. 병합 리퀘스트를 검토할 때 병합 리퀘스트의 변경 사항을 승인하면 자동 병합으로 설정하세요. GitLab은 프로젝트 설정을 적용하며, 병합 리퀘스트가 필수 코드 소유자 및 승인 규칙과 같은 모든 머지 점검을 만족할 때까지 병합할 수 없습니다. 모든 필수 머지 점검을 만족한 후 병합 리퀘스트가 병합되며 사용자의 조치가 필요 없습니다.

머지 점검에는 성공한 CI/CD 파이프라인 등이 포함됩니다:

- 필수 승인이 모두 제공되어야 합니다.
- 다른 병합 리퀘스트가 이 병합 리퀘스트를 차단하지 않습니다.
- 병합 충돌이 없어야 합니다.
- CI/CD 파이프라인은 [프로젝트 설정](#require-a-successful-pipeline-for-merge)에 관계없이 성공적으로 완료되어야 합니다.
- 모든 토의가 해결되었습니다.
- 병합 리퀘스트는 **초안**이 아닙니다.
- 모든 외부 상태 점검이 통과했습니다.
- 병합 리퀘스트는 열려 있어야 합니다.
- 거부된 정책이 없습니다.
- [스캔 실행 정책](../../application_security/policies/scan_execution_policies.md) 또는 [파이프라인 실행 정책](../../application_security/policies/pipeline_execution_policies.md)이 구성되어 있을 때 최신 커밋의 모든 파이프라인이 병합 리퀘스트가 병합되기 전에 성공해야 합니다.
- 프로젝트가 [병합 리퀘스트가 Jira 이슈를 참조하도록 요구](../../../integration/jira/issues.md#require-associated-jira-issue-for-merge-requests-to-be-merged)하면 병합 리퀘스트 제목 또는 설명에 Jira 이슈 링크가 포함되어 있습니다.
- [제목 검증 패턴](title_validation.md)이 구성되어 있으면 병합 리퀘스트 제목이 패턴과 일치해야 합니다.
- 병합 리퀘스트에 **머지 후** 날짜가 설정되어 있으면 현재 시간이 구성된 날짜보다 이후여야 합니다.

전체 점검 목록 및 API 동등값은 [병합 상태](../../../api/merge_requests.md#merge-status)를 참조하세요.

![자동 병합 준비 완료](img/auto_merge_ready_v16_0.png)

자동 병합을 설정한 후에는 병합 리퀘스트가 병합될 때 어떤 이슈가 [자동 종료](../issues/managing_issues.md#closing-issues-automatically)되는지 변경할 수 없습니다.

## 병합 리퀘스트 자동 병합 {#auto-merge-a-merge-request}

사전 요구 사항:

- 프로젝트에 대해 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 프로젝트 구성이 필요한 경우 병합 리퀘스트의 모든 스레드를 해결해야 합니다.
- 병합 리퀘스트는 필수 승인을 모두 받아야 합니다.

명령줄에서 푸시할 때 이를 수행하려면 `merge_request.merge_when_pipeline_succeeds` [푸시 옵션](../../../topics/git/commit.md#push-options)을 사용하세요.

GitLab 사용자 인터페이스에서 이를 수행하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**을 선택합니다.
1. 편집할 병합 리퀘스트를 선택합니다.
1. 병합 리퀘스트 보고서 섹션으로 스크롤합니다.
1. 선택 사항. **소스 브랜치 삭제**, **Squash commits** 또는 **커밋 메시지 수정**과 같은 원하는 병합 옵션을 선택합니다.
1. 병합 리퀘스트 보고서 섹션의 내용을 검토합니다. [이슈 종료 패턴](../issues/managing_issues.md#closing-issues-automatically)이 포함되어 있으면 병합 리퀘스트가 병합될 때 이슈가 종료되어야 하는지 확인하세요:

   ![이 병합 리퀘스트는 이슈 #2754를 종료합니다.](img/closing_pattern_v18_5.png)

1. **자동 병합으로 설정**을 선택합니다.

자동 병합을 설정한 후 파이프라인이 완료되기 전에 병합 리퀘스트에 대해 댓글을 달면 모든 기존 스레드를 해결할 때까지 병합이 차단됩니다.

## 자동 머지 취소 {#cancel-an-auto-merge}

병합 리퀘스트의 자동 병합을 취소할 수 있습니다.

사전 요구 사항:

- 병합 리퀘스트의 작성자이거나 개발자, 관리자 또는 소유자 역할을 가진 프로젝트 멤버여야 합니다.
- 병합 리퀘스트의 파이프라인은 여전히 진행 중이어야 합니다.

다음과 같이 설정합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**을 선택합니다.
1. 원하는 병합 리퀘스트를 선택합니다.
1. 병합 리퀘스트 보고서 섹션으로 스크롤합니다.
1. **자동 머지 취소**를 선택합니다.

![파이프라인이 성공하면 병합 취소 옵션](img/cancel-mwps_v15_4.png)

## 자동 병합의 파이프라인 성공 {#pipeline-success-for-auto-merge}

{{< history >}}

- 대상 브랜치가 업데이트되고 자동 리베이스가 활성화되었을 때 자동 병합 유지 [GitLab 19.3에서 도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248017) [기능 플래그](../../../administration/feature_flags/_index.md) `retain_auto_merge_with_automatic_rebase` 포함. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

파이프라인이 성공하면 병합 리퀘스트가 병합됩니다. 파이프라인이 실패하면 작성자는 실패한 작업을 다시 시도하거나 새 커밋을 푸시하여 실패를 수정할 수 있습니다:

- 다시 시도한 작업이 두 번째 시도에서 성공하면 병합 리퀘스트가 병합됩니다.
- 병합 리퀘스트에 새 커밋을 추가하면 GitLab은 새 변경 사항이 병합 전에 검토를 받도록 요청을 취소합니다.
- 대상 브랜치에 새 커밋을 추가하고 프로젝트가 **준선형 이력으로 머지 커밋** 또는 **패스트 포워드 머지** 방법을 사용하는데 [병합 전 자동 리베이스](methods/_index.md#automatic-rebase-before-merge)가 켜지지 않았으면 GitLab은 머지 충돌을 방지하기 위해 요청을 취소합니다. 병합 전 자동 리베이스를 켜면 자동 병합이 활성 상태로 유지되고 병합 리퀘스트가 병합될 때 GitLab이 리베이스합니다.

파이프라인 상태를 더 엄격하게 제어하려면 병합 전에 [성공한 파이프라인을 요구](#require-a-successful-pipeline-for-merge)할 수도 있습니다.

### 병합에 성공한 파이프라인 필요 {#require-a-successful-pipeline-for-merge}

병합 전에 완전하고 성공한 파이프라인을 요구하도록 프로젝트를 구성할 수 있습니다. 이 구성은 다음과 같이 작동합니다:

- GitLab CI/CD 파이프라인.
- [외부 CI 통합](../integrations/_index.md#available-integrations)에서 실행되는 파이프라인.

결과적으로 [GitLab CI/CD 파이프라인 비활성화](../../../ci/pipelines/settings.md#disable-gitlab-cicd-pipelines)는 이 기능을 비활성화하지 않지만 외부 CI 공급자의 파이프라인을 사용할 수 있습니다.

사전 요구 사항:

- 프로젝트의 CI/CD 구성이 모든 병합 리퀘스트에 대해 파이프라인을 실행하는지 확인합니다.
- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

이 설정을 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **병합 요청**을 선택합니다.
1. **머지 점검**으로 스크롤하고 **파이프라인이 성공해야 함**을 선택합니다. 이 설정은 또한 파이프라인이 없을 때 병합 리퀘스트가 병합되는 것을 방지하므로 [일부 규칙과 충돌](#merge-request-cant-merge-despite-no-failed-pipeline)할 수 있습니다.
1. **저장**을 선택합니다.

[동일한 병합 리퀘스트에 대해 여러 파이프라인 유형이 실행](#merge-request-can-still-be-merged-despite-a-failed-pipeline)되는 경우 병합 리퀘스트 파이프라인이 다른 파이프라인 유형보다 우선합니다. 예를 들어 이전이지만 성공한 병합 리퀘스트 파이프라인은 더 최신이지만 실패한 브랜치 파이프라인에도 불구하고 병합 리퀘스트가 병합되도록 합니다.

마찬가지로 [프로젝트와 함께 가져온](../../group/import/migrated_items.md#migrated-project-items) 파이프라인은 소스 상태를 유지하고 대상에서 실행하지 않고도 이 점검을 만족할 수 있습니다. 병합하기 전에 가져온 머지 리퀘스트에서 새 파이프라인을 실행합니다.

### 생략된 파이프라인 이후 병합 허용 {#allow-merge-after-skipped-pipelines}

프로젝트에 대해 **파이프라인이 성공해야 함**을 설정하면 [생략된 파이프라인](../../../ci/pipelines/_index.md#skip-a-pipeline)이 병합 리퀘스트가 병합되는 것을 방지합니다.

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

이 동작을 변경하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **병합 요청**을 선택합니다.
1. **머지 점검** 아래:
   - **파이프라인이 성공해야 함**을 선택합니다.
   - **생략한 파이프라인은 성공한 것으로 간주됩니다.**를 선택합니다.
1. **저장**을 선택합니다.

## 특정 날짜 전에 병합 방지 {#prevent-merge-before-a-specific-date}

{{< history >}}

- GitLab 17.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/14380)되었습니다.

{{< /history >}}

병합 리퀘스트가 특정 날짜 및 시간 이전에 병합되지 않아야 하면 **머지 시작 가능** 날짜를 설정합니다. 이 값은 병합(또는 머지 트레인)이 시작될 수 있는 시기를 설정합니다. 그러나 병합의 정확한 시간은 다른 머지 점검의 충족 또는 머지 트레인의 길이에 따라 달라질 수 있습니다.

사전 요구 사항:

- 프로젝트에 대해 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

다음과 같이 설정합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**을 선택합니다.
1. 편집할 병합 리퀘스트를 선택합니다.
1. **편집**을 선택합니다.
1. **머지 시작 가능** 드롭다운 목록에서 `After scheduled date`을 선택한 다음 날짜와 시간을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 문제 해결 {#troubleshooting}

### 실패한 파이프라인이 없는데도 병합 리퀘스트를 병합할 수 없음 {#merge-request-cant-merge-despite-no-failed-pipeline}

경우에 따라 [병합에 성공한 파이프라인을 요구](#require-a-successful-pipeline-for-merge)할 수 있지만 실패한 파이프라인이 없는 병합 리퀘스트를 병합할 수 없습니다. 이 설정은 실패한 파이프라인의 부재가 아니라 성공한 파이프라인의 존재를 요구합니다. 파이프라인이 없는 병합 리퀘스트는 성공한 파이프라인을 가진 것으로 간주되지 않으므로 병합할 수 없습니다.

이 설정을 활성화하면 [`rules`](../../../ci/yaml/_index.md#rules) 또는 [`workflow:rules`](../../../ci/yaml/_index.md#workflowrules)를 사용하여 모든 병합 리퀘스트에 대해 파이프라인이 실행되도록 합니다.

### 실패한 파이프라인에도 불구하고 병합 리퀘스트를 여전히 병합할 수 있음 {#merge-request-can-still-be-merged-despite-a-failed-pipeline}

경우에 따라 [병합에 성공한 파이프라인을 요구](#require-a-successful-pipeline-for-merge)할 수 있지만 여전히 실패한 파이프라인이 있는 병합 리퀘스트를 병합할 수 있습니다.

병합 리퀘스트 파이프라인은 **파이프라인이 성공해야 함** 설정에서 가장 높은 우선순위를 가집니다. 동일한 병합 리퀘스트에 대해 여러 파이프라인 유형이 실행되는 경우 GitLab은 병합 리퀘스트 파이프라인의 성공만 확인합니다.

병합 리퀘스트에 여러 파이프라인이 있을 수 있는 경우:

- [`rules`](../../../ci/yaml/_index.md#rules) 구성으로 인해 [중복 파이프라인](../../../ci/jobs/job_rules.md#avoid-duplicate-pipelines)이 발생합니다: 하나의 병합 리퀘스트 파이프라인과 하나의 브랜치 파이프라인. 이 경우 최신 병합 리퀘스트 파이프라인의 상태가 브랜치 파이프라인이 아니라 병합 리퀘스트를 병합할 수 있는지 결정합니다.
- 병합 리퀘스트와 동일한 브랜치를 대상으로 하는 외부 도구에서 트리거된 파이프라인.

모든 경우에 CI/CD 구성을 업데이트하여 동일한 병합 리퀘스트에 대해 여러 파이프라인 유형이 실행되지 않도록 합니다.
