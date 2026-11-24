---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitHub
description: GitHub에 GitLab CI/CD 파이프라인 상태 업데이트를 전송합니다.
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab에서 GitHub에 파이프라인 상태 업데이트를 보낼 수 있습니다. CI/CD를 위해 GitLab을 사용하는 경우 GitHub 통합이 도움이 될 수 있습니다.

![GitHub의 파이프라인 상태 업데이트](img/github_status_check_pipeline_update_v10_6.png)

이 프로젝트 통합은 [인스턴스 전체 GitHub 통합](../import/github.md#mirror-a-repository-and-share-pipeline-status)과 별개이며, [GitHub 프로젝트](../../../integration/github.md)를 가져올 때 자동으로 구성됩니다.

## 통합 구성 {#configure-the-integration}

이 통합을 사용하려면 [GitHub API 토큰](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens)에 `repo:status` 액세스 권한이 필요합니다.

GitHub에서 다음 단계를 완료하세요:

1. **개인 액세스 토큰** 페이지(<https://github.com/settings/tokens>)로 이동합니다.
1. **새 토큰 생성**을 선택합니다.
1. **노트**에 새 토큰의 이름을 입력합니다.
1. `repo:status`이(가) 선택되었는지 확인하고 **토큰 생성**을 선택합니다.
1. 생성된 토큰을 복사하여 GitLab에서 사용합니다.

GitLab에서 다음 단계를 완료하세요:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **GitHub**를 선택합니다.
1. **활성** 확인란이 선택되었는지 확인합니다.
1. **토큰**에 GitHub에서 생성한 토큰을 붙여넣습니다.
1. **리포지토리 URL**에 GitHub의 프로젝트 경로를 입력합니다(예: `https://github.com/username/repository`).
1. 선택 사항. [정적 상태 점검 이름](#static-or-dynamic-status-check-names)을 비활성화하려면 **정적 상태 점검 이름 활성화** 확인란을 선택 해제합니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

통합을 구성한 후 [외부 풀 요청에 대한 파이프라인](../../../ci/ci_cd_for_external_repos/_index.md#pipelines-for-external-pull-requests)을 참조하여 열린 풀 요청에 대해 실행할 파이프라인을 구성합니다.

### 정적 또는 동적 상태 점검 이름 {#static-or-dynamic-status-check-names}

상태 점검 이름은 정적이거나 동적일 수 있습니다:

- **정적**: GitLab 인스턴스의 호스트 이름이 상태 점검 이름에 추가됩니다.

- **동적**: 분기 이름이 상태 점검 이름에 추가됩니다.

**정적 상태 점검 이름 활성화** 옵션을 사용하면 GitHub에서 필수 상태 점검을 구성할 수 있으며, 이는 올바르게 작동하려면 일관성 있는(정적) 이름이 필요합니다.

[이 옵션을 비활성화](#configure-the-integration)하면 GitLab은 대신 동적 상태 점검 이름을 사용합니다.
