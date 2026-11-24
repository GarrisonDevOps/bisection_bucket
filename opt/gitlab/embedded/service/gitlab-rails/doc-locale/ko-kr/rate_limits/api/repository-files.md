---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
gitlab_dedicated: yes
description: 리포지토리 파일 API의 속도 제한을 구성합니다.
title: 리포지토리 파일 API 속도 제한
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[리포지토리 파일 API](../../api/repository_files.md)를 통해 리포지토리의 파일을 가져오기, 만들기, 업데이트 및 삭제할 수 있습니다. 웹 애플리케이션의 보안과 안정성을 개선하기 위해 이 API에 [속도 제한](../_index.md)을 적용할 수 있습니다. 파일 API에 대해 만드는 모든 속도 제한은 [일반 사용자 및 IP 속도 제한](../../administration/settings/user_and_ip_rate_limits.md)을 재정의합니다.

## 파일 API 속도 제한 정의 {#define-files-api-rate-limits}

파일 API의 속도 제한은 기본적으로 비활성화됩니다. 활성화되면 [리포지토리 파일 API](../../api/repository_files.md)에 대한 요청의 일반 사용자 및 IP 속도 제한을 무시합니다. 이미 적용된 일반 사용자 및 IP 속도 제한을 유지하면서 파일 API의 속도 제한을 늘리거나 줄일 수 있습니다. 이 재정의를 통해 제공되는 다른 새 기능은 없습니다.

전제 조건:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

리포지토리 파일 API에 대한 요청의 일반 사용자 및 IP 속도 제한을 재정의하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **파일 API 속도 제한**을 확장합니다.
1. 활성화할 속도 제한 유형의 확인란을 선택합니다:
   - **인증되지 않은 API 요청 속도 제한**
   - **인증된 API 요청 속도 제한**
1. **인증되지 않음**을 선택한 경우:
   1. **IP당 기간당 최대 인증되지 않은 API 요청**을 선택합니다.
   1. **인증되지 않은 API 속도 제한 기간(초)**를 선택합니다.
1. **인증됨**을 선택한 경우:
   1. **사용자당 기간당 최대 인증된 API 요청**을 선택합니다.
   1. **인증된 API 속도 제한 기간(초)**를 선택합니다.

## 파일 비난 속도 제한 구성 {#configure-file-blame-rate-limits}

{{< history >}}

- [GitLab 19.6](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/261912)에서 도입되었습니다.

{{< /history >}}

[파일 비난 엔드포인트](../../api/repository_files.md#retrieve-file-blame-history-from-a-repository)와 `blame` GraphQL 필드는 `RepositoryBlob`에 이러한 속도 제한을 공유합니다. GraphQL의 경우 쿼리의 각 블롭이 하나의 요청으로 계산됩니다. 이러한 제한은 파일 API 속도 제한 외에 적용되며 기본적으로 활성화됩니다.

| 요청 유형    | 기본 제한             | 적용 대상            | 애플리케이션 설정 |
|-----------------|---------------------------|-----------------------|---------------------|
| 인증됨   | 분당 400개 요청 | 각 사용자 및 프로젝트 | `project_repositories_blame_limit` |
| 인증되지 않음 | 분당 400개 요청 | 각 IP 주소       | `project_repositories_blame_unauthenticated_limit` |

제한을 변경하려면 [애플리케이션 설정 API](../../api/settings.md#available-settings)를 사용합니다. 제한을 `0`로 설정하면 비활성화됩니다.

## 관련 항목 {#related-topics}

- [속도 제한](../_index.md)
- [리포지토리 파일 API](../../api/repository_files.md)
- [사용자 및 IP 속도 제한](../../administration/settings/user_and_ip_rate_limits.md)
