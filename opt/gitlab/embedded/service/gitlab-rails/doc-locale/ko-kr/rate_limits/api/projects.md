---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 프로젝트 API 속도 제한
description: 프로젝트 API 끝점에 속도 제한을 설정합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!note]
> GitLab 18.0 이상으로 업그레이드할 때 이 API에 대한 사용자 정의 가능한 속도 제한은 `0`로 설정됩니다. 관리자는 필요에 따라 속도 제한을 조정할 수 있습니다. 영향을 받는 속도 제한에 대한 정보는 [프로젝트, 그룹 및 사용자 API에 대해 발표된 속도 제한](https://about.gitlab.com/blog/rate-limitations-announced-for-projects-groups-and-users-apis/#rate-limitation-details)을 참조하세요.

## 프로젝트 API 속도 제한 구성 {#configure-projects-api-rate-limits}

{{< history >}}

- GitLab 17.1에서 그룹 및 프로젝트 API에 대한 속도 제한을 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/421909)했으며, `rate_limit_groups_and_projects_api`이라는 [플래그](../../administration/feature_flags/_index.md)가 포함되어 있습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.1에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/461316)하게 되었습니다. 기능 플래그 `rate_limit_groups_and_projects_api`가 제거되었습니다.
- GitLab 19.3에서 프로젝트 생성 시 속도 제한을 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245318)했으며, `namespace_create_rate_limit`이라는 [플래그](../../administration/feature_flags/_index.md)가 포함되어 있습니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

다음 프로젝트 API 끝점에 대한 요청에 대해 각 IP 주소 및 사용자에 대한 속도 제한을 구성합니다:

| 한도                                                                                                       | 기본값 | 간격 |
|-------------------------------------------------------------------------------------------------------------|---------|----------|
| [`GET /projects`](../../api/projects.md#list-all-projects) (인증되지 않은 요청)                       | 400     | 10분 |
| [`GET /projects`](../../api/projects.md#list-all-projects) (인증된 요청)                         | 2000    | 10분 |
| [`GET /projects/:id`](../../api/projects.md#retrieve-a-project)                                             | 400     | 1분 |
| [`GET /users/:user_id/projects`](../../api/projects.md#list-all-personal-projects-for-a-user)               | 300     | 1분 |
| [`GET /users/:user_id/contributed_projects`](../../api/projects.md#list-all-projects-contributions-for-a-user) | 100     | 1분 |
| [`GET /users/:user_id/starred_projects`](../../api/project_starring.md#list-projects-starred-by-a-user)     | 100     | 1분 |
| [`POST /projects`](../../api/projects.md#create-a-project)                                                  | 200     | 1일 |

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

속도 제한을 변경하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **프로젝트 API 속도 제한**을 확장합니다.
1. 속도 제한값을 변경하거나 속도 제한을 `0`으로 설정하여 비활성화합니다.
1. **변경 사항 저장**을 선택합니다.

속도 제한:

- 인증된 각 사용자에게 적용됩니다. 요청이 인증되지 않은 경우 속도 제한이 IP 주소에 적용됩니다.

속도 제한을 초과하는 요청은 `auth.log` 파일에 기록됩니다.

예를 들어, `GET /projects/:id`에 대해 400의 제한을 설정하면 분당 400개 요청 비율을 초과하는 API 끝점에 대한 요청이 차단됩니다. 엔드포인트에 대한 액세스는 1분 후에 복원됩니다.

프로젝트 API 끝점에 대한 자세한 내용은 [프로젝트 API](../../api/projects.md#list-all-projects)를 참조하세요.

## 프로젝트 멤버 삭제 시 속도 제한 구성 {#configure-rate-limits-on-deleting-project-members}

각 프로젝트 및 사용자에 대해 [멤버 삭제 끝점](../../api/project_members.md#remove-a-direct-member-of-a-project)에 대한 요청의 속도 제한을 구성합니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

속도 제한을 변경하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **멤버 API 속도 제한**을 확장합니다.
1. **그룹/프로젝트별 분당 최대 요청 수** 텍스트 상자에 값을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

속도 제한:

- 기본값은 분당 60개 요청입니다.
- 각 프로젝트 및 사용자에 적용됩니다.
- `0`으로 설정하여 속도 제한을 비활성화할 수 있습니다.

속도 제한을 초과하는 요청은 `auth.log` 파일에 기록됩니다.

예를 들어, 60의 제한을 설정하면 분당 60개 요청 비율을 초과하는 API 끝점에 대한 요청이 차단됩니다. 1분 후 끝점에 대한 액세스가 다시 시작됩니다.

## 프로젝트 멤버 나열 시 속도 제한 구성 {#configure-rate-limits-on-listing-project-members}

{{< history >}}

- GitLab 18.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/578527)되었습니다.

{{< /history >}}

요청에 대해 [프로젝트 멤버 나열 끝점](../../api/project_members.md#list-all-members-of-a-project)으로의 속도 제한을 구성합니다.

`GET /projects/:id/members/all` 및 `GET /groups/:id/members/all` API 끝점은 동일한 속도 제한 구성을 공유합니다. 프로젝트 끝점에서 속도 제한을 설정하면 속도 제한이 그룹 끝점에도 적용됩니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

속도 제한을 변경하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **프로젝트 API 속도 제한**을 확장합니다.
1. **사용자 또는 IP 주소별 분당 `GET /projects/:id/members/all` API에 대한 최대 요청 수** 텍스트 상자에 값을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

속도 제한:

- 기본값은 분당 200개 요청입니다.
- 인증된 각 사용자에게 적용됩니다. 요청이 인증되지 않은 경우 속도 제한이 IP 주소에 적용됩니다.
- `0`로 설정하여 속도 제한을 비활성화할 수 있습니다.

속도 제한을 초과하는 요청은 `auth.log` 파일에 기록됩니다.

예를 들어, 200의 제한을 설정하면 분당 200개 요청 비율을 초과하는 API 끝점에 대한 요청이 차단됩니다. 1분 후 끝점에 대한 액세스가 다시 시작됩니다.
