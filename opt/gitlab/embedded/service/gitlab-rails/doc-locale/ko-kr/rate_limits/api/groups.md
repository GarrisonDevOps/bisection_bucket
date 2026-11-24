---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 그룹 API 속도 제한
description: 그룹 API 엔드포인트에 속도 제한을 설정합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!note]
> GitLab 18.0 이상으로 업그레이드할 때 이 API의 구성 가능한 속도 제한은 `0`으로 설정됩니다. 관리자는 필요에 따라 속도 제한을 조정할 수 있습니다. 영향을 받는 속도 제한에 대한 자세한 내용은 [프로젝트, 그룹 및 사용자 API에 대해 발표된 속도 제한](https://about.gitlab.com/blog/rate-limitations-announced-for-projects-groups-and-users-apis/#rate-limitation-details)을 참조하세요.

## 그룹 API 속도 제한 구성 {#configure-groups-api-rate-limits}

{{< history >}}

- [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/152733): GitLab 17.1에서 [플래그](../../administration/feature_flags/_index.md) `rate_limit_groups_and_projects_api`을 사용하여 그룹 및 프로젝트 API에 대한 속도 제한을 제공했습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.1에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/461316)합니다. 기능 플래그 `rate_limit_groups_and_projects_api`가 제거되었습니다.
- [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245318): GitLab 19.3에서 [플래그](../../administration/feature_flags/_index.md) `namespace_create_rate_limit`을 사용하여 그룹 생성 시 속도 제한을 제공했습니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

다음 그룹 API 엔드포인트에 대한 요청에 대해 각 IP 주소 및 사용자의 속도 제한을 구성합니다:

| 한도                                                           | 기본값 | 간격 |
|-----------------------------------------------------------------|---------|----------|
| [`GET /groups`](../../api/groups.md#list-groups)                | 200     | 1분 |
| [`GET /groups/:id`](../../api/groups.md#retrieve-a-group)     | 400     | 1분 |
| [`GET /groups/:id/groups/shared`](../../api/groups.md#list-shared-groups) | 60    | 1분 |
| [`GET /groups/:id/invited_groups`](../../api/groups.md#list-shared-groups) | 60     | 1분 |
| [`GET /groups/:id/projects`](../../api/groups.md#list-projects) | 600     | 1분 |
| [`POST /groups/:id/archive`](../../api/groups.md#archive-a-group) | 60    | 1분 |
| [`POST /groups`](../../api/groups.md#create-a-group)            | 200     | 1일 |

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

속도 제한을 변경하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **그룹 API 속도 제한**을 확장합니다.
1. 모든 속도 제한의 값을 변경하거나 속도 제한을 `0`으로 설정하여 비활성화합니다.
1. **변경 사항 저장**을 선택합니다.

속도 제한:

- 인증된 각 사용자에게 적용됩니다. 요청이 인증되지 않은 경우 속도 제한이 IP 주소에 적용됩니다.
- 0으로 설정하여 속도 제한을 비활성화할 수 있습니다.

속도 제한을 초과한 요청은 `auth.log` 파일에 기록됩니다.

예를 들어 `GET /groups/:id`에 대해 400의 제한을 설정하면 분당 400을 초과하는 요청은 API 엔드포인트에서 차단됩니다. 엔드포인트에 대한 액세스는 1분 후에 복구됩니다.

## 그룹 및 프로젝트 구성원 목록 속도 제한 {#rate-limit-on-listing-group-and-project-members}

{{< history >}}

- GitLab 18.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/578527)되었습니다.

{{< /history >}}

속도 제한은 [모든 그룹 구성원 API 엔드포인트](../../api/group_members.md#list-all-group-members-including-inherited-and-invited-members)에 설정됩니다.

`GET /projects/:id/members/all`와 `GET /groups/:id/members/all` API 엔드포인트는 동일한 속도 제한 구성을 공유합니다. 프로젝트 엔드포인트에 속도 제한을 설정하면 속도 제한이 그룹 엔드포인트에도 적용됩니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

두 엔드포인트에 대해 이 속도 제한을 수정하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **프로젝트 API 속도 제한**을 확장합니다.
1. **`GET /projects/:id/members/all` API에 대한 최대 요청(분당 사용자 또는 IP 주소당)** 텍스트 상자에 값을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

속도 제한:

- 기본값은 매분 200개 요청입니다.
- 인증된 각 사용자에게 적용됩니다. 요청이 인증되지 않은 경우 속도 제한이 IP 주소에 적용됩니다.
- 프로젝트 API 속도 제한 설정을 통해 구성됩니다. 자세한 내용은 [프로젝트 구성원 목록에서 속도 제한 구성](projects.md#configure-rate-limits-on-listing-project-members)을 참조하세요.
- `0`으로 설정하여 두 엔드포인트의 속도 제한을 비활성화할 수 있습니다.

속도 제한을 초과한 요청은 `auth.log` 파일에 기록됩니다.

예를 들어 분당 200개 요청을 초과하는 API 엔드포인트에 대한 요청이 차단됩니다. 엔드포인트에 대한 액세스는 1분 후에 재개됩니다.

## 그룹 보관 및 보관 해제에 대한 속도 제한 구성 {#configure-rate-limits-on-group-archiving-and-unarchiving}

{{< details >}}

- 상태:  실험

{{< /details >}}

{{< history >}}

- GitLab 18.0에서 `archive_group` [기능 플래그](../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/481969)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.9에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/526771)합니다. 기능 플래그 `archive_group`가 제거되었습니다.

{{< /history >}}

다음 그룹 보관 엔드포인트에 대한 요청에 속도 제한을 구성합니다:

```plaintext
POST /groups/:id/archive
POST /groups/:id/unarchive
```

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

속도 제한을 변경하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **그룹 API 속도 제한**을 확장합니다.
1. **`POST /groups/:id/archive` 및 `POST /groups/:id/unarchive` API에 대한 최대 요청(분당 사용자 또는 IP 주소당)** 텍스트 상자에 값을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

속도 제한:

- 기본값은 매분 60개 요청입니다.
- 인증된 각 사용자에게 적용됩니다. 요청이 인증되지 않은 경우 속도 제한이 IP 주소에 적용됩니다.
- `0`으로 설정하여 두 엔드포인트의 속도 제한을 비활성화할 수 있습니다.

속도 제한을 초과한 요청은 `auth.log` 파일에 기록됩니다.

예를 들어 60의 제한을 설정하면 분당 60개 요청을 초과하는 API 엔드포인트에 대한 요청이 차단됩니다. 엔드포인트에 대한 액세스는 1분 후에 재개됩니다.

그룹 보관 엔드포인트에 대한 자세한 내용은 [그룹 보관](../../api/groups.md#archive-a-group)을 참조하세요.

## 그룹 구성원 삭제에 대한 속도 제한 구성 {#configure-rate-limits-on-deleting-group-members}

[구성원 삭제 엔드포인트](../../api/group_members.md#remove-a-group-member)에 대한 요청에 대해 각 그룹 및 사용자의 속도 제한을 구성합니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

속도 제한을 변경하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **구성원 API 속도 제한**을 확장합니다.
1. **그룹/프로젝트별 분당 최대 요청 수** 텍스트 상자에 값을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

속도 제한:

- 기본값은 매분 60개 요청입니다.
- 각 그룹 및 사용자에게 적용됩니다.
- `0`으로 설정하여 속도 제한을 비활성화할 수 있습니다.

속도 제한을 초과한 요청은 `auth.log` 파일에 기록됩니다.

예를 들어 60의 제한을 설정하면 분당 60개 요청을 초과하는 API 엔드포인트에 대한 요청이 차단됩니다. 엔드포인트에 대한 액세스는 1분 후에 복구됩니다.
