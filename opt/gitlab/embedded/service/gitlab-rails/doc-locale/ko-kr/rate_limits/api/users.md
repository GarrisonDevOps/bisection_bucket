---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 사용자 API 속도 제한
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 사용자 API의 속도 제한은 GitLab 17.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/452349)되었으며 [플래그](../../administration/feature_flags/_index.md) `rate_limiting_user_endpoints`로 명명되었습니다. 기본적으로 비활성화되었습니다.
- [GitLab 17.10에서 사용자 정의 가능한 속도 제한이 추가](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/181054)되었습니다.
- GitLab 18.1에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/524831)하게 되었습니다. 기능 플래그 `rate_limiting_user_endpoints`가 제거되었습니다.

{{< /history >}}

> [!note]
> GitLab 18.0 이상으로 업그레이드할 때 이 API에 대한 사용자 정의 가능한 속도 제한은 `0`로 설정됩니다. 관리자는 필요에 따라 속도 제한을 조정할 수 있습니다. 영향을 받는 속도 제한에 대한 정보는 [프로젝트, 그룹 및 사용자 API에 대해 발표된 속도 제한](https://about.gitlab.com/blog/rate-limitations-announced-for-projects-groups-and-users-apis/#rate-limitation-details)을 참조하세요.

다음 [사용자 API](../../api/users.md)에 대한 요청의 분당 IP 주소별 속도 제한 및 사용자별 속도 제한을 구성할 수 있습니다.

| 한도                                                           | 기본값 |
|-----------------------------------------------------------------|---------|
| [`GET /users/:id/followers`](../../api/user_follow_unfollow.md#list-all-accounts-that-follow-a-user) | 분당 100개 |
| [`GET /users/:id/following`](../../api/user_follow_unfollow.md#list-all-accounts-followed-by-a-user) | 분당 100개 |
| [`GET /users/:id/status`](../../api/users.md#retrieve-the-status-of-a-user)                               | 분당 240회 |
| [`GET /users/:id/keys`](../../api/user_keys.md#list-all-ssh-keys-for-a-user)                         | 분당 120회 |
| [`GET /users/:id/keys/:key_id`](../../api/user_keys.md#retrieve-an-ssh-key-for-a-user)                               | 분당 120회 |
| [`GET /users/:id/gpg_keys`](../../api/user_keys.md#list-all-gpg-keys-for-a-user)                     | 분당 120회 |
| [`GET /users/:id/gpg_keys/:key_id`](../../api/user_keys.md#retrieve-a-gpg-key-for-a-user)                 | 분당 120회 |

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

속도 제한을 변경하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **사용자 API 속도 제한**을 확장합니다.
1. 사용 가능한 속도 제한에 대한 값을 설정합니다. 속도 제한은 인증된 요청의 경우 분당, 사용자별이며 인증되지 않은 요청의 경우 IP 주소별입니다. `0`을 입력하여 속도 제한을 비활성화합니다.
1. **변경 사항 저장**을 선택합니다.

각 속도 제한:

- 요청이 인증된 경우 사용자별로 적용됩니다.
- 요청이 인증되지 않은 경우 IP 주소별로 적용됩니다.
- `0`로 설정하여 속도 제한을 비활성화할 수 있습니다.

로그:

- 속도 제한을 초과하는 요청은 `auth.log` 파일에 로깅됩니다.
- 속도 제한 수정은 `audit_json.log` 파일에 로깅됩니다.

예:

`GET /users/:id/followers`에 대한 속도 제한을 150으로 설정하고 1분에 155개의 요청을 보내면 마지막 5개의 요청이 차단됩니다. 1분 후 속도 제한을 다시 초과할 때까지 계속 요청을 보낼 수 있습니다.
