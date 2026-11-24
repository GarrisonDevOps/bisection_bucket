---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 웹훅 작업 속도 제한
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 웹훅 테스트를 위한 속도 제한이 GitLab 17.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/150066)되었으며, [플래그](../feature_flags/_index.md)는 `web_hook_test_api_endpoint_rate_limit`입니다. 기본적으로 활성화되어 있습니다.
- 웹훅 이벤트 재전송을 위한 속도 제한이 GitLab 17.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/151130)되었으며, [플래그](../feature_flags/_index.md)는 `web_hook_event_resend_api_endpoint_rate_limit`입니다. 기본적으로 활성화되어 있습니다.
- 사용자 지정 가능한 속도 제한이 GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/587887)되었습니다. 기능 플래그 `web_hook_test_api_endpoint_rate_limit` 및 `web_hook_event_resend_api_endpoint_rate_limit`이 제거되었습니다.
- 프로젝트 웹훅 생성을 위한 속도 제한이 GitLab 19.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/605597)되었습니다.
- 그룹 웹훅 및 시스템 훅 생성을 위한 속도 제한이 GitLab 19.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/635281)되었습니다.

{{< /history >}}

다음 요청에 대한 분당 속도 제한을 구성합니다:

- API를 사용하여 [프로젝트 웹훅 추가](../../api/project_webhooks.md#add-a-webhook-to-a-project)합니다.
- API를 사용하여 [그룹 웹훅 생성](../../api/group_webhooks.md#create-a-group-hook)합니다.
- API를 사용하여 [시스템 훅 추가](../../api/system_hooks.md#add-new-system-hook)합니다.
- [웹훅 테스트](../../user/project/integrations/webhooks.md#test-a-webhook)합니다.
- [웹훅 이벤트 재전송](../../user/project/integrations/webhooks.md#inspect-request-and-response-details)합니다.

| 한도 | 기본값 |
|-------|---------|
| 프로젝트 웹훅 생성 요청 | 분당 5회 |
| 그룹 웹훅 생성 요청 | 분당 10회 |
| 시스템 훅 생성 요청 | 분당 5회 |
| 웹훅 테스트 요청 | 분당 5회 |
| 웹훅 이벤트 재전송 요청 | 분당 5회 |

프로젝트 및 그룹 제한은 사용자 기준으로 주어진 프로젝트 또는 그룹에 적용됩니다. 동일한 프로젝트 또는 그룹의 모든 웹훅은 제한을 공유합니다. 시스템 훅 생성 제한은 인스턴스 전체에서 사용자 기준으로 적용됩니다. 테스트 및 이벤트 재전송 제한은 UI와 API 모두를 포함합니다. 웹훅 생성 제한은 API만 포함합니다.

이러한 제한은 웹훅이 트리거되는 빈도를 제한하는 [웹훅 배포 속도 제한](../instance_limits.md#webhook-rate-limit)과 별개입니다. 웹훅 배포 속도 제한 구성은 인스턴스 유형에 따라 달라집니다:

- GitLab Self-Managed에서 관리자는 [Plan limits API](../../api/plan_limits.md)를 사용하여 구성합니다.
- GitLab.com에서 배포 제한은 [요금제에 따라 다르며](../../user/gitlab_com/_index.md#webhooks) 변경할 수 없습니다.

예를 들어 웹훅 테스트 속도 제한을 5로 설정하고 1분 내에 웹훅을 6번 테스트하려고 하면 최종 요청이 차단됩니다. 1분이 지난 후 웹훅을 다시 테스트할 수 있습니다.

웹훅 생성 제한은 유효성 검사에 실패한 요청을 포함하여 인증 및 권한 부여를 통과하는 웹훅을 생성하기 위한 각 요청을 계산합니다. 제한을 초과하는 요청은 `429 Too Many Requests`를 반환합니다.

## 속도 제한 변경 {#change-the-rate-limit}

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

속도 제한을 변경하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **웹훅 속도 제한**을 확장합니다.
1. 사용 가능한 속도 제한에 대한 값을 설정합니다. `0`을 입력하여 속도 제한을 비활성화합니다.
1. **변경 사항 저장**을 선택합니다.

속도 제한을 초과하는 요청은 `auth.log` 파일에 로깅됩니다.
