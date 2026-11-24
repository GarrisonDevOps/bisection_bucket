---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 조직 API 속도 제한
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed
- 상태: 실험

{{< /details >}}

{{< history >}}

- GitLab 17.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/470613)되었으며, [기능 플래그](../../administration/feature_flags/_index.md) `allow_organization_creation`를 사용합니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../../policy/development_stages_support.md)입니다.
- GitLab 18.4에서 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/549062)되었습니다. 기능 플래그 `allow_organization_creation`가 통합되고 `organization_switching`로 이름이 변경되었습니다.
- 기능 플래그는 GitLab 19.4에서 `org_stage_experimental`로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249678)되었습니다. 기본적으로 비활성화되었습니다. 기능 플래그 `organization_switching`가 제거되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

속도 제한을 초과하는 요청은 `auth.log` 파일에 기록됩니다.

`POST /organizations`에 대해 400의 제한을 설정한 경우, 1분 이내에 400의 속도를 초과하는 API 엔드포인트에 대한 요청이 차단됩니다. 엔드포인트에 대한 액세스는 1분 후에 복원됩니다.

[POST /organizations API](../../api/organizations.md#create-an-organization)에 대한 요청의 분당 사용자당 속도 제한을 구성할 수 있습니다. 기본값은 10입니다.

## 속도 제한 변경 {#change-the-rate-limit}

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

속도 제한을 변경하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **조직 API 속도 제한**을 확장합니다.
1. 모든 속도 제한의 값을 변경합니다. 속도 제한은 분당 사용자당입니다. 속도 제한을 비활성화하려면 값을 `0`로 설정합니다.
1. **변경 사항 저장**을 선택합니다.
