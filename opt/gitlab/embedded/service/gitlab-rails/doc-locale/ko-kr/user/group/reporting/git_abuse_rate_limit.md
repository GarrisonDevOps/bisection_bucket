---
stage: Software Supply Chain Security
group: Authorization
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Git 악용 속도 제한
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- GitLab 15.2에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/8066)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `limit_unique_project_downloads_per_namespace_user`로 명명되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 15.6에서 [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/365724)되었습니다.
- GitLab 18.0에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/183101)하게 되었습니다. 기능 플래그 `limit_unique_project_downloads_per_namespace_user`이 제거되었습니다.

{{< /history >}}

이는 그룹 수준의 문서입니다. GitLab Self-Managed 인스턴스의 경우 [관리 문서](../../../administration/reporting/git_abuse_rate_limit.md)를 참조하세요.

Git 악용 속도 제한은 사용자가 지정된 시간 프레임 내에 그룹의 지정된 수보다 많은 리포지토리를 다운로드, 복제, 끌어오기, 페치 또는 포크하는 경우 자동으로 사용자를 차단하는 기능입니다. 차단된 사용자는 HTTP 또는 SSH를 통해 최상위 그룹 또는 공개되지 않은 하위 그룹에 액세스할 수 없습니다. 속도 제한은 [개인](../../profile/personal_access_tokens.md) 또는 [그룹 액세스 토큰](../settings/group_access_tokens.md)으로 인증하는 사용자에게도 적용되며 [CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md)도 마찬가지입니다. 관련 없는 그룹에 대한 액세스는 영향을 받지 않습니다.

Git 악용 속도 제한은 최상위 그룹 소유자, [배포 토큰](../../project/deploy_tokens/_index.md) 또는 [배포 키](../../project/deploy_keys/_index.md)에 적용되지 않습니다.

## 자동 차단 알림 {#automatic-ban-notifications}

선택된 사용자는 사용자가 차단되면 이메일 알림을 받습니다.

자동 차단이 비활성화되면 사용자가 제한을 초과할 때 자동으로 차단되지 않습니다. 그러나 알림은 여전히 전송됩니다. 이 설정을 사용하여 자동 차단을 활성화하기 전에 속도 제한 설정의 올바른 값을 결정할 수 있습니다.

자동 차단이 활성화되면 사용자가 차단될 예정일 때 이메일 알림이 전송되고 사용자는 그룹 및 하위 그룹에서 자동으로 차단됩니다.

## Git 악용 속도 제한 구성 {#configure-git-abuse-rate-limiting}

1. 왼쪽 사이드바에서 **Settings** > **Reporting**을 선택합니다.
1. Git 악용 속도 제한 설정을 업데이트합니다:
   1. **리포지토리 갯수** 필드에 숫자를 입력하세요. `0` 이상 `10,000` 이하여야 합니다. 이 숫자는 지정된 시간 기간 내에 사용자가 다운로드할 수 있는 최대 고유 리포지토리 수를 지정합니다. 차단되기 전입니다. `0`로 설정하면 Git 악용 속도 제한이 비활성화됩니다.
   1. **보고 주기 (초)** 필드에 숫자를 입력하세요. `0` 이상 `86,400` 이하여야 합니다(10일). 이 숫자는 사용자가 최대 리포지토리 수를 다운로드할 수 있는 시간(초)을 지정합니다. 차단되기 전입니다. `0`로 설정하면 Git 악용 속도 제한이 비활성화됩니다.
   1. 선택 사항. **제외된 사용자** 필드에 추가하여 최대 `100`명의 사용자를 제외합니다. 제외된 사용자는 자동으로 차단되지 않습니다.
   1. **다음 사용자에게 알림 보내기** 필드에 최대 `100`명의 사용자를 추가합니다. 최소 한 명의 사용자를 선택해야 합니다. 기본 그룹의 소유자 역할을 가진 모든 사용자는 기본적으로 선택됩니다.
   1. 선택 사항. **사용자가 지정된 제한을 초과할 때 이 네임스페이스에서 자동으로 사용자 차단** 토글을 켜서 자동 차단을 활성화합니다.
1. **변경 사항 저장**을 선택합니다.

## 관련 항목 {#related-topics}

- [사용자 차단 및 차단 해제](../moderate_users.md).
