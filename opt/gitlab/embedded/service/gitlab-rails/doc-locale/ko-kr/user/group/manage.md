---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 그룹 관리
---

그룹을 사용하여 하나 이상의 관련 프로젝트를 동시에 관리할 수 있습니다.

> [!note]
> GitLab Self-Managed에서 전체 조직의 개요를 보려면 최상위 그룹을 하나 만들어야 합니다. 모든 그룹의 조직 뷰를 만들기 위한 노력에 대한 자세한 내용은 [에픽 9266 참조](https://gitlab.com/groups/gitlab-org/-/work_items/9266)하세요. 최상위 그룹은 완전한 [보안 대시보드 및 센터](../application_security/security_dashboard/_index.md), [취약성 보고서](../application_security/vulnerability_report/_index.md), [규정 준수 센터](../compliance/compliance_center/_index.md), [가치 스트림 분석](value_stream_analytics/_index.md)을 통해 전체 조직에 대한 인사이트를 제공합니다.

## 그룹 README 추가 {#add-a-group-readme}

README 파일을 추가하여 팀에 대한 정보를 제공하고 사용자를 프로젝트에 기여하도록 초대할 수 있습니다. README는 그룹 개요 페이지에 표시됩니다. 모든 그룹 멤버는 README를 보고 편집할 수 있습니다.

사전 요구 사항:

- 그룹 설정에서 README를 생성하려면 그룹의 소유자 역할이 있어야 합니다.

그룹 README를 추가하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **그룹 README 파일** 섹션에서 **README 추가**를 선택하세요. 이 작업은 `README.md` 파일이 포함된 새 프로젝트 `gitlab-profile`을 생성합니다.
1. README 생성 프롬프트에서 **README 생성 및 추가**를 선택하세요. Web IDE로 리디렉션되어 README 파일이 생성됩니다.
1. Web IDE에서 `README.md` 파일을 편집하고 커밋하세요.

## 그룹의 소유자 변경 {#change-the-owner-of-a-group}

그룹의 소유자를 변경할 수 있습니다. 각 그룹에는 항상 소유자 역할을 가진 최소 한 명의 인간 멤버가 있어야 합니다. 내부 사용자("봇") 및 서비스 계정은 그룹의 유일한 소유자가 될 수 없습니다.

- 관리자로서:
  1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
  1. **관리** > **멤버**를 선택하세요.
  1. 다른 멤버에게 소유자 역할을 부여하세요.
  1. 페이지를 새로 고칩니다. 이제 원래 소유자로부터 소유자 역할을 제거할 수 있습니다.
- 현재 그룹의 소유자로서:
  1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
  1. **관리** > **멤버**를 선택하세요.
  1. 다른 멤버에게 소유자 역할을 부여하세요.
  1. 새 소유자가 로그인하여 당신의 소유자 역할을 제거하게 하세요.

## 그룹의 경로 변경 {#change-a-groups-path}

그룹의 경로(그룹 URL) 변경은 의도하지 않은 부작용을 초래할 수 있습니다. [프로젝트](../project/repository/_index.md#repository-path-changes)의 리디렉션 작동 방식과 [API](../../api/rest/_index.md#redirects)를 읽은 후 진행하세요.

다른 그룹 또는 사용자가 경로를 청구할 수 있도록 경로를 변경하는 경우 그룹도 이름을 바꿔야 합니다. 이름과 경로는 모두 고유해야 합니다.

원래 네임스페이스의 소유권을 유지하고 URL 리디렉션을 보호하려면 새 그룹을 만들고 프로젝트를 전송하세요.

그룹 경로(그룹 URL)를 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급** 섹션을 펼치세요.
1. **그룹 URL 변경** 아래에서 새 이름을 입력하세요.
1. **그룹 URL 변경**을 선택하세요.

> [!warning]
> [컨테이너 레지스트리](../packages/container_registry/_index.md) 태그가 포함된 프로젝트가 있는 경우 네임스페이스를 이름을 바꿀 수 없습니다. 프로젝트를 이동할 수 없기 때문입니다.
>
> 수천 개의 하위 그룹이 있는 그룹이 올바르게 처리되도록 하려면 테스트 환경에서 경로 변경을 테스트해야 합니다. [Puma 워커 타임아웃](../../administration/operations/puma.md#change-the-worker-timeout)을 일시적으로 늘리는 것을 고려하세요. 이 타임아웃 위험을 완화하는 솔루션에 대한 자세한 내용은 [이슈 432065](https://gitlab.com/gitlab-org/gitlab/-/issues/432065)를 참조하세요.

## 그룹의 기본 브랜치 보호 변경 {#change-the-default-branch-protection-of-a-group}

GitLab 인스턴스의 관리자는 [인스턴스의 모든 프로젝트](../project/repository/branches/default.md#for-all-projects-in-an-instance)에 대한 기본 브랜치 보호를 구성할 수 있습니다. 해당 인스턴스의 그룹은 전역 수준에서 설정된 브랜치 보호를 상속합니다. 그룹 소유자는 [인스턴스 설정을 무시](../project/repository/branches/default.md#for-all-projects-in-a-group)하여 그룹의 프로젝트에 적용할 수 있습니다. [GitLab Premium 또는 Ultimate](https://about.gitlab.com/pricing/)에서 인스턴스의 관리자는 이 권한을 비활성화할 수 있습니다.

## 초기 브랜치의 사용자 정의 이름 사용 {#use-a-custom-name-for-the-initial-branch}

GitLab에서 새 프로젝트를 만들 때 첫 푸시로 기본 브랜치가 생성됩니다. 그룹 소유자는 [초기 브랜치를 사용자 정의](../project/repository/branches/default.md#change-the-default-branch-name-for-new-projects-in-a-group)하여 그룹의 프로젝트가 그룹의 요구를 충족하도록 할 수 있습니다.

## 그룹 아카이빙 {#archive-a-group}

{{< history >}}

- GitLab 18.3에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/15019)되었으며 `archive_group` 이름의 [기능 플래그가 포함](../../administration/feature_flags/_index.md)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.9에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/526771)합니다. 기능 플래그 `archive_group`이 제거되었습니다.

{{< /history >}}

그룹 및 모든 하위 그룹과 프로젝트를 아카이빙합니다. 아카이빙되면 그룹과 해당 컨텐츠는 읽기 전용이 되며 그룹 데이터는 나중에 참조하기 위해 보존됩니다.

또한 아카이빙된 그룹:

- 그룹 페이지에 `Archived` 배지를 표시합니다
- **비활성** 탭의 **귀하의 작업** 페이지 및 **탐색** 페이지에 표시됩니다
- 다른 네임스페이스로 전송할 수 없습니다

### 알려진 제한 사항 {#known-limitations}

아카이빙된 그룹의 이슈는 [이슈 585677](https://gitlab.com/gitlab-org/gitlab/-/work_items/585677)이 해결될 때까지 이슈 보드에 계속 표시됩니다.

사전 요구 사항:

- 관리자이거나 그룹의 소유자 역할이 있어야 합니다.

그룹을 아카이빙하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급**을 펼치세요.
1. **그룹 아카이빙** 섹션에서 **아카이브**를 선택하세요.

> [!note]
> 그룹을 아카이빙하면 모든 하위 그룹과 프로젝트가 자동으로 아카이빙됩니다. 아카이빙된 그룹 내의 개별 하위 그룹 또는 프로젝트는 별도로 아카이빙을 해제할 수 없습니다.

**귀하의 작업** 목록 보기에서 직접 그룹을 아카이빙하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택합니다.
1. **내 모든 그룹 보기**를 선택하세요.
1. **멤버** 탭에서 아카이빙할 그룹을 찾아 {{< icon name="ellipsis_v" >}}을 선택하세요.
1. **Archive**를 선택합니다.

이 작업은 다른 목록 페이지에서도 사용할 수 있습니다.

### 그룹 아카이빙 해제 {#unarchive-a-group}

그룹 및 모든 하위 그룹과 프로젝트의 아카이빙을 해제합니다. 그룹의 아카이빙을 해제할 때:

- 읽기 전용 제한이 그룹과 해당 컨텐츠에서 제거됩니다.
- 그룹 및 하위 그룹과 프로젝트는 그룹 목록의 **활성** 또는 **멤버** 탭으로 돌아갑니다.

사전 요구 사항:

- 관리자이거나 그룹의 소유자 역할이 있어야 합니다.

그룹의 아카이빙을 해제하려면:

1. 아카이빙된 그룹을 찾으세요.
   1. 상단 표시줄에서 **검색 또는 이동**을 선택합니다.
   1. **내 모든 그룹 보기**를 선택하세요.
   1. **비활성** 탭에서 그룹을 선택하세요.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급** 아래에서 **펼침**을 선택하세요.
1. **그룹 아카이빙 해제** 섹션에서 **아카이빙 해제**를 선택하세요.

**귀하의 작업** 목록 보기에서 직접 그룹의 아카이빙을 해제하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택합니다.
1. **내 모든 그룹 보기**를 선택하세요.
1. **비활성** 탭에서 아카이빙을 해제할 그룹을 찾아 {{< icon name="ellipsis_v" >}}을 선택하세요.
1. **Unarchive**를 선택합니다.

이 작업은 다른 목록 페이지에서도 사용할 수 있습니다.

## 그룹 이동 {#transfer-a-group}

{{< history >}}

- 그룹의 비동기 전송이 GitLab 18.11 [기능 플래그](../../administration/feature_flags/_index.md) `groups_and_projects_async_transfer`(포함)에 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/594575). 기본적으로 비활성화되었습니다.
- GitLab 19.4에서 [일반적으로 사용 가능합니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/250913). 기능 플래그 `groups_and_projects_async_transfer`이 제거되었습니다.

{{< /history >}}

같은 GitLab 인스턴스 내에서 한 위치에서 다른 위치로 그룹을 이동하려면 그룹을 전송합니다. 다음과 같이 수행할 수 있습니다.

- 하위 그룹을 다른 부모 그룹으로 전송합니다.
- 최상위 그룹을 하위 그룹으로 변환합니다.
- 하위 그룹을 최상위 그룹으로 변환합니다.

사전 요구 사항:

- 소스 및 대상 그룹의 소유자 역할.
- 대상 그룹에서 하위 그룹 생성을 활성화합니다(해당하는 경우).

> [!note]
> 아카이빙되었거나 삭제 대기 중인 그룹은 전송할 수 없습니다.

그룹을 전송하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급** 섹션을 펼치세요.
1. **그룹 이전**을 선택하세요.
1. 드롭다운 목록에서 그룹을 선택하세요.
1. **그룹 이전**을 선택하세요.

전송을 확인한 후:

- 그룹이 비동기적으로 전송됩니다.
- 전송이 완료되거나 실패한 후 확인 이메일이 전송됩니다.
- 이전 그룹 URL이 새 그룹 URL로 리디렉션됩니다. 페이지를 새로 고쳐서 새 그룹 URL을 보세요. 큰 그룹의 경우 전송이 완료될 때까지 기다렸다가 대상 네임스페이스 아래의 그룹을 볼 수 있습니다.

그룹을 전송한 후 다음을 확인하세요:

- 로컬 리포지토리 원격을 새 URL로 업데이트합니다.
- 그룹 멤버 액세스 및 권한을 확인합니다.
- 필요한 경우 패키지 구성을 업데이트합니다.
- CI/CD 파이프라인 및 통합을 테스트합니다.

다른 GitLab 인스턴스로 그룹을 복사해야 하는 경우 [직접 전송으로 그룹을 마이그레이션](import/_index.md)하세요.

### 전송되는 데이터 {#what-data-gets-transferred}

그룹 전송에는 다음이 포함됩니다:

- 그룹의 모든 하위 그룹 및 프로젝트
- 명시적 그룹 멤버십 및 역할
- 그룹 설정 및 구성

### 알려진 이슈 {#known-issues}

그룹을 전송할 때 다음 제한 사항을 명심하세요.

멤버십 제한:

- 상속된 멤버십이 손실됩니다. 직접 그룹 멤버만 전송됩니다.
- 그룹 소유자가 상속된 멤버십을 가지고 있는 경우 그룹을 전송하는 사용자가 새 소유자가 됩니다.

가시성 및 액세스 제한:

- 대상 부모 그룹의 가시성이 낮으면 모든 하위 그룹 및 프로젝트의 가시성 설정이 대상 부모 그룹의 가시성과 일치하도록 조정됩니다.
- 리포지토리 URL이 변경됩니다. 로컬 리포지토리를 새 위치를 가리키도록 업데이트해야 합니다. 자세한 내용은 [리포지토리 페이지 변경](../project/repository/_index.md#repository-path-changes)을 참조하세요.

패키지 및 컨테이너 레지스트리 제한:

- 대상 그룹이 [npm 명명 규칙](../packages/npm_registry/_index.md#naming-convention)을 따르는 npm 패키지가 그룹의 프로젝트나 하위 그룹에 있는 최상위 그룹인 경우 전송이 실패합니다.
- 그룹 엔드포인트를 사용하는 기존 패키지는 패키지의 그룹 수준 엔드포인트 설정 단계에 따라 업데이트해야 합니다.
- 패키지가 인스턴스 수준 엔드포인트를 사용하고 그룹이 다른 최상위 그룹으로 이동된 경우 기존 패키지 이름을 업데이트해야 합니다.

구독 제한:

- GitLab.com에 구독이 있는 최상위 그룹은 전송할 수 없습니다. 전송을 가능하게 하려면 먼저 최상위 그룹의 구독을 제거해야 합니다. 그런 다음 최상위 그룹을 다른 최상위 그룹의 하위 그룹으로 전송할 수 있습니다.

Secrets Manager 제한:

> [!warning]
> GitLab Secrets Manager의 그룹, 하위 그룹 및 프로젝트의 모든 비밀은 [전송 중에 영구적으로 삭제됩니다](../../ci/secrets/secrets_manager/_index.md#transfer-of-a-project-or-group).

## 이메일 알림 비활성화 {#disable-email-notifications}

그룹, 하위 그룹 및 프로젝트를 포함하는 그룹과 관련된 모든 이메일 알림을 비활성화할 수 있습니다.

이메일 알림을 비활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능** 섹션을 펼치세요.
1. **이메일 알림 활성화** 확인란을 선택 취소하세요.

### 이메일 알림에서 diff 미리보기 비활성화 {#disable-diff-previews-in-email-notifications}

{{< history >}}

- [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/24733) GitLab 15.6 [기능 플래그](../../administration/feature_flags/_index.md) `diff_preview_in_email`(포함). 기본적으로 비활성화되었습니다.
- GitLab 17.1에서 [일반적으로 사용 가능합니다](https://gitlab.com/gitlab-org/gitlab/-/issues/382055). 기능 플래그 `diff_preview_in_email`이 제거되었습니다.

{{< /history >}}

병합 요청의 코드에 주석을 달 때 GitLab은 이메일 알림에 diff의 몇 줄을 포함합니다. 일부 조직 정책은 이메일을 보안이 덜한 시스템으로 취급하거나 이메일을 위한 자체 인프라를 제어하지 못할 수 있습니다. 이는 소스 코드의 IP 또는 액세스 제어에 위험을 초래할 수 있습니다.

사전 요구 사항:

- 그룹의 소유자 역할이 있어야 합니다.

그룹의 모든 프로젝트에 대해 diff 미리보기를 비활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **diff 미리보기 포함**을 선택 취소하세요.
1. **변경 사항 저장**을 선택합니다.

## 그룹 및 프로젝트 액세스 토큰의 만료 이메일 {#expiry-emails-for-group-and-project-access-tokens}

{{< history >}}

- 상속된 그룹 멤버에 대한 알림이 GitLab 17.7 [기능 플래그](../../administration/feature_flags/_index.md) `pat_expiry_inherited_members_notification`(포함)에 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/463016). 기본적으로 비활성화되었습니다.
- 기능 플래그 `pat_expiry_inherited_members_notification`이 [GitLab 17.10에서 기본적으로 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/393772).
- 기능 플래그 `pat_expiry_inherited_members_notification`이 GitLab `17.11`에서 제거되었습니다

{{< /history >}}

다음 그룹 및 프로젝트 멤버는 곧 만료될 액세스 토큰에 대한 알림 이메일을 받습니다:

- 그룹 액세스 토큰의 경우:
  - 소유자 역할을 가진 멤버.
  - GitLab 17.7 이상에서는 그룹 또는 부모 그룹이 적절한 설정을 구성한 경우 그룹의 소유자 역할을 상속하는 멤버.
- 프로젝트 액세스 토큰의 경우:
  - 유지관리자 또는 소유자 역할을 가진 프로젝트의 멤버.
  - GitLab 17.7 이상에서는 프로젝트가 그룹에 속하기 때문에 유지관리자 또는 소유자 역할을 상속한 프로젝트 멤버이며, 해당 그룹 또는 부모 그룹이 적절한 설정을 구성한 경우.

그룹의 상속된 멤버에 대한 알림을 활성화할 수 있습니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **이 그룹 내 그룹 및 프로젝트 액세스 토큰에 대한 만료 알림 이메일은 다음으로 전송됩니다:** 아래에서 **그룹 또는 프로젝트의 모든 직접 및 상속된 멤버**를 선택하세요.
1. 선택 사항. **모든 하위 그룹에 대해 적용** 확인란을 선택하세요.
1. **변경 사항 저장**을 선택합니다.

자세한 정보는 다음을 참조하세요.

- 그룹의 경우 [그룹 액세스 토큰 설명서](settings/group_access_tokens.md#group-access-token-expiry-emails).
- 프로젝트의 경우 [프로젝트 액세스 토큰 설명서](../project/settings/project_access_tokens.md#project-access-token-expiry-emails).

## 그룹 액세스 토큰 만료에 대한 추가 웹훅 트리거 추가 {#add-additional-webhook-triggers-for-group-access-token-expiration}

{{< history >}}

- GitLab 17.9 [기능 플래그](../../administration/feature_flags/_index.md) `extended_expiry_webhook_execution_setting`(포함)에서 프로젝트 및 그룹 액세스 토큰 웹훅에 60일 및 30일 트리거를 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/499732)했습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.10에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/513684)합니다. 기능 플래그 `extended_expiry_webhook_execution_setting`이 제거되었습니다.

{{< /history >}}

GitLab은 그룹 토큰이 만료되기 전에 여러 [만료 이메일](settings/group_access_tokens.md#group-access-token-expiry-emails)을 보내고 관련 [웹훅](../project/integrations/webhook_events.md#project-and-group-access-token-events)을 트리거합니다. 기본적으로 이러한 웹훅은 토큰이 만료되기 7일 전에 트리거됩니다.

토큰이 만료되기 60일 및 30일 전에도 트리거하도록 이러한 웹훅을 구성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능** 섹션을 펼치세요.
1. **그룹 액세스 토큰 만료에 대한 추가 웹훅 트리거 추가** 확인란을 선택하세요.
1. **변경 사항 저장**을 선택합니다.

## 그룹 멘션 비활성화 {#disable-group-mentions}

사용자가 대화에 추가되고 [그룹을 멘션](../discussions/_index.md#mentions)할 때 이러한 사용자가 멤버인 그룹을 알림 받지 못하도록 할 수 있습니다.

멘션이 비활성화된 그룹은 자동 완성 드롭다운 목록에서 시각적으로 표시됩니다.

이러한 시각적 신호는 많은 사용자가 있는 그룹에 특히 유용합니다.

그룹 멘션을 비활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능** 섹션을 펼치세요.
1. **그룹 멘션이 비활성화되었습니다.**를 선택하세요.
1. **변경 사항 저장**을 선택합니다.

## 엔터프라이즈 사용자를 위한 개인 스니펫 제한 {#restrict-personal-snippets-for-enterprise-users}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

{{< history >}}

- GitLab 18.5에서 `allow_personal_snippets_setting`라는 [기능 플래그](../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200575)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.9에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/work_items/583564)합니다. 기능 플래그 `allow_personal_snippets_setting`이 제거되었습니다.

{{< /history >}}

그룹의 [엔터프라이즈 사용자](../enterprise_user/_index.md)가 개인 네임스페이스에서 [스니펫](../snippets.md)을 생성하지 못하도록 할 수 있습니다. 비활성화되면 엔터프라이즈 사용자는 여전히 프로젝트 스니펫을 만들 수 있으며 기존 개인 스니펫을 보고 편집할 수 있습니다.

사전 요구 사항:

- 그룹의 소유자 역할이 있어야 합니다.

엔터프라이즈 사용자를 위한 개인 스니펫을 제한하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능** 섹션을 펼치세요.
1. **개인 스니펫 허용** 확인란을 선택 취소하세요.
1. **변경 사항 저장**을 선택합니다.

## 그룹으로의 초대 방지 {#prevent-invitations-to-a-group}

{{< history >}}

- GitLab 18.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/189898)되었습니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

GitLab.com에서 사용자가 최상위 그룹의 하위 그룹 또는 프로젝트에 새 멤버를 초대하는 기능을 제거할 수 있습니다. 이것은 또한 그룹 소유자가 초대를 보내는 것을 중지합니다. 다시 사용자를 초대할 수 있으려면 먼저 이 설정을 비활성화해야 합니다.

GitLab Self-Managed 및 GitLab Dedicated 인스턴스에서 전체 인스턴스에 대한 사용자 초대를 방지할 수 있습니다. 자세한 내용은 [그룹 및 프로젝트로의 초대 방지](../../administration/settings/visibility_and_access_controls.md#prevent-invitations-to-groups-and-projects)를 참조하세요.

> [!note]
> [공유](../project/members/sharing_projects_groups.md) 또는 [마이그레이션](../import/_index.md) 같은 기능은 여전히 이러한 하위 그룹 및 프로젝트에 대한 액세스를 허용할 수 있습니다.

사전 요구 사항:

- 그룹의 소유자 역할이 있어야 합니다.

그룹으로의 초대를 방지하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능** 섹션을 펼치세요.
1. **그룹/프로젝트 멤버 초대 비활성화**를 선택하세요.
1. **변경 사항 저장**을 선택합니다.

## 멤버를 CSV로 내보내기 {#export-members-as-csv}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹 또는 하위 그룹의 멤버 목록을 CSV로 내보낼 수 있습니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹 또는 하위 그룹을 찾습니다.
1. **관리** > **멤버**를 선택하세요.
1. **CSV로 내보내기**를 선택합니다.
1. CSV 파일이 생성된 후 요청한 사용자에게 첨부 파일로 이메일로 전송됩니다.

출력은 직접 멤버 및 상위 그룹에서 상속된 멤버를 나열합니다. 선택한 그룹에서 `Minimal Access`를 가진 멤버의 경우 해당 `Max Role` 및 `Source`은 하위 그룹의 멤버십에서 파생됩니다. [이슈 390358](https://gitlab.com/gitlab-org/gitlab/-/issues/390358)은 그룹 멤버 CSV 내보내기 목록이 UI 멤버 목록과 일치하지 않는 것에 대한 논의를 추적합니다.

## 제한된 액세스 활성화 {#turn-on-restricted-access}

사전 요구 사항:

- 그룹의 소유자 역할이 있어야 합니다.
- 그룹 또는 그 하위 그룹 또는 프로젝트 중 하나가 외부적으로 공유되지 않아야 합니다.

제한된 액세스를 활성화하려면:

1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **좌석 제어** 아래에서 **제한된 액세스**를 선택하세요.

제한된 액세스를 켜면 [그룹 계층 구조 외부의 그룹 초대 방지](../project/members/sharing_projects_groups.md#prevent-inviting-groups-outside-the-group-hierarchy) 설정이 자동으로 켜집니다.

[그룹 및 하위 그룹의 프로젝트 공유](../project/members/sharing_projects_groups.md#prevent-a-project-from-being-shared-with-groups)를 독립적으로 구성할 수 있습니다.

## 그룹의 사용자 한도 설정 {#set-a-user-cap-for-a-group}

사전 요구 사항:

- 그룹의 소유자 역할을 할당받아야 합니다.

사용자 한도를 설정하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 최상위 그룹에만 한도를 설정할 수 있습니다.
1. **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **좌석 제어**에서 **사용자 한도 설정** 확인란을 선택하고 필드에 사용자 수를 입력하세요.
1. **변경 사항 저장**을 선택합니다.

그룹에 이미 사용자 한도 값보다 많은 사용자가 있는 경우 사용자는 제거되지 않습니다. 그러나 승인 없이는 더 추가할 수 없습니다.

사용자 한도를 늘려도 대기 중인 멤버가 승인되지 않습니다.

사용자 한도를 설정하면 [그룹 계층 구조 외부의 그룹 초대 방지](../project/members/sharing_projects_groups.md#prevent-inviting-groups-outside-the-group-hierarchy) 설정이 자동으로 켜집니다.

## 그룹의 사용자 한도 제거 {#remove-the-user-cap-for-a-group}

사용자 한도를 제거할 수 있으므로 그룹에 추가할 수 있는 멤버 수에 제한이 없습니다.

사전 요구 사항:

- 그룹의 소유자 역할을 할당받아야 합니다.

사용자 한도를 제거하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **좌석 제어**에서 **오픈 액세스**를 선택하세요.
1. **변경 사항 저장**을 선택합니다.

## 그룹의 대기 중인 멤버 승인 {#approve-pending-members-for-a-group}

청구 가능한 사용자 수가 사용자 한도에 도달하면 새 멤버가 대기 상태에 있게 되며 승인해야 합니다.

대기 중인 멤버는 청구 가능하지 않습니다. 멤버는 승인되고 더 이상 대기 상태가 아닌 후에만 청구 가능한 것으로 계산됩니다.

사전 요구 사항:

- 그룹의 소유자 역할을 할당받아야 합니다.

사용자 한도를 초과했기 때문에 대기 중인 멤버를 승인하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **사용 할당량**을 선택하세요.
1. **좌석** 탭에서 경고 아래 **대기 중인 승인 보기**를 선택하세요.
1. 승인할 각 멤버에 대해 **승인**을 선택하세요.

## 기본 제공 프로젝트 템플릿 제어 {#control-built-in-project-templates}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- `use_built_in_project_templates_enabled`라는 [기능 플래그](../../administration/feature_flags/_index.md)로 GitLab 19.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/230790)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 19.2에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/work_items/593623)입니다. 기능 플래그 `use_built_in_project_templates_enabled`이 제거되었습니다.

{{< /history >}}

[빌트인 프로젝트 템플릿](../project/_index.md#create-a-project-from-a-built-in-template)은 새 프로젝트에 시작 파일로 채웁니다. 사용자가 그룹에서 프로젝트를 만들 때 이러한 템플릿을 사용할 수 있는지 여부를 제어할 수 있습니다. 모든 하위 그룹에 대해 선택을 적용할 수도 있습니다.

이 설정은 계단식 상속을 사용합니다.

- 그룹은 가장 가까운 상위 그룹 또는 인스턴스에서 설정을 상속합니다.
- 그룹에 대해 설정된 값은 상속된 값을 무시합니다.
- 그룹에 대해 설정을 적용하면 모든 하위 그룹이 이를 상속하고 변경할 수 없습니다.
- 그룹에 대한 설정을 변경하면 새 값이 모든 하위 그룹으로 계단식으로 전달됩니다.

사전 요구 사항:

- 그룹의 소유자 역할이 있어야 합니다.

그룹의 기본 제공 프로젝트 템플릿을 제어하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **빌트인 프로젝트 템플릿**을 확장합니다.
1. **빌트인 프로젝트 템플릿 활성화** 확인란을 선택하거나 선택 해제합니다.
1. 선택 사항. 하위 그룹이 이 설정을 변경하지 못하도록 하려면 **모든 하위 그룹에 대해 적용** 확인란을 선택하세요.
1. **변경 사항 저장**을 선택합니다.

관리자가 [이 설정을 적용](../../administration/project_templates.md#built-in-project-templates)했거나 부모 그룹이 하위 그룹에 대해 적용했으면 설정이 잠겨 있고 변경할 수 없습니다.

## 그룹 파일 템플릿 {#group-file-templates}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹 파일 템플릿을 사용하여 일반적인 파일 유형의 템플릿 집합을 그룹의 모든 프로젝트와 공유합니다. 이는 [인스턴스 템플릿 리포지토리](../../administration/settings/instance_template_repository.md)와 유사합니다. 선택한 프로젝트는 해당 페이지에서 문서화한 것과 동일한 명명 규칙을 따라야 합니다.

템플릿 소스로 그룹의 프로젝트만 선택할 수 있습니다. 여기에는 그룹과 공유되는 프로젝트가 포함되지만 구성되는 그룹의 하위 그룹 또는 부모 그룹의 프로젝트는 제외됩니다.

하위 그룹 및 즉시 부모 그룹 모두에 대해 이 기능을 구성할 수 있습니다. 하위 그룹의 프로젝트는 해당 하위 그룹 및 즉시 부모 그룹의 템플릿에 액세스할 수 있습니다.

이슈 및 병합 요청에 대한 템플릿을 만드는 방법을 알아보려면 [설명 템플릿](../project/description_templates.md)을 참조하세요.

그룹을 템플릿 소스로 설정하여 그룹 수준에서 프로젝트 템플릿을 정의합니다. 자세한 내용은 [그룹 수준 프로젝트 템플릿](custom_project_templates.md)을 참조하세요.

### 그룹 파일 템플릿 활성화 {#enable-group-file-template}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹 파일 템플릿을 활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **템플릿** 섹션을 펼치세요.
1. 템플릿 리포지토리로 작동할 프로젝트를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 그룹 머지 점검 설정 {#group-merge-checks-settings}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹 소유자는 최상위 그룹에서 병합 요청 점검을 설정할 수 있으며, 이는 모든 하위 그룹 및 프로젝트에 적용됩니다.

설정이 하위 그룹 또는 프로젝트에 의해 상속되면 상속된 하위 그룹 또는 프로젝트에서 변경할 수 없습니다.

### 머지를 위해 성공적인 파이프라인 필요 {#require-a-successful-pipeline-for-merge}

그룹의 모든 자식 프로젝트를 구성하여 머지 전에 완벽하고 성공적인 파이프라인이 필요하도록 할 수 있습니다.

[프로젝트 수준 설정](../project/merge_requests/auto_merge.md#require-a-successful-pipeline-for-merge)도 참조하세요.

사전 요구 사항:

- 그룹의 소유자여야 합니다.

이 설정을 활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **병합 요청**을 펼치세요.
1. **머지 점검** 아래에서 **파이프라인이 성공해야 함**을 선택하세요. 이 설정은 또한 파이프라인이 없는 경우 병합 요청이 머지되는 것을 방지합니다.
1. **변경 사항 저장**을 선택합니다.

#### 생략한 파이프라인 후 머지 허용 {#allow-merge-after-skipped-pipelines}

[생략한 파이프라인](../../ci/pipelines/_index.md#skip-a-pipeline)이 병합 요청이 머지되는 것을 방지하지 않도록 구성할 수 있습니다.

[프로젝트 수준 설정](../project/merge_requests/auto_merge.md#allow-merge-after-skipped-pipelines)도 참조하세요.

사전 요구 사항:

- 그룹의 소유자여야 합니다.

이 동작을 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **병합 요청**을 펼치세요.
1. **머지 점검** 아래:
   - **파이프라인이 성공해야 함**을 선택하세요.
   - **생략한 파이프라인은 성공한 것으로 간주됩니다.**를 선택하세요.
1. **변경 사항 저장**을 선택합니다.

### 모든 스레드가 해결될 때까지 머지 방지 {#prevent-merge-unless-all-threads-are-resolved}

모든 스레드가 해결될 때까지 병합 요청이 머지되는 것을 방지할 수 있습니다. 이 설정을 활성화하면 그룹의 자식 프로젝트가 최소 하나의 열린 스레드가 있는 병합 요청에서 주황색으로 열린 스레드 수를 표시합니다.

사전 요구 사항:

- 그룹의 소유자여야 합니다.

이 설정을 활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **병합 요청**을 펼치세요.
1. **머지 점검** 아래에서 **모든 스레드가 해결되어야 합니다.**를 선택하세요.
1. **변경 사항 저장**을 선택합니다.

## 병합 요청 API에서 커밋 SHA 필요 {#require-a-commit-sha-on-the-merge-requests-api}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/244421)되었습니다. 새 그룹에 대해 기본적으로 활성화됩니다.
- 그룹 및 인스턴스 설정 UI가 GitLab 19.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/243465)되었습니다.
- GitLab 19.2.6, GitLab 19.3.2 및 GitLab 19.4에서 새 그룹에 대해 [비활성화로 변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251669)됨.

{{< /history >}}

검토된 커밋만 머지되도록 하기 위해 병합 요청 API에서 커밋 SHA를 요구합니다. 이 설정을 활성화하면 GitLab은 `sha` 매개변수를 생략하는 [병합 요청 머지](../../api/merge_requests.md#merge-a-merge-request) 엔드포인트에 대한 호출을 거부하고 `400` 오류를 반환합니다. `sha` 매개변수가 소스 브랜치의 현재 HEAD와 일치하지 않으면 머지가 실패합니다.

이 설정은 기본적으로 비활성화됩니다.

> [!note]
> GitLab Self-Managed 및 GitLab Dedicated의 경우 이 설정은 다음에서 생성된 새 그룹에 대해 기본적으로 활성화됩니다:
>
> - GitLab 19.2.0~GitLab 19.2.5
> - GitLab 19.3.0~GitLab 19.3.1
>
> 모든 새 그룹에 대해 기본적으로 설정을 비활성화하려면 설정을 끄고 **모든 하위 그룹에 대해 적용** 또는 **이 인스턴스의 모든 그룹에 대해 이 설정을 적용**을 선택하세요.

사전 요구 사항:

- 그룹의 소유자 역할.

병합 요청 API에서 커밋 SHA를 요구하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **병합 요청**을 펼치세요.
1. **병합 요청 API에서 커밋 SHA 필요** 확인란을 선택하세요.
1. 선택 사항. 이 설정을 모든 하위 그룹에 적용하고 하위 그룹이 변경하지 못하도록 하려면 **모든 하위 그룹에 대해 적용** 확인란을 선택하세요.
1. **변경 사항 저장**을 선택합니다.

관리자는 이 설정에 대한 인스턴스 전체 기본값을 설정할 수 있으며 선택적으로 새 그룹이 이를 무시할 수 없도록 적용할 수 있습니다.

사전 요구 사항:

- 인스턴스에 대한 관리자 액세스.

모든 그룹의 기본값을 설정하려면:

1. 왼쪽 사이드바 맨 아래에서 **운영자**를 선택합니다.
1. **설정** > **일반**을 선택합니다.
1. **병합 요청**을 펼치세요.
1. **병합 요청 API에서 커밋 SHA 필요** 확인란을 선택하세요.
1. 선택 사항. 이 설정을 인스턴스의 모든 새 그룹 및 기존 그룹에 적용하고 그룹이 변경하지 못하도록 하려면 **이 인스턴스의 모든 그룹에 대해 이 설정을 적용**을 선택하세요.
1. **변경 사항 저장**을 선택합니다.

## 그룹 병합 요청 승인 설정 {#group-merge-request-approval-settings}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹 승인 설정은 최상위 그룹의 하위 그룹 및 프로젝트의 [프로젝트 병합 요청 승인 설정](../project/merge_requests/approvals/settings.md)에 대한 기본값을 정의합니다. 그룹에 대해 방지 설정을 활성화하면 해당 프로젝트 설정이 잠기고 프로젝트 유지관리자가 변경할 수 없습니다. 방지 설정을 비활성화 상태로 두면 프로젝트 유지관리자가 개별 프로젝트에 대해 구성할 수 있습니다. 자세한 내용은 [인스턴스 또는 최상위 그룹에서 설정 계단식으로 전달](../project/merge_requests/approvals/settings.md#cascade-settings-from-the-instance-or-top-level-group)을 참조하세요.

그룹의 병합 요청 승인 설정을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **병합 요청 승인** 섹션을 펼치세요.
1. 원하는 설정을 선택하세요.
1. **변경 사항 저장**을 선택합니다.

승인 설정을 [승인 규칙](../project/merge_requests/approvals/rules.md)과 혼동하면 안 됩니다. 그룹에 대한 병합 요청 승인 규칙을 설정하는 기능에 대한 지원은 [에픽 4367](https://gitlab.com/groups/gitlab-org/-/work_items/4367)에서 추적됩니다.

## 그룹 활동 분석 {#group-activity-analytics}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹의 경우 지난 90일 동안 만든 병합 요청, 이슈 및 멤버 수를 볼 수 있습니다.

[그룹 위키](../project/wiki/group.md)의 변경 사항은 그룹 활동 분석에 표시되지 않습니다.

### 그룹 활동 보기 {#view-group-activity}

브라우저나 RSS 피드에서 그룹에서 수행된 가장 최근의 작업을 볼 수 있습니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **관리** > **활동**을 선택하세요.

활동 피드를 Atom 형식으로 보려면 **RSS** ({{< icon name="rss" >}}) 아이콘을 선택하세요.

## GitLab 크레딧 사용자 데이터 표시 {#display-gitlab-credits-user-data}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 사용자 데이터 표시를 허용하는 네임스페이스 설정이 GitLab 18.7 [기능 플래그](../../administration/feature_flags/_index.md) `usage_billing_dev`(포함)에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/215371)되었습니다. [기본적으로 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/215714).
- GitLab 18.10에서 `usage_billing_dev` 기능 플래그가 [제거](https://gitlab.com/gitlab-org/gitlab/-/work_items/566581)되었습니다.

{{< /history >}}

사전 요구 사항:

- 그룹 소유자여야 합니다.
- 보고 있는 그룹은 최상위 그룹이어야 합니다.

[GitLab 크레딧 대시보드](../../subscriptions/gitlab_credits_dashboard.md)에 사용자 데이터를 표시하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능** 섹션을 펼치세요.
1. **GitLab 크레딧 대시보드**의 경우 **사용자 데이터 표시** 확인란을 선택하세요.
1. **변경 사항 저장**을 선택합니다.
