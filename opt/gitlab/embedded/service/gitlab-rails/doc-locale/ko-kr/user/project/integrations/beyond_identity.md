---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Beyond Identity와 GitLab을 통합하여 사용자 계정에 추가된 GPG 키를 확인합니다.
title: Beyond Identity
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab에서 사용자는 [프로필에 GPG 키를 추가한 후](../repository/signed_commits/gpg.md) 커밋에 서명할 수 있습니다. [Beyond Identity](https://www.beyondidentity.com/)와의 GitLab 통합은 이 기능을 확장합니다.

구성되면 이 통합은 Beyond Identity를 사용하여 사용자가 프로필에 추가하는 모든 새로운 GPG 키를 검증합니다. 검증을 통과하지 못한 키는 거부되며, 사용자는 새 키를 업로드해야 합니다.

사용자가 서명된 커밋을 GitLab 인스턴스에 푸시하면 GitLab은 사전 수신 확인을 실행하여 해당 커밋을 사용자 프로필에 저장된 GPG 키와 비교하여 검증합니다. 이렇게 하면 검증된 키로 서명된 커밋만 허용됩니다.

## 인스턴스에 대한 Beyond Identity 통합 설정 {#set-up-the-beyond-identity-integration-for-your-instance}

사전 요구 사항:

- GitLab 인스턴스에 대한 관리자(administrator) 액세스 권한이 있어야 합니다.
- GitLab 프로필에 사용된 이메일 주소는 Beyond Identity Authenticator의 키에 할당된 이메일 주소와 동일해야 합니다.
- Beyond Identity API 토큰이 필요합니다. 해당 영업 엔지니어에게 요청할 수 있습니다.

인스턴스에 대한 Beyond Identity 통합을 활성화하려면:

1. 관리자로 GitLab에 로그인합니다.
1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Beyond Identity**를 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. **API 토큰**에 Beyond Identity에서 받은 API 토큰을 붙여넣습니다.
1. **변경 사항 저장**을 선택합니다.

인스턴스에 대한 Beyond Identity 통합이 이제 활성화되었습니다.

## GPG 키 검증 {#gpg-key-verification}

사용자가 프로필에 GPG 키를 추가하면 키가 검증됩니다:

- Beyond Identity Authenticator에서 발급하지 않은 키는 허용됩니다.
- Beyond Identity Authenticator에서 발급했지만 키가 유효하지 않으면 거부됩니다. 예를 들어 사용자의 GitLab 프로필에 사용된 이메일이 Beyond Identity Authenticator의 키에 할당된 이메일과 다릅니다.

사용자가 커밋을 푸시하면 GitLab은 해당 커밋이 사용자 프로필에 업로드된 GPG 서명으로 서명되었는지 확인합니다. 서명을 검증할 수 없으면 푸시가 거부됩니다. 웹 커밋은 서명 없이 허용됩니다.

## 서비스 계정에 대한 푸시 확인 건너뛰기 {#skip-push-check-for-service-accounts}

사전 요구 사항:

- GitLab 인스턴스에 대한 관리자(administrator) 액세스 권한이 있어야 합니다.

[서비스 계정](../../profile/service_accounts.md)에 대한 푸시 확인을 건너뛰려면:

1. 관리자로 GitLab에 로그인합니다.
1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Beyond Identity**를 선택합니다.
1. **서비스 계정 제외** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## Beyond Identity 확인에서 그룹 또는 프로젝트 제외 {#exclude-groups-or-projects-from-the-beyond-identity-check}

{{< history >}}

- GitLab 17.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/454372)되었으며, [기능 플래그](../../../administration/feature_flags/_index.md)는 `beyond_identity_exclusions`로 명명되었습니다. 기본적으로 활성화됩니다.
- 그룹을 제외하는 옵션은 GitLab 17.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/454372)되었습니다.
- GitLab 17.7에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/457893)됩니다. `beyond_identity_exclusions` 기능 플래그가 제거되었습니다.

{{< /history >}}

사전 요구 사항:

- GitLab 인스턴스에 대한 관리자(administrator) 액세스 권한이 있어야 합니다.

Beyond Identity 확인에서 그룹 또는 프로젝트를 제외하려면:

1. 관리자로 GitLab에 로그인합니다.
1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Beyond Identity**를 선택합니다.
1. **제외 사항** 탭을 선택합니다.
1. **배제 추가**를 선택합니다.
1. 드로어에서 제외할 그룹 또는 프로젝트를 검색하고 선택합니다.
1. **배제 추가**를 선택합니다.
