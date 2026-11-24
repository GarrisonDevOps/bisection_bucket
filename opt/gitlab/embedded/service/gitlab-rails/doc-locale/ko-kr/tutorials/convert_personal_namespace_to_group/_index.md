---
stage: Tenant Scale
group: Organizations
info: For assistance with this tutorial, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
title: '자습서: 개인 네임스페이스를 그룹으로 전환'
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

개인 [네임스페이스](../../user/namespace/_index.md)로 시작했지만 기능이 부족하다면, 대신 그룹 네임스페이스로 전환할 수 있습니다. 그룹 네임스페이스를 사용하면 여러 하위 그룹을 만들고 멤버와 권한을 관리할 수 있습니다.

처음부터 시작할 필요는 없습니다. 새 그룹을 만들고 기존 프로젝트를 그룹으로 이동하여 추가 이점을 얻을 수 있습니다. 방법을 알아보려면 [튜토리얼: 개인 프로젝트를 그룹으로 이동](../move_personal_project_to_group/_index.md)

더 나아가서 개인 네임스페이스를 그룹 네임스페이스로 전환할 수 있습니다. 네임스페이스를 전환하면 기존 사용자명과 URL을 유지할 수 있습니다. 예를 들어 사용자명이 `alex`인 경우, 그룹의 `https://gitlab.example.com/alex` URL을 계속 사용할 수 있습니다.

이 튜토리얼은 다음 단계를 사용하여 개인 네임스페이스를 그룹 네임스페이스로 전환하는 방법을 설명합니다:

1. [그룹 만들기](#create-a-group)
1. [개인 네임스페이스에서 그룹으로 프로젝트 이전](#transfer-projects-from-the-personal-namespace-to-the-group)
1. [원래 사용자명 변경](#rename-the-original-username)
1. [새 그룹 네임스페이스를 원래 사용자명으로 변경](#rename-the-new-group-namespace-to-the-original-username)

예를 들어 개인 네임스페이스의 사용자명이 `alex`인 경우, 먼저 `alex-group` 이름의 그룹 네임스페이스를 만듭니다. 그런 다음 `alex`에서 `alex-group` 네임스페이스로 모든 프로젝트를 이동합니다. 마지막으로 `alex` 네임스페이스를 `alex-user`로 변경하고, `alex-group` 네임스페이스를 이제 사용 가능한 `alex` 사용자명으로 변경합니다.

## 그룹 생성 {#create-a-group}

1. 오른쪽 위 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 및 **새 그룹**을 선택합니다.
1. **그룹 이름**에서 그룹의 이름을 입력합니다.
1. **그룹 URL**에 그룹의 경로를 입력합니다. 이는 네임스페이스로 사용됩니다. 실제 경로에 대해 걱정하지 마세요. 이는 임시일 뿐입니다. 이 URL을 [마지막 단계](#rename-the-new-group-namespace-to-the-original-username)에서 개인 네임스페이스의 사용자명으로 변경합니다.
1. [가시성 수준](../../user/public_access.md)을 선택합니다.
1. 선택사항. 정보를 입력하여 경험을 개인화합니다.
1. **그룹 생성**를 선택합니다.

## 개인 네임스페이스에서 그룹으로 프로젝트 이전 {#transfer-projects-from-the-personal-namespace-to-the-group}

다음으로, 개인 네임스페이스에서 새 그룹으로 프로젝트를 이전해야 합니다. 한 번에 하나의 프로젝트만 이전할 수 있습니다. 여러 프로젝트를 이전하려면 각 프로젝트에 대해 아래 단계를 수행해야 합니다.

이전 프로세스를 시작하기 전에 다음을 확인합니다:

- 프로젝트에 대한 소유자 역할이 있습니다.
- [컨테이너 이미지](../../user/packages/container_registry/_index.md#move-or-rename-container-registry-repositories)를 제거합니다. 컨테이너 이미지가 포함된 프로젝트는 이전할 수 없습니다.
- npm 패키지를 제거합니다. npm 패키지가 포함된 프로젝트의 루트 네임스페이스는 업데이트할 수 없습니다.

프로젝트를 그룹으로 이전하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급**을 확장합니다.
1. **프로젝트 전송**에서 프로젝트를 이전할 그룹을 선택합니다.
1. **프로젝트 전송**을 선택합니다.
1. 프로젝트의 이름을 입력하고 **확인**을 선택합니다.

## 원래 사용자명 변경 {#rename-the-original-username}

다음으로, 개인 네임스페이스의 원래 사용자명을 변경하여 새 그룹 네임스페이스에서 사용자명을 사용할 수 있도록 합니다. 개인 네임스페이스를 계속 다른 개인 프로젝트에 사용하거나, [해당 사용자 계정을 삭제](../../user/profile/account/delete_account.md)할 수 있습니다.

개인 네임스페이스의 이름을 변경하는 순간부터 사용자명을 사용할 수 있으므로 다른 사람이 이 사용자명으로 계정을 등록할 수 있습니다. 이를 방지하려면 가능한 한 빨리 [새 그룹의 이름을 변경](#rename-the-new-group-namespace-to-the-original-username)해야 합니다.

[사용자의 사용자명을 변경](../../user/profile/_index.md#change-your-username)하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **계정**을 선택합니다.
1. **사용자명 변경** 섹션에서 경로로 사용할 새 사용자명을 입력합니다.
1. **사용자명 업데이트**를 선택합니다.

## 새 그룹 네임스페이스를 원래 사용자명으로 변경 {#rename-the-new-group-namespace-to-the-original-username}

마지막으로, 새 그룹의 URL을 원래 개인 네임스페이스의 사용자명으로 변경합니다.

[그룹 경로를 변경](../../user/group/manage.md#change-a-groups-path)하려면 (그룹 URL):

1. 상단 바에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급** 섹션을 펼칩니다.
1. **그룹 URL 변경** 아래에서 사용자의 원래 사용자명을 입력합니다.
1. **그룹 URL 변경**을 선택합니다.

완료되었습니다! 개인 네임스페이스를 그룹으로 전환했으므로 이제 프로젝트에서 작업하고 더 많은 멤버와 협업할 수 있는 새로운 가능성이 열립니다.
