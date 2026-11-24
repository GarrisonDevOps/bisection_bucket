---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 사용자 계정을 제거하고 관련 기록 및 기여도를 관리합니다.
title: 사용자 삭제
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab 인스턴스에서 사용자를 삭제할 수 있습니다:

- 사용자 본인입니다.
- 관리자입니다.

> [!note]
> 사용자를 삭제하면 해당 사용자 네임스페이스의 모든 프로젝트가 삭제됩니다.

## 자신의 계정 삭제 {#delete-your-own-account}

{{< details >}}

- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

{{< history >}}

- GitLab 16.0에서 사용자가 자신의 계정을 삭제한 후 사용자 레코드 삭제 사이의 지연 [기능 플래그](../../../administration/feature_flags/_index.md)가 도입되었으며 `delay_delete_own_user` 이름으로 지정되었습니다. GitLab.com에서 기본적으로 활성화됨.

{{< /history >}}

> [!note]
> GitLab Self-Managed에서는 이 기능이 기본적으로 비활성화되어 있습니다. [애플리케이션 설정 API](../../../api/settings.md)를 사용하여 인스턴스에 대해 `delay_user_account_self_deletion` 설정을 활성화합니다.

계정 삭제를 예약할 수 있습니다. 계정을 삭제하면 삭제 대기 상태가 됩니다. 일반적으로 삭제는 1~2시간 내에 완료되지만 댓글, 이슈, 머지 리퀘스트, 노트 또는 스니펫과 연관된 계정의 경우 최대 7일이 걸릴 수 있습니다.

계정이 삭제 대기 중인 동안:

- 계정이 [차단](../../../administration/moderate_users.md#block-a-user)됩니다.
- 동일한 사용자명으로 새 계정을 생성할 수 없습니다.
- 먼저 이메일 주소를 변경하지 않는 한 동일한 주요 이메일 주소로 새 계정을 생성할 수 없습니다.

> [!note]
> 계정이 삭제된 후 모든 사용자가 동일한 사용자명으로 사용자 계정을 생성할 수 있습니다. 다른 사용자가 사용자명을 차지하면 이를 다시 요청할 수 없습니다.

자신의 계정을 삭제하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **계정**을 선택합니다.
1. **계정 삭제**를 선택합니다.

GitLab.com에서 계정을 삭제할 수 없으면 [개인 데이터 요청](https://support.gitlab.io/personal-data-request/)을 제출하여 계정 및 데이터를 GitLab에서 제거하세요.

## 사용자와 기여도 삭제 {#delete-users-and-user-contributions}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

사전 요구 사항:

- 인스턴스의 관리자여야 합니다.

사용자를 삭제하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **개요** > **사용자**를 선택합니다.
1. 사용자를 선택합니다.
1. **계정** 탭 아래에서 다음을 선택합니다:
   - **사용자 삭제**는 사용자만 삭제하고 [관련 기록](#associated-records)을 유지합니다. 선택한 사용자가 그룹의 유일한 소유자인 경우 이 옵션을 사용할 수 없습니다.
   - **사용자와 기여 삭제**는 사용자 및 관련 기록을 삭제합니다. 이 옵션은 사용자가 그룹의 유일한 직접 소유자인 모든 그룹(및 이 그룹 내의 프로젝트)도 제거합니다. 상속된 소유권은 적용되지 않습니다.

> [!warning]
> **사용자와 기여 삭제** 옵션을 사용하면 의도한 것보다 더 많은 데이터를 제거할 수 있습니다. 추가 정보는 [관련 기록](#associated-records)을 참조하세요.

### 관련 기록 {#associated-records}

사용자를 삭제할 때 다음 중 하나를 수행할 수 있습니다:

- 사용자만 삭제하되 기여도는 고스트 사용자로 이동:
  - 이 내부 사용자는 모든 삭제된 사용자의 기여도에 대한 컨테이너 역할을 합니다.
  - GitLab.com에서는 이 사용자를 Ghost User(`@ghost1`)라고 합니다.
  - 사용자 프로필 및 개인 프로젝트는 Ghost User로 이동하는 대신 삭제됩니다.
- 사용자 및 기여도를 삭제합니다(다음 포함):
  - 학대 보고서입니다.
  - 이모지 반응입니다.
  - 사용자가 소유자 역할을 가진 유일한 사용자인 그룹입니다.
  - 개인 액세스 토큰입니다.
  - 에픽.
  - 이슈.
  - 머지 리퀘스트.
  - 스니펫입니다.
  - 다른 사용자의 [커밋](../../project/repository/_index.md#commit-changes-to-a-repository), [에픽](../../group/epics/_index.md), [이슈](../../project/issues/_index.md), [머지 리퀘스트](../../project/merge_requests/_index.md) 및 [스니펫](../../snippets.md)에 대한 [노트 및 댓글](../../../api/notes.md)입니다.

두 경우 모두 커밋은 [사용자 정보](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects#_git_commit_objects)를 보유하며 따라서 [Git 리포지토리](../../project/repository/_index.md) 내의 데이터 무결성을 유지합니다.

삭제의 대안은 [사용자 차단](../../../administration/moderate_users.md#block-a-user)입니다.

사용자가 [학대 보고서](../../../administration/review_abuse_reports.md) 또는 스팸 로그에서 삭제되면 이 관련 기록은 항상 제거됩니다.

관련 기록 삭제 옵션은 [API](../../../api/users.md#delete-a-user)뿐만 아니라 **운영자** 영역에서도 요청할 수 있습니다.

> [!warning]
> 사용자 승인은 사용자 ID와 연결됩니다. 다른 사용자 기여도는 관련 사용자 ID가 없습니다. 사용자를 삭제하고 기여도를 고스트 사용자로 이동하면 승인 기여도는 누락되었거나 잘못된 사용자 ID를 참조합니다. 사용자를 삭제하는 대신 [차단](../../../administration/moderate_users.md#block-a-user), [금지](../../../administration/moderate_users.md#ban-a-user) 또는 [비활성화](../../../administration/moderate_users.md#deactivate-a-user)를 고려하세요.

## GitLab Self-Managed 인스턴스에서 루트 계정 삭제 {#delete-the-root-account-on-a-gitlab-self-managed-instance}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

> [!warning]
> 루트 계정은 시스템에서 가장 권한이 높은 계정입니다. 루트 계정을 삭제하면 인스턴스에 사용 가능한 다른 관리자가 없는 경우 인스턴스 [**운영자** 영역](../../../administration/admin_area.md)에 대한 액세스 권한을 잃을 수 있습니다.

UI 또는 [GitLab Rails 콘솔](../../../administration/operations/rails_console.md)을 사용하여 루트 계정을 삭제할 수 있습니다.

루트 계정을 삭제하기 전에:

1. 루트 계정에 대해 [프로젝트](../../project/settings/project_access_tokens.md) 또는 [개인 액세스 토큰](../personal_access_tokens.md)을 생성했고 워크플로우에서 사용하는 경우 루트 계정에서 새 관리자로 필요한 권한 또는 소유권을 전송하세요.
1. [GitLab Self-Managed 인스턴스를 백업](../../../administration/backup_restore/backup_gitlab.md)하세요.
1. 대신 [비활성화](../../../administration/moderate_users.md#deactivate-a-user) 또는 [차단](../../../administration/moderate_users.md#block-and-unblock-users) 루트 계정을 고려하세요.

### UI 사용 {#use-the-ui}

사전 요구 사항:

- GitLab Self-Managed 인스턴스의 관리자여야 합니다.

루트 계정을 삭제하려면:

1. **운영자** 영역에서 [관리자 액세스 권한이 있는 새 사용자 생성](create_accounts.md#create-a-user-in-the-admin-area)을 수행하세요. 이렇게 하면 루트 계정 삭제와 관련된 위험을 완화하면서 인스턴스에 대한 관리자 액세스 권한을 유지합니다.
1. [루트 계정 삭제](#delete-users-and-user-contributions)합니다.

### GitLab Rails 콘솔 사용 {#use-the-gitlab-rails-console}

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 잘못된 조건에서 실행되면 손상을 일으킬 수 있습니다. 항상 먼저 테스트 환경에서 명령을 실행하고 복원할 준비가 된 백업 인스턴스를 준비합니다.

사전 요구 사항:

- GitLab Rails 콘솔에 액세스할 수 있어야 합니다.

Rails 콘솔에서 루트 계정을 삭제하려면:

1. 다른 기존 사용자에게 관리자 액세스 권한을 부여합니다:

   ```ruby
   user = User.find(username: 'Username') # or use User.find_by(email: 'email@example.com') to find by email
   user.admin = true
   user.save!
   ```

   이렇게 하면 루트 계정 삭제와 관련된 위험을 완화하면서 인스턴스에 대한 관리자 액세스 권한을 유지합니다.

1. 루트 계정을 삭제하려면 다음 중 하나를 수행하세요:

   - 루트 계정을 차단합니다:

     ```ruby
     # This needs to be a current admin user
     current_user = User.find(username: 'Username')

     # This is the root user to block
     user = User.find(username: 'Username')

     ::Users::BlockService.new(current_user).execute(user)
     ```

   - 루트 사용자를 비활성화합니다:

     ```ruby
     # This needs to be a current admin user
     current_user = User.find(username: 'Username')

     # This is the root user to deactivate
     user = User.find(username: 'Username')

     ::Users::DeactivateService.new(current_user, skip_authorization: true).execute(user)
     ```
