---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 그룹 문제 해결
---

## 네임스페이스 및 그룹의 유효성 검사 오류 {#validation-errors-on-namespaces-and-groups}

네임스페이스 또는 그룹을 생성하거나 업데이트할 때 다음 검사를 수행합니다:

- 네임스페이스는 상위 항목을 가져야 하지 않습니다.
- 그룹 상위 항목은 네임스페이스가 아닌 그룹이어야 합니다.

GitLab 설치에서 이러한 오류가 발생할 가능성은 낮지만 [지원 문의](https://support.gitlab.com/)하면 GitLab이 이 유효성 검사를 개선할 수 있습니다.

## SQL 쿼리를 사용하여 그룹 찾기 {#find-groups-using-an-sql-query}

[Rails 콘솔](../../administration/operations/rails_console.md)에서 SQL 쿼리를 기반으로 하는 그룹 배열을 찾아서 저장하려면:

```ruby
# Finds groups and subgroups that end with '%oup'
Group.find_by_sql("SELECT * FROM namespaces WHERE name LIKE '%oup'")
=> [#<Group id:3 @test-group>, #<Group id:4 @template-group/template-subgroup>]
```

## Rails 콘솔을 사용하여 하위 그룹을 다른 위치로 이동 {#transfer-subgroup-to-another-location-using-rails-console}

UI 또는 API를 통해 그룹 이동이 작동하지 않으면 [Rails 콘솔 세션](../../administration/operations/rails_console.md#starting-a-rails-console-session)에서 이동을 시도할 수 있습니다:

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 올바른 조건 하에서 실행되지 않으면 손상을 야기할 수 있습니다. 항상 테스트 환경에서 먼저 명령을 실행하고 복원할 준비가 된 백업 인스턴스가 있어야 합니다.

```ruby
user = User.find_by_username('<username>')
group = Group.find_by_name("<group_name>")
## Set parent_group = nil to make the subgroup a top-level group
parent_group = Group.find_by(id: "<group_id>")
service = ::Groups::TransferService.new(group, user)
service.execute(parent_group)
```

## 그룹 이동이 `transfer_in_progress` 또는 `transfer_scheduled` 상태로 멈춤 {#group-transfer-stuck-in-transfer_in_progress-or-transfer_scheduled-state}

그룹 이동은 비동기 이동 작업이 실패할 때 멈출 수 있습니다. 예를 들어 잠금 경합 또는 명령문 시간 초과로 인해 멈출 수 있습니다. 이동을 다시 시도하면 다음이 반환됩니다:

`Unable to initiate transfer. The group may already have a transfer in progress.`

GitLab 19.1 이상에서는 이동을 다시 시도하세요. 네임스페이스가 여전히 `transfer_in_progress` 또는 `transfer_scheduled` 상태에 있어도 GitLab이 이동을 다시 예약합니다.

GitLab 19.1보다 이전 버전에서는 이동을 다시 시도하기 전에 [Rails 콘솔 세션](../../administration/operations/rails_console.md#starting-a-rails-console-session)에서 오래된 이동 상태를 취소하세요:

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 올바른 조건 하에서 실행되지 않으면 손상을 야기할 수 있습니다. 항상 테스트 환경에서 먼저 명령을 실행하고 복원할 준비가 된 백업 인스턴스가 있어야 합니다.

```ruby
Group.find_by_full_path('<group_path>').cancel_transfer!
```

## 삭제 대기 중인 그룹을 Rails 콘솔을 사용하여 찾기 {#find-groups-pending-deletion-using-rails-console}

삭제 대기 중인 모든 그룹을 찾아야 하면 [Rails 콘솔 세션](../../administration/operations/rails_console.md#starting-a-rails-console-session)에서 다음 명령을 사용할 수 있습니다:

```ruby
Group.all.each do |g|
 if g.self_deletion_scheduled?
    puts "Group ID: #{g.id}"
    puts "Group name: #{g.name}"
    puts "Group path: #{g.full_path}"
 end
end
```

## Rails 콘솔을 사용하여 그룹 삭제 {#delete-a-group-using-rails-console}

경우에 따라 그룹 삭제가 멈힐 수 있습니다. 필요한 경우 [Rails 콘솔 세션](../../administration/operations/rails_console.md#starting-a-rails-console-session)에서 다음 명령을 사용하여 그룹을 삭제할 수 있습니다:

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 올바른 조건 하에서 실행되지 않으면 손상을 야기할 수 있습니다. 항상 테스트 환경에서 먼저 명령을 실행하고 복원할 준비가 된 백업 인스턴스가 있어야 합니다.

```ruby
GroupDestroyWorker.new.perform(group_id, user_id)
```

## 그룹 또는 프로젝트에 대한 사용자의 최대 권한 찾기 {#find-a-users-maximum-permissions-for-a-group-or-project}

관리자는 그룹 또는 프로젝트에 대한 사용자의 최대 권한을 찾을 수 있습니다.

1. [Rails 콘솔 세션](../../administration/operations/rails_console.md#starting-a-rails-console-session)을 시작합니다.
1. 다음 명령을 실행합니다:

   ```ruby
   user = User.find_by_username 'username'
   project = Project.find_by_full_path 'group/project'
   user.max_member_access_for_project project.id
   ```

   ```ruby
   user = User.find_by_username 'username'
   group = Group.find_by_full_path 'group'
   user.max_member_access_for_group group.id
   ```

## 배지 `Project Invite/Group Invite`를 사용하여 청구 가능한 멤버를 제거할 수 없음 {#unable-to-remove-billable-members-with-badge-project-invitegroup-invite}

다음 오류는 일반적으로 사용자가 [프로젝트](../project/members/sharing_projects_groups.md) 또는 [그룹](../project/members/sharing_projects_groups.md#invite-a-group-to-a-group)과 공유된 외부 그룹에 속할 때 발생합니다:

<!-- vale gitlab_base.LatinTerms = NO -->
`Members who were invited via a group invitation cannot be removed. You can either remove the entire group, or ask an Owner of the invited group to remove the member.`
<!-- vale gitlab_base.LatinTerms = YES -->

사용자를 청구 가능한 멤버로 제거하려면 다음 옵션 중 하나를 따르세요:

- 프로젝트 또는 그룹 멤버 페이지에서 초대된 그룹 멤버십을 제거하세요.
- 권장하는 방식입니다. 그룹에 액세스할 수 있으면 초대된 그룹에서 직접 사용자를 제거하세요.

## 권한 부족 또는 권한 없음, 삭제 버튼 비활성화 {#missing-or-insufficient-permission-delete-button-disabled}

이 오류는 일반적으로 사용자가 그룹 이동 중에 보관된 프로젝트에서 `container_registry` 이미지를 제거하려고 할 때 발생합니다. 이 오류를 해결하려면:

1. 프로젝트 보관을 취소하세요.
1. `container_registry` 이미지를 삭제하세요.
1. 프로젝트를 보관하세요.

## `Awaiting user signup` 배지가 있는 보류 중인 사용자를 승인할 수 없는 그룹 소유자 {#group-owner-unable-to-approve-pending-users-with-awaiting-user-signup-badge}

GitLab이 아닌 사용자에 대한 이메일 초대장은 `Pending members` 아래에 `Awaiting user signup` 상태로 나열됩니다. 사용자가 GitLab.com에 등록하면 상태가 `Pending owner action`로 업데이트되고 그룹 소유자가 승인 프로세스를 완료할 수 있습니다.

## 지원 기술 자료 {#support-knowledge-base}

문제가 계속되면 [GitLab 지원 기술 자료](https://support.gitlab.com/hc/en-us/)를 참조하세요.
