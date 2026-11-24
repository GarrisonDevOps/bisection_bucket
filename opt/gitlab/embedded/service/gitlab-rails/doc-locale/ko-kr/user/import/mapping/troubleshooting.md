---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 마이그레이션 후 기여도 및 멤버십 매핑 문제 해결
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

플레이스홀더 사용자를 다시 할당하는 중에 다음과 같은 문제가 발생할 수 있습니다.

## 소스 사용자 재할당 실패 {#source-user-reassignment-failed}

`failed` 상태인 소스 사용자의 재할당을 다시 시도하려면 GraphQL API 또는 Rails 콘솔을 사용할 수 있습니다. 자세한 내용은 [이슈 589777](https://gitlab.com/gitlab-org/gitlab/-/work_items/589777)을 참조하세요. UI 지원은 [이슈 593001](https://gitlab.com/gitlab-org/gitlab/-/work_items/593001)에서 논의됩니다.

### GraphQL API 사용 {#use-the-graphql-api}

{{< history >}}

- GitLab 18.11에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/589777)되었습니다.

{{< /history >}}

`importSourceUserRetryFailedReassignment` 뮤테이션을 사용하여 실패한 재할당을 다시 시도하세요:

```graphql
mutation {
  importSourceUserRetryFailedReassignment(input: { id: "gid://gitlab/Import::SourceUser/<SOURCE_USER_ID>" }) {
    importSourceUser {
      id
      status
    }
    errors
  }
}
```

`<SOURCE_USER_ID>`을 import 소스 사용자 ID로 바꾸세요. 네임스페이스에서 `importSourceUsers`을 쿼리하여 이 ID를 찾을 수 있습니다.

### Rails 콘솔 사용 {#use-the-rails-console}

[Rails 콘솔](../../../administration/operations/rails_console.md)에서 수동으로 실패한 소스 사용자를 다시 시도할 수 있습니다:

```ruby
# Find by the source user's placeholder user ID because placeholder user IDs are easy to fetch from the UI
placeholder_user_id = <PLACEHOLDER_USER_ID>
import_source_user = Import::SourceUser.find_by(placeholder_user_id: placeholder_user_id)

if import_source_user.failed?
  import_source_user.update!(status: Import::SourceUser::STATUSES[:reassignment_in_progress])
  Import::ReassignPlaceholderUserRecordsWorker.perform_async(import_source_user.id)
  puts "Reassignment retry queued"
else
  puts "Import source user status: #{import_source_user.status} (expected 'failed')"
end
```

### 반복된 실패 조사 {#investigate-repeated-failures}

소스 사용자가 다시 실패하면 [`importer.log`](../../../administration/logs/_index.md#importerlog)을 확인하여 `Failed to reassign placeholder user` 메시지가 포함된 모든 로그를 찾아 근본 원인을 조사하기 시작하세요.

## 소스 사용자는 성공적으로 재할당되었지만 플레이스홀더 사용자가 삭제되지 않음 {#source-user-reassigned-successfully-but-its-placeholder-user-was-not-deleted}

플레이스홀더 사용자는 사용자 기여도를 성공적으로 재할당한 후 삭제됩니다. 그러나 플레이스홀더 사용자의 ID를 참조하는 일부 데이터베이스 레코드가 재할당 후에도 데이터베이스에 계속 존재할 수 있어 플레이스홀더 사용자가 삭제되는 것을 방지할 수 있습니다. 이 경우 관리자는 관리자 사용자 테이블에서 플레이스홀더 사용자를 계속 볼 수 있습니다. 플레이스홀더 사용자는 라이선스 제한에 포함되지 않으며 일반적인 GitLab 작업에 영향을 주지 않지만 일부 관리자는 마이그레이션 후 모든 플레이스홀더 사용자가 삭제되기를 원할 수 있습니다.

GitLab 18.5 이전 버전에서 플레이스홀더 사용자를 재할당하는 사용자는 이 시나리오에 더 자주 마주칠 가능성이 있습니다. 이 경우 `Unable to delete placeholder user because it is still referenced in other tables` 메시지가 [`importer.log`](../../../administration/logs/_index.md#importerlog)에 나타나며 플레이스홀더 사용자의 ID와 연결됩니다.

이러한 사용자를 삭제하려면 다음 중 하나를 수행할 수 있습니다:

- [관리자로서 플레이스홀더 사용자 삭제](../../profile/account/delete_account.md#delete-users-and-user-contributions). 이 방식은 남은 플레이스홀더 사용자 기여도를 모두 삭제할 수 있다고 확신할 때 가장 좋습니다.
- GitLab 인스턴스를 GitLab 18.6 이상으로 업그레이드하고 Rails 콘솔에서 플레이스홀더 사용자의 플레이스홀더 재할당을 다시 시도하세요. 이 방식은 재할당이 GitLab 18.5 이전에 완료되었고 남은 플레이스홀더 사용자 기여도가 무엇인지 확실하지 않을 때 가장 좋습니다.

[Rails 콘솔](../../../administration/operations/rails_console.md)에서 완료된 플레이스홀더 사용자의 재할당을 다시 시도하려면:

```ruby
# Find the placeholder user's source user
placeholder_user_id = <PLACEHOLDER_USER_ID>
import_source_user = Import::SourceUser.find_by(placeholder_user_id: placeholder_user_id)

if import_source_user.completed?
  import_source_user.update!(status: Import::SourceUser::STATUSES[:reassignment_in_progress])
  Import::ReassignPlaceholderUserRecordsWorker.perform_async(import_source_user.id)
  puts "Reassignment retry queued"
else
  puts "Import source user status: #{import_source_user.status} (expected 'completed')"
end
```
