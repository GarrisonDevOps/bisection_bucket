---
stage: Tenant Scale
group: Organizations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 프로젝트 문제 해결
description: "문제 해결, 일반적인 문제, 디버깅 및 오류 해결."
---

프로젝트로 작업할 때 다음의 문제가 발생하거나 특정 작업을 완료하기 위해 다른 방법이 필요할 수 있습니다.

## `An error occurred while fetching commit data` {#an-error-occurred-while-fetching-commit-data}

프로젝트를 방문할 때, 브라우저에서 광고 차단기를 사용하면 `An error occurred while fetching commit data` 메시지가 표시될 수 있습니다. 해결책은 액세스하려는 GitLab 인스턴스에 대해 광고 차단기를 비활성화하는 것입니다.

## SQL 쿼리를 사용하여 프로젝트 찾기 {#find-projects-using-an-sql-query}

[Rails 콘솔 세션](../../administration/operations/rails_console.md#starting-a-rails-console-session)에서 SQL 쿼리를 기반으로 프로젝트 배열을 찾고 저장할 수 있습니다:

```ruby
# Finds projects that end with '%ject'
projects = Project.find_by_sql("SELECT * FROM projects WHERE name LIKE '%ject'")
=> [#<Project id:12 root/my-first-project>>, #<Project id:13 root/my-second-project>>]
```

## 프로젝트 또는 리포지토리의 캐시 지우기 {#clear-a-projects-or-repositorys-cache}

프로젝트 또는 리포지토리가 업데이트되었지만 상태가 UI에 반영되지 않는 경우, 프로젝트 또는 리포지토리의 캐시를 지워야 할 수 있습니다. [Rails 콘솔 세션](../../administration/operations/rails_console.md#starting-a-rails-console-session)과 다음 중 하나를 통해 이를 수행할 수 있습니다:

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 올바른 조건 하에서 실행되지 않으면 손상을 야기할 수 있습니다. 항상 테스트 환경에서 먼저 명령을 실행하고 복원할 준비가 된 백업 인스턴스가 있어야 합니다.

```ruby
## Clear project cache
ProjectCacheWorker.perform_async(project.id)

## Clear repository .exists? cache
project.repository.expire_exists_cache
```

## 삭제 대기 중인 프로젝트 찾기 {#find-projects-that-are-pending-deletion}

삭제 표시되었지만 아직 삭제되지 않은 모든 프로젝트를 찾아야 하는 경우, [Rails 콘솔 세션을 시작](../../administration/operations/rails_console.md#starting-a-rails-console-session)하고 다음을 실행합니다:

```ruby
projects = Project.where(pending_delete: true)
projects.each do |p|
  puts "Project ID: #{p.id}"
  puts "Project name: #{p.name}"
  puts "Repository path: #{p.repository.full_path}"
end
```

### 콘솔을 사용하여 프로젝트 이전 {#transfer-a-project-using-console}

UI 또는 API를 통해 프로젝트를 이전하는 것이 작동하지 않는 경우, [Rails 콘솔 세션](../../administration/operations/rails_console.md#starting-a-rails-console-session)에서 이전을 시도할 수 있습니다.

```ruby
p = Project.find_by_full_path('<project_path>')

# To set the owner of the project
current_user = p.creator

# Namespace where you want this to be moved
namespace = Namespace.find_by_full_path("<new_namespace>")

Projects::TransferService.new(p, current_user).execute(namespace)
```

## `transfer_in_progress` 또는 `transfer_scheduled` 상태에 갇힌 프로젝트 이전 {#project-transfer-stuck-in-transfer_in_progress-or-transfer_scheduled-state}

프로젝트 이전은 비동기 이전 작업이 실패할 때, 예를 들어 잠금 경합 또는 문 시간 초과로 인해 중단될 수 있습니다. 이동을 다시 시도하면 다음이 반환됩니다:

`Unable to initiate transfer. The project may already have a transfer in progress.`

GitLab 19.1 이상에서는 이동을 다시 시도하세요. GitLab은 프로젝트 네임스페이스가 여전히 `transfer_in_progress` 또는 `transfer_scheduled` 상태일 때도 이전을 다시 예약합니다.

GitLab 19.1보다 이전 버전에서는 이동을 다시 시도하기 전에 [Rails 콘솔 세션](../../administration/operations/rails_console.md#starting-a-rails-console-session)에서 오래된 이동 상태를 취소하세요:

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 올바른 조건 하에서 실행되지 않으면 손상을 야기할 수 있습니다. 항상 테스트 환경에서 먼저 명령을 실행하고 복원할 준비가 된 백업 인스턴스가 있어야 합니다.

```ruby
Project.find_by_full_path('<group>/<project_name>').project_namespace.cancel_transfer!
```

## 콘솔을 사용하여 프로젝트 삭제 {#delete-a-project-using-console}

프로젝트를 삭제할 수 없는 경우, [Rails 콘솔](../../administration/operations/rails_console.md#starting-a-rails-console-session)을 통해 삭제를 시도할 수 있습니다.

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 올바른 조건 하에서 실행되지 않으면 손상을 야기할 수 있습니다. 항상 테스트 환경에서 먼저 명령을 실행하고 복원할 준비가 된 백업 인스턴스가 있어야 합니다.

```ruby
project = Project.find_by_full_path('<project_path>')
user = User.find_by_username('<username>')
Projects::DestroyService.new(project, user, {}).execute
```

실패한 경우 다음을 사용하여 작동하지 않는 이유를 표시합니다:

```ruby
project = Project.find_by_full_path('<project_path>')
project.deletion_error
```

## 그룹 내의 모든 프로젝트에 대한 기능 전환 {#toggle-a-feature-for-all-projects-within-a-group}

프로젝트에서 기능을 전환하는 것을 [프로젝트 API](../../api/projects.md)를 통해 수행할 수 있지만, 많은 수의 프로젝트에 대해 이를 수행해야 할 수 있습니다.

특정 기능을 전환하려면 [Rails 콘솔 세션을 시작](../../administration/operations/rails_console.md#starting-a-rails-console-session)하고 다음 함수를 실행할 수 있습니다:

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 올바른 조건 하에서 실행되지 않으면 손상을 야기할 수 있습니다. 항상 테스트 환경에서 먼저 명령을 실행하고 복원할 준비가 된 백업 인스턴스가 있어야 합니다.

```ruby
projects = Group.find_by_name('_group_name').projects
projects.each do |p|
  ## replace <feature-name> with the appropriate feature name in all instances
  state = p.<feature-name>

  if state != 0
    puts "#{p.name} has <feature-name> already enabled. Skipping..."
  else
    puts "#{p.name} didn't have <feature-name> enabled. Enabling..."
    p.project_feature.update!(<feature-name>: ProjectFeature::PRIVATE)
  end
end
```

전환할 수 있는 기능을 찾으려면 `pp p.project_feature`을 실행합니다. 사용 가능한 권한 수준이 [concerns/featurable.rb](https://gitlab.com/gitlab-org/gitlab/blob/master/app/models/concerns/featurable.rb)에 나열됩니다.

## 지원 기술 자료 {#support-knowledge-base}

문제가 계속되면 [GitLab 지원 기술 자료](https://support.gitlab.com/hc/en-us/)를 참조하세요.
