---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 병합 요청 문제 해결 도움말입니다.
title: 병합 요청 문제 해결
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

병합 요청을 사용하는 동안 다음 문제를 만날 수 있습니다.

## 병합 요청이 파이프라인 상태를 검색할 수 없음 {#merge-request-cannot-retrieve-the-pipeline-status}

Sidekiq이 변경 사항을 충분히 빨리 선택하지 않으면 이 문제가 발생할 수 있습니다.

### Sidekiq {#sidekiq}

Sidekiq이 CI 상태 변경을 충분히 빨리 처리하지 않았습니다. 몇 초 기다리면 상태가 자동으로 업데이트됩니다.

### 파이프라인 상태를 검색할 수 없음 {#pipeline-status-cannot-be-retrieved}

다음 상황이 발생할 때 병합 요청 파이프라인 상태를 검색할 수 없습니다:

1. 병합 요청이 생성됨
1. 병합 요청이 닫힘
1. 프로젝트에서 변경 사항이 이루어짐
1. 병합 요청이 다시 열림

파이프라인 상태를 올바르게 검색할 수 있도록 하려면 병합 요청을 닫았다가 다시 열어야 합니다.

## Rails 콘솔에서 병합 요청을 리베이스 {#rebase-a-merge-request-from-the-rails-console}

{{< details >}}

- 티어: Free, Premium, Ultimate

{{< /details >}}

[`/rebase` 빠른 작업](../quick_actions.md#ready) 외에도 [Rails 콘솔](../../../administration/operations/rails_console.md)에 액세스할 수 있는 사용자는 Rails 콘솔에서 병합 요청을 리베이스할 수 있습니다. `<username>`, `<namespace/project>`, `<iid>`을 적절한 값으로 바꿉니다:

> [!warning]
> 데이터를 직접 변경하는 모든 명령은 올바르게 실행되지 않거나 올바른 조건에서 실행되지 않으면 손상될 수 있습니다. 인스턴스 백업이 복원될 준비가 된 테스트 환경에서 이들을 실행하는 것이 좋습니다.

```ruby
u = User.find_by_username('<username>')
p = Project.find_by_full_path('<namespace/project>')
m = p.merge_requests.find_by(iid: <iid>)
MergeRequests::RebaseService.new(project: m.target_project, current_user: u).execute(m)
```

## 잘못된 병합 요청 상태 수정 {#fix-incorrect-merge-request-status}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

병합 요청이 변경 사항이 병합된 후에도 **열기** 상태로 남아 있으면 [Rails 콘솔](../../../administration/operations/rails_console.md)에 액세스할 수 있는 사용자가 병합 요청 상태를 수정할 수 있습니다. `<username>`, `<namespace/project>`, `<iid>`을 적절한 값으로 바꿉니다:

> [!warning]
> 데이터를 직접 변경하는 모든 명령은 올바르게 실행되지 않거나 올바른 조건에서 실행되지 않으면 손상될 수 있습니다. 인스턴스 백업이 복원될 준비가 된 테스트 환경에서 이들을 실행하는 것이 좋습니다.

```ruby
u = User.find_by_username('<username>')
p = Project.find_by_full_path('<namespace/project>')
m = p.merge_requests.find_by(iid: <iid>)
MergeRequests::PostMergeService.new(project: p, current_user: u).execute(m)
```

병합되지 않은 변경 사항이 있는 병합 요청에 대해 이 명령을 실행하면 병합 요청이 잘못된 메시지를 표시합니다: `merged into <branch-name>`.

## Rails 콘솔에서 병합 요청 닫기 {#close-a-merge-request-from-the-rails-console}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

UI 또는 API를 통해 병합 요청을 닫을 수 없으면 [Rails 콘솔 세션](../../../administration/operations/rails_console.md#starting-a-rails-console-session)에서 닫을 수 있습니다:

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 올바른 조건에서 실행되지 않으면 손상될 수 있습니다. 항상 명령을 먼저 테스트 환경에서 실행하고 복원할 준비가 된 백업 인스턴스를 보유합니다.

```ruby
u = User.find_by_username('<username>')
p = Project.find_by_full_path('<namespace/project>')
m = p.merge_requests.find_by(iid: <iid>)
MergeRequests::CloseService.new(project: p, current_user: u).execute(m)
```

## Rails 콘솔에서 병합 요청 삭제 {#delete-a-merge-request-from-the-rails-console}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

UI 또는 API를 통해 병합 요청을 삭제할 수 없으면 [Rails 콘솔 세션](../../../administration/operations/rails_console.md#starting-a-rails-console-session)에서 삭제할 수 있습니다:

> [!warning]
> 데이터를 직접 변경하는 모든 명령은 올바르게 실행되지 않거나 올바른 조건에서 실행되지 않으면 손상될 수 있습니다. 인스턴스 백업이 복원될 준비가 된 테스트 환경에서 이들을 실행하는 것이 좋습니다.

```ruby
u = User.find_by_username('<username>')
p = Project.find_by_full_path('<namespace/project>')
m = p.merge_requests.find_by(iid: <iid>)
Issuable::DestroyService.new(container: m.project, current_user: u).execute(m)
```

## 병합 요청 사전 수신 훅 실패 {#merge-request-pre-receive-hook-failed}

병합 요청이 시간 초과되면 Puma 워커 시간 초과 문제를 나타내는 메시지가 표시될 수 있습니다:

- GitLab UI에서:

  ```plaintext
  Something went wrong during merge pre-receive hook.
  500 Internal Server Error. Try again.
  ```

- `gitlab-rails/api_json.log` 로그 파일에서:

  ```plaintext
  Rack::Timeout::RequestTimeoutException
  Request ran for longer than 60000ms
  ```

다음과 같은 경우 이 오류가 발생할 수 있습니다:

- 많은 차이점을 포함합니다.
- 대상 브랜치보다 많은 커밋이 뒤에 있습니다.
- 잠긴 Git LFS 파일을 참조합니다.

GitLab Self-Managed의 사용자는 관리자에게 서버 로그를 검토하도록 요청하여 오류의 원인을 파악할 수 있습니다. GitLab.com 사용자는 도움을 받으려면 [지원팀에 문의](https://support.gitlab.com/hc/en-us/articles/11626483177756-GitLab-Support#contact-support)해야 합니다.

## 캐시된 병합 요청 수 {#cached-merge-request-count}

그룹에서 사이드바는 열려 있는 병합 요청의 총 개수를 표시합니다. 이 값은 1000보다 크면 캐시됩니다. 캐시된 값은 천 단위(또는 백만 단위)로 반올림되고 24시간마다 업데이트됩니다.

## `head` ref를 통해 병합 요청을 로컬로 확인 {#check-out-merge-requests-locally-through-the-head-ref}

병합 요청은 리포지토리의 모든 기록과 병합 요청과 연결된 브랜치에 추가된 추가 커밋을 포함합니다. 다음은 병합 요청을 로컬로 확인하는 몇 가지 방법입니다.

소스 프로젝트가 대상 프로젝트의 포크(비공개 포크도 포함)인 경우에도 병합 요청을 로컬로 확인할 수 있습니다.

이는 각 병합 요청에 사용할 수 있는 병합 요청 `head` ref(`refs/merge-requests/:iid/head`)에 따라 다릅니다. 브랜치 대신 ID를 사용하여 병합 요청을 확인할 수 있습니다.

병합 요청 `head` ref는 병합 요청이 닫히거나 병합된 후 14일 후 삭제됩니다. 그러면 병합 요청 `head` ref에서 더 이상 로컬 확인에 사용할 수 없습니다. 병합 요청을 다시 열 수 있습니다. 병합 요청의 브랜치가 있으면 영향을 받지 않으므로 여전히 브랜치를 확인할 수 있습니다.

### `glab`을 사용하여 로컬로 확인 {#check-out-locally-using-glab}

```plaintext
glab mr checkout <merge_request_iid>
```

[GitLab 터미널 클라이언트](../../../editor_extensions/gitlab_cli/_index.md)에 대한 자세한 정보.

### Git 별칭을 추가하여 로컬로 확인 {#check-out-locally-by-adding-a-git-alias}

다음 별칭을 `~/.gitconfig`에 추가합니다:

```plaintext
[alias]
    mr = !sh -c 'git fetch $1 merge-requests/$2/head:mr-$1-$2 && git checkout mr-$1-$2' -
```

이제 모든 리포지토리와 모든 원격에서 특정 병합 요청을 확인할 수 있습니다. 예를 들어 GitLab에서 보이는 ID 5인 병합 요청을 `origin` 원격에서 확인하려면 다음을 수행합니다:

```shell
git mr origin 5
```

이는 병합 요청을 로컬 `mr-origin-5` 브랜치로 가져오고 이를 확인합니다.

### 주어진 리포지토리에 대해 `.git/config`을 수정하여 로컬로 확인 {#check-out-locally-by-modifying-gitconfig-for-a-given-repository}

GitLab 원격의 섹션을 `.git/config` 파일에서 찾습니다. 다음과 같습니다:

```plaintext
[remote "origin"]
  url = https://gitlab.com/gitlab-org/gitlab-foss.git
  fetch = +refs/heads/*:refs/remotes/origin/*
```

다음 명령으로 파일을 열 수 있습니다:

```shell
git config -e
```

이제 이전 섹션에 다음 줄을 추가합니다:

```plaintext
fetch = +refs/merge-requests/*/head:refs/remotes/origin/merge-requests/*
```

결국 다음과 같습니다:

```plaintext
[remote "origin"]
  url = https://gitlab.com/gitlab-org/gitlab-foss.git
  fetch = +refs/heads/*:refs/remotes/origin/*
  fetch = +refs/merge-requests/*/head:refs/remotes/origin/merge-requests/*
```

이제 모든 병합 요청을 가져올 수 있습니다:

```shell
git fetch origin

...
From https://gitlab.com/gitlab-org/gitlab-foss.git
 * [new ref]         refs/merge-requests/1/head -> origin/merge-requests/1
 * [new ref]         refs/merge-requests/2/head -> origin/merge-requests/2
...
```

특정 병합 요청을 확인하려면:

```shell
git checkout origin/merge-requests/1
```

이러한 명령은 [`git-mr`](https://gitlab.com/glensc/git-mr) 스크립트로도 수행할 수 있습니다.

## 오류: `source branch <branch_name> does not exist.` 브랜치가 있을 때 {#error-source-branch-branch_name-does-not-exist-when-the-branch-exists}

GitLab 캐시가 Git 리포지토리의 실제 상태를 반영하지 않으면 이 오류가 발생할 수 있습니다. Git 데이터 폴더이 `noexec` 플래그로 마운트되면 이 문제가 발생할 수 있습니다.

사전 요구 사항:

- 관리자여야 합니다.

캐시 업데이트를 강제로 적용하려면:

1. 다음 명령으로 GitLab Rails 콘솔을 엽니다:

   ```shell
   sudo gitlab-rails console
   ```

1. Rails 콘솔에서 다음 스크립트를 실행합니다:

   ```ruby
   # Get the project
   project = Project.find_by_full_path('affected/project/path')

   # Check if the affected branch exists in cache (it may return `false`)
   project.repository.branch_names.include?('affected_branch_name')

   # Expire the branches cache
   project.repository.expire_branches_cache

   # Check again if the affected branch exists in cache (this time it should return `true`)
   project.repository.branch_names.include?('affected_branch_name')
   ```

1. 병합 요청을 다시 로드합니다.

## 자동화가 병합 요청을 승인할 때 승인이 재설정됨 {#approvals-reset-when-automation-approves-a-merge-request}

병합 요청 생성을 자동화하거나 이 리퀘스트에 푸시하는 경우 이러한 병합 요청에 대한 자동 승인을 빌드할 수 있습니다. GitLab Premium 및 Ultimate에서는 기본적으로 [소스 브랜치에 커밋이 추가될 때](approvals/settings.md#remove-all-approvals-when-commits-are-added-to-the-source-branch) 모든 승인이 제거됩니다. 이 문제를 방지하려면 자동화에 로직을 추가하여 병합 요청을 승인하기 전에 [커밋이 처리됨](../../../api/merge_request_approvals.md#prevent-approval-resets-in-automated-merge-requests)을 확인합니다.

## 병합 요청이 예기치 않게 병합으로 표시됨 {#merge-request-unexpectedly-marked-as-merged}

병합된 병합 요청에 `merged manually` 시스템 노트가 포함되어 있으면 소스 브랜치 커밋이 GitLab UI 외부에서 병합되었거나 다른 병합 요청의 일부로 병합되었습니다.

### GitLab UI 외부에서 병합됨 {#merged-outside-the-gitlab-ui}

`git merge`을 사용하여 브랜치를 UI 외부의 대상 브랜치로 직접 병합하면 GitLab이 작업을 감지하고 병합 요청을 `merged manually`로 표시합니다.

대상 브랜치에 대한 직접 푸시가 허용될 때 이 문제가 발생할 수 있습니다. 이 상황을 방지하려면 대상 브랜치를 보호하고 직접 푸시를 허용하지 않도록 구성할 수 있습니다(**푸시와 머지가 허용됨**이 **아무도 없음**으로 설정됨).

자세한 정보는 [브랜치 보호](../repository/branches/protected.md#protect-a-branch)를 참조하세요.

### 다른 병합 요청의 일부로 병합됨 {#merged-as-part-of-a-different-merge-request}

병합 요청에 다른 병합 요청의 일부로 이미 병합된 커밋이 포함되어 있습니다. 이것이 보호된 브랜치에서 발생하면 보호된 브랜치 설정에 따라 커밋이 병합되기 전에 승인되었습니다.

자세한 정보는 [같은 커밋을 포함하는 여러 브랜치](../repository/branches/_index.md#multiple-branches-containing-the-same-commit)를 참조하세요.

> [!note]
> 일부 경우에 GitLab은 `Merged with !<merge_request_id>` 대신 `merged manually`를 표시할 수 있습니다. 자세한 정보는 [이슈 456426](https://gitlab.com/gitlab-org/gitlab/-/issues/456426)을 참조하세요.
