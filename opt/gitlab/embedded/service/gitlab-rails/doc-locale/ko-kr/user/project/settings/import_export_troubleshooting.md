---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 파일 내보내기 프로젝트 마이그레이션 문제 해결
description: "파일 내보내기 프로젝트 마이그레이션 문제 해결. 일반적인 오류, 성능 문제 및 해결 방법을 다룹니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[파일 내보내기를 사용하여 프로젝트를 마이그레이션](import_export.md)할 때 문제가 발생하면 아래의 가능한 해결 방법을 참조하세요.

## 문제 해결 명령 {#troubleshooting-commands}

[Rails 콘솔](../../../administration/operations/rails_console.md)을 사용하여 JID를 이용해 가져오기 상태 및 추가 로그에 대한 정보를 찾습니다:

```ruby
Project.find_by_full_path('group/project').import_state.slice(:jid, :status, :last_error)
> {"jid"=>"414dec93f941a593ea1a6894", "status"=>"finished", "last_error"=>nil}
```

```shell
# Logs
grep JID /var/log/gitlab/sidekiq/current
grep "Import/Export error" /var/log/gitlab/sidekiq/current
grep "Import/Export backtrace" /var/log/gitlab/sidekiq/current
tail /var/log/gitlab/gitlab-rails/importer.log
```

## 불일치로 인해 프로젝트 가져오기 실패 {#project-fails-to-import-due-to-mismatch}

[인스턴스 러너 활성화](../../../ci/runners/runners_scope.md#enable-instance-runners-for-a-project)가 내보낸 프로젝트와 프로젝트 가져오기 간에 일치하지 않으면 프로젝트 가져오기가 실패합니다. [이슈 276930](https://gitlab.com/gitlab-org/gitlab/-/issues/276930)을 검토하고 다음 중 하나를 수행합니다:

- 인스턴스 러너가 소스 및 대상 프로젝트 모두에서 활성화되어 있는지 확인합니다.
- 프로젝트를 가져올 때 부모 그룹에서 인스턴스 러너를 비활성화합니다.

## 가져온 프로젝트에서 누락된 사용자 {#users-missing-from-imported-project}

사용자를 가져온 프로젝트와 함께 가져오지 않으면 [사용자 기여도 보존](import_export.md#preserving-user-contributions) 요구 사항을 참조하세요.

누락된 사용자의 일반적인 원인은 [공개 이메일 설정](../../profile/_index.md#set-your-public-email)이 사용자에 대해 구성되지 않았기 때문입니다. 이 문제를 해결하려면 사용자에게 GitLab UI를 사용하여 이 설정을 구성하도록 요청합니다.

수동 구성이 가능하지 않을 정도로 사용자가 많은 경우 [Rails 콘솔](../../../administration/operations/rails_console.md#starting-a-rails-console-session)을 사용하여 모든 사용자 프로필을 공개 이메일 주소를 사용하도록 설정할 수 있습니다:

```ruby
User.where("public_email IS NULL OR public_email = '' ").find_each do |u|
  next if u.bot?

  puts "Setting #{u.username}'s currently empty public email to #{u.email}…"
  u.public_email = u.email
  u.save!
end
```

## 대규모 리포지토리에 대한 가져오기 해결 방법 {#import-workarounds-for-large-repositories}

[최대 가져오기 크기 제한](import_export.md#import-a-project-and-its-data)은 가져오기가 성공하지 못하게 할 수 있습니다. 가져오기 제한을 변경할 수 없으면 여기에 나열된 해결 방법 중 하나를 시도할 수 있습니다.

### 해결 방법 옵션 1 {#workaround-option-1}

다음 로컬 워크플로를 사용하여 다른 가져오기 시도를 위해 리포지토리 크기를 임시로 줄일 수 있습니다:

1. 내보내기에서 임시 작업 디렉토리를 생성합니다:

   ```shell
   EXPORT=<filename-without-extension>

   mkdir "$EXPORT"
   tar -xf "$EXPORT".tar.gz --directory="$EXPORT"/
   cd "$EXPORT"/
   git clone project.bundle

   # Prevent interference with recreating an importable file later
   mv project.bundle ../"$EXPORT"-original.bundle
   mv ../"$EXPORT".tar.gz ../"$EXPORT"-original.tar.gz

   git switch --create smaller-tmp-main
   ```

1. 이 `smaller-tmp-main` 브랜치에서 작업하여 리포지토리 크기를 줄입니다. [대용량 파일 식별 및 제거](../repository/repository_size.md#methods-to-reduce-repository-size) 또는 [대화형 리베이스 및 수정](../../../topics/git/git_rebase.md#interactive-rebase)을 수행하여 커밋 수를 줄입니다.

   ```shell
   # Reduce the .git/objects/pack/ file size
   cd project
   git reflog expire --expire=now --all
   git gc --prune=now --aggressive

   # Prepare recreating an importable file
   git bundle create ../project.bundle <default-branch-name>
   cd ..
   mv project/ ../"$EXPORT"-project
   cd ..

   # Recreate an importable file
   tar -czf "$EXPORT"-smaller.tar.gz --directory="$EXPORT"/ .
   ```

1. 이 새로운 작은 파일을 GitLab으로 가져옵니다.
1. 원본 리포지토리의 전체 클론에서 `git remote set-url origin <new-url> && git push --force --all`을 사용하여 가져오기를 완료합니다.
1. 가져온 리포지토리의 [브랜치 보호 규칙](../repository/branches/protected.md) 및 [기본 브랜치](../repository/branches/default.md)를 업데이트하고 임시 `smaller-tmp-main` 브랜치 및 로컬 임시 데이터를 삭제합니다.

### 해결 방법 옵션 2 {#workaround-option-2}

> [!note]
> 이 해결 방법은 LFS 개체를 고려하지 않습니다.

한 번에 모든 변경 사항을 푸시하려고 시도하지 않고 이 해결 방법은 다음을 수행합니다:

- 프로젝트 가져오기를 Git 리포지토리 가져오기에서 분리합니다.
- 리포지토리를 GitLab으로 증분 푸시합니다.

1. 마이그레이션할 리포지토리의 로컬 클론을 생성합니다. 이후 단계에서 이 클론을 프로젝트 내보내기 외부로 푸시합니다.
1. 내보내기를 다운로드하고 `project.bundle` (Git 리포지토리 포함)을 제거합니다:

   ```shell
   tar -czvf new_export.tar.gz --exclude='project.bundle' @old_export.tar.gz
   ```

1. Git 리포지토리 없이 내보내기를 가져옵니다. 리포지토리 없이 가져오기를 원하는지 확인하라는 메시지가 표시됩니다.
1. 이 bash 스크립트를 파일로 저장하고 적절한 원본을 추가한 후 실행합니다.

   ```shell
   #!/bin/sh

   # ASSUMPTIONS:
   # - The GitLab location is "origin"
   # - The default branch is "main"
   # - This will attempt to push in chunks of 500 MB (dividing the total size by 500 MB).
   #   Decrease this size to push in smaller chunks if you still receive timeouts.

   git gc
   SIZE=$(git count-objects -v 2> /dev/null | grep size-pack | awk '{print $2}')

   # Be conservative and try to push 2 GB at a time
   # (given this assumes each commit is the same size - which is wrong)
   BATCHES=$(($SIZE / 500000))
   TOTAL_COMMITS=$(git rev-list --count HEAD)
   if (( BATCHES > TOTAL_COMMITS )); then
       BATCHES=$TOTAL_COMMITS
   fi

   INCREMENTS=$(( ($TOTAL_COMMITS / $BATCHES) - 1 ))

   for (( BATCH=BATCHES; BATCH>=1; BATCH-- ))
   do
     COMMIT_NUM=$(( $BATCH - $INCREMENTS ))
     COMMIT_SHA=$(git log -n $COMMIT_NUM --format=format:%H | tail -1)
     git push -u origin ${COMMIT_SHA}:refs/heads/main
   done
   git push -u origin main
   git push -u origin --all
   git push -u origin --tags
   ```

## 오류: `HTTP 524 A timeout occurred` (프로젝트를 가져올 때) {#error-http-524-a-timeout-occurred-when-importing-a-project}

GitLab.com에서 프로젝트 가져오기가 `HTTP 524 A timeout occurred` 오류로 실패할 수 있습니다. 이 오류는 여러 기가바이트 크기의 아카이브에서 발생할 수 있습니다.

각 업로드는 시간 제한 내에 완료되어야 합니다. 대용량 아카이브는 해당 제한을 초과하여 업로드가 완료되기 전에 연결을 닫을 수 있습니다.

오류를 방지하려면 HTTPS 위치(예: AWS S3 버킷)에서 아카이브를 호스트하고 가져오기 중에 GitLab이 다운로드하도록 합니다. 다음 엔드포인트 중 하나를 사용합니다:

- [`POST /api/v4/projects/remote-import`](../../../api/project_import_export.md#import-a-project-from-a-remote-archive)는 S3 미리 서명된 URL을 포함한 모든 HTTPS URL에서 작동합니다.
- [`POST /api/v4/projects/remote-import-s3`](../../../api/project_import_export.md#import-a-project-from-an-aws-s3-bucket)는 자격 증명을 사용하여 AWS S3에서 작동합니다.

GitLab이 백그라운드에서 아카이브를 다운로드하므로 아카이브 크기로 인해 타임아웃이 발생하지 않습니다.

## Sidekiq 프로세스가 프로젝트를 내보내지 못함 {#sidekiq-process-fails-to-export-a-project}

경우에 따라 Sidekiq 프로세스가 프로젝트를 내보내지 못할 수 있습니다. 예를 들어 실행 중에 종료되는 경우입니다.

GitLab.com 사용자는 이 문제를 해결하기 위해 [지원팀에 문의](https://support.gitlab.com/hc/en-us/articles/11626483177756-GitLab-Support#contact-support)해야 합니다.

GitLab Self-Managed 관리자는 Rails 콘솔을 사용하여 Sidekiq 프로세스를 우회하고 프로젝트 내보내기를 수동으로 트리거할 수 있습니다:

```ruby
project = Project.find(1)
current_user = User.find_by(username: 'my-user-name')
RequestStore.begin!
ActiveRecord::Base.logger = Logger.new(STDOUT)
params = {}

::Projects::ImportExport::ExportService.new(project, current_user, params).execute(nil)
```

이렇게 하면 UI를 통해 내보내기를 사용할 수 있지만 사용자에게 이메일을 트리거하지 않습니다. 프로젝트 내보내기를 수동으로 트리거하고 이메일을 보냅니다:

```ruby
project = Project.find(1)
current_user = User.find_by(username: 'my-user-name')
RequestStore.begin!
ActiveRecord::Base.logger = Logger.new(STDOUT)
params = {}

ProjectExportWorker.new.perform(current_user.id, project.id)
```

## 수동으로 내보내기 단계 실행 {#manually-execute-export-steps}

일반적으로 [웹 인터페이스](import_export.md#export-a-project-and-its-data)를 통해 또는 [프로젝트 가져오기 및 내보내기 API](../../../api/project_import_export.md)를 통해 프로젝트를 내보냅니다. 이러한 방법을 사용한 내보내기는 문제 해결을 위한 충분한 정보를 제공하지 않고 때때로 실패할 수 있습니다. 이러한 경우 [Rails 콘솔 세션을 열고](../../../administration/operations/rails_console.md#starting-a-rails-console-session) [정의된 모든 내보내기](https://gitlab.com/gitlab-org/gitlab/-/blob/master/app/services/projects/import_export/export_service.rb)를 통해 루프합니다. 전체 블록을 한 번에 붙여넣지 않고 각 줄을 개별적으로 실행하여 각 명령이 반환하는 오류를 볼 수 있습니다.

```ruby
# User needs to have permission to export
u = User.find_by_username('someuser')
p = Project.find_by_full_path('some/project')
e = Projects::ImportExport::ExportService.new(p,u)

e.send(:version_saver).send(:save)
e.send(:repo_saver).send(:save)
e.send(:avatar_saver).send(:save)
e.send(:project_tree_saver).send(:save)
e.send(:uploads_saver).send(:save)
e.send(:wiki_repo_saver).send(:save)
e.send(:lfs_saver).send(:save)
e.send(:snippets_repo_saver).send(:save)
e.send(:design_repo_saver).send(:save)
## continue using `e.send(:exporter_name).send(:save)` going through the list of exporters

# The following line should show you the export_path similar to /var/opt/gitlab/gitlab-rails/shared/tmp/gitlab_exports/@hashed/49/94/4994....
s = Gitlab::ImportExport::Saver.new(exportable: p, shared: p.import_export_shared, user: u)

# Prior to GitLab 17.0, the `user` parameter was not supported. If you encounter an
# error with the above or are unsure whether or not to supply the `user`
# argument, use the following check:
Gitlab::ImportExport::Saver.instance_method(:initialize).parameters.include?([:keyreq, :user])
# If the preceding check returns false, omit the user argument:
s = Gitlab::ImportExport::Saver.new(exportable: p, shared: p.import_export_shared)

# To try and upload use:
s.send(:compress_and_save)
s.send(:save_upload)
```

프로젝트가 성공적으로 업로드된 후 내보낸 프로젝트는 `.tar.gz` 파일 형식으로 `/var/opt/gitlab/gitlab-rails/uploads/-/system/import_export_upload/export_file/`에 위치합니다.

## 오류: `PG::QueryCanceled: ERROR: canceling statement due to statement timeout` {#error-pgquerycanceled-error-canceling-statement-due-to-statement-timeout}

일부 마이그레이션은 오류 `PG::QueryCanceled: ERROR: canceling statement due to statement timeout`로 시간 초과될 수 있습니다. 이 문제를 방지하는 한 가지 방법은 마이그레이션 배치 크기를 줄이는 것입니다. 이렇게 하면 마이그레이션이 시간 초과될 가능성이 줄어들지만 마이그레이션이 더 느려집니다.

배치 크기를 줄이려면 기능 플래그를 활성화해야 합니다. 자세한 내용은 [이슈 456948](https://gitlab.com/gitlab-org/gitlab/-/issues/456948)을 참조하세요.

## 오류: `JSON exceeds 50 MB limit` {#error-json-exceeds-50-mb-limit}

파일 내보내기를 사용하여 프로젝트를 가져올 때 다음 오류가 발생할 수 있습니다:

```plaintext
JSON exceeds 50 MB limit
```

이 오류는 내보내기의 단일 레코드(예: 큰 설명 또는 diff가 포함된 머지 리퀘스트 또는 이슈)가 가져오기가 각 레코드에 적용하는 50MB 제한보다 클 때 발생합니다.

이 오류를 해결하려면 소스 프로젝트에서 영향을 받은 레코드의 크기를 줄인 다음 프로젝트를 다시 내보내고 가져옵니다.

## 오류: `command exited with error code 15 and Unable to save [FILTERED] into [FILTERED]` {#error-command-exited-with-error-code-15-and-unable-to-save-filtered-into-filtered}

파일 내보내기를 사용하여 프로젝트를 마이그레이션할 때 로그에서 다음 오류가 발생할 수 있습니다:

```plaintext
command exited with error code 15 and Unable to save [FILTERED] into [FILTERED]
```

이 오류는 Sidekiq이 `SIGTERM`을 수신할 때 내보내기 또는 가져오기 중에 발생합니다. 종종 `tar` 명령을 실행하는 동안 발생합니다.

GitLab.com 및 GitLab Dedicated와 같은 Kubernetes 환경에서 운영 체제는 메모리 또는 디스크 부족, 코드 배포 또는 인스턴스 업그레이드로 인해 `SIGTERM` 신호를 트리거합니다. 근본 원인을 파악하려면 관리자가 Kubernetes가 인스턴스를 종료한 이유를 조사해야 합니다.

비Kubernetes 환경에서 이 오류는 `tar` 명령을 실행하는 동안 인스턴스가 종료되는 경우 발생할 수 있습니다. 그러나 이 오류는 디스크 부족으로 인해 발생하지 않으므로 메모리 부족이 가장 가능성 높은 원인입니다.

이 오류가 발생하면:

- 파일을 내보낼 때 GitLab은 최대 재시도 횟수에 도달할 때까지 내보내기를 재시도한 다음 내보내기를 실패로 표시합니다. GitLab.com의 경우 인스턴스의 로드가 적은 주말에 내보내기를 시도합니다.
- 파일을 가져올 때 직접 가져오기를 재시도해야 합니다. GitLab은 가져오기를 자동으로 재시도하지 않습니다.

## 성능 문제 해결 {#troubleshooting-performance-issues}

아래의 가져오기/내보내기를 사용하여 현재 성능 문제를 읽어봅니다.

### OOM 오류 {#oom-errors}

메모리 부족(OOM) 오류는 일반적으로 [Sidekiq 메모리 킬러](../../../administration/sidekiq/sidekiq_memory_killer.md)로 인해 발생합니다:

```shell
SIDEKIQ_MEMORY_KILLER_MAX_RSS = 2000000
SIDEKIQ_MEMORY_KILLER_HARD_LIMIT_RSS = 3000000
SIDEKIQ_MEMORY_KILLER_GRACE_TIME = 900
```

`started`의 가져오기 상태 및 다음 Sidekiq 로그는 메모리 문제를 나타냅니다:

```shell
WARN: Work still in progress <struct with JID>
```

### 타임아웃 {#timeouts}

타임아웃 오류는 `Gitlab::Import::StuckProjectImportJobsWorker`이 프로세스를 실패로 표시함으로 인해 발생합니다:

```ruby
module Gitlab
  module Import
    class StuckProjectImportJobsWorker
      include Gitlab::Import::StuckImportJob
      # ...
    end
  end
end

module Gitlab
  module Import
    module StuckImportJob
      # ...
      IMPORT_JOBS_EXPIRATION = 15.hours.to_i
      # ...
      def perform
        stuck_imports_without_jid_count = mark_imports_without_jid_as_failed!
        stuck_imports_with_jid_count = mark_imports_with_jid_as_failed!

        track_metrics(stuck_imports_with_jid_count, stuck_imports_without_jid_count)
      end
      # ...
    end
  end
end
```

```shell
Marked stuck import jobs as failed. JIDs: xyz
```

```plaintext
  +-----------+    +-----------------------------------+
  |Export Job |--->| Calls ActiveRecord `as_json` and  |
  +-----------+    | `to_json` on all project models   |
                   +-----------------------------------+

  +-----------+    +-----------------------------------+
  |Import Job |--->| Loads all JSON in memory, then    |
  +-----------+    | inserts into the DB in batches    |
                   +-----------------------------------+
```

### 문제 및 해결 방법 {#problems-and-solutions}

[느린 JSON](https://gitlab.com/gitlab-org/gitlab/-/issues/25251) 로딩/데이터베이스에서 모델 덤프:

- [워커 분할](https://gitlab.com/gitlab-org/gitlab/-/issues/25252)
- 배치 내보내기
- SQL 최적화
- `ActiveRecord` 콜백에서 벗어나기(어려움)

높은 메모리 사용량(몇 가지 [분석](https://gitlab.com/gitlab-org/gitlab/-/issues/18857)도 참조):

- 메모리를 적게 사용하는 DB 커밋 최적값
- [Netflix Fast JSON API](https://github.com/Netflix/fast_jsonapi)가 도움이 될 수 있습니다.
- 디스크로의 배치 읽기/쓰기 및 모든 SQL
