---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitHub 마이그레이션 문제 해결
description: "실패한 프로세스, 누락된 접두사 및 대규모 프로젝트 오류를 포함한 GitHub 가져오기 문제 해결."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitHub에서 GitLab으로 프로젝트를 가져올 때 다음 문제가 발생할 수 있습니다.

## 이전에 실패한 가져오기 프로세스 수동으로 계속하기 {#manually-continue-a-previously-failed-import-process}

경우에 따라 GitHub 가져오기 프로세스가 리포지토리를 가져오지 못할 수 있습니다. 이로 인해 GitLab이 프로젝트 가져오기 프로세스를 중단하고 리포지토리를 수동으로 가져와야 합니다. 관리자는 실패한 가져오기 프로세스의 리포지토리를 수동으로 가져올 수 있습니다:

1. Rails 콘솔을 엽니다.
1. 콘솔에서 다음 일련의 명령을 실행합니다:

   ```ruby
   project_id = <PROJECT_ID>
   github_access_token =  <GITHUB_ACCESS_TOKEN>
   github_repository_path = '<GROUP>/<REPOSITORY>'

   github_repository_url = "https://#{github_access_token}@github.com/#{github_repository_path}.git"

   # Find project by ID
   project = Project.find(project_id)
   # Set import URL and credentials
   project.import_url = github_repository_url
   project.import_type = 'github'
   project.import_source = github_repository_path
   project.save!
   # Create an import state if the project was created manually and not from a failed import
   project.create_import_state if project.import_state.blank?
   # Set state to start
   project.import_state.force_start

   # Optional: If your import had certain optional stages selected or a timeout strategy
   # set, you can reset them here. Below is an example.
   # The params follow the format documented in the API:
   # https://docs.gitlab.com/api/import/#import-repository-from-github
   Gitlab::GithubImport::Settings
   .new(project)
   .write(
     timeout_strategy: "optimistic",
     optional_stages: {
       attachments_import: true,
       collaborators_import: true
     }
   )

   # Trigger import from second step
   Gitlab::GithubImport::Stage::ImportRepositoryWorker.perform_async(project.id)
   ```

## 누락된 접두사로 인해 가져오기 실패 {#import-fails-due-to-missing-prefix}

`Import failed due to a GitHub error: (HTTP 406)`라는 오류가 표시될 수 있습니다.

이 문제는 경로 접두사 `api/v3`이(가) GitHub 가져오기 도구에서 제거되었기 때문에 발생합니다. 이는 가져오기 도구가 `Gitlab::LegacyGithubImport::Client` 사용을 중단했기 때문입니다. 이 클라이언트는 GitHub Enterprise URL에서 가져올 때 자동으로 `api/v3` 접두사를 추가했습니다.

이 오류를 해결하려면 GitHub Enterprise URL에서 가져올 때 [`api/v3` 접두사를 추가](https://gitlab.com/gitlab-org/gitlab/-/issues/438358#note_1978902725)하세요.

## 대규모 프로젝트를 가져올 때 오류 {#errors-when-importing-large-projects}

GitHub 가져오기 도구는 대규모 프로젝트를 가져올 때 일부 오류가 발생할 수 있습니다.

### 누락된 의견 {#missing-comments}

GitHub API에는 약 30,000개 이상의 노트 또는 차이 노트를 가져오지 못하게 하는 제한이 있습니다. 이 제한에 도달하면 GitHub API는 대신 다음 오류를 반환합니다:

```plaintext
In order to keep the API fast for everyone, pagination is limited for this resource. Check the rel=last link relation in the Link response header to see how far back you can traverse.
```

이 오류는 **대체 의견 가져오기 방법** 옵션이 선택되지 않은 경우 GitLab 19.3 이하의 프로젝트 가져오기에서만 발생할 수 있습니다. 이 방법이 항상 활성화되어 있기 때문에 GitLab 19.4 이상에서 구성된 프로젝트 가져오기에서는 이 오류가 발생할 수 없습니다.

## 관련 항목 {#related-topics}

- [가져오기 및 내보내기 설정](../../../administration/settings/import_and_export_settings.md).
- [가져오기를 위한 Sidekiq 구성](../../../administration/sidekiq/configuration_for_imports.md).
- [여러 Sidekiq 프로세스 실행](../../../administration/sidekiq/extra_sidekiq_processes.md).
- [특정 작업 클래스 처리](../../../administration/sidekiq/processing_specific_job_classes.md).
