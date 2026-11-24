---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Git URL을 통한 마이그레이션
description: "Git URL을 사용하여 리포지토리를 GitLab으로 가져옵니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Git URL을 사용하여 기존 리포지토리를 가져옵니다. 이 방식으로 수행된 가져오기에는 GitLab 이슈 또는 머지 리퀘스트가 포함되지 않습니다.

## 사전 요구 사항 {#prerequisites}

- [리포지토리 URL](../../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources) 가져오기 소스가 활성화되어 있습니다. 활성화되지 않은 경우 GitLab 관리자에게 활성화를 요청하세요. 리포지토리 URL 가져오기 소스는 GitLab.com에서 기본적으로 활성화되어 있습니다.
- 가져올 대상 그룹의 유지 관리자 또는 소유자 역할입니다.
- 비공개 리포지토리를 가져오는 경우 암호 대신 소스 리포지토리에 대한 인증된 액세스를 위한 액세스 토큰이 필요할 수 있습니다.

## UI를 통해 리포지토리 가져오기 {#import-a-repository-through-the-ui}

UI를 통해 리포지토리를 가져오려면:

1. 오른쪽 위 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **프로젝트 가져오기**를 선택합니다.
1. **리포지토리 URL**을 선택합니다.
1. **Git 리포지토리 URL**을 입력합니다.
1. 나머지 필드를 완성합니다. 비공개 리포지토리에서 가져오기 위해서는 사용자 이름과 암호(또는 액세스 토큰)가 필요합니다.
1. **프로젝트 생성**을 선택합니다.

새로 생성된 프로젝트가 표시됩니다.

## API를 통해 리포지토리 가져오기 {#import-a-repository-through-the-api}

[Projects API](../../../api/projects.md#create-a-project)를 사용하여 Git 리포지토리를 가져올 수 있습니다:

```shell
curl --location "https://gitlab.example.com/api/v4/projects/" \
--header 'Content-Type: application/json' \
--header 'Authorization: Bearer <your-token>' \
--data-raw '{
    "description": "New project description",
    "path": "new_project_path",
    "import_url": "https://username:password@example.com/group/project.git"
}'
```

일부 공급자는 암호를 허용하지 않으며 대신 액세스 토큰을 요구합니다.

## 시간이 초과된 리포지토리 가져오기 {#import-a-timed-out-repository}

대용량 리포지토리의 가져오기는 3시간 후 시간이 초과될 수 있습니다. 시간이 초과된 리포지토리를 가져오려면:

1. 리포지토리를 복제합니다:

   ```shell
   git clone --mirror https://example.com/group/project.git
   ```

   `--mirror` 옵션은 모든 브랜치, 태그 및 참조가 복사되도록 합니다.

1. 새 원격 리포지토리를 추가합니다:

   ```shell
   cd repository.git
   git remote add new-origin https://gitlab.com/group/project.git
   ```

1. 모든 내용을 새 원격 리포지토리로 푸시합니다:

   ```shell
   git push --mirror new-origin
   ```

## 관련 항목 {#related-topics}

- [가져오기 및 내보내기 설정](../../../administration/settings/import_and_export_settings.md).
- [가져오기를 위한 Sidekiq 구성](../../../administration/sidekiq/configuration_for_imports.md).
- [여러 Sidekiq 프로세스 실행](../../../administration/sidekiq/extra_sidekiq_processes.md).
- [특정 작업 클래스 처리](../../../administration/sidekiq/processing_specific_job_classes.md).
