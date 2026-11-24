---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: manifest 파일을 통한 마이그레이션
description: "manifest 파일을 사용하여 GitLab으로 리포지토리를 가져옵니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Android 리포지토리](https://android.googlesource.com/platform/manifest/+/6dc9af1b583e5c6a4ab9c38e3f5646efd8079b7d/default.xml)에서 사용하는 파일과 같은 manifest 파일을 기반으로 Git 리포지토리를 가져옵니다. manifest를 사용하여 Android Open Source Project(AOSP)와 같이 많은 리포지토리를 포함한 프로젝트를 가져옵니다.

## 사전 요구 사항 {#prerequisites}

- [Manifest 가져오기 소스](../../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources)가 활성화되어 있습니다. 활성화되지 않은 경우 GitLab 관리자에게 이를 활성화하도록 요청하세요. Manifest 가져오기 소스는 GitLab.com에서 기본적으로 활성화됩니다.
- 가져올 대상 최상위 그룹의 Maintainer 또는 Owner 역할입니다. 가져오기용으로 새로운 최상위 그룹을 생성할 수 있습니다.

## Manifest 파일 형식 {#manifest-file-format}

manifest 파일은 크기가 최대 1MB인 XML 파일이어야 합니다. 파일에는 다음이 포함되어야 합니다:

- `remote` 태그에 Git 서버의 URL을 포함하는 `review` 속성이 있습니다.
- `project` 태그에 `name`와 `path` 속성이 있습니다.

GitLab은 `remote` 태그의 URL을 프로젝트 이름과 결합하여 리포지토리의 URL을 빌드합니다. path 속성은 GitLab에서 프로젝트 경로를 나타내는 데 사용됩니다.

예를 들어:

```xml
<manifest>
  <remote review="https://android.googlesource.com/" />

  <project path="build/make" name="platform/build" />
  <project path="build/blueprint" name="platform/build/blueprint" />
</manifest>
```

이 예에서 GitLab은 다음 프로젝트를 생성합니다:

| GitLab                                            | 가져오기 URL |
|:--------------------------------------------------|:-----------|
| `https://gitlab.com/<group_name>/build/make`      | <https://android.googlesource.com/platform/build> |
| `https://gitlab.com/<group_name>/build/blueprint` | <https://android.googlesource.com/platform/build/blueprint> |

## 리포지토리 가져오기 {#import-the-repositories}

manifest 파일을 사용하여 리포지토리를 가져오려면:

1. 오른쪽 위 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택하세요.
1. **프로젝트 가져오기**를 선택하세요.
1. **Manifest 파일**을 선택하세요.
1. 가져올 그룹을 선택하세요.
1. 사용할 XML 형식의 manifest 파일을 선택하세요.
1. **사용 가능한 리포지토리 목록**을 선택하세요. manifest 파일을 기반으로 하는 프로젝트 목록이 있는 가져오기 상태 페이지로 이동됩니다.
1. 가져오려면:
   - 처음으로 모든 프로젝트를 가져오려면 **모든 리포지토리 가져오기**를 선택하세요.
   - 개별 프로젝트를 다시 가져오려면 **다시 가져오기**를 선택하세요. 새 이름을 지정하고 **다시 가져오기**를 다시 선택하세요. 다시 가져오기는 소스 프로젝트의 새 복사본을 생성합니다.

## 관련 항목 {#related-topics}

- [가져오기 및 내보내기 설정](../../../administration/settings/import_and_export_settings.md).
- [가져오기용 Sidekiq 구성](../../../administration/sidekiq/configuration_for_imports.md).
- [여러 Sidekiq 프로세스 실행](../../../administration/sidekiq/extra_sidekiq_processes.md).
- [특정 작업 클래스 처리](../../../administration/sidekiq/processing_specific_job_classes.md).
