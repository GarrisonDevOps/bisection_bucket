---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab으로 가져오기 및 마이그레이션
description: "리포지토리 마이그레이션, 타사 리포지토리 및 사용자 기여도 매핑."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

기존 작업을 GitLab으로 가져옵니다.

일부 타사 플랫폼에는 마이그레이션 도구를 사용할 수 있습니다. 일부는 사용자 기여도 및 멤버십의 [마이그레이션 후 매핑](mapping/post_migration_mapping.md)을 지원합니다.

| 마이그레이션 원본                                                                   | 그룹                  | 프로젝트    | 마이그레이션 도구 | 마이그레이션 후 매핑 |
|:-------------------------------------------------------------------------------|:------------------------|:------------|:---------------|:-----------------------|
| [GitLab(직접 전송 사용)](../group/import/_index.md)                 | {{< yes >}}             | {{< yes >}} | {{< yes >}}    | {{< yes >}}            |
| [GitLab(파일 내보내기 사용)](../project/settings/import_export.md)          | {{< yes >}}[^file-export-deprecated] | {{< yes >}} | {{< yes >}}    | {{< no >}}             |
| [Bitbucket Server](bitbucket_server.md)                                        | {{< no >}}              | {{< yes >}} | {{< yes >}}    | {{< yes >}}            |
| [GitHub](../project/import/github.md)                                          | {{< no >}}              | {{< yes >}} | {{< yes >}}    | {{< yes >}}            |
| [Gitea](gitea.md)                                                              | {{< no >}}              | {{< yes >}} | {{< yes >}}    | {{< yes >}}            |
| [Bitbucket Cloud](bitbucket_cloud.md)                                          | {{< no >}}              | {{< yes >}} | {{< yes >}}    | {{< no >}}             |
| [FogBugz](third_party_systems/fogbugz.md)                                      | {{< no >}}              | {{< yes >}} | {{< yes >}}    | {{< no >}}             |
| [매니페스트 파일](third_party_systems/manifest_file.md)을 통한 Git 리포지토리 | {{< no >}}              | {{< yes >}} | {{< yes >}}    | {{< no >}}             |
| [리포지토리 URL](third_party_systems/repo_by_url.md)을 통한 Git 리포지토리  | {{< no >}}              | {{< yes >}} | {{< yes >}}    | {{< no >}}             |
| [IBM DevOps ClearCase](third_party_systems/clearcase.md)                       | {{< no >}}              | {{< yes >}} | {{< no >}}     | {{< no >}}             |
| [Concurrent Versions System(CVS)](third_party_systems/cvs.md)                 | {{< no >}}              | {{< yes >}} | {{< no >}}     | {{< no >}}             |
| [Perforce P4](third_party_systems/perforce.md)                                 | {{< no >}}              | {{< yes >}} | {{< no >}}     | {{< no >}}             |
| [Subversion](#migrate-from-subversion)                                         | {{< no >}}              | {{< yes >}} | {{< no >}}     | {{< no >}}             |
| [Team Foundation Version Control(TFVC)](third_party_systems/tfvc.md)          | {{< no >}}              | {{< yes >}} | {{< no >}}     | {{< no >}}             |
| [Jira(이슈만)](third_party_systems/jira.md)                              | {{< no >}}              | {{< no >}}  | {{< yes >}}    | {{< no >}}             |

[^file-export-deprecated]: 그룹 마이그레이션을 위한 파일 내보내기는 더 이상 지원되지 않습니다.

## Subversion에서 마이그레이션 {#migrate-from-subversion}

GitLab은 Subversion 리포지토리를 Git으로 자동 마이그레이션할 수 없습니다. Subversion 리포지토리를 Git으로 변환하려면 외부 도구를 사용할 수 있습니다. 예를 들어:

- [`git svn`](https://git-scm.com/book/en/v2/Git-and-Other-Systems-Migrating-to-Git)는 매우 작고 기본적인 리포지토리용입니다.
- [`reposurgeon`](http://www.catb.org/~esr/reposurgeon/repository-editing.html)는 더 크고 복잡한 리포지토리용입니다.

## Professional Services를 통해 마이그레이션 {#migrate-by-engaging-professional-services}

원한다면 GitLab Professional Services를 통해 그룹 및 프로젝트를 GitLab으로 마이그레이션할 수 있습니다. 자세한 내용은 [Professional Services 카탈로그](https://about.gitlab.com/services/catalog/)를 참조하세요.

## 프로젝트 가져오기 이력 보기 {#view-project-import-history}

생성한 모든 프로젝트 가져오기를 볼 수 있습니다. 이 목록에는 다음이 포함됩니다:

- 외부 시스템에서 가져온 경우 원본 프로젝트의 경로 또는 GitLab 프로젝트를 마이그레이션한 경우 가져오기 방법.
- 대상 프로젝트의 경로.
- 각 가져오기의 시작 날짜.
- 각 가져오기의 상태.
- 오류가 발생한 경우 오류 세부 정보.

이력에는 다음 중 하나에서 생성된 프로젝트도 포함됩니다:

- [기본 제공](../project/_index.md#create-a-project-from-a-built-in-template) 템플릿.
- [사용자 지정](../project/_index.md#create-a-project-from-a-custom-template) 템플릿.

GitLab은 [URL로 리포지토리 가져오기](third_party_systems/repo_by_url.md)를 사용하여 템플릿에서 새 프로젝트를 생성합니다.

프로젝트 가져오기 이력을 보려면:

1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **프로젝트 가져오기**를 선택합니다.
1. 오른쪽 위 모서리에서 **이력** 링크를 선택합니다.
1. 특정 가져오기에 오류가 있으면 **상세정보**를 선택하여 확인합니다.

## LFS 객체가 있는 프로젝트 가져오기 {#importing-projects-with-lfs-objects}

LFS 객체를 포함하는 프로젝트를 가져올 때, 프로젝트에 리포지토리 URL 호스트와 다른 URL 호스트(`lfs.url`)가 있는 [`.lfsconfig`](https://github.com/git-lfs/git-lfs/blob/main/docs/man/git-lfs-config.adoc) 파일이 있으면 LFS 파일이 다운로드되지 않습니다.

## 관련 항목 {#related-topics}

- [GitLab에서 관리하는 리포지토리 이동](../../administration/operations/moving_repositories.md).
