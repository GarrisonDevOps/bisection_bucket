---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "그룹 전체 프로젝트에서 설명서를 공유할 수 있도록 그룹 위키를 생성, 편집 및 관리합니다."
title: 그룹 위키
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

여러 프로젝트를 관리하기 위해 GitLab 그룹을 사용하면, 문서가 여러 그룹에 걸쳐 있을 수 있습니다. 모든 그룹 멤버가 기여할 수 있도록 올바른 액세스 권한을 갖도록 하려면 [프로젝트 위키](_index.md) 대신 그룹 위키를 생성할 수 있습니다. 그룹 위키는 [프로젝트 위키](_index.md)와 유사하지만 몇 가지 제한 사항이 있습니다:

- [Git LFS](../../../topics/git/lfs/_index.md)는 지원되지 않습니다.
- 그룹 위키에 대한 변경 사항은 [그룹의 활동 피드](../../group/manage.md#group-activity-analytics)에 표시되지 않습니다.

업데이트를 위해 [프로젝트 위키와의 기능 패리티를 추적하는 에픽](https://gitlab.com/groups/gitlab-org/-/work_items/2782)을(를) 팔로우하세요.

프로젝트 위키와 유사하게 개발자, 유지보수자 또는 소유자 역할을 가진 그룹 멤버는 그룹 위키를 편집할 수 있습니다. 그룹 위키 리포지토리는 [그룹 리포지토리 저장소 이동 API](../../../api/group_repository_storage_moves.md)를 사용하여 이동할 수 있습니다.

## 그룹 위키 보기 {#view-a-group-wiki}

그룹 위키에 액세스하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **위키**를 선택합니다.

## 그룹 위키 내보내기 {#export-a-group-wiki}

그룹에서 소유자 역할을 가진 사용자는 그룹을 가져오거나 내보낼 때 [그룹 위키를 가져오거나 내보낼](../settings/import_export.md#migrate-groups-by-uploading-an-export-file-deprecated) 수 있습니다.

그룹 위키에서 생성된 콘텐츠는 계정이 다운그레이드되거나 GitLab 평가판이 종료되어도 삭제되지 않습니다. 그룹 위키 데이터는 위키의 그룹 소유자를 내보낼 때마다 내보내집니다.

기능을 더 이상 사용할 수 없는 경우 내보내기 파일에서 그룹 위키 데이터에 액세스하려면:

1. [내보내기 파일 tarball](../settings/import_export.md#migrate-groups-by-uploading-an-export-file-deprecated)을(를) 이 명령으로 추출하고 `FILENAME`을(를) 파일 이름으로 바꿉니다: `tar -xvzf FILENAME.tar.gz`
1. `repositories` 디렉토리로 이동합니다. 이 디렉토리에는 [Git 번들](https://git-scm.com/docs/git-bundle)이 포함되어 있으며 확장자는 `.wiki.bundle`입니다.
1. Git 번들을 새 리포지토리로 복제하고 `FILENAME`을(를) 번들 이름으로 바꿉니다: `git clone FILENAME.wiki.bundle`

위키의 모든 파일을 이 Git 리포지토리에서 사용할 수 있습니다.

## 그룹 위키 가시성 구성 {#configure-group-wiki-visibility}

위키는 GitLab에서 기본적으로 활성화됩니다. 그룹 [관리자](../../permissions.md)는 그룹 설정을 통해 그룹 위키를 활성화하거나 비활성화할 수 있습니다.

그룹 설정을 열려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **위키**로 스크롤하고 다음 옵션 중 하나를 선택합니다:
   - **활성화**: 공개 그룹의 경우 모든 사용자가 위키에 액세스할 수 있습니다. 내부 그룹의 경우 인증된 사용자만 위키에 액세스할 수 있습니다.
   - **비공개**: 그룹 멤버만 위키에 액세스할 수 있습니다.
   - **비활성화됨**: 위키에 액세스할 수 없으며 다운로드할 수 없습니다.
1. **변경 사항 저장**을 선택합니다.

## 그룹 위키의 콘텐츠 삭제 {#delete-the-contents-of-a-group-wiki}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> 이 작업은 위키의 모든 데이터를 삭제합니다.

Rails 콘솔을 사용하여 그룹 위키의 콘텐츠를 삭제할 수 있습니다. 그러면 위키를 새 콘텐츠로 채울 수 있습니다.

> [!warning]
> 이 명령은 데이터를 직접 변경하므로 올바르게 실행하지 않으면 손상될 수 있습니다. 먼저 테스트 환경에서 이 지침을 실행해야 합니다. 필요한 경우 인스턴스를 복원할 수 있도록 인스턴스의 백업을 준비합니다.

사전 요구 사항:

- 관리자여야 합니다.

그룹 위키에서 모든 데이터를 삭제하고 빈 상태로 다시 생성하려면:

1. [Rails 콘솔 세션](../../../administration/operations/rails_console.md#starting-a-rails-console-session)을 시작합니다.
1. 다음 명령을 실행합니다:

   ```ruby
   # Enter your group's path
   g = Group.find_by_full_path('<group-name>')

   # This command deletes the wiki group from the filesystem.
   g.wiki.repository.remove

   # Refresh the wiki repository state.
   g.wiki.repository.expire_exists_cache
   ```

위키의 모든 데이터가 지워졌으며 위키를 사용할 준비가 되었습니다.

## 관련 항목 {#related-topics}

- [관리자를 위한 위키 설정](../../../administration/wikis/_index.md)
- [프로젝트 위키 API](../../../api/wikis.md)
- [그룹 리포지토리 저장소 이동 API](../../../api/group_repository_storage_moves.md)
- [그룹 위키 API](../../../api/group_wikis.md)
- [위키 바로가기](../../shortcuts.md#wiki-pages)
- [에픽: 프로젝트 위키와의 기능 패리티](https://gitlab.com/groups/gitlab-org/-/work_items/2782)
