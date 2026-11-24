---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 직접 기여할 권한이 없는 업스트림 리포지토리에 변경 사항을 기여하려고 할 때 Git 리포지토리를 포크합니다.
title: 포크
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

포크는 다른 프로젝트의 개인 복사본이며, 선택한 네임스페이스에 생성됩니다. 포크에는 업스트림 프로젝트의 리포지토리와 일부 프로젝트 설정이 포함되지만, 이슈, 머지 리퀘스트, 위키 페이지 등의 프로젝트 콘텐츠는 포함되지 않습니다. 포크에서 업스트림 프로젝트를 대상으로 하는 머지 리퀘스트를 만들 수 있습니다. 개별 커밋을 포크에서 업스트림 프로젝트로 [체리픽](../merge_requests/cherry_pick_changes.md)할 수도 있습니다.

원래 프로젝트에 쓰기 액세스 권한이 있으면 포크가 필요하지 않습니다. 대신 브랜치를 사용하여 작업을 관리합니다. 기여하려는 프로젝트에 쓰기 액세스 권한이 없으면 포크합니다. 포크에서 변경 사항을 만든 다음 머지 리퀘스트를 통해 업스트림 프로젝트에 제출합니다.

[기밀 머지 리퀘스트](../merge_requests/confidential.md)를 만들려면 공개 프로젝트의 개인 포크를 사용합니다.

> [!note]
> 업스트림 프로젝트가 보관된 경우 포크 관계가 자동으로 제거됩니다. 포크 관계가 끊어져서 닫힌 머지 리퀘스트는 포크 관계가 나중에 복원되어도 다시 열리지 않습니다.
>
> 자세한 내용은 [프로젝트 보관](../working_with_projects.md#archive-a-project)을 참조하세요.

## 포크 만들기 {#create-a-fork}

GitLab에서 기존 프로젝트를 포크하려면:

1. 프로젝트의 홈페이지 오른쪽 위 모서리에서 **포크**({{< icon name="fork" >}})를 선택합니다.
1. 선택 사항. **프로젝트 이름**을 편집합니다.
1. **프로젝트 URL**의 경우 포크가 속할 [네임스페이스](../../namespace/_index.md)를 선택합니다.
1. **프로젝트 슬러그**를 추가합니다. 이 값은 포크에 대한 URL의 일부가 됩니다. 네임스페이스 내에서 고유해야 합니다.
1. 선택 사항. **프로젝트 설명**을 추가합니다.
1. **포함할 브랜치** 옵션 중 하나를 선택합니다:
   - **모든 브랜치**(기본값).
   - **기본 브랜치만**. `--single-branch` 및 `--no-tags` [Git 옵션](https://git-scm.com/docs/git-clone)을 사용합니다.
1. 포크의 **공개 수준**을 선택합니다. 포크의 공개 수준은 업스트림 프로젝트와 포크가 속한 네임스페이스의 공개 수준 모두 이상으로 제한적이어야 합니다. 다른 공개 수준은 선택할 수 없습니다. 공개 수준에 대한 자세한 내용은 [프로젝트 및 그룹 공개 수준](../../public_access.md)을 참조하세요.

   > [!note]
   > 포크를 만든 후 업스트림 프로젝트가 더 제한적이 되면 포크의 공개 수준이 자동으로 변경되지 않습니다. 직접 변경할 수 있지만 동일한 규칙이 적용됩니다. 포크는 업스트림 프로젝트 이상으로 제한적이어야 합니다.

1. **프로젝트 포크**를 선택합니다.

GitLab이 포크를 만들고 새 포크의 페이지로 리디렉션한 후 포크 생성을 [감사 로그](../../compliance/audit_event_types.md)에 기록합니다.

업스트림에 자주 변경 사항을 기여할 계획이라면 포크에 대한 [기본 대상](../merge_requests/creating_merge_requests.md#set-the-default-target-project)을 설정하는 것을 고려하세요.

## 포크 업데이트 {#update-your-fork}

포크가 업스트림 프로젝트와 동기화되지 않을 수 있으며 업데이트가 필요합니다:

- **앞서감**: 포크에 업스트림 리포지토리에 없는 새 커밋이 포함되어 있습니다. 포크를 동기화하려면 머지 리퀘스트를 만들어 업스트림 리포지토리에 변경 사항을 푸시합니다.
- **뒤쳐짐**: 업스트림 리포지토리에 포크에 없는 새 커밋이 포함되어 있습니다. 포크를 동기화하려면 새 커밋을 포크로 가져옵니다.
- **앞서감 및 뒤쳐짐**: 업스트림 리포지토리와 포크 모두 다른 리포지토리에 없는 새 커밋을 포함합니다. 포크를 완전히 동기화하려면 머지 리퀘스트를 만들어 변경 사항을 푸시하고 업스트림 리포지토리의 새 변경 사항을 포크로 가져옵니다.

포크를 업스트림 프로젝트와 동기화하려면 GitLab UI 또는 명령줄에서 업데이트합니다. GitLab Premium 및 Ultimate 티어는 [포크를 업스트림 프로젝트의 풀 미러로 구성](#with-repository-mirroring)하여 업데이트를 자동화할 수도 있습니다.

### UI에서 {#from-the-ui}

UI에서 포크를 업데이트할 때 포크의 다음 리포지토리 보호 설정이 무시됩니다:

- 포크에 구성된 푸시 규칙.
- 포크의 파일에 적용된 파일 잠금.

이 동작은 업스트림 프로젝트와 포크가 다른 보호 구성을 가질 때 동기화 오류를 방지합니다. 동기화 프로세스는 업스트림 리포지토리에서 변경 사항을 가져와 포크에 직접 적용합니다.

사전 요구 사항:

- 업스트림 프로젝트에서 [보호되지 않은 브랜치](branches/protected.md)를 통해 포크를 만들어야 합니다.

GitLab UI에서 포크를 업데이트하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택합니다.
1. **내 모든 프로젝트 보기**를 선택합니다.
1. 업데이트하려는 포크를 선택합니다.
1. 브랜치 이름의 드롭다운 목록 아래에서 **다른 프로젝트에서 포크됨:**({{< icon name="fork" >}}) 정보 상자를 찾아 포크가 앞서가는지, 뒤쳐지는지 또는 둘 다인지 확인합니다. 이 예에서 포크는 업스트림 프로젝트보다 뒤쳐져 있습니다:

   ![업스트림 프로젝트보다 뒤쳐진 포크의 정보 상자](img/update-fork_v16_6.png)

1. 포크가 업스트림 프로젝트보다 **앞서가면** **머지 리퀘스트 생성**를 선택하여 포크의 변경 사항을 업스트림 프로젝트에 추가하도록 제안합니다.
1. 포크가 업스트림 프로젝트보다 **뒤쳐지면** **포크 업데이트**를 선택하여 업스트림 리포지토리에서 변경 사항을 가져옵니다.
1. 포크가 업스트림 프로젝트보다 **앞서가고 뒤쳐지면** GitLab이 머지 충돌을 감지하지 않는 경우에만 UI에서 업데이트할 수 있습니다:
   - 포크에 머지 충돌이 없으면 **머지 리퀘스트 생성**를 선택하여 업스트림 프로젝트에 변경 사항을 푸시하도록 제안하거나, **포크 업데이트**를 선택하여 포크로 변경 사항을 가져오거나 둘 다 수행할 수 있습니다. 포크의 변경 사항 유형에 따라 적절한 작업이 결정됩니다.
   - 포크에 머지 충돌이 있으면 GitLab은 명령줄에서 포크를 업데이트하는 단계별 가이드를 표시합니다.

### 명령줄에서 {#from-the-command-line}

명령줄에서도 포크를 업데이트할 수 있습니다.

사전 요구 사항:

- 로컬 머신에 [Git 클라이언트를 다운로드 및 설치](../../../topics/git/how_to_install_git/_index.md)해야 합니다.
- 업데이트하려는 프로젝트의 [포크를 만들어](#create-a-fork)야 합니다.

명령줄에서 포크를 업데이트하려면 [Git을 사용하여 포크 업데이트](../../../topics/git/forks.md)의 지침을 따릅니다.

### 리포지토리 미러링 {#with-repository-mirroring}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이러한 모든 조건이 충족되면 포크를 업스트림 프로젝트의 미러로 구성할 수 있습니다:

1. 구독이 GitLab Premium 또는 GitLab Ultimate입니다.
1. 모든 변경 사항을 브랜치에서만 생성합니다(`main`이 아님).
1. 주 브랜치(`main`) 변경이 필요한 [기밀 이슈에 대한 머지 리퀘스트](../merge_requests/confidential.md)는 작업하지 않습니다.

[리포지토리 미러링](mirror/_index.md)은 포크를 원래 프로젝트와 동기화된 상태로 유지합니다. 이 방법은 수동 `git pull` 없이 포크를 시간당 한 번씩 업데이트합니다. 지침은 [풀 미러링 구성](mirror/pull.md#configure-pull-mirroring)을 참조하세요.

> [!warning]
> 미러링을 사용하면 머지 리퀘스트를 승인하기 전에 동기화하도록 요청됩니다. 자동화해야 합니다.

## 변경 사항을 업스트림으로 머지 {#merge-changes-back-upstream}

코드를 업스트림 프로젝트로 다시 보낼 준비가 되면 [포크에서 작업할 때](../merge_requests/creating_merge_requests.md#when-you-work-in-a-fork)에 설명된 대로 새 머지 리퀘스트를 만듭니다. 성공적으로 머지되면 변경 사항이 업스트림 리포지토리에 추가됩니다.

머지 리퀘스트가 업스트림으로 머지된 후 포크의 브랜치는 일괄 삭제 목적으로 자동으로 **머지됨**으로 간주되지 않습니다. 브랜치는 포크의 기본 브랜치가 이러한 변경 사항을 포함하는 경우에만 머지된 것으로 간주됩니다. 포크의 브랜치를 머지됨으로 표시하려면 [포크 업데이트](#update-your-fork)를 수행하여 업스트림 프로젝트와 동기화합니다.

## 포크 연결 해제 {#unlink-a-fork}

포크 관계를 제거하면 포크가 업스트림 프로젝트에서 연결 해제됩니다. 그러면 포크가 독립적인 프로젝트가 됩니다.

사전 요구 사항:

- 포크를 연결 해제하려면 프로젝트 소유자여야 합니다.

> [!warning]
> 포크 관계를 제거하면 소스에 새 머지 리퀘스트를 보낼 수 없습니다. 포크에서 소스로의 기존 열린 머지 리퀘스트도 닫힙니다. 누군가가 프로젝트를 포크한 경우 해당 포크도 관계를 잃습니다. 포크 관계를 복원하려면 [프로젝트 포크 API](../../../api/project_forks.md#create-a-fork-relationship)를 사용합니다.

포크 관계를 제거하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급**을 확장합니다.
1. **포크 관계 제거** 섹션에서 **포크 관계 제거**를 선택합니다.
1. 확인하려면 프로젝트 경로를 입력하고 **확인**을 선택합니다.

GitLab이 연결 해제 작업을 [감사 로그](../../compliance/audit_event_types.md)에 기록합니다. [해시된 스토리지 풀](../../../administration/repository_storage_paths.md#hashed-object-pools)을 사용하는 포크의 연결을 해제할 때 다른 리포지토리와 객체를 공유합니다:

- 모든 객체가 풀에서 포크로 복사됩니다.
- 복사 프로세스가 완료된 후 스토리지 풀의 추가 업데이트는 포크로 전파되지 않습니다.

## 포크 삭제 {#delete-a-fork}

포크를 삭제하면 포크 관계를 포함하여 프로젝트와 모든 콘텐츠가 영구적으로 제거됩니다. 이 작업은 다른 프로젝트를 삭제하는 것과 같습니다.

포크를 삭제하려면 [프로젝트 삭제](../working_with_projects.md#delete-a-project)를 참조하세요.

## 포크의 스토리지 사용량 확인 {#check-a-forks-storage-usage}

포크는 중복 제거 전략을 사용하여 필요한 스토리지 공간을 줄입니다. 포크는 소스 프로젝트에 연결된 객체 풀에 액세스할 수 있습니다.

자세한 내용 및 스토리지 사용량을 확인하려면 [프로젝트 포크 스토리지 사용량 보기](../../storage_usage_quotas.md#view-project-fork-storage-usage)를 참조하세요.

## 관련 항목 {#related-topics}

- GitLab 커뮤니티 포럼: [포크 새로 고치기](https://forum.gitlab.com/t/refreshing-a-fork/32469)
- [그룹 외부 프로젝트 포크 방지](../../group/access_and_permissions.md#prevent-project-forking-outside-group)
- [Git LFS가 포크와 함께 작동하는 방식 이해](../../../topics/git/lfs/_index.md#understand-how-git-lfs-works-with-forks)

## 문제 해결 {#troubleshooting}

### 오류: `An error occurred while forking the project. Please try again` {#error-an-error-occurred-while-forking-the-project-please-try-again}

이 오류는 포크된 프로젝트와 새 네임스페이스 간의 인스턴스 러너 설정 불일치로 인해 발생할 수 있습니다. 자세한 내용은 [포크된 프로젝트에서 인스턴스 러너 사용](../../../ci/runners/configure_runners.md#using-instance-runners-in-forked-projects)을 참조하세요.

### 포크 관계 제거 실패 {#removing-fork-relationship-fails}

UI 또는 API를 통해 포크 제거가 작동하지 않으면 [Rails 콘솔 세션](../../../administration/operations/rails_console.md#starting-a-rails-console-session)에서 포크 관계 제거를 시도할 수 있습니다:

```ruby
p = Project.find_by_full_path('<project_path>')
u = User.find_by_username('<username>')
Projects::UnlinkForkService.new(p, u).execute
```

### 오류: `User is not allowed to import projects` {#error-user-is-not-allowed-to-import-projects}

서비스 계정을 사용하여 프로젝트를 포크할 때 다음 오류가 나타날 수 있습니다:

```plaintext
{"message":["Namespace is not valid","User is not allowed to import projects"]}
```

이 문제는 서비스 계정이 봇 사용자이며 프로젝트 제한이 증가한 경우에도 프로젝트를 개인 네임스페이스로 포크할 수 없기 때문에 발생합니다.

서비스 계정을 사용하여 프로젝트를 포크할 때, 해결 방법은 [프로젝트 포크 API](../../../api/project_forks.md)에서 `namespace_id` 또는 `namespace_path`을 사용하여 대상 그룹 네임스페이스를 지정하는 것입니다. 서비스 계정은 개발자, 유지관리자 또는 소유자 역할을 가진 대상 그룹의 멤버여야 합니다.
