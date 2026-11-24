---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "GitLab 리포지토리를 만들고, 복제하고, 사용하는 방법입니다."
title: 리포지토리
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[리포지토리](https://git-scm.com/book/en/v2/Git-Basics-Getting-a-Git-Repository)는 GitLab 프로젝트의 구성 요소입니다. 리포지토리에 코드를 저장하고 버전 제어를 사용하여 변경 사항을 추적합니다.

각 리포지토리는 [GitLab 프로젝트](../_index.md)의 일부이며, GitLab 프로젝트 없이는 존재할 수 없습니다. 프로젝트는 리포지토리에 대한 구성 옵션을 제공합니다.

## 리포지토리 만들기 {#create-a-repository}

리포지토리를 만들려면:

- [프로젝트 만들기](../_index.md) 또는
- [기존 프로젝트 포크](forking_workflow.md).

## 리포지토리에 파일 추가 {#add-files-to-a-repository}

리포지토리에 파일을 추가할 수 있습니다:

- [프로젝트를 만들](../_index.md) 때 또는
- 프로젝트를 만든 후 다음 옵션을 사용합니다:
  - [웹 편집기](web_editor.md#upload-a-file).
  - [사용자 인터페이스(UI)](#add-a-file-from-the-ui).
  - [명령줄](../../../topics/git/add_files.md).

### UI에서 파일 추가 {#add-a-file-from-the-ui}

GitLab UI에서 파일을 추가하거나 업로드하려면:

<!-- Original source for this list: doc/user/project/repository/web_editor.md#upload-a-file -->
<!-- For why we duplicated the info, see <https://gitlab.com/gitlab-org/gitlab/-/merge_requests/111072#note_1267429478> -->

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 파일을 업로드할 디렉토리로 이동합니다.
1. 디렉토리 이름 옆에서 더하기 아이콘({{< icon name="plus" >}}) > **파일 업로드**를 선택합니다.
1. 파일을 드롭하거나 업로드합니다.
1. 커밋 메시지를 입력합니다.
1. 선택 사항. 변경 사항으로 병합 요청을 만들려면 **타겟 브랜치**에서 리포지토리의 [기본 브랜치](branches/default.md)가 아닌 브랜치 이름을 입력합니다.
1. **파일 업로드**를 선택합니다.

## 리포지토리에 변경 사항 커밋 {#commit-changes-to-a-repository}

리포지토리의 브랜치에 변경 사항을 커밋할 수 있습니다. 명령줄을 사용할 때 [`git commit`](../../../topics/git/commands.md#git-commit)를 사용합니다.

커밋을 사용하여 통신과 협업을 개선하고, 파이프라인을 트리거하거나 건너뛰고, 변경 사항을 되돌리는 방법에 대한 자세한 내용은 [커밋](../merge_requests/commits.md)을 참조하세요.

## 리포지토리 복제 {#clone-a-repository}

다음을 사용하여 리포지토리를 복제할 수 있습니다:

- 명령줄: 
  - [SSH로 복제](../../../topics/git/clone.md#clone-with-ssh): SSH 키가 구성되어 있고 각 작업에 대해 인증 정보를 입력하지 않고 인증하려면 SSH를 사용합니다.
  - [HTTPS로 복제](../../../topics/git/clone.md#clone-with-https): 개인 액세스 토큰으로 인증하거나 네트워크에서 SSH 연결을 차단하는 경우 HTTPS를 사용합니다.
- GitLab UI: 
  - [Apple Xcode에서 복제하고 열기](../../../topics/git/clone.md#clone-and-open-in-apple-xcode)
  - [Visual Studio Code에서 복제하고 열기](../../../topics/git/clone.md#clone-and-open-in-visual-studio-code)
  - [IntelliJ IDEA에서 복제하고 열기](../../../topics/git/clone.md#clone-and-open-in-intellij-idea)

## 리포지토리 소스 코드 다운로드 {#download-repository-source-code}

리포지토리의 소스 코드를 압축 파일로 다운로드하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 파일 목록 위에서 **코드**를 선택합니다.
1. 옵션에서 다운로드할 파일을 선택합니다:

   - **소스 코드**:

     현재 보고 있는 브랜치에서 소스 코드를 다운로드합니다. 사용 가능한 확장: `zip`, `tar`, `tar.gz`, 및 `tar.bz2`.

   - **디렉토리**:

     특정 디렉토리를 다운로드합니다. 하위 디렉토리를 볼 때만 표시됩니다. 사용 가능한 확장: `zip`, `tar`, `tar.gz`, 및 `tar.bz2`.

   - **아티팩트**:

     최신 CI/CD 작업에서 아티팩트를 다운로드합니다.

리포지토리 자체가 변경되지 않더라도 생성된 아카이브의 체크섬이 변경될 수 있습니다. 예를 들어 GitLab에서 사용하는 Git 또는 타사 라이브러리가 변경되는 경우 발생합니다.

> [!note]
> 두 다운로드가 동일한 리포지토리 내용을 포함하는지 확인하기 위해 아카이브 체크섬을 사용하지 마세요. 대신 [서명된 커밋 및 태그](signed_commits/_index.md)로 내용을 확인합니다.

## Git 리비전별 리포지토리 보기 {#view-repository-by-git-revision}

커밋 SHA, 브랜치 이름 또는 태그 같은 특정 Git 리비전에서 모든 리포지토리 파일 및 폴더를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 맨 위에서 **Git 리비전 선택** 드롭다운 목록을 열도록 선택합니다.
1. Git 리비전을 선택하거나 검색합니다.

[커밋](commits/_index.md) 페이지에서 특정 Git 리비전의 파일을 볼 수 있고 탐색할 수 있습니다.

## 리포지토리 언어 {#repository-languages}

GitLab은 기본 브랜치에서 사용된 프로그래밍 언어를 감지합니다. 이 정보는 **프로젝트 개요** 페이지에 표시됩니다.

![리포지토리 언어 막대](img/repository_languages_v15_2.png)

새 파일을 추가하면 이 정보는 최대 5분까지 업데이트되는 데 걸릴 수 있습니다.

### 리포지토리 언어 추가 {#add-repository-languages}

모든 파일이 감지되고 **프로젝트 개요** 페이지에 나열되는 것은 아닙니다. 설명서, 공급업체 코드 및 [대부분의 마크업 언어](files/_index.md#supported-markup-languages)는 제외됩니다. 지원되는 파일 및 언어의 목록을 보려면 [지원되는 데이터 유형](https://github.com/github/linguist/blob/master/lib/linguist/languages.yml)을 참조하세요.

이 동작을 변경하고 기본 설정에 추가 파일 유형을 포함하려면:

1. 리포지토리의 루트 디렉토리에 `.gitattributes`이라는 파일을 만듭니다.
1. 특정 파일 유형을 포함하도록 GitLab에 지시하는 줄을 추가합니다. 예를 들어 `.proto` 파일을 활성화하려면 다음을 추가합니다:

   ```plaintext
   *.proto linguist-detectable=true
   ```

이 기능은 과도한 CPU를 사용할 수 있습니다. 문제가 발생하면 [과도한 CPU 사용](files/_index.md#repository-languages-excessive-cpu-use) 문제 해결 섹션을 참조하세요.

## 리포지토리 기여자 분석 {#repository-contributor-analytics}

시간 경과에 따른 선택한 프로젝트 브랜치의 커밋 수를 나타내는 라인 차트와 각 프로젝트 멤버별 커밋 수를 나타내는 라인 차트를 볼 수 있습니다. 자세한 내용은 [기여자 분석](../../analytics/contributor_analytics.md)을 참조하세요.

## 리포지토리 히스토리 그래프 {#repository-history-graph}

리포지토리 그래프는 브랜치 및 병합을 포함한 리포지토리 네트워크의 시각적 히스토리를 표시합니다. 이 그래프는 리포지토리의 변경 흐름을 확인하는 데 도움이 됩니다.

리포지토리 히스토리 그래프를 보려면 프로젝트의 **코드** > **리포지토리 그래프**로 이동합니다.

![리포지토리의 커밋 흐름을 보여주는 그래프입니다.](img/repo_graph_v17_9.png)

## 리포지토리 경로 변경 {#repository-path-changes}

리포지토리 경로가 변경되면 GitLab은 이전 위치에서 새 위치로의 전환을 리디렉션으로 처리합니다.

[사용자 이름을 바꾸거나](../../profile/_index.md#change-your-username), [그룹 경로를 변경](../../group/manage.md#change-a-groups-path)하거나, [리포지토리의 이름을 바꾸면](../working_with_projects.md#rename-a-repository):

- 프로젝트 같은 네임스페이스 및 그 아래의 모든 URL이 새 URL로 리디렉션됩니다.
- 네임스페이스 아래의 프로젝트에 대한 Git 원격 URL이 새 원격 URL로 리디렉션됩니다. 위치가 변경된 리포지토리로 푸시하거나 풀할 때 원격을 업데이트하라는 경고 메시지가 표시됩니다. 자동화 스크립트 또는 Git 클라이언트는 이름 바꾸기 후에도 계속 작동합니다.
- 원본 경로가 다른 그룹, 사용자 또는 프로젝트에 의해 요청되지 않는 한 리디렉션을 사용할 수 있습니다.
- [API 리디렉션](../../../api/rest/_index.md#redirects)을 명시적으로 따라야 할 수도 있습니다.

경로를 변경한 후 다음 리소스의 기존 URL을 업데이트해야 합니다:

- [Include 문](../../../ci/yaml/includes.md) (단, [`include:component`](../../../ci/components/_index.md) 제외), 그렇지 않으면 파이프라인이 구문 오류로 실패합니다. CI/CD 구성 요소 참조는 리디렉션을 따를 수 있습니다.
- 숫자 네임스페이스 및 프로젝트 ID 대신 [인코딩된 경로](../../../api/rest/_index.md#namespaced-paths)를 사용하는 네임스페이스 API 호출.
- [Docker 이미지 참조](../../../ci/yaml/_index.md#image).
- 프로젝트 또는 네임스페이스를 지정하는 변수.
- [`CODEOWNERS` 파일](../codeowners/_index.md#codeowners-file).

## 관련 항목 {#related-topics}

- [GitLab for VS Code 확장](../../../editor_extensions/visual_studio_code/_index.md)
- [파일을 잠그고 변경 충돌 방지](../file_lock.md)
- [리포지토리 API](../../../api/repositories.md)
- [파일](files/_index.md)
- [브랜치](branches/_index.md)
- [디렉토리 만들기](web_editor.md#create-a-directory)
- [파일 히스토리 찾기](files/git_history.md)
- [라인별로 변경 사항 식별(Git blame)](files/git_blame.md)

## 문제 해결 {#troubleshooting}

### 리포지토리에 푸시 시퀀스 검색 {#search-sequence-of-pushes-to-a-repository}

커밋이 "누락"된 것으로 보이면 리포지토리에 대한 푸시 시퀀스를 검색합니다. 이 [Stack Overflow 스레드](https://stackoverflow.com/questions/13468027/the-mystery-of-the-missing-commit-across-merges)는 강제 푸시 없이 이 상태에 도달하는 방법을 설명합니다. 또 다른 원인은 HEAD ref를 `git reset` 작업에서 변경하는 잘못 구성된 [서버 훅](../../../administration/server_hooks.md)일 수 있습니다.

아래의 샘플 코드 출력을 대상 브랜치에서 확인하면 출력을 단계별로 진행하면서 from/to 커밋에 불연속이 표시됩니다. 각 새 푸시의 `commit_from`은(는) 이전 푸시의 `commit_to`과(와) 같아야 합니다. 이 시퀀스의 중단은 하나 이상의 커밋이 리포지토리 히스토리에서 "누락"되었음을 나타냅니다.

[Rails 콘솔](../../../administration/operations/rails_console.md#starting-a-rails-console-session)을 사용하면 다음 예에서 마지막 100개의 푸시를 확인하고 `commit_from` 및 `commit_to` 항목을 인쇄합니다:

```ruby
p = Project.find_by_full_path('project/path')
p.events.pushed_action.last(100).each do |e|
  printf "%-20.20s %8s...%8s (%s)", e.push_event_payload[:ref], e.push_event_payload[:commit_from], e.push_event_payload[:commit_to], e.author.try(:username)
end ; nil
```

예제 출력이 4번 줄에서 시퀀스 중단을 표시합니다:

```plaintext
master f21b07713251e04575908149bdc8ac1f105aabc3...6bc56c1f46244792222f6c85b11606933af171de root
master 6bc56c1f46244792222f6c85b11606933af171de...132da6064f5d3453d445fd7cb452b148705bdc1b root
master 132da6064f5d3453d445fd7cb452b148705bdc1b...a62e1e693150a2e46ace0ce696cd4a52856dfa65 root
master 58b07b719a4b0039fec810efa52f479ba1b84756...f05321a5b5728bd8a89b7bf530aa44043c951dce root
master f05321a5b5728bd8a89b7bf530aa44043c951dce...7d02e575fd790e76a3284ee435368279a5eb3773 root
```

### 오류: Xcode에서 리포지토리 복제 실패 {#error-xcode-fails-to-clone-repository}

GitLab은 [허용된 SSH 키의 목록을 제한](../../../security/ssh_keys_restrictions.md)하는 옵션을 제공합니다. SSH 키가 허용 목록에 없으면 `The repository rejected the provided credentials`과(와) 같은 오류가 발생할 수 있습니다.

이 문제를 해결하려면 [지원되는 SSH 키 유형](../../ssh.md#supported-ssh-key-types)의 지침을 충족하는 새 SSH 키 쌍을 만듭니다. 지원되는 SSH 키를 생성한 후 리포지토리를 다시 복제해 봅니다.
