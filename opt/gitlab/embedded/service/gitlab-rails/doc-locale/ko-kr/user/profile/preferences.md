---
stage: Facilitated functionality
group: Facilitated functionality
info: For more information, see <https://handbook.gitlab.com/handbook/product/categories/#facilitated-functionality>
title: 프로필 기본 설정
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

기본 설정을 업데이트하여 GitLab의 모양과 느낌을 변경할 수 있습니다.

## 모드 변경 {#change-the-mode}

{{< history >}}

- GitLab 13.1에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/28252).
- GitLab 17.11에서 실험에서 베타로 [변경됨](https://gitlab.com/gitlab-org/gitlab/-/issues/524846).
- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/issues/470413) **외관**에서 **모드**로 GitLab 18.1.

{{< /history >}}

인터페이스의 색상 모드를 밝음, 어두움으로 변경하거나 기기 기본 설정에 따라 자동으로 업데이트할 수 있습니다.

외관을 변경하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **모드** 섹션에서 옵션을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 탐색 테마 변경 {#change-the-navigation-theme}

{{< history >}}

- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/issues/470413) **색상 테마**에서 **탐색 테마**로 GitLab 18.1.
- 테마: 라이트 인디고, 라이트 블루, 라이트 그린, 라이트 레드가 GitLab 18.4에서 [제거됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200475).

{{< /history >}}

GitLab UI의 탐색 테마를 변경할 수 있습니다. 이러한 색상은 왼쪽 사이드바에 표시됩니다. 개별 탐색 테마를 사용하면 다양한 GitLab 인스턴스를 구분하는 데 도움이 될 수 있습니다.

탐색 테마를 변경하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **테마** 섹션에서 테마를 선택합니다.

## 구문 강조 테마 변경 {#change-the-syntax-highlighting-theme}

구문 강조는 코드 편집기 및 IDE의 기능입니다. 강조 프로그램은 문자열 및 주석과 같은 각 유형의 코드에 색상을 할당합니다.

구문 강조 테마를 변경하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **구문 하이라이트** 섹션에서 테마를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

업데이트된 구문 강조 테마를 보려면 프로젝트의 페이지를 새로 고칩니다.

구문 강조 테마를 사용자 지정하려면 [응용 프로그램 설정 API](../../api/settings.md#available-settings)를 사용할 수도 있습니다. `default_syntax_highlighting_theme` 및 `default_dark_syntax_highlighting_theme`를 사용하여 구문 강조 색상을 더 세밀한 수준에서 변경합니다.

이러한 단계가 작동하지 않으면 프로그래밍 언어가 구문 강조 프로그램에서 지원되지 않을 수 있습니다. 자세한 내용은 코드 파일 및 스니펫에 대한 지침은 [Rouge Ruby 라이브러리](https://github.com/rouge-ruby/rouge)를 참조하세요. Web IDE에 대한 지침은 [Monaco Editor](https://microsoft.github.io/monaco-editor/) 및 [Monarch](https://microsoft.github.io/monaco-editor/monarch.html)를 보세요.

## diff 색상 변경 {#change-the-diff-colors}

Diff는 두 가지 다른 배경색을 사용하여 코드 버전 간의 변경사항을 표시합니다. 기본적으로 원본 파일은 빨간색이고 변경사항은 녹색입니다.

diff 색상을 변경하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **Diffs** 섹션으로 이동합니다.
1. 색상을 선택하거나 색상 코드를 입력합니다.
1. **변경 사항 저장**을 선택합니다.

기본 색상으로 돌아가려면 **삭제된 줄 색상** 및 **추가된 줄 색상** 텍스트 상자를 지우고 **변경사항 저장**을 선택합니다.

## 행동 {#behavior}

**행동** 섹션을 사용하여 시스템 레이아웃 및 기본 뷰의 동작을 사용자 지정합니다. 레이아웃 너비를 변경하고 홈페이지, 그룹 및 프로젝트 개요 페이지의 기본 콘텐츠를 선택할 수 있습니다. 공백 렌더링, 파일 표시 및 텍스트 자동화 같은 모양 및 기능을 사용자 지정할 수 있는 옵션이 있습니다.

이 섹션을 사용하여 GitLab Duo에 대한 기본 네임스페이스를 설정할 수도 있습니다.

### UI의 레이아웃 너비 변경 {#change-the-layout-width-on-the-ui}

GitLab UI의 콘텐츠를 늘려서 전체 페이지를 채울 수 있습니다. 기본적으로 페이지 콘텐츠는 1280픽셀 너비로 고정됩니다.

UI의 레이아웃 너비를 변경하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **레이아웃 너비** 아래에서 **고쳐짐** 또는 **Fluid**를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### 기본 텍스트 편집기 설정 {#set-the-default-text-editor}

{{< history >}}

- GitLab 17.7에 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/423104)되었습니다.
- 새 사용자의 경우 18.2에서 [리치 텍스트 편집기로 설정됨](https://gitlab.com/gitlab-org/gitlab/-/issues/536611).

{{< /history >}}

기본적으로 모든 새 사용자는 콘텐츠를 편집할 때 **리치 텍스트 편집기**를 봅니다. GitLab에서 콘텐츠 편집을 위한 기본 편집기를 변경할 수 있습니다.

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **기본 텍스트 편집기** 아래에서 **기본 텍스트 편집기 활성화** 확인란이 선택되어 있는지 확인합니다.
1. **리치 텍스트 편집기** 또는 **일반 텍스트 편집기**를 기본값으로 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### 홈페이지 선택 {#choose-your-homepage}

{{< history >}}

- [홈페이지 옵션이 변경됨](https://gitlab.com/groups/gitlab-org/-/work_items/13066) GitLab 17.9 [기능 플래그](../../administration/feature_flags/_index.md) `your_work_projects_vue`를 포함합니다. 기본적으로 비활성화되었습니다.
- [홈페이지 옵션이 일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/465889) GitLab 17.10. 기능 플래그 `your_work_projects_vue`이 제거되었습니다.
- [개인 홈페이지 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/546151) GitLab 18.1 [기능 플래그](../../administration/feature_flags/_index.md) `personal_homepage`를 포함합니다. 기본적으로 비활성화되었습니다.
- [개인 홈페이지가 GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/554048) GitLab 18.4 (사용자의 일부).
- [개인 홈페이지가 GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화됨](https://gitlab.com/groups/gitlab-org/-/work_items/17932) GitLab 18.5.
- [개인 홈페이지가 일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/561388) GitLab 19.4. 기능 플래그 `personal_homepage`이 제거되었습니다.

{{< /history >}}

GitLab 로고({{< icon name="tanuki" >}})를 선택할 때 보는 페이지를 제어합니다. 홈페이지를 개인 홈페이지(기본값), 기여한 프로젝트, 그룹, 활동 및 기타 콘텐츠로 설정할 수 있습니다.

홈페이지 보기를 선택하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **홈페이지** 드롭다운 목록에서 옵션을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### 그룹 개요 페이지의 기본 콘텐츠 사용자 지정 {#customize-default-content-on-your-group-overview-page}

그룹 개요 페이지의 기본 콘텐츠를 변경할 수 있습니다. 그룹 개요 페이지는 왼쪽 사이드바에서 **그룹**을 선택할 때 표시되는 페이지입니다. 그룹 개요 페이지의 기본 콘텐츠를 다음과 같이 사용자 지정할 수 있습니다:

- 세부 정보 대시보드(기본값): 그룹 활동 및 프로젝트에 대한 개요를 포함합니다.
- 보안 대시보드: 그룹 보안 정책 및 기타 보안 항목을 포함할 수 있습니다.

자세한 내용은 [그룹](../group/_index.md)을 참조하세요.

그룹 개요 페이지의 기본 콘텐츠를 변경하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **그룹 개요 콘텐츠** 드롭다운 목록에서 옵션을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### 프로젝트 개요 페이지의 기본 콘텐츠 사용자 지정 {#customize-default-content-on-your-project-overview-page}

프로젝트 개요 페이지는 왼쪽 사이드바에서 **프로젝트 개요**를 선택할 때 보는 페이지입니다. 기본 프로젝트 개요 페이지를 활동 페이지, README 파일 및 기타 콘텐츠로 설정할 수 있습니다.

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **프로젝트 개요 콘텐츠** 드롭다운 목록에서 옵션을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### 기본 GitLab Duo 네임스페이스 설정 {#set-a-default-gitlab-duo-namespace}

{{< history >}}

- GitLab 18.3에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/552081) [플래그](../../administration/feature_flags/_index.md) `ai_user_default_duo_namespace`. 기본적으로 비활성화되었습니다.
- GitLab 18.4에서 [활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/560319)되었습니다.
- GitLab 18.7에서 [제거됨](https://gitlab.com/gitlab-org/gitlab/-/issues/569140) `ai_user_default_duo_namespace` 기능 플래그.

{{< /history >}}

기본 GitLab Duo 네임스페이스를 설정하여 GitLab Duo를 프로젝트에서 사용할 수 있도록 합니다. 기본 GitLab Duo 네임스페이스는 사용 가능한 [AI 모델](../gitlab_duo/model_selection.md) 및 GitLab Duo 기능과 [GitLab Credits](../../subscriptions/gitlab_credits.md) 소비를 결정합니다.

기본 GitLab Duo 네임스페이스는 다음 시나리오에서 기능 가용성 및 크레딧 소비를 결정합니다:

- 작업 중인 프로젝트의 구성원이 아닙니다.
- 여러 GitLab Duo 네임스페이스에 속합니다.
- GitLab 원격이 구성되지 않은 프로젝트를 사용하여 IDE에서 작업합니다.
- CLI에서 GitLab Duo를 사용합니다.

직접 또는 상속된 구성원인 프로젝트 또는 그룹에서 작업할 때 해당 프로젝트 또는 그룹의 최상위 그룹이 대신 기능 가용성 및 크레딧 소비에 사용됩니다:

- 구성원인 프로젝트에서 GitLab Duo 기능을 사용하면 해당 프로젝트의 최상위 그룹에 사용량이 청구됩니다.
- 프로젝트 외부에서 GitLab Duo 기능을 사용하면(예: 열린 프로젝트 없이 IDE에서 또는 CLI에서) 기본 네임스페이스에 사용량이 청구됩니다.
- 구성원이 아닌 프로젝트에서 GitLab Duo 기능을 사용하면 기본 네임스페이스에 사용량이 청구됩니다.

기본 네임스페이스를 설정하지 않으면 GitLab Duo Agentic Chat 및 GitLab Duo Agent Platform이 비활성화됩니다.

기본 GitLab Duo 네임스페이스를 설정하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **기본 GitLab Duo 그룹** 드롭다운 목록에서 기본값으로 설정할 그룹을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

#### 로컬 환경에서의 네임스페이스 확인 {#namespace-resolution-in-your-local-environment}

{{< history >}}

- IDE에 대한 사용자 기본 네임스페이스에 대한 액세스 GitLab 18.10에서 [도입됨](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/work_items/2043).
- GitLab for VS Code 6.71.7에서 사용자 기본 네임스페이스에 대한 액세스가 도입되었습니다.
- GitLab Duo CLI 8.76.0에서 사용자 기본 네임스페이스에 대한 액세스가 도입되었습니다.
- 편집기 확장의 기본 네임스페이스 설정 GitLab 19.4에서 [제거됨](https://gitlab.com/gitlab-org/editor-extensions/gitlab-lsp/-/work_items/2369).
  - GitLab Duo plugin for JetBrains IDEs 3.46.0에서 [제거됨](https://gitlab.com/gitlab-org/editor-extensions/gitlab-jetbrains-plugin/-/releases/v3.46.0).
  - GitLab for VS Code 6.90.0에서 [제거됨](https://gitlab.com/gitlab-org/gitlab-vscode-extension/-/releases/v6.90.0).

{{< /history >}}

IDE 또는 CLI에서 GitLab Duo를 사용할 때 첫 번째 사용 가능한 네임스페이스가 기능 가용성 및 크레딧 소비를 결정합니다. 다른 Agent Platform 요구사항과 함께 작업 중인 프로젝트는 [그룹 네임스페이스](../namespace/_index.md)에 있어야 합니다.

GitLab Duo는 다음 순서로 네임스페이스를 확인합니다:

1. 프로젝트가 GitLab의 원격 저장소에 연결된 경우 프로젝트 네임스페이스입니다.
1. 사용자 기본 설정에서 설정한 기본 네임스페이스입니다.

식별된 첫 번째 네임스페이스에 요청된 기능 또는 사용 가능한 크레딧에 대한 액세스 권한이 없으면 기능을 사용할 수 없습니다. GitLab Duo는 목록의 다음 네임스페이스로 폴백하지 않습니다.

프로젝트가 GitLab의 원격 저장소에 연결되지 않은 경우 사용자 기본 설정에서 [기본 GitLab Duo 네임스페이스를 설정](#set-a-default-gitlab-duo-namespace)해야 합니다.

### 바로가기 버튼 숨기기 {#hide-shortcut-buttons}

바로가기 버튼은 프로젝트 개요 페이지의 파일 목록보다 앞에 옵니다. 이러한 버튼은 README 파일 또는 라이선스 계약과 같은 프로젝트의 일부로 연결됩니다.

프로젝트 개요 페이지에서 바로가기 버튼을 숨기려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **프로젝트 개요에서 파일 위에 바로가기 버튼 표시** 확인란을 지웁니다.
1. **변경 사항 저장**을 선택합니다.

### Web IDE에서 공백 문자 표시 {#show-whitespace-characters-in-the-web-ide}

공백 문자는 공백 및 들여쓰기와 같은 텍스트의 모든 빈 문자입니다. 공백을 사용하여 코드에서 콘텐츠를 구성할 수 있습니다. 프로그래밍 언어가 공백에 민감하면 Web IDE에서 변경사항을 감지할 수 있습니다.

Web IDE에서 공백을 렌더링하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **Web IDE에서 공백 문자 렌더링** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

diff에서 공백 변경사항을 볼 수 있습니다.

Web IDE에서 diff를 보려면 다음 단계를 따릅니다:

1. 왼쪽 사이드바에서 **소스 제어**({{< icon name="branch" >}})를 선택합니다.
1. **변경사항** 탭 아래에서 파일을 선택합니다.

### diff에서 공백 변경사항 표시 {#show-whitespace-changes-in-diffs}

diff 파일에서 공백 변경사항을 봅니다. 공백에 대한 자세한 내용은 이전 작업을 참조하세요.

diff에서 공백 변경사항을 보려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **diff에서 공백 변경 사항 표시** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

diff에 대한 자세한 내용은 [diff 색상 변경](#change-the-diff-colors)을 참조하세요.

### 머지 리퀘스트에서 한 페이지에 파일 하나 표시 {#show-one-file-per-page-in-a-merge-request}

**변경사항** 탭을 통해 한 페이지에서 머지 리퀘스트의 모든 파일 변경사항을 볼 수 있습니다. 대신 한 번에 하나의 파일을 볼 수 있습니다.

**변경사항** 탭에서 한 페이지에 하나의 파일을 표시하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **머지 리퀘스트의 변경 탭에서 한 번에 하나의 파일 표시** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

그런 다음 **변경사항** 탭에서 각 파일 아래로 **이전** 및 **다음** 버튼을 선택합니다.

### 자동으로 문자 묶기 {#auto-enclose-characters}

여는 문자를 입력할 때 자동으로 해당 닫는 문자를 텍스트에 추가합니다. 예를 들어 여는 괄호를 입력할 때 자동으로 닫는 괄호를 삽입할 수 있습니다. 이 설정은 설명 및 주석 상자에서만 작동하며 다음 문자에 대해 작동합니다: `**"`, `'`, ```, `(`, `[`, `{`, `<`, `*`, `_**`.

설명 및 주석 상자에서 문자를 자동으로 묶으려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **따옴표 또는 괄호를 입력할 때 선택된 텍스트를 감싸기** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

설명 또는 주석 상자에서 단어를 입력하고 강조한 다음 여는 문자를 입력할 수 있습니다. 텍스트를 바꾸는 대신 닫는 문자가 끝에 추가됩니다.

### 새 목록 항목 자동화 {#automate-new-list-items}

설명 및 주석 상자의 목록에서 <kbd>Enter</kbd>를 눌러 새 목록 항목을 만듭니다.

<kbd>Enter</kbd> 키를 누를 때 새 목록 항목을 추가하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **자동으로 새 목록 항목 추가** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### emoji 자동 완성 끄기 {#turn-off-emoji-autocomplete}

기본적으로 설명 또는 주석 상자에서 콜론(`:`)을 입력하면 GitLab은 일치하는 emoji를 제안합니다. 콜론 앞에 공백을 두는 언어처럼 다른 이유로 콜론을 입력하는 경우 이러한 제안을 끌 수 있습니다. 꺼졌을 때 복사 및 붙여넣기와 같은 다른 방법으로 emoji를 삽입할 수 있습니다.

emoji 자동 완성을 끄려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **emoji 자동 완성 활성화** 확인란을 지웁니다.
1. **변경 사항 저장**을 선택합니다.

### 커서 들여쓰기 유지 {#maintain-cursor-indentation}

<kbd>Enter</kbd>를 누를 때 들여쓰기를 유지합니다. 새 줄의 커서는 이전 줄과 동일하게 자동으로 들여쓰기됩니다. 이 설정은 설명 및 주석 상자에서만 작동합니다.

<kbd>Enter</kbd> 키를 누를 때 새 목록 항목을 추가하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **커서 들여쓰기 유지** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### 탭 너비 변경 {#change-the-tab-width}

diff, blob 및 스니펫에서 탭의 기본 크기를 변경합니다. Web IDE, 파일 편집기 및 Markdown 편집기는 이 기능을 지원하지 않습니다.

기본 탭 너비를 조정하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **행동** 섹션으로 스크롤합니다.
1. **Tab 간격**에 값을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

## 현지화 {#localization}

언어, 달력 시작 날짜 및 시간 기본 설정과 같은 현지화 설정을 변경합니다.

### GitLab UI의 표시 언어 변경 {#change-your-display-language-on-the-gitlab-ui}

GitLab은 UI의 여러 언어를 지원합니다.

GitLab UI의 언어를 선택하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **현지화** 섹션으로 이동합니다.
1. **언어** 아래에서 옵션을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

업데이트된 언어를 보려면 페이지를 새로 고쳐야 할 수도 있습니다.

### 기여 달력 시작 날짜 사용자 지정 {#customize-your-contribution-calendar-start-day}

기여 달력이 시작되는 요일을 선택합니다. 기여 달력은 지난 1년간의 프로젝트 기여를 표시합니다. 각 사용자 프로필에서 이 달력을 볼 수 있습니다. 사용자 프로필에 액세스하려면:

- 오른쪽 위 모서리에서 아바타를 선택한 다음 이름 또는 사용자 이름을 선택합니다.

기여 달력 시작 날짜를 변경하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **현지화** 섹션으로 이동합니다.
1. **첫번째 요일** 아래에서 옵션을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

달력 시작 날짜를 변경한 후 사용자 프로필 페이지를 새로 고칩니다.

### 상대 시간 대신 정확한 시간 표시 {#show-exact-times-instead-of-relative-times}

그룹 및 프로젝트 개요 페이지와 사용자 프로필에 활동 시간을 표시하는 데 사용되는 형식을 사용자 지정합니다. 시간을 다음과 같이 표시할 수 있습니다:

- 상대 형식: 예 `30 minutes ago`.
- 절대 형식: 예 `September 3, 2022, 3:57 PM`.

GitLab UI에서 정확한 시간을 사용하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **시간 설정** 섹션으로 이동합니다.
1. **상대 시간 사용** 확인란을 지웁니다.
1. **변경 사항 저장**을 선택합니다.

### 시간 형식 사용자 지정 {#customize-time-format}

그룹 및 프로젝트 개요 페이지와 사용자 프로필에 활동 시간을 표시하는 데 사용되는 형식을 사용자 지정할 수 있습니다. 다음과 같이 시간을 표시할 수 있습니다:

- 12시간 형식. 예: `2:34 PM`.
- 24시간 형식. 예: `14:34`.

또한 시스템의 설정을 따를 수 있습니다.

시간 형식을 사용자 지정하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **시간 설정** 섹션으로 이동합니다.
1. **시간 형식** 아래에서 **시스템**, **12시간** 또는 **24시간** 옵션을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## CI 작업 JSON 웹 토큰의 사용자 ID {#user-identities-in-ci-job-json-web-tokens}

CI/CD 작업은 외부 ID 목록을 포함할 수 있는 JSON 웹 토큰을 생성합니다. 개별 계정을 가져오기 위해 별도의 API 호출을 하는 대신 단일 인증 토큰에서 사용자 ID를 찾을 수 있습니다.

외부 ID는 기본적으로 포함되지 않습니다. 외부 ID 포함을 활성화하려면 [토큰 페이로드](../../ci/secrets/id_token_authentication.md#token-payload)를 참조하세요.

## 팔로워 참여 제어 {#control-follower-engagement}

다른 GitLab 사용자를 팔로우하거나 따르는 기능을 끕니다. 기본적으로 이름 및 프로필 사진을 포함한 사용자 프로필은 다른 사용자의 **팔로잉** 탭에서 공개됩니다. 이 설정을 비활성화하면:

- GitLab은 모든 팔로워 및 팔로우 연결을 삭제합니다.
- GitLab은 각 연결의 페이지에서 자동으로 사용자 프로필을 제거합니다.

다른 사용자를 팔로우하고 따르는 기능을 제거하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **사용자 팔로우 활성화** 확인란을 지웁니다.
1. **변경 사항 저장**을 선택합니다.

**팔로워** 및 **팔로잉** 탭에 액세스하려면:

- 오른쪽 위 모서리에서 아바타를 선택합니다.
- **팔로워** 또는 **팔로잉**을 선택합니다.

## GitLab 인스턴스를 타사 서비스와 연동 {#integrate-your-gitlab-instance-with-third-party-services}

타사 서비스에 GitLab 환경을 향상시키기 위한 액세스 권한을 제공합니다.

### GitLab 인스턴스를 Ona와 연동 {#integrate-your-gitlab-instance-with-ona}

GitLab 브라우저에서 직접 코드를 시작하고 관리하려는 경우 Ona를 사용하여 GitLab 인스턴스를 구성합니다. Ona는 프로젝트의 개발 환경을 자동으로 준비하고 구축합니다.

Ona와 연동하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **연동** 섹션을 찾습니다.
1. **Ona 통합 활성화** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

### GitLab 인스턴스를 Sourcegraph와 연동 {#integrate-your-gitlab-instance-with-sourcegraph}

GitLab은 GitLab의 모든 공개 프로젝트에 대한 Sourcegraph 연동을 지원합니다.

Sourcegraph와 연동하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **연동** 섹션을 찾습니다.
1. **코드 뷰에서 통합 코드 인텔리전스 활성화** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

Sourcegraph로 GitLab을 구성하려면 GitLab 인스턴스의 관리자여야 합니다.

### extension marketplace와 연동 {#integrate-with-the-extension-marketplace}

{{< details >}}

- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [베타](../../policy/development_stages_support.md#beta)로 GitLab 17.0에서 `web_ide_oauth` 및 `web_ide_extensions_marketplace`라는 [기능 플래그](../../administration/feature_flags/_index.md)와 함께 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/151352)되었습니다. 기본적으로 비활성화되었습니다.
- `web_ide_oauth` [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163181) GitLab 17.4.
- `web_ide_extensions_marketplace` [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/459028) GitLab 17.4.
- `web_ide_oauth` [제거됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/167464) GitLab 17.5.
- [워크스페이스](../workspace/_index.md)에 대해 GitLab 17.6에서 기본적으로 활성화되었습니다. 워크스페이스에서는 extension marketplace를 사용 가능하게 하기 위해 기능 플래그가 필요하지 않습니다.
- GitLab 17.10에서 `vscode_extension_marketplace_settings` [기능 플래그](../../administration/feature_flags/_index.md)를 [도입했습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/508996). 기본적으로 비활성화되었습니다.
- `web_ide_extensions_marketplace` [GitLab Self-Managed에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184662), `vscode_extension_marketplace_settings` [GitLab.com 및 GitLab Self-Managed에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184662) GitLab 17.11.
- GitLab 18.1에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192659)하게 되었습니다. 기능 플래그 `web_ide_extensions_marketplace` 및 `vscode_extension_marketplace_settings`이 제거되었습니다.

{{< /history >}}

VS Code Extension Marketplace는 Web IDE 및 워크스페이스의 기능을 향상시키는 확장 프로그램에 대한 액세스를 제공합니다.

사전 요구 사항:

- GitLab Self-Managed 및 GitLab Dedicated의 경우 GitLab 관리자는 [extension registry를 활성화](../../administration/settings/vscode_extension_marketplace.md#enable-the-extension-registry)해야 합니다.
- 엔터프라이즈 사용자의 경우 그룹 소유자는 관련 그룹에 대해 [Extension Marketplace를 활성화](../enterprise_user/_index.md#enable-the-extension-marketplace-for-enterprise-users)해야 합니다.

Extension Marketplace와 연동하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **환경설정**을 선택합니다.
1. **연동** 섹션으로 이동합니다.
1. **extension marketplace 활성화** 확인란을 선택합니다.
1. 타사 확장 확인에서 **이해합니다**를 선택합니다.
1. **변경 사항 저장**을 선택합니다.
