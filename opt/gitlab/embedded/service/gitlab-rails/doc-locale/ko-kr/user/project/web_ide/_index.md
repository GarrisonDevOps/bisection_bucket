---
stage: AI Clients
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "Web IDE를 사용하여 GitLab UI에서 여러 파일을 편집하고, 커밋을 스테이징하며, 머지 리퀘스트를 생성합니다."
title: Web IDE
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.0에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/188427)하게 되었습니다. `vscode_web_ide` 기능 플래그가 제거되었습니다.

{{< /history >}}

Web IDE는 GitLab UI에서 직접 여러 파일을 편집하고, 변경 사항을 스테이징하며, 커밋을 생성할 수 있는 고급 편집기입니다. [Web 편집기](../repository/web_editor.md)와 달리 Web IDE는 소스 제어 관리 기능을 포함한 완전한 개발 환경을 제공합니다.

Web IDE에서 [GitLab Flavored Markdown](../../markdown.md) 미리보기 지원은 [에픽 15810](https://gitlab.com/groups/gitlab-org/-/epics/15810)에서 제안되었습니다.

## Web IDE 열기 {#open-the-web-ide}

여러 방법으로 Web IDE에 접근할 수 있습니다.

### 키보드 단축키 사용 {#with-a-keyboard-shortcut}

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. <kbd>.</kbd> 키보드 단축키를 사용합니다.

### 디렉토리에서 {#from-a-directory}

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 디렉토리로 이동합니다.
1. **코드** > **웹 IDE에서 열기**를 선택합니다.

### 파일에서 {#from-a-file}

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 파일로 이동합니다.
1. **편집** > **웹 IDE에서 열기**를 선택합니다.

### 머지 리퀘스트에서 {#from-a-merge-request}

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 머지 리퀘스트로 이동합니다.
1. 오른쪽 위에서 **코드** > **웹 IDE에서 열기**를 선택합니다.

Web IDE는 새 파일과 수정된 파일을 별도의 탭에서 열고, 변경 사항을 나란히 표시합니다. 로드 시간을 줄이기 위해 변경된 줄이 가장 많은 10개 파일만 자동으로 열립니다.

Web IDE 인터페이스는 왼쪽 사이드바 **탐색기** 보기에서 새로운 파일이나 수정된 파일 옆에 머지 리퀘스트 아이콘({{< icon name="merge-request" >}})을 표시합니다. 파일의 변경 사항을 보려면 파일을 마우스 오른쪽 버튼으로 클릭하고 **머지 리퀘스트 기반과 비교**를 선택합니다.

## 파일 관리 {#manage-files}

Web IDE를 사용하여 여러 파일을 열고, 편집하고, 업로드할 수 있습니다.

### 파일 열기 {#open-a-file}

Web IDE에서 파일을 이름으로 열려면:

1. <kbd>Command</kbd>+<kbd>P</kbd>를 누릅니다.
1. 검색창에 파일 이름을 입력합니다.

### 열린 파일 검색 {#search-open-files}

Web IDE에서 열린 파일 전체를 검색하려면:

1. <kbd>Shift</kbd>+<kbd>Command</kbd>+<kbd>F</kbd>를 누릅니다.
1. 검색 상자에 검색 용어를 입력합니다.

### 파일 업로드 {#upload-a-file}

Web IDE에서 파일을 업로드하려면:

1. Web IDE의 왼쪽에서 **탐색기**({{< icon name="documents" >}})를 선택하거나 <kbd>Shift</kbd>+<kbd>Command</kbd>+<kbd>E</kbd>를 누릅니다.
1. 파일을 업로드할 디렉토리로 이동합니다. 새 디렉토리를 생성하려면:

   - **탐색기** 보기에서 오른쪽 위의 **새 폴더**({{< icon name="folder-new" >}})를 선택합니다.

1. 디렉토리를 마우스 오른쪽 버튼으로 클릭하고 **업로드**를 선택합니다.
1. 업로드할 파일을 선택합니다.

한 번에 여러 파일을 업로드할 수 있습니다. 파일이 업로드되고 리포지토리에 자동으로 추가됩니다.

### 커밋하지 않은 변경 사항 복원 {#restore-uncommitted-changes}

Web IDE에서 편집하는 파일을 수동으로 저장할 필요가 없습니다. Web IDE는 수정한 파일을 스테이징하므로 [변경 사항을 커밋](#commit-changes)할 수 있습니다. 커밋하지 않은 변경 사항은 브라우저의 로컬 저장소에 저장됩니다. 브라우저 탭을 닫거나 Web IDE를 새로 고친 후에도 변경 사항이 유지됩니다.

커밋하지 않은 변경 사항을 사용할 수 없으면 로컬 기록에서 변경 사항을 복원할 수 있습니다. Web IDE에서 커밋하지 않은 변경 사항을 복원하려면:

1. <kbd>Shift</kbd>+<kbd>Command</kbd>+<kbd>P</kbd>를 누릅니다.
1. 검색창에 `Local History: Find Entry to Restore`를 입력합니다.
1. 커밋하지 않은 변경 사항이 있는 파일을 선택합니다.

## 소스 제어 사용 {#use-source-control}

소스 제어를 사용하여 수정된 파일을 보고, 브랜치를 생성 및 전환하고, 변경 사항을 커밋하며, 머지 리퀘스트를 생성할 수 있습니다.

### 수정된 파일 보기 {#view-modified-files}

Web IDE에서 수정한 파일의 목록을 보려면:

- Web IDE의 왼쪽에서 **소스 제어**({{< icon name="branch" >}})를 선택하거나 <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>G</kbd>를 누릅니다.

`CHANGES`, `STAGED CHANGES`, `MERGE CHANGES`이 표시됩니다. 자세한 내용은 [VS Code 문서](https://code.visualstudio.com/docs/sourcecontrol/overview#_commit)를 참조하세요.

### 브랜치 전환 {#switch-branches}

Web IDE는 기본적으로 현재 브랜치를 사용합니다. Web IDE에서 브랜치를 전환하려면:

1. 아래쪽 상태 표시줄의 왼쪽에서 현재 브랜치 이름을 선택합니다.
1. 기존 브랜치를 입력하거나 선택합니다.

### 브랜치 생성 {#create-a-branch}

Web IDE에서 현재 브랜치로부터 브랜치를 생성하려면:

1. 아래쪽 상태 표시줄의 왼쪽에서 현재 브랜치 이름을 선택합니다.
1. 드롭다운 목록에서 **새 브랜치 생성**을 선택합니다.
1. 새 브랜치 이름을 입력합니다.

Web IDE는 체크아웃한 브랜치를 기반으로 하여 브랜치를 생성합니다. 또는 다음 단계에 따라 다른 기반에서 브랜치를 생성할 수 있습니다:

1. Web IDE의 왼쪽에서 **소스 제어**({{< icon name="branch" >}})를 선택하거나 <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>G</kbd>를 누릅니다.
1. 소스 제어 패널의 오른쪽 위에서 줄임표 메뉴({{< icon name="ellipsis_h" >}})를 선택합니다.
1. 드롭다운 목록에서 **브랜치** > **다음에서 브랜치 생성...**을 선택합니다.
1. 드롭다운 목록에서 기반으로 사용할 브랜치를 선택합니다.

리포지토리에 쓰기 액세스 권한이 없으면 **새 브랜치 생성**이 표시되지 않습니다.

### 브랜치 삭제 {#delete-a-branch}

1. Web IDE의 왼쪽에서 **소스 제어**({{< icon name="branch" >}})를 선택하거나 <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>G</kbd>를 누릅니다.
1. 소스 제어 패널의 오른쪽 위에서 줄임표 메뉴({{< icon name="ellipsis_h" >}})를 선택합니다.
1. 드롭다운 목록에서 **브랜치** > **브랜치 지우기**를 선택합니다.
1. 드롭다운 목록에서 삭제할 브랜치를 선택합니다.

Web IDE에서 보호된 브랜치는 삭제할 수 없습니다.

### 변경 사항 커밋 {#commit-changes}

Web IDE에서 변경 사항을 커밋하려면:

1. Web IDE의 왼쪽에서 **소스 제어**({{< icon name="branch" >}})를 선택하거나 <kbd>Control</kbd>+<kbd>Shift</kbd>+<kbd>G</kbd>를 누릅니다.
1. 커밋 메시지를 입력합니다.
1. 다음 커밋 옵션 중 하나를 선택합니다:
   - **현재 브랜치에 커밋** \- 현재 브랜치에 변경 사항을 커밋합니다
   - **[새 브랜치 생성](#create-a-branch)** \- 새 브랜치를 생성하고 변경 사항을 커밋합니다
   - **[커밋 및 강제 푸시](#commit-and-force-push)** \- 원격 브랜치에 변경 사항을 강제 푸시합니다
   - **[커밋 수정 및 강제 푸시](#amend-commit-and-force-push)** \- 마지막 커밋을 수정하고 강제 푸시합니다

### 커밋 및 강제 푸시 {#commit-and-force-push}

변경 사항을 커밋하고 강제 푸시하려면:

1. 작업 버튼 메뉴를 선택하거나 줄임표({{< icon name="ellipsis_h" >}})를 선택합니다.
1. **커밋 및 강제 푸시**를 선택합니다.

> [!warning]
> 이 작업은 현재 브랜치의 원격 기록을 덮어씁니다. 주의해서 사용하세요.

### 커밋 수정 및 강제 푸시 {#amend-commit-and-force-push}

마지막 커밋을 수정하고 강제 푸시하려면:

1. 작업 버튼 메뉴를 선택하거나 줄임표({{< icon name="ellipsis_h" >}})를 선택합니다.
1. **커밋 수정 및 강제 푸시**를 선택합니다.

이 작업은 마지막 커밋을 업데이트하고 원격 리포지토리에 강제 푸시합니다. 이를 사용하여 새로운 커밋을 생성하지 않고 최근 커밋을 수정합니다.

## 머지 리퀘스트 생성 {#create-a-merge-request}

Web IDE에서 [머지 리퀘스트](../merge_requests/_index.md)를 생성하려면:

1. [변경 사항을 커밋](#commit-changes)합니다.
1. 오른쪽 아래에 나타나는 알림에서 **MR 생성**을 선택합니다.

자세한 내용은 [놓친 알림 보기](#view-missed-notifications)를 참조하세요.

## Web IDE 사용자 지정 {#customize-the-web-ide}

Web IDE를 사용자 지정하여 키보드 단축키, 테마, 설정 및 동기화에 대한 기본 설정을 맞춥니다.

### 명령 팔레트 사용 {#use-the-command-palette}

명령 팔레트를 사용하여 많은 명령에 액세스할 수 있습니다. Web IDE에서 명령 팔레트를 열고 명령을 실행하려면:

1. <kbd>Shift</kbd>+<kbd>Command</kbd>+<kbd>P</kbd>를 누릅니다.
1. 명령을 입력하거나 선택합니다.

### 설정 편집 {#edit-settings}

설정 편집기를 사용하여 사용자 및 Web IDE 워크스페이스 설정을 보고 편집할 수 있습니다. Web IDE에서 설정 편집기를 열려면:

- 상단 메뉴 모음에서 **파일** > **환경설정** > **설정**을 선택하거나 <kbd>Command</kbd>+<kbd>,</kbd>를 누릅니다.

설정 편집기에서 변경할 설정을 검색할 수 있습니다.

### 키보드 단축키 편집 {#edit-keyboard-shortcuts}

키보드 단축키 편집기를 사용하여 사용 가능한 모든 명령의 기본 키 바인딩을 보고 변경할 수 있습니다. Web IDE에서 키보드 단축키 편집기를 열려면:

- 상단 메뉴 모음에서 **파일** > **환경설정** > **키보드 단축키**를 선택하거나 <kbd>Command</kbd>+<kbd>K</kbd>를 누른 다음 <kbd>Command</kbd>+<kbd>S</kbd>를 누릅니다.

키보드 단축키 편집기에서 다음을 검색할 수 있습니다:

- 변경할 키 바인딩
- 키 바인딩을 추가하거나 제거할 명령

키 바인딩은 키보드 레이아웃을 기반으로 합니다. 키보드 레이아웃을 변경하면 기존 키 바인딩이 자동으로 업데이트됩니다.

### 색상 테마 변경 {#change-the-color-theme}

Web IDE에서 다양한 색상 테마를 선택할 수 있습니다. 기본 테마는 **GitLab Dark**입니다.

Web IDE에서 색상 테마를 변경하려면:

1. 상단 메뉴 모음에서 **파일** > **환경설정** > **테마** > **색상 테마**를 선택하거나 <kbd>Command</kbd>+<kbd>K</kbd>를 누른 다음 <kbd>Command</kbd>+<kbd>T</kbd>를 누릅니다.
1. 드롭다운 목록에서 화살표 키로 테마를 미리 봅니다.
1. 테마를 선택합니다.

Web IDE는 활성 색상 테마를 [사용자 설정](#edit-settings)에 저장합니다.

### 동기화 설정 구성 {#configure-sync-settings}

Web IDE에서 동기화 설정을 구성하려면:

1. <kbd>Shift</kbd>+<kbd>Command</kbd>+<kbd>P</kbd>를 누릅니다.
1. 검색창에 `Settings Sync: Configure`를 입력합니다.
1. 다음의 확인란을 선택하거나 선택 해제합니다:
   - **설정**
   - **키보드 바로 가기**
   - **사용자 코드 조각**
   - **사용자 작업**
   - **UI 상태**
   - **확장**
   - **프로필**

이 설정은 여러 Web IDE 인스턴스 간에 자동으로 동기화됩니다. 사용자 프로필을 동기화하거나 동기화된 설정의 이전 버전으로 되돌릴 수 없습니다.

### 놓친 알림 보기 {#view-missed-notifications}

Web IDE에서 작업을 수행하면 알림이 오른쪽 아래에 나타납니다. 놓친 알림을 보려면:

1. 아래쪽 상태 표시줄의 오른쪽에서 종 모양 아이콘({{< icon name="notifications" >}})을 선택하여 알림 목록을 봅니다.
1. 보려는 알림을 선택합니다.

## 확장 관리 {#manage-extensions}

{{< details >}}

- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 17.0에서 [베타](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/151352)로 [도입](../../../policy/development_stages_support.md#beta)되었으며, `web_ide_oauth` 및 `web_ide_extensions_marketplace` 이름의 [기능 플래그](../../../administration/feature_flags/_index.md)를 포함합니다. 기본적으로 비활성화되었습니다.
- `web_ide_oauth`이 GitLab 17.4에서 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/163181)되었습니다.
- `web_ide_extensions_marketplace`이 GitLab 17.4에서 [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/459028)되었습니다.
- `web_ide_oauth`이 GitLab 17.5에서 [제거](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/167464)되었습니다.
- GitLab 17.10에서 `vscode_extension_marketplace_settings` [기능 플래그](../../../administration/feature_flags/_index.md)가 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/508996)되었습니다. 기본적으로 비활성화되었습니다.
- `web_ide_extensions_marketplace`이 GitLab 17.11에서 [GitLab Self-Managed에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184662)되었고, `vscode_extension_marketplace_settings`이 [GitLab.com 및 GitLab Self-Managed에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184662)되었습니다.
- GitLab 18.1에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/192659)하게 되었습니다. 기능 플래그 `web_ide_extensions_marketplace` 및 `vscode_extension_marketplace_settings`이 제거되었습니다.

{{< /history >}}

VS Code 확장 마켓플레이스는 Web IDE의 기능을 향상시키는 확장에 대한 액세스를 제공합니다. 기본적으로 GitLab Web IDE는 [Open VSX Registry](https://open-vsx.org/)에 연결됩니다.

> [!note]
> VS Code 확장 마켓플레이스에 액세스하려면 브라우저에서 `.cdn.web-ide.gitlab-static.net` 자산 호스트에 액세스할 수 있어야 합니다. 이 보안 요구 사항은 타사 확장이 격리된 상태에서 실행되고 계정에 액세스할 수 없도록 합니다. 이는 GitLab.com과 GitLab Self-Managed 모두에 적용됩니다.

사전 요구 사항:

- 사용자 환경설정에서 [확장 마켓플레이스 통합](../../profile/preferences.md#integrate-with-the-extension-marketplace)을 수행해야 합니다.
- GitLab Self-Managed 및 GitLab Dedicated의 경우 GitLab 관리자는 [확장 레지스트리 활성화](../../../administration/settings/vscode_extension_marketplace.md)를 수행해야 합니다.
- 엔터프라이즈 사용자의 경우 그룹 소유자는 [엔터프라이즈 사용자를 위한 확장 마켓플레이스 활성화](../../enterprise_user/_index.md#enable-the-extension-marketplace-for-enterprise-users)를 수행해야 합니다.

### 확장 설치 {#install-an-extension}

Web IDE에서 확장을 설치하려면:

1. 상단 메뉴 모음에서 **보기** > **확장**을 선택하거나 <kbd>Command</kbd>+<kbd>Shift</kbd>+<kbd>X</kbd>를 누릅니다.
1. 검색창에 확장 이름을 입력합니다.
1. 설치할 확장을 선택합니다.
1. **설치**를 선택합니다.

### 확장 제거 {#uninstall-an-extension}

Web IDE에서 확장을 제거하려면:

1. 상단 메뉴 모음에서 **보기** > **확장**을 선택하거나 <kbd>Command</kbd>+<kbd>Shift</kbd>+<kbd>X</kbd>를 누릅니다.
1. 설치된 확장 목록에서 제거할 확장을 선택합니다.
1. **제거**를 선택합니다.

### 확장 설정 {#extension-setup}

Web IDE 확장은 프로젝트에서 작동하도록 추가 구성이 필요할 수 있습니다.

#### Vim 키 바인딩 사용 {#use-vim-keybindings}

Vim 텍스트 편집기의 키보드 단축키를 사용하여 텍스트를 탐색하고 편집하려면 Vim 키 바인딩을 사용합니다. 확장 마켓플레이스를 사용하면 Web IDE에 Vim 키 바인딩을 추가할 수 있습니다.

Vim 키 바인딩을 활성화하려면 [Vim](https://open-vsx.org/extension/vscodevim/vim) 확장을 설치합니다. 자세한 내용은 [확장 설치](#install-an-extension)를 참조하세요.

#### AsciiDoc 지원 {#asciidoc-support}

[AsciiDoc](https://open-vsx.org/extension/asciidoctor/asciidoctor-vscode) 확장은 Web IDE의 AsciiDoc 파일에 대한 라이브 미리보기, 구문 강조 및 코드 조각을 제공합니다. Web IDE에서 AsciiDoc 마크업 미리보기를 사용하려면 AsciiDoc 확장을 설치해야 합니다. 자세한 내용은 [확장 설치](#install-an-extension)를 참조하세요.

## 관련 항목 {#related-topics}

- [Web IDE의 GitLab Duo 비에이전트 채팅](../../gitlab_duo_chat/_index.md#use-gitlab-duo-chat-in-the-web-ide)

## 문제 해결 {#troubleshooting}

Web IDE로 작업할 때 다음과 같은 문제가 발생할 수 있습니다.

### 입력할 때 문자 오프셋 {#character-offset-when-typing}

Web IDE에 입력할 때 4자 오프셋이 발생할 수 있습니다. 해결 방법으로:

1. 상단 메뉴 모음에서 **파일** > **환경설정** > **설정**을 선택하거나 <kbd>Command</kbd>+<kbd>,</kbd>를 누릅니다.
1. 오른쪽 위 모서리에서 **설정 열기 (JSON)**를 선택합니다.
1. `settings.json` 파일에서 `"editor.disableMonospaceOptimizations": true`을 추가하거나 `"editor.fontFamily"` 설정을 변경합니다.

자세한 내용은 [VS Code 이슈 80170](https://github.com/microsoft/vscode/issues/80170)을 참조하세요.

### OAuth 콜백 URL 업데이트 {#update-the-oauth-callback-url}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

사전 요구 사항:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

Web IDE는 인증을 위해 [인스턴스 전체 OAuth 애플리케이션](../../../integration/oauth_provider.md#create-an-instance-wide-application)을 사용합니다. OAuth 콜백 URL이 잘못 구성된 경우 다음 메시지와 함께 `Cannot open Web IDE` 오류 페이지가 표시될 수 있습니다:

```plaintext
The URL you're using to access the Web IDE and the configured OAuth callback URL do not match. This issue often occurs when you're using a proxy.
```

이 문제를 해결하려면 OAuth 콜백 URL을 GitLab 인스턴스에 액세스하는 데 사용되는 URL과 일치하도록 업데이트해야 합니다.

사전 요구 사항:

- 관리자 액세스 권한이 있어야 합니다.

OAuth 콜백 URL을 업데이트하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **응용 프로그램**을 선택합니다.
1. **GitLab Web IDE**의 경우 **편집**을 선택합니다.
1. OAuth 콜백 URL을 입력합니다. 줄 바꿈으로 구분된 여러 URL을 입력할 수 있습니다.

### 액세스 토큰 수명이 5분 미만일 수 없습니다 {#access-token-lifetime-cannot-be-less-than-5-minutes}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

액세스 토큰 수명이 5분 미만일 수 없다는 오류 메시지가 표시될 수 있습니다.

이 오류는 GitLab 인스턴스가 5분 미만의 액세스 토큰 만료 시간으로 구성된 경우 발생합니다. Web IDE는 제대로 작동하려면 최소 5분의 수명을 가진 액세스 토큰이 필요합니다.

이 문제를 해결하려면 인스턴스 구성에서 액세스 토큰 수명을 최소 5분으로 늘립니다. 액세스 토큰 만료 구성에 대한 자세한 내용은 [액세스 토큰 만료](../../../integration/oauth_provider.md#access-token-expiration)를 참조하세요.

### Workhorse 종속성 {#workhorse-dependency}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

GitLab Self-Managed에서 Workhorse는 GitLab Rails 서버 앞에 설치되고 실행되어야 합니다. 설치되지 않은 경우 Web IDE를 열거나 마크다운 미리보기와 같은 특정 기능을 사용할 때 문제가 발생할 수 있습니다.

보안상의 이유로 Web IDE의 일부는 별도의 원본에서 실행되어야 합니다. 이 접근 방식을 지원하기 위해 Web IDE는 Workhorse를 사용하여 Web IDE 자산과 주고받는 요청을 적절하게 라우팅합니다. Web IDE 자산은 정적 프론트엔드 자산이므로 Rails에 의존하는 것은 불필요한 오버헤드입니다.

### CORS 문제 {#cors-issues}

Web IDE는 GitLab Self-Managed 인스턴스에서 제대로 작동하기 위해 특정 CORS(Cross-Origin Resource Sharing) 구성이 필요합니다. GitLab API 엔드포인트(`/api/*`)는 Web IDE를 지원하기 위해 다음 HTTP 응답 헤더를 포함해야 합니다:

| 헤더 | 값 | 설명 |
|--------|-------|-------------|
| `Access-Control-Allow-Origin` | `https://[subdomain].cdn.web-ide.gitlab-static.net` | Web IDE 원본의 요청을 허용합니다. `[subdomain]`은 동적으로 생성되는 영숫자 문자열(최대 52자)입니다. |
| `Access-Control-Allow-Headers` | `Authorization` | 교차 원본 요청에서 권한 부여 헤더를 허용합니다. |
| `Access-Control-Allow-Methods` | `GET, POST, PUT, DELETE, OPTIONS` | 허용되는 HTTP 메서드를 지정합니다(권장). |
| `Access-Control-Allow-Credentials` | `false` | Web IDE는 이 [헤더](https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Credentials)로 제어되는 HTTP 요청에 자격 증명을 포함할 필요가 없습니다. |
| `Access-Control-Expose-Headers` | `Link, X-Total, X-Total-Pages, X-Per-Page, X-Page, X-Next-Page, X-Prev-Page, X-Gitlab-Blob-Id, X-Gitlab-Commit-Id, X-Gitlab-Content-Sha256, X-Gitlab-Encoding, X-Gitlab-File-Name, X-Gitlab-File-Path, X-Gitlab-Last-Commit-Id X-Gitlab-Ref, X-Gitlab-Size, X-Request-Id, ETag, X-Streaming-Format` | GitLab Rest 및 GraphQL API에서 사용되는 헤더입니다. |
| `Vary` | `Origin` | CORS 응답에 대한 적절한 캐싱 동작을 보장합니다. |

Web IDE는 동적으로 확장 호스트 도메인의 하위 도메인 부분을 생성합니다. CORS 헤더가 다음 규칙을 충족하는지 확인합니다:

- **패턴 일치**: `https://*.cdn.web-ide.gitlab-static.net` 패턴과 일치하는 원본을 허용합니다.
- **Validation**: 하위 도메인이 영숫자만 포함하고 ≤52자인지 확인합니다.
- **보안**:  Access-Control-Allow-Origin에 와일드카드(`*`)를 사용하지 않으세요. 보안 위험이 있습니다.

GitLab 인스턴스의 기본 CORS 구성이 이 요구 사항을 만족합니다. GitLab Self-Managed 인스턴스가 HTTP 역 프록시 서버 뒤에 있거나 사용자 지정 CORS 정책 구성을 사용하는 경우 문제가 발생할 수 있습니다.

### 오프라인 환경 {#offline-environments}

Web IDE는 기본 확장 호스트 도메인(`https://*.cdn.web-ide.gitlab-static.net`)에 연결할 수 없을 때 기능이 제한됩니다. 오프라인 환경에서 GitLab 관리자는 [사용자 지정 확장 호스트 도메인](../../../administration/settings/web_ide.md)을 해결 방법으로 설정할 수 있습니다.

### 문제 보고 {#report-a-problem}

문제를 보고하려면 다음 정보와 함께 [새 이슈를 생성](https://gitlab.com/gitlab-org/gitlab-web-ide/-/issues/new)합니다:

- 오류 메시지
- 전체 오류 세부 정보
- 문제가 발생하는 빈도
- 문제를 재현하는 단계

유료 티어를 사용 중인 경우 [지원팀에 문의](https://support.gitlab.com/hc/en-us/articles/11626483177756-GitLab-Support#contact-support)하여 도움을 받을 수도 있습니다.
