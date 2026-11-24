---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 파일 트리 브라우저를 사용하여 리포지토리 파일과 디렉터리를 탐색합니다.
title: 파일 트리 브라우저
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.0에서 `repository_file_tree_browser` [기능 플래그](../../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/19530)되었습니다. 기본적으로 비활성화되었습니다.
- [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/19530) GitLab 18.9.
- GitLab 19.2에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/537970)입니다. 기능 플래그 `repository_file_tree_browser`이 제거되었습니다.

{{< /history >}}

파일 트리 브라우저는 리포지토리의 파일과 디렉터리를 축소 가능한 트리 구조로 표시하는 드로어입니다. 이를 사용하여 긴 파일 목록을 스크롤하지 않고 리포지토리를 탐색합니다.

파일 트리 브라우저는 다음을 도와줍니다:

- 중첩된 디렉터리 구조 탐색.
- 리포지토리 계층 보기.
- 디렉터리 구조의 컨텍스트를 유지하면서 파일 간 전환.

## 파일 트리 브라우저 표시 또는 숨기기 {#show-or-hide-the-file-tree-browser}

파일 트리 브라우저를 표시하거나 숨기려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. `/<project>/-/tree/<branch>`에서 리포지토리 파일로 이동합니다.
1. 왼쪽 위 모서리에서 파일 트리 브라우저 아이콘({{< icon name="file-tree" >}})을 선택합니다.

## 파일 및 디렉터리 탐색 {#navigate-files-and-directories}

파일 트리 브라우저는 확장하고 축소할 수 있는 파일과 디렉터리를 사용하여 리포지토리의 구조를 표시합니다.

파일 트리 브라우저에서 탐색하려면:

1. 왼쪽 위 모서리에서 파일 트리 브라우저 아이콘({{< icon name="file-tree" >}})을 선택합니다.
1. 디렉터리를 확장하려면 디렉터리 이름 옆에 {{< icon name="chevron-right" >}}을 선택합니다.
1. 파일을 보려면 파일명을 선택합니다.

중첩된 파일로 직접 탐색하면 파일 트리 브라우저는 자동으로 상위 디렉터리를 확장하고 현재 파일을 강조 표시합니다.

## 파일 검색 {#search-files}

검색 패널을 사용하여 리포지토리에서 이름으로 파일을 찾습니다.

파일을 검색하려면:

1. 왼쪽 위 모서리에서 파일 트리 브라우저 아이콘({{< icon name="file-tree" >}})을 선택합니다.
1. 검색 패널을 열려면 **파일 검색**을 선택합니다.
1. 찾으려는 파일명의 일부를 입력합니다. 결과 목록에 일치하는 파일과 상위 디렉터리가 표시됩니다.
1. 이동하려는 파일을 선택합니다.

검색과 일치하는 파일이 없으면 검색에 **검색 결과가 없음**가 표시됩니다.

## 키보드 단축키 {#keyboard-shortcuts}

파일 트리 브라우저는 다음 키보드 단축키를 지원합니다:

| 단축키                      | 작업 |
|-------------------------------|--------|
| <kbd>Shift</kbd>+<kbd>F</kbd> | 파일 트리 브라우저를 표시하거나 숨깁니다. |
| <kbd>F</kbd>                  | 검색 패널을 엽니다. |

사용 가능한 키보드 단축키의 전체 목록을 보려면 [GitLab 키보드 단축키](../../../shortcuts.md)를 참조하세요.

### 트리 탐색 {#tree-navigation}

파일 트리 브라우저는 키보드 탐색을 위해 [W3C ARIA 트리뷰 패턴](https://www.w3.org/WAI/ARIA/apg/patterns/treeview/)을 구현합니다:

| 키                                                  | 기능 |
|------------------------------------------------------|----------|
| <kbd>Enter</kbd> 또는 <kbd>Space</kbd>                 | 포커스가 있는 파일 또는 디렉터리를 선택합니다 |
| <kbd>아래쪽 화살표</kbd>                                | 디렉터리를 열거나 닫지 않고 포커스를 다음 파일 또는 디렉터리로 이동합니다. 포커스가 마지막 항목에 있으면 아무 작업도 수행하지 않습니다. |
| <kbd>위쪽 화살표</kbd>                                  | 디렉터리를 열거나 닫지 않고 포커스를 이전 파일 또는 디렉터리로 이동합니다. 포커스가 첫 번째 항목에 있으면 아무 작업도 수행하지 않습니다. |
| <kbd>오른쪽 화살표</kbd>                               | 포커스가 닫힌 디렉터리에 있으면 엽니다. 포커스가 열린 디렉터리에 있으면 포커스를 내부의 첫 번째 항목으로 이동합니다. 포커스가 파일에 있으면 아무 작업도 수행하지 않습니다. |
| <kbd>왼쪽 화살표</kbd>                                | 포커스가 열린 디렉터리에 있으면 닫습니다. 포커스가 파일 또는 중첩된 항목에 있으면 포커스를 상위 디렉터리로 이동합니다. 포커스가 닫힌 루트 디렉터리에 있으면 아무 작업도 수행하지 않습니다. |
| <kbd>Home</kbd>[^home-end-keys]                                     | 디렉터리를 열거나 닫지 않고 포커스를 첫 번째 파일 또는 디렉터리로 이동합니다. |
| <kbd>End</kbd>[^home-end-keys]                                       | 닫힌 디렉터리를 확장하지 않고 포커스를 마지막 파일 또는 디렉터리로 이동합니다. |
| <kbd>a</kbd>-<kbd>z</kbd>, <kbd>A</kbd>-<kbd>Z</kbd> | 입력한 문자로 시작하는 이름의 다음 파일 또는 디렉터리로 포커스를 이동합니다. 일치하는 항목이 없으면 검색이 첫 번째 항목으로 래핑됩니다. 닫힌 디렉터리 내의 항목을 무시합니다. |
| <kbd>\*</kbd> (별표)                              | 포커스가 있는 항목과 같은 수준의 모든 닫힌 디렉터리를 확장합니다. 포커스가 이동하지 않습니다. |

[^home-end-keys]: <kbd>Home</kbd> 및 <kbd>End</kbd> 키는 모든 키보드에서 사용 가능하지 않을 수 있습니다.

## 관련 항목 {#related-topics}

- [웹 편집기](../web_editor.md)
- [Git 파일 이력](git_history.md)
- [Git 파일 blame](git_blame.md)
