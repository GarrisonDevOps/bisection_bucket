---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 위키 특정 Markdown
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

## 링크 {#links}

다음 항목은 위키 내 링크 동작 방식을 설명합니다.

위키 페이지에 링크할 때는 페이지 이름 대신 페이지 슬러그를 사용합니다. 페이지 슬러그는 페이지 제목의 URL 친화적 버전으로, 공백은 하이픈으로 바뀌고 특수 문자는 제거되거나 변환됩니다. 예를 들어, "How to Use GitLab"이라는 제목의 페이지는 `How-to-Use-GitLab` 슬러그를 갖습니다.

### 위키 스타일 링크 {#wiki-style-links}

표준 [Markdown 링크](../../markdown.md#links)에 추가로, 위키는 위키 페이지 간 링크를 간단하게 하는 특수한 위키 스타일 링크 문법을 지원합니다.

#### 이중 괄호 문법 {#double-bracket-syntax}

이중 괄호를 사용하여 위키 페이지에 링크할 수 있습니다:

```markdown
[[Home]]
```

이 문법은 슬러그가 `Home`인 위키 페이지에 대한 링크를 만듭니다. 페이지가 없으면, 링크를 선택할 때 이 페이지를 만들 수 있습니다.

페이지 슬러그에 하이픈이 포함되면, 링크는 슬러그를 그대로 표시합니다:

```markdown
[[Home-page-new-slug]]
```

이것은 `Home-page-new-slug`을 링크 텍스트로 표시합니다.

#### 사용자 지정 텍스트가 있는 이중 괄호 문법 {#double-bracket-syntax-with-custom-text}

페이지 슬러그가 표시할 제목과 다른 경우, 파이프 (`|`) 문자를 사용하여 표시 텍스트와 페이지 슬러그를 구분합니다:

```markdown
[[How to use GitLab|how-to-use-gitlab]]
```

이것은 "How to use GitLab"을 링크 텍스트로 표시하지만, 슬러그가 `how-to-use-gitlab`인 페이지에 링크합니다.

이 문법을 사용하여 하이픈 처리된 슬러그가 있는 페이지에 더 읽기 쉬운 제목을 제공할 수도 있습니다:

```markdown
[[Home page (renamed)|Home-page-new-slug]]
```

이것은 "Home page (renamed)"을 링크 텍스트로 표시하지만, 슬러그가 `Home-page-new-slug`인 페이지에 링크합니다.

#### 대체 위키 페이지 문법 {#alternative-wiki-page-syntax}

`[wiki_page:PAGE_SLUG]` 문법을 사용할 수도 있습니다:

```markdown
[wiki_page:Home]
```

프로젝트 간 참조의 경우, 전체 프로젝트 경로를 지정합니다:

```markdown
[wiki_page:namespace/project:Home]
[wiki_page:group1/subgroup:Home]
```

#### 자동 URL 인식 {#automatic-url-recognition}

Markdown 서식 없이 위키 페이지에 대한 전체 URL을 붙여넣으면, GitLab은 자동으로 이를 링크로 변환하고 하이픈 대신 공백이 있는 페이지 슬러그를 표시합니다:

```markdown
https://gitlab.com/namespace/project/-/wikis/Home-page-new-slug
```

이것은 자동으로 "Home page new slug" 텍스트가 있는 링크로 렌더링됩니다(하이픈은 공백으로 변환됨).

### 직접 페이지 링크 {#direct-page-link}

직접 페이지 링크는 위키의 기본 수준에서 해당 페이지를 가리키는 페이지의 슬러그를 포함합니다.

이 예제는 위키의 루트에 있는 `documentation` 페이지에 링크합니다:

```markdown
[Link to Documentation](documentation-top-page)
```

### 직접 파일 링크 {#direct-file-link}

직접 파일 링크는 현재 페이지를 기준으로 파일의 파일 확장자를 가리킵니다.

다음 예제가 `<your_wiki>/documentation/related`의 페이지에 있으면, `<your_wiki>/documentation/file.md`에 링크합니다:

```markdown
[Link to File](file.md)
```

### 계층적 링크 {#hierarchical-link}

계층적 링크는 `./<page>` 또는 `../<page>`와 같은 상대 경로를 사용하여 현재 위키 페이지를 기준으로 구성할 수 있습니다.

이 예제가 `<your_wiki>/documentation/main`의 페이지에 있으면, `<your_wiki>/documentation/related`에 링크합니다:

```markdown
[Link to Related Page](related)
```

이 예제가 `<your_wiki>/documentation/related/content`의 페이지에 있으면, `<your_wiki>/documentation/main`에 링크합니다:

```markdown
[Link to Related Page](../main)
```

이 예제가 `<your_wiki>/documentation/main`의 페이지에 있으면, `<your_wiki>/documentation/related.md`에 링크합니다:

```markdown
[Link to Related Page](related.md)
```

이 예제가 `<your_wiki>/documentation/related/content`의 페이지에 있으면, `<your_wiki>/documentation/main.md`에 링크합니다:

```markdown
[Link to Related Page](../main.md)
```

### 루트 링크 {#root-link}

루트 링크는 `/`로 시작하고 위키 루트를 기준으로 합니다.

이 예제는 `<wiki_root>/documentation`에 링크합니다:

```markdown
[Link to Related Page](/documentation)
```

이 예제는 `<wiki_root>/documentation.md`에 링크합니다:

```markdown
[Link to Related Page](/documentation.md)
```

## diagrams.net 편집기 {#diagramsnet-editor}

위키에서 [diagrams.net](https://app.diagrams.net/) 편집기를 사용하여 다이어그램을 만들 수 있습니다. diagrams.net 편집기로 만든 다이어그램을 편집할 수도 있습니다. 다이어그램 편집기는 일반 텍스트 편집기와 리치 텍스트 편집기 모두에서 사용할 수 있습니다.

자세한 내용은 [Diagrams.net](../../../administration/integration/diagrams_net.md)을 참조하세요.

### 일반 텍스트 편집기 {#plain-text-editor}

일반 텍스트 편집기에서 다이어그램을 만들려면:

1. 편집하려는 위키 페이지에서 **편집**을 선택합니다.
1. 텍스트 상자에서 일반 텍스트 편집기를 사용하고 있는지 확인합니다(왼쪽 하단의 버튼에 **리치 텍스트 편집으로 전환**이라고 표시됨).
1. 편집기의 도구 모음에서 **다이어그램 삽입 또는 편집** ({{< icon name="diagram" >}})을 선택합니다.
1. [app.diagrams.net](https://app.diagrams.net/) 편집기에서 다이어그램을 만듭니다.
1. **저장 및 종료**를 선택합니다.

위키 콘텐츠에 다이어그램에 대한 Markdown 이미지 참조가 삽입됩니다.

일반 텍스트 편집기에서 다이어그램을 편집하려면:

1. 편집하려는 위키 페이지에서 **편집**을 선택합니다.
1. 텍스트 상자에서 일반 텍스트 편집기를 사용하고 있는지 확인합니다(왼쪽 하단의 버튼에 **리치 텍스트 편집으로 전환**이라고 표시됨).
1. 다이어그램을 포함하는 Markdown 이미지 참조에 커서를 놓습니다.
1. **다이어그램 삽입 또는 편집** ({{< icon name="diagram" >}})을 선택합니다.
1. [app.diagrams.net](https://app.diagrams.net/) 편집기에서 다이어그램을 편집합니다.
1. **저장 및 종료**를 선택합니다.

위키 콘텐츠에 다이어그램에 대한 Markdown 이미지 참조가 삽입되고 이전 다이어그램을 대체합니다.

### 리치 텍스트 편집기 {#rich-text-editor}

리치 텍스트 편집기에서 다이어그램을 만들려면:

1. 편집하려는 위키 페이지에서 **편집**을 선택합니다.
1. 텍스트 상자에서 리치 텍스트 편집기를 사용하고 있는지 확인합니다(왼쪽 하단의 버튼에 **일반 텍스트 편집으로 전환**이라고 표시됨).
1. 편집기의 도구 모음에서 **추가 옵션** ({{< icon name="plus" >}})을 선택합니다.
1. 드롭다운 목록에서 **다이어그램을 생성 또는 편집**을 선택합니다.
1. [app.diagrams.net](https://app.diagrams.net/) 편집기에서 다이어그램을 만듭니다.
1. **저장 및 종료**를 선택합니다.

diagrams.net 편집기에서 시각화된 다이어그램이 위키 콘텐츠에 삽입됩니다.

리치 텍스트 편집기에서 다이어그램을 편집하려면:

1. 편집하려는 위키 페이지에서 **편집**을 선택합니다.
1. 텍스트 상자에서 리치 텍스트 편집기를 사용하고 있는지 확인합니다(왼쪽 하단의 버튼에 **일반 텍스트 편집으로 전환**이라고 표시됨).
1. 편집하려는 다이어그램을 선택합니다.
1. 부동 도구 모음에서 **다이어그램 편집** ({{< icon name="diagram" >}})을 선택합니다.
1. [app.diagrams.net](https://app.diagrams.net/) 편집기에서 다이어그램을 편집합니다.
1. **저장 및 종료**를 선택합니다.

선택한 다이어그램은 업데이트된 버전으로 대체됩니다.
