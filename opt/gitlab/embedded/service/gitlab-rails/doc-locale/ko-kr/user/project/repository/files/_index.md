---
stage: Create
group: Remote Development
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab 리포지토리에서 파일을 직접 GitLab 사용자 인터페이스에서 검색합니다.
title: 파일 관리
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab UI는 브라우저에서 Git의 기록 및 추적 기능을 사용자 친화적인 기능으로 확장합니다. 다음과 같이 수행할 수 있습니다.

- 파일을 검색합니다.
- 파일 처리를 변경합니다.
- 전체 파일 또는 한 줄의 기록을 살펴봅니다.

## UI에서 파일 유형이 렌더링되는 방식을 이해합니다 {#understand-how-file-types-render-in-the-ui}

프로젝트에 이러한 유형의 파일을 추가하면 GitLab은 가독성을 개선하기 위해 출력을 렌더링합니다:

- [GeoJSON](geojson.md) 파일은 지도로 표시됩니다.
- [Jupyter Notebook](jupyter_notebooks/_index.md) 파일은 렌더링된 HTML로 표시됩니다.
- 많은 마크업 언어의 파일이 표시되도록 렌더링됩니다.

### 지원되는 마크업 언어 {#supported-markup-languages}

파일에 이러한 파일 확장자 중 하나가 있으면 GitLab은 파일의 [마크업 언어](https://en.wikipedia.org/wiki/Lightweight_markup_language) 내용을 UI에 렌더링합니다.

| 마크업 언어                                              | 확장자 |
|--------------------------------------------------------------|------------|
| 일반 텍스트                                                   | `txt`      |
| [마크다운](../../../markdown.md)                             | `mdown`, `mkd`, `mkdn`, `md`, `markdown`, `rmd` |
| [reStructuredText](https://docutils.sourceforge.io/rst.html) | `rst`      |
| [AsciiDoc](../../../asciidoc.md)                             | `adoc`, `ad`, `asciidoc` |
| [Textile](https://textile-lang.com/)                         | `textile`  |
| [Rdoc](https://rdoc.sourceforge.net/doc/index.html)          | `rdoc`     |
| [Org mode](../../../org_mode.md)                             | `org`      |
| [creole](http://www.wikicreole.org/)                         | `creole`   |
| [MediaWiki](https://www.mediawiki.org/wiki/MediaWiki)        | `wiki`, `mediawiki` |

### 지원되는 다이어그램 형식 {#supported-diagram-formats}

파일에 이러한 파일 확장자 중 하나가 있으면 GitLab은 파일의 내용을 UI에서 다이어그램으로 렌더링합니다:

| 다이어그램 형식                                  | 확장자                                                              | 가용성 |
|-------------------------------------------------|-------------------------------------------------------------------------|--------------|
| [Mermaid](https://mermaid.js.org/)[^mermaid-diagrams-mermaid] | `mermaid`                                                               | 항상 사용할 수 있습니다. |
| [PlantUML](https://plantuml.com/)[^both-plantuml-kroki]  | `plantuml`, `pu`, `puml`, `iuml`                                        | 관리자가 [PlantUML 통합을 활성화](../../../../administration/integration/plantuml.md)해야 합니다. |
| [Kroki](https://kroki.io/)[^both-plantuml-kroki]         | `d2`, `dot`, `gv`, `noml`, `plantuml`, `pu`, `puml`, `iuml`, `vg`, `vl` | 관리자가 [Kroki 통합을 활성화](../../../../administration/integration/kroki.md)해야 합니다. |

[^mermaid-diagrams-mermaid]: Mermaid 다이어그램의 경우 `mermaid` 확장자만 렌더링됩니다. `mmd` 확장자는 지원되지 않습니다.
[^both-plantuml-kroki]: PlantUML과 Kroki 통합이 모두 활성화되면 GitLab은 `plantuml`, `pu`, `puml`, `iuml` 확장자가 있는 파일을 렌더링하기 위해 PlantUML을 사용합니다.

다이어그램 구문에 대한 정보는 [Markdown의 다이어그램](../../../markdown.md#diagrams-and-flowcharts) 및 [AsciiDoc의 다이어그램](../../../asciidoc.md#diagrams-and-flowcharts)을 참고하세요.

### README 및 인덱스 파일 {#readme-and-index-files}

{{< history >}}

- `_index.md` 파일에 대한 지원은 GitLab 18.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/206533)되었습니다.

{{< /history >}}

리포지토리에 `README`, `index` 또는 `_index` 파일이 있으면 GitLab은 해당 내용을 렌더링합니다. 이러한 파일은 일반 텍스트이거나 지원되는 마크업 언어의 확장자를 가질 수 있습니다.

자동 렌더링의 우선 순위는 다음과 같습니다:

- 미리보기 가능한 파일: `README.md`, `index.md`, `_index.md`, 등
- 일반 텍스트 파일: `README`, `index`, `_index`, 등

각 범주에서 발견된 첫 번째 파일(알파벳 순서)이 선택되며 미리보기 가능한 파일이 일반 텍스트 파일보다 우선합니다. 예를 들어 여러 README를 사용할 수 있으면 GitLab은 다음 순서로 렌더링합니다:

1. `README.adoc`
1. `README.md`
1. `README.rst`
1. `README`

### OpenAPI 파일 렌더링 {#render-openapi-files}

파일명에 `openapi` 또는 `swagger`이(가) 포함되고 확장자가 `yaml`, `yml` 또는 `json`이면 GitLab은 OpenAPI 사양 파일을 렌더링합니다. 이 모든 예는 정확합니다:

- `openapi.yml`, `openapi.yaml`, `openapi.json`
- `swagger.yml`, `swagger.yaml`, `swagger.json`
- `OpenAPI.YML`, `openapi.Yaml`, `openapi.JSON`
- `openapi_gitlab.yml`, `openapi.gitlab.yml`
- `gitlab_swagger.yml`
- `gitlab.openapi.yml`

OpenAPI 파일을 렌더링하려면:

1. 리포지토리에서 OpenAPI 파일을 [검색](#search-for-a-file)합니다.
1. **렌더링된 파일 표시**를 선택합니다.
1. 작업 목록에 `operationId`을(를) 표시하려면 쿼리 문자열에 `displayOperationId=true`을(를) 추가합니다.

> [!note]
> `displayOperationId`이(가) 쿼리 문자열에 있고 어떤 값이든 있으면 `true`으로 평가됩니다. 이 동작은 Swagger의 기본 동작과 일치합니다.

## Markdown 파일을 PDF로 인쇄 {#print-a-markdown-file-as-pdf}

{{< history >}}

- GitLab 19.1에서 `blob_markdown_pdf_download` [기능 플래그](../../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/414692)되었습니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

Markdown 파일을 PDF로 인쇄하여 렌더링된 내용을 공유하거나 보관할 수 있도록 저장합니다. Markdown 파일을 보면 **다운로드** 작업은 두 가지 옵션이 있는 드롭다운 목록입니다: **마크다운으로 다운로드** 및 **PDF 출력**

Markdown 파일을 PDF로 인쇄하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 인쇄하려는 Markdown 파일로 이동합니다.
1. 오른쪽 위에서 **다운로드**({{< icon name="download" >}}) > **PDF 출력**을 선택합니다.
1. 브라우저의 인쇄 대화 상자에서 파일을 PDF로 저장합니다.

## 파일의 Git 레코드 보기 {#view-git-records-for-a-file}

리포지토리의 파일에 대한 기록 정보는 GitLab UI에서 사용할 수 있습니다:

- [Git 파일 기록](git_history.md): 전체 파일의 커밋 기록을 표시합니다.
- [Git blame](git_blame.md): 텍스트 기반 파일의 각 줄과 해당 줄을 변경한 가장 최근 커밋을 표시합니다.

## 영구 링크 생성 {#create-permalinks}

영구 링크는 리포지토리의 특정 파일, 디렉토리 또는 코드 섹션을 가리키는 영구 URL입니다. 리포지토리가 변경되어도 유효하게 유지되므로 설명서, 이슈 또는 머지 리퀘스트에서 코드를 공유하고 참조하는 데 이상적입니다.

영구 링크를 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 링크하려는 파일 또는 디렉토리로 이동합니다.
1. 선택 사항. 특정 코드 선택:
   - **한 줄**: 줄 번호를 선택합니다.
   - **여러 줄**: 첫 번째 줄 번호를 선택한 후 <kbd>Shift</kbd> 키를 누르고 마지막 줄 번호를 선택합니다.
   - **Markdown 앵커**: 제목 위에 마우스를 올리면 앵커 링크({{< icon name="link" >}})가 나타나면 선택합니다.
1. **조치**({{< icon name="ellipsis_v" >}})을 선택한 후 **영구 링크 복사**를 선택합니다. 또는 <kbd>y</kbd>를 누릅니다. 더 많은 바로가기는 [키보드 바로가기](../../../shortcuts.md)를 참고하세요.

댓글이나 설명에서 파일의 줄로 영구 링크를 붙여넣으면 GitLab은 링크 대신 [코드를 포함](../../../markdown.md#embed-code-from-a-repository)할 수 있습니다.

## 파일의 열린 머지 리퀘스트 보기 {#view-open-merge-requests-for-a-file}

{{< history >}}

- GitLab 17.10에서 `filter_blob_path`라는 [기능 플래그](../../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/448868)되었습니다.
- GitLab 17.11에서 [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/505449)되었습니다.
- GitLab 18.0에서 [GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/505449)되었습니다.
- GitLab 18.2에서 [정식 출시](https://gitlab.com/gitlab-org/gitlab/-/issues/539215)되었습니다. 기능 플래그 `filter_blob_path`이 제거되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

리포지토리 파일을 볼 때 GitLab은 현재 브랜치를 대상으로 하고 파일을 수정하는 열린 머지 리퀘스트의 수가 표시된 배지를 표시합니다. 이를 통해 보류 중인 변경 사항이 있는 파일을 식별할 수 있습니다.

파일의 열린 머지 리퀘스트를 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 보려는 파일로 이동합니다.
1. 화면의 오른쪽 위, 파일명 옆에서 {{< icon name="merge-request-open" >}} **열기** 머지 리퀘스트의 수가 표시된 녹색 배지를 찾습니다.
1. 배지를 선택하여 지난 30일 동안 생성된 열린 머지 리퀘스트의 목록을 봅니다.
1. 목록의 모든 머지 리퀘스트를 선택하여 해당 머지 리퀘스트로 이동합니다.

## 파일 검색 {#search-for-a-file}

파일 찾기를 사용하여 GitLab UI에서 직접 리포지토리의 파일을 검색합니다. 파일 찾기는 퍼지 검색을 사용하고 입력할 때 결과를 강조합니다.

파일을 검색하려면 프로젝트의 어디든지 <kbd>t</kbd>를 누르거나:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **리포지토리**를 선택합니다.
1. 오른쪽 위에서 **파일 찾기**를 선택합니다.
1. 대화 상자에서 파일명을 입력하기 시작합니다:

   ![파일 찾기 버튼](img/file_finder_v17_2.png)

1. 선택 사항. 검색 옵션을 좁히려면 <kbd>Command</kbd>+<kbd>K</kbd>를 누르거나 대화 상자의 오른쪽 아래 모서리에서 **Commands**를 선택합니다:
   - **Pages 또는 동작**의 경우 <kbd>></kbd>를 입력합니다.
   - **사용자**의 경우 <kbd>@</kbd>를 입력합니다.
   - **프로젝트**의 경우 <kbd>:</kbd>를 입력합니다.
   - **파일**의 경우 <kbd>~</kbd>를 입력합니다.
1. 드롭다운 목록에서 파일을 선택하여 리포지토리에서 봅니다.

**파일** 페이지로 돌아가려면 <kbd>Esc</kbd>를 누릅니다.

이 기능은 [`fuzzaldrin-plus`](https://github.com/jeancroy/fuzz-aldrin-plus) 라이브러리를 사용합니다.

## Git이 파일을 처리하는 방식 변경 {#change-how-git-handles-a-file}

파일 또는 파일 유형의 기본 처리를 변경하려면 [`.gitattributes` 파일](git_attributes.md)을 생성합니다. `.gitattributes` 파일을 사용하여:

- diffs에서 파일 표시를 구성합니다(예: [구문 강조](highlighting.md) 또는 [생성된 파일 축소](../../merge_requests/changes.md#collapse-generated-files)).
- 파일 저장소 및 보호를 제어합니다(예: [파일을 읽기 전용으로 만들기](../../file_lock.md) 또는 [Git LFS로 큰 파일 저장](../../../../topics/git/lfs/_index.md)).

## 관련 항목 {#related-topics}

- [리포지토리 파일 API](../../../../api/repository_files.md)
- [Git을 사용한 파일 관리](../../../../topics/git/file_management.md)

## 문제 해결 {#troubleshooting}

### 리포지토리 언어: 과도한 CPU 사용 {#repository-languages-excessive-cpu-use}

리포지토리의 파일에 어떤 언어가 있는지 확인하기 위해 GitLab은 Ruby gem을 사용합니다. gem이 파일을 구문 분석하여 파일 유형을 확인할 때 [프로세스에서 과도한 CPU를 사용](https://gitlab.com/gitlab-org/gitaly/-/issues/1565)할 수 있습니다. gem에는 구문 분석할 파일 확장자를 정의하는 [휴리스틱 구성 파일](https://github.com/github-linguist/linguist/blob/main/lib/linguist/heuristics.yml)이 포함되어 있습니다. 이러한 파일 유형은 과도한 CPU를 사용할 수 있습니다:

- `.txt` 확장자가 있는 파일입니다.
- gem에서 정의한 확장자가 없는 XML 파일입니다.

이 문제를 해결하려면 `.gitattributes` 파일을 편집하고 특정 파일 확장자에 언어를 할당합니다. 이 방법을 사용하여 잘못 식별된 파일 유형을 수정할 수도 있습니다:

1. 지정할 언어를 식별합니다. gem에는 [알려진 데이터 유형의 구성 파일](https://github.com/github-linguist/linguist/blob/main/lib/linguist/languages.yml)이 포함되어 있습니다.

1. 예를 들어 텍스트 파일 항목을 추가하려면:

   ```yaml
   Text:
     type: prose
     wrap: true
     aliases:
     - fundamental
     - plain text
     extensions:
     - ".txt"
   ```

1. 리포지토리의 루트에 `.gitattributes`을(를) 추가하거나 편집합니다:

   ```plaintext
   *.txt linguist-language=Text
   ```

   `*.txt` 파일은 휴리스틱 파일에 항목이 있습니다. 이 예는 이러한 파일의 구문 분석을 방지합니다.
