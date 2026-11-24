---
stage: Analytics
group: Global Search
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: GitLab에서 검색
description: "기본, 고급, 정확, 검색 범위 및 커밋 SHA 검색."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

확장하는 코드베이스 또는 조직에서 필요한 것을 찾습니다. 프로젝트 전체에서 특정 코드, 작업 항목, 머지 리퀘스트 및 기타 콘텐츠를 검색하여 시간을 절약합니다. 필요에 맞는 세 가지 검색 유형 중에서 선택합니다: **기본 검색**, [**고급 검색**](advanced_search.md) 및 [**정확한 코드 검색**](exact_code_search.md).

코드 검색의 경우 GitLab은 다음 순서로 이러한 유형을 사용합니다:

- **정확한 코드 검색**: 정확한 일치 및 정규 표현식 모드를 사용할 수 있습니다.
- **고급 검색**: 정확한 코드 검색을 사용할 수 없을 때입니다.
- **기본 검색**: 정확한 코드 검색 및 고급 검색을 사용할 수 없거나 기본이 아닌 브랜치에 대해 검색할 때입니다. 이 유형은 그룹 또는 글로벌 검색을 지원하지 않습니다.

## 사용 가능한 범위 {#available-scopes}

{{< history >}}

- 그룹 범위는 GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249760)되었으며 [기능 플래그](../../administration/feature_flags/_index.md)로 명명되었습니다. `elasticsearch_group_search` 기본적으로 비활성화되었습니다.
- 그룹 범위는 GitLab 19.5에서 [일반적으로 사용 가능합니다](https://gitlab.com/gitlab-org/gitlab/-/issues/607018). `elasticsearch_group_search` 기능 플래그가 제거되었습니다.

{{< /history >}}

범위는 검색하고 있는 데이터의 유형을 설명합니다. 기본 검색에 사용 가능한 범위는 다음과 같습니다:

| 범위          | 글로벌[^disable-global-search-scopes] |    그룹    | 프로젝트 |
|----------------|:-------------------:|:-----------:|:-------:|
| 코드           |     {{< no >}}      | {{< no >}}  | {{< yes >}} |
| 댓글       |     {{< no >}}      | {{< no >}}  | {{< yes >}} |
| 커밋        |     {{< no >}}      | {{< no >}}  | {{< yes >}} |
| 그룹         |     {{< yes >}}     | {{< yes >}} | {{< no >}} |
| 작업 항목     |     {{< yes >}}     | {{< yes >}} | {{< yes >}} |
| 머지 리퀘스트 |     {{< yes >}}     | {{< yes >}} | {{< yes >}} |
| 마일스톤[^global-basic-search] |     {{< yes >}}     | {{< yes >}} | {{< yes >}} |
| 프로젝트       |     {{< yes >}}     | {{< yes >}} | {{< no >}} |
| 사용자          |     {{< yes >}}     | {{< yes >}} | {{< yes >}} |
| 위키          |     {{< no >}}      | {{< no >}}  | {{< yes >}} |

[^disable-global-search-scopes]: 관리자는 [글로벌 검색 범위를 사용하지 않도록 설정](#disable-global-search-scopes)할 수 있습니다.
[^global-basic-search]: 글로벌 기본 검색은 그룹 마일스톤이 아닌 프로젝트 마일스톤만 반환합니다.

## 검색 유형 지정 {#specify-a-search-type}

{{< history >}}

- GitLab 17.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/161999)되었습니다.

{{< /history >}}

검색 유형을 지정하려면 `search_type` URL 매개변수를 다음과 같이 설정합니다:

- `search_type=zoekt` 를 사용하여 [정확한 코드 검색](exact_code_search.md)
- `search_type=advanced` 를 사용하여 [고급 검색](advanced_search.md)
- `search_type=basic` 를 사용하여 기본 검색

`search_type`은 더 이상 사용되지 않는 `basic_search` 매개변수를 대체합니다. 자세한 내용은 [이슈 477333](https://gitlab.com/gitlab-org/gitlab/-/issues/477333)을 참조하세요.

## 검색 액세스 제한 {#restrict-search-access}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

{{< history >}}

- 글로벌 검색을 인증된 사용자로 제한하는 기능이 GitLab 13.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/41041)되었으며 [기능 플래그](../../administration/feature_flags/_index.md)로 명명되었습니다. `block_anonymous_global_searches` 기본적으로 비활성화되었습니다.
- 인증되지 않은 사용자를 위한 검색은 GitLab 16.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/138975)되었으며 [기능 플래그](../../administration/feature_flags/_index.md)로 명명되었습니다. `allow_anonymous_searches` 기본적으로 활성화됩니다.
- 글로벌 검색을 인증된 사용자로 제한하는 기능이 GitLab 17.11에서 [일반적으로 사용 가능합니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/186727). `block_anonymous_global_searches` 기능 플래그가 제거되었습니다.
- 인증되지 않은 사용자를 위한 검색은 GitLab 18.0에서 [일반적으로 사용 가능합니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/190090). `allow_anonymous_searches` 기능 플래그가 제거되었습니다.

{{< /history >}}

사전 요구 사항:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

기본적으로 `/search` 및 글로벌 검색은 인증되지 않은 사용자가 사용할 수 있습니다.

`/search`를 인증된 사용자만으로 제한하려면 다음 중 하나를 수행합니다:

- [공개 범위 제한](../../administration/settings/visibility_and_access_controls.md#restrict-visibility-levels)을 프로젝트 또는 그룹에 대해 설정합니다. 공개 프로젝트가 제한된 경우 익명 글로벌 검색은 GitLab 로그인 페이지로 리디렉션됩니다.
- **운영자** 영역에서 액세스를 제한합니다:

  1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
  1. **설정** > **검색**을 선택합니다.
  1. **고급 검색**을 확장합니다.
  1. **인증되지 않은 사용자가 검색을 사용하도록 허용** 체크박스를 선택 해제합니다.
  1. **변경 사항 저장**을 선택합니다.

글로벌 검색을 인증된 사용자만으로 제한하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **검색**을 선택합니다.
1. **공개 범위 및 액세스 설정**을 확장합니다.
1. **인증된 사용자에게만 글로벌 검색을 제한합니다.** 체크박스를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 글로벌 검색 범위 사용 안 함 {#disable-global-search-scopes}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

{{< history >}}

- GitLab 17.9에 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/179688)되었습니다.

{{< /history >}}

사전 요구 사항:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

인스턴스의 글로벌 검색 성능을 향상시키기 위해 하나 이상의 검색 범위를 사용하지 않도록 설정할 수 있습니다. GitLab Self-Managed 인스턴스에서는 기본적으로 모든 글로벌 검색 범위가 사용됩니다.

하나 이상의 글로벌 검색 범위를 사용하지 않도록 설정하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **검색**을 선택합니다.
1. **공개 범위 및 액세스 설정**을 확장합니다.
1. 사용하지 않도록 설정할 범위의 체크박스를 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

## 기본 검색 범위 구성 {#configure-a-default-search-scope}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

사전 요구 사항:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

기본적으로 사용자가 검색 범위를 선택하지 않으면 컨텍스트 및 가용성을 기반으로 범위가 자동으로 선택됩니다. 기본 검색 범위를 대신 구성하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **검색**을 선택합니다.
1. **공개 범위 및 액세스 설정**을 확장합니다.
1. **기본 검색 범위** 드롭다운 목록에서 범위를 선택합니다. 자동 선택의 경우 **시스템 기본값 (자동)**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

사용자는 다른 범위를 선택하여 기본 범위를 재정의할 수 있습니다. 기본 범위를 사용할 수 없는 경우 (예: 글로벌 검색의 코드) 범위가 자동으로 선택됩니다.

## 글로벌 검색 유효성 검사 {#global-search-validation}

글로벌 검색은 다음을 포함하는 검색을 무시하고 남용으로 기록합니다:

- 2자 미만
- 100자보다 긴 용어 (URL 검색 용어는 200자를 초과할 수 없음)
- 중지 단어만 (예: `the`, `and` 또는 `if`)
- 알 수 없는 `scope`
- `group_id` 또는 `project_id`이 완전히 숫자가 아님
- `repository_ref` 또는 `project_ref`에 [Git refname](https://git-scm.com/docs/git-check-ref-format)에서 허용하지 않는 특수 문자가 있음

글로벌 검색은 다음보다 더 많은 경우만 오류로 플래그 지정합니다:

- 4096자
- 64개 용어

이슈 검색에서는 부분 일치가 지원되지 않습니다. 예를 들어 `play`를 위해 이슈를 검색할 때 쿼리는 `display`를 포함하는 이슈를 반환하지 않습니다. 그러나 쿼리는 문자열의 모든 가능한 변형 (예: `plays`)과 일치합니다.

## 자동 완성 제안 {#autocomplete-suggestions}

{{< history >}}

- 권한이 있는 프로젝트 및 그룹의 사용자만 표시하는 기능이 GitLab 17.10에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/442091)되었으며 [기능 플래그](../../administration/feature_flags/_index.md)로 명명되었습니다. `users_search_scoped_to_authorized_namespaces_advanced_search`, `users_search_scoped_to_authorized_namespaces_basic_search` 및 `users_search_scoped_to_authorized_namespaces_basic_search_by_ids`. 기본적으로 비활성화되었습니다.
- GitLab 17.11에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/185577)합니다. 기능 플래그 `users_search_scoped_to_authorized_namespaces_advanced_search`, `users_search_scoped_to_authorized_namespaces_basic_search` 및 `users_search_scoped_to_authorized_namespaces_basic_search_by_ids`가 제거되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그에 의해 제어됩니다. 자세한 내용은 기록을 참조하세요.

검색 상자에 입력하면 자동 완성 제안이 다음에 대해 표시됩니다:

- 프로젝트 및 그룹
- 권한이 있는 프로젝트 및 그룹의 사용자
- 도움말 페이지
- 프로젝트 기능 (예: 마일스톤)
- 설정 (예: 사용자 설정)
- 최근에 본 머지 리퀘스트
- 최근에 본 작업 항목
- [GitLab Flavored Markdown 참조](../markdown.md#gitlab-specific-references) (프로젝트의 작업 항목)

## 모든 GitLab에서 검색 {#search-in-all-gitlab}

모든 GitLab에서 검색하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택합니다.
1. 검색 쿼리를 입력합니다. 최소 2자를 입력해야 합니다.
1. <kbd>Enter</kbd> 키를 누르거나 목록에서 선택합니다.

결과가 표시됩니다. 결과를 필터링하려면 왼쪽 사이드바에서 필터를 선택합니다.

## 프로젝트에서 검색 {#search-in-a-project}

프로젝트에서 검색하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **검색 또는 이동**을 다시 선택하고 검색하려는 문자열을 입력합니다.
1. <kbd>Enter</kbd> 키를 누르거나 목록에서 선택합니다.

결과가 표시됩니다. 결과를 필터링하려면 왼쪽 사이드바에서 필터를 선택합니다.

## 검색 결과에 아카이빙된 프로젝트 포함 {#include-archived-projects-in-search-results}

기본적으로 아카이빙된 프로젝트는 검색 결과에서 제외됩니다. 검색 결과에 아카이빙된 프로젝트를 포함하려면:

1. 검색 페이지의 왼쪽 사이드바에서 **아카이빙된 항목 포함** 체크박스를 선택합니다.
1. 왼쪽 사이드바에서 **적용**을 선택합니다.

## 코드 검색 {#search-for-code}

프로젝트에서 코드를 검색하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **검색 또는 이동**을 다시 선택하고 검색하려는 코드를 입력합니다.
1. <kbd>Enter</kbd> 키를 누르거나 목록에서 선택합니다.

코드 검색은 파일의 첫 번째 결과만 표시합니다. 모든 GitLab에서 코드를 검색하려면 관리자에게 [고급 검색](advanced_search.md)을 활성화하도록 요청합니다.

### 코드 검색에서 Git blame 보기 {#view-git-blame-from-code-search}

검색 결과를 찾은 후 결과가 발견된 줄을 마지막으로 변경한 사람을 볼 수 있습니다.

1. 코드 검색 결과에서 줄 번호 위로 마우스를 올립니다.
1. 왼쪽에서 **Blame 표시**를 선택합니다.

### 언어별로 코드 검색 결과 필터링 {#filter-code-search-results-by-language}

하나 이상의 언어별로 코드 검색 결과를 필터링하려면:

1. 코드 검색 페이지의 왼쪽 사이드바에서 하나 이상의 언어를 선택합니다.
1. 왼쪽 사이드바에서 **적용**을 선택합니다.

## 커밋 SHA 검색 {#search-for-a-commit-sha}

커밋 SHA를 검색하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **검색 또는 이동**을 다시 선택하고 검색하려는 커밋 SHA를 입력합니다.
1. <kbd>Enter</kbd> 키를 누르거나 목록에서 선택합니다.

단일 결과가 반환되면 GitLab은 커밋 결과로 리디렉션되며 검색 결과 페이지로 돌아갈 수 있는 옵션이 제공됩니다.

## 구문 {#syntax}

기본 검색은 다음 옵션으로 정확한 부분 문자열 일치를 사용합니다:

| 문법       | 설명                                     | 예제 |
|--------------|-------------------------------------------------|---------|
| `filename:`  | 파일 이름                                        | `filename:*spec.rb` |
| `path:`      | 리포지토리 위치 (전체 또는 부분 일치)   | `path:spec/workers/` |
| `extension:` | `.` 없는 파일 확장자 (정확한 일치만) | `extension:js` |

### 예제 {#examples}

| 쿼리                                 | 설명 |
|---------------------------------------|-------------|
| `rails -filename:gemfile.lock`        | `rails`을 `gemfile.lock` 파일을 제외한 모든 파일에서 반환합니다. |
| `helper -extension:yml -extension:js` | `helper`을 `.yml` 또는 `.js` 확장자가 있는 파일을 제외한 모든 파일에서 반환합니다. |
| `helper path:lib/git`                 | `helper`을 `lib/git*` 경로 (예: `spec/lib/gitlab`)가 있는 모든 파일에서 반환합니다. |
