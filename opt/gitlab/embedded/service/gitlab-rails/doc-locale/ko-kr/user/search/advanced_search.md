---
stage: Analytics
group: Global Search
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 고급 검색
description: "고급 검색을 사용하여 전체 GitLab 인스턴스에서 코드, 커밋, 작업 항목 및 머지 리퀘스트를 찾습니다."
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

고급 검색을 사용하여 전체 GitLab 인스턴스에서 필요한 정확한 내용을 찾습니다.

고급 검색으로 다음을 수행할 수 있습니다:

- 모든 프로젝트에서 코드 패턴을 식별하여 공유 구성 요소를 더 효율적으로 리팩토링합니다.
- 전체 조직의 코드베이스 및 종속성에서 보안 취약점을 찾습니다.
- 모든 리포지토리에서 더 이상 사용되지 않는 함수 또는 라이브러리의 사용을 추적합니다.
- 이슈, 머지 리퀘스트 또는 댓글에 숨겨진 토론을 찾습니다.
- 이미 존재하는 기능을 다시 개발하는 대신 기존 솔루션을 발견합니다.

고급 검색은 다음에서 작동합니다:

- 코드
- 댓글
- 커밋
- 그룹
- 작업 항목
- 머지 리퀘스트
- 마일스톤
- 프로젝트
- 사용자
- 위키

## 고급 검색 사용 {#use-advanced-search}

사전 요구 사항:

- 고급 검색을 활성화해야 합니다:
  - GitLab.com 및 GitLab Dedicated의 경우 고급 검색이 유료 구독에서 기본적으로 활성화됩니다.
  - GitLab Self-Managed의 경우 관리자가 [고급 검색을 활성화](../../integration/advanced_search/elasticsearch.md#enable-advanced-search)해야 합니다.

고급 검색을 사용하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택합니다.
1. 검색 상자에 검색 용어를 입력합니다.

프로젝트 또는 그룹에서도 고급 검색을 사용할 수 있습니다.

## 사용 가능한 범위 {#available-scopes}

{{< history >}}

- 이슈에 대한 댓글 검색은 GitLab 18.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/513146)되었으며 [기능 플래그](../../administration/feature_flags/_index.md) `search_work_item_queries_notes`로 명명됩니다. 기본적으로 사용 중지됩니다.
- 이슈에 대한 댓글 검색은 GitLab 18.1에서 [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/536912)되었습니다.
- 이슈에 대한 댓글 검색은 GitLab 18.6에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/191369)합니다. 기능 플래그 `search_work_item_queries_notes`이 제거되었습니다.
- 머지 리퀘스트에 대한 댓글 검색은 GitLab 18.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/572590)되었으며 [기능 플래그](../../administration/feature_flags/_index.md) `search_merge_request_queries_notes`로 명명됩니다. 기본적으로 사용 중지됩니다.
- 머지 리퀘스트에 대한 댓글 검색은 GitLab 18.7에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/573750)합니다. 기능 플래그 `search_merge_request_queries_notes`이 제거되었습니다.
- 그룹 범위는 GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/249760)되었으며 [기능 플래그](../../administration/feature_flags/_index.md) `elasticsearch_group_search`로 명명됩니다. 기본적으로 사용 중지됩니다.
- 그룹 범위는 GitLab 19.5에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/607018)합니다. 기능 플래그 `elasticsearch_group_search`이 제거되었습니다.

{{< /history >}}

범위는 검색하고 있는 데이터의 유형을 설명합니다. 고급 검색에 사용할 수 있는 범위는 다음과 같습니다:

| 범위                       | 전역[^disable-global-search-scopes], [^global-search-saas] | 그룹       | 프로젝트     |
|-----------------------------|----------------------------------|-------------|-------------|
| 코드                        | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| 댓글                    | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| 커밋                     | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| 그룹[^group-search-returns]         | {{< yes >}}                      | {{< yes >}} | {{< no >}}  |
| 작업 항목[^search-work-items]     | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| 머지 리퀘스트[^search-work-items] | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| 마일스톤[^advanced-search-returns]     | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| 프로젝트                    | {{< yes >}}                      | {{< yes >}} | {{< no >}}  |
| 사용자                       | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |
| 위키                       | {{< yes >}}                      | {{< yes >}} | {{< yes >}} |

[^disable-global-search-scopes]: 관리자는 [전역 검색 범위 비활성화](_index.md#disable-global-search-scopes)할 수 있습니다. GitLab Self-Managed에서는 제한된 인덱싱이 기본적으로 활성화되어 있을 때 전역 검색을 사용할 수 없습니다. 관리자는 [제한된 인덱싱에 대한 전역 검색을 활성화](../../integration/advanced_search/elasticsearch.md#indexed-namespaces)할 수 있습니다.
[^global-search-saas]: GitLab.com에서는 코드, 커밋 및 위키에 대해 전역 검색이 활성화되지 않습니다.
[^search-work-items]: 작업 항목 및 머지 리퀘스트를 검색하면 검색 용어와 일치하는 댓글이 결과에 포함됩니다.
[^advanced-search-returns]: 고급 검색은 그룹 마일스톤이 Elasticsearch에 인덱싱되지 않기 때문에 프로젝트 마일스톤만 반환합니다. 자세한 내용은 [이슈 428589](https://gitlab.com/gitlab-org/gitlab/-/issues/428589)를 참조하세요.
[^group-search-returns]: 그룹 검색은 검색 중인 그룹 자체가 아니라 그룹의 하위 그룹을 반환합니다. `backfill_groups_to_elasticsearch` 고급 검색 마이그레이션이 완료되어야 이 범위가 결과를 반환합니다.

## 구문 {#syntax}

<!-- Remember to also update the tables in `doc/drawers/advanced_search_syntax.md` -->

고급 검색은 [`simple_query_string`](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-simple-query-string-query)를 사용하며, 이는 정확한 검색과 흐릿한 검색을 모두 지원합니다.

사용자를 검색할 때 [`fuzzy`](https://www.elastic.co/docs/reference/query-languages/query-dsl/query-dsl-fuzzy-query) 쿼리가 기본적으로 사용됩니다. `simple_query_string`로 사용자 검색을 개선할 수 있습니다.

| 문법 | 설명      | 예제 |
|--------|------------------|---------|
| `"`    | 정확한 검색     | `"gem sidekiq"` |
| `~`    | 흐릿한 검색     | `J~ Doe` |
| `\|`   | 또는               | `display \| banner` |
| `+`    | 그리고              | `display +banner` |
| `-`    | 제외          | `display -banner` |
| `*`    | 부분          | `bug error 50*` |
| ` \ `  | 이스케이프           | `\*md`  |
| `#`    | 이슈 ID         | `#23456` |
| `!`    | 머지 리퀘스트 ID | `!23456` |

### 코드 검색 {#code-search}

| 문법       | 설명                                     | 예제 |
|--------------|-------------------------------------------------|---------|
| `filename:`  | 파일 이름                                        | `filename:*spec.rb` |
| `path:`      | 리포지토리 위치(전체 또는 부분 일치)   | `path:spec/workers/` |
| `extension:` | `.` 없이 파일 확장자(정확한 일치만) | `extension:js` |
| `blob:`      | Git 객체 ID(정확한 일치만)              | `blob:998707*` |

### 예제 {#examples}

| 쿼리                                 | 설명 |
|---------------------------------------|-------------|
| `rails -filename:gemfile.lock`        | `rails`을 `gemfile.lock` 파일을 제외한 모든 파일에서 반환합니다. |
| `RSpec.describe Resolvers -*builder`  | `RSpec.describe Resolvers`을 `builder`로 시작하지 않는 것으로 반환합니다. |
| `bug \| (display +banner)`            | `bug`또는 `display` 및 `banner`을 모두 반환합니다. |
| `helper -extension:yml -extension:js` | `helper`을 `.yml` 또는 `.js` 확장자가 있는 파일을 제외한 모든 파일에서 반환합니다. |
| `helper path:lib/git`                 | `helper`을 `lib/git*` 경로가 있는 모든 파일에서 반환합니다(예: `spec/lib/gitlab`). |

## 알려진 이슈 {#known-issues}

- 1 MB보다 작은 파일만 검색할 수 있습니다. GitLab Self-Managed의 경우 관리자는 [인덱싱된 최대 파일 크기](../../administration/instance_limits.md#maximum-file-size-indexed)에 대한 제한을 설정할 수 있습니다.
- 프로젝트의 기본 브랜치에서만 고급 검색을 사용할 수 있습니다. 자세한 내용은 [이슈 229966](https://gitlab.com/gitlab-org/gitlab/-/issues/229966)을 참조하세요.
- 검색 쿼리에는 다음 문자가 포함되어서는 안 됩니다:

  ```plaintext
  . , : ; / ` ' = ? $ & ^ | < > ( ) { } [ ] @
  ```

- 검색 결과는 파일의 첫 번째 일치만 표시합니다.

## 관련 항목 {#related-topics}

- [보안 취약점 찾기](../application_security/vulnerability_report/_index.md#advanced-vulnerability-management)
