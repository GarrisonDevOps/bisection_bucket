---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 위키를 계획 워크플로우와 함께 사용하세요
description: "GitLab 위키를 계획 워크플로우와 함께 사용합니다. 에픽, 이슈, 보드에 설명서를 연결합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab 위키는 계획 도구와 함께 작동합니다. 별도의 도구가 아닙니다. 위키 페이지를 에픽, 이슈, 보드에 연결할 수 있습니다. GitLab Query Language(GLQL)로 구동되는 임베드된 보기를 사용하면 위키 페이지에서 이슈와 작업 항목의 라이브 자동 업데이트 보기를 표시하여 설명서를 동적 대시보드로 변환할 수 있습니다. 위키를 이슈, 에픽, 보드와 연결하여 설명서와 계획이 함께 작동하는 매끄러운 워크플로우를 만드는 방법을 알아봅니다.

위키는 다음을 제공하여 계획 도구에 도움이 됩니다:

- 풍부한 설명서 공간: 이슈 설명에 맞지 않는 복잡한 요구 사항, 설계 결정, 프로세스 설명서입니다.
- 버전 제어 지식: 시간에 따라 사양 및 결정에 대한 변경 사항을 추적합니다.
- 라이브 데이터 보기: GLQL 쿼리를 임베드하여 위키 페이지에서 직접 이슈 및 작업 항목 데이터를 실시간으로 표시합니다.
- 지속되는 컨텍스트: 이슈가 종료된 후에도 결정 뒤의 "이유"를 유지합니다.
- 중앙 참고: 팀 프로세스, 표준, 계약의 단일 정보 소스입니다.
- 유연한 형식: 전체 Markdown 지원을 포함한 표, 다이어그램, 긴 형식 콘텐츠입니다.
- 통합 액세스 제어: 위키는 GitLab의 기존 역할 및 권한 시스템을 사용하므로 팀 구성원은 별도의 인증 없이 프로젝트 역할에 따라 자동으로 적절한 위키 액세스 권한을 가집니다.

## 사전 요구 사항 {#prerequisites}

이 가이드를 효과적으로 사용하려면 다음을 숙지해야 합니다:

- [GitLab 위키](_index.md)
- [GitLab Flavored Markdown](../../markdown.md)
- [이슈](../issues/_index.md) 및 [에픽](../../group/epics/_index.md)과 같은 다양한 작업 항목을 생성하고 관리합니다

## 위키 페이지를 작업 항목에 연결 {#connect-wiki-pages-to-work-items}

위키 설명서와 계획 항목 사이의 링크를 생성하여 연결된 지식 네트워크를 만듭니다.

### 위키 설명서를 에픽에 연결 {#link-wiki-documentation-to-epics}

에픽은 종종 에픽 설명에 너무 길어서 맞지 않는 자세한 사양이 필요합니다. 전체 설명서를 위키에 유지합니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **위키**를 선택합니다.
1. 자세한 요구 사항을 포함한 위키 페이지를 만듭니다(예: slug `product-requirements`).
1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트의 그룹을 찾습니다.
1. **계획** > **작업 항목**을 선택합니다.
1. 필터 막대에서 **유형** 필터, **다음과 같음** 연산자, **에픽** 값을 선택합니다.
1. 원하는 에픽을 식별하고 제목을 선택합니다.
1. 에픽 설명에서 위키 페이지에 링크합니다:

   ```markdown
   ## Requirements

   See full specification: [[product-requirements]]

   Or with custom text: [[Full PRD|product-requirements]]

   Or use the full URL:
   [Full PRD](https://gitlab.example.com/group/project/-/wikis/product-requirements)
   ```

1. 위키 페이지에서 에픽으로 다시 링크합니다:

   ```markdown
   Related epic: &123
   ```

예제 사용 사례:

- 제품 요구 사항 문서(PRD)
- 기술 설계 사양
- 사용자 조사 결과
- 경쟁 분석
- 성공 지표 및 KPI

### 이슈에서 위키 참조 {#reference-wiki-from-issues}

이슈를 위키 페이지에 링크하여 구현 세부 사항, 표준, 가이드:

```markdown
## Implementation notes

Follow our [[API-design-standards]] when implementing this endpoint.

For local setup, see [[Development Setup Guide|development-environment-setup]].

Definition of Done: [[team-dod]]
```

예제 사용 사례:

- 코딩 표준 및 스타일 가이드
- 개발 환경 설정
- 테스트 절차
- 배포 런북
- 문제 해결 가이드
- 온보딩 설명서

### 위키에서 작업 항목으로 링크 {#link-from-wiki-to-work-items}

위키 페이지에서 직접 이슈 및 에픽을 참조합니다:

```markdown
## Current sprint goals

- Implement user authentication: #1234
- Fix performance regression: #1235
- Update API documentation: #1236

## Q3 roadmap

Major initiatives:
- Authentication overhaul: &10
- Performance improvements: &11
- API v2 release: &12
```

### 교차 프로젝트 위키 참조 {#cross-project-wiki-references}

다른 프로젝트의 위키 페이지에 링크합니다:

```markdown
## Related documentation

See the backend team's API guide: [[backend/api:api-standards]]

Or use the alternative syntax: [wiki_page:backend/api:api-standards]

With custom text: [[Backend API Standards|backend/api:api-standards]]
```

## 임베드된 보기를 사용한 동적 대시보드 생성 {#create-dynamic-dashboards-with-embedded-views}

{{< history >}}

- `glql_integration`라는 이름의 [기능 플래그](../../../administration/feature_flags/_index.md)와 함께 GitLab 17.4에 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/14767)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.4의 그룹 및 프로젝트의 일부에서 GitLab.com에 활성화되었습니다.
- [GitLab 17.10에서 실험에서 베타로 변경되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/issues/476990)
- GitLab 17.10의 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/work_items/476990)되었습니다.
- GitLab 18.3에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/554870)입니다. 기능 플래그 `glql_integration`이 제거되었습니다.

{{< /history >}}

[GitLab Query Language(GLQL)](../../glql/_index.md)을 사용하여 위키 페이지를 라이브 대시보드로 변환합니다. 임베드된 보기는 데이터가 변경될 때 자동으로 업데이트되어 위키를 떠나지 않고도 계획 데이터에 대한 실시간 가시성을 제공합니다.

> [!note]
> 임베드된 보기는 성능 고려 사항이 있습니다. 큰 쿼리는 타임아웃되거나 속도 제한될 수 있습니다. 타임아웃이 발생하면 더 많은 필터를 추가하거나 `limit` 매개변수를 줄여 쿼리의 범위를 줄입니다.

### 기본 임베드된 보기 구문 {#basic-embedded-view-syntax}

GLQL 쿼리를 임베드하려면 언어 식별자로 `glql`를 사용하는 코드 블록을 사용합니다:

````yaml
```glql
display: table
title: Sprint 18.5 Dashboard
description: Current sprint work items
fields: title, assignee, state, health, labels, milestone, updated
limit: 20
sort: updated desc
query: project = "gitlab-org/gitlab" and milestone = "18.5" and opened = true
```
````

이는 현재 마일스톤의 모든 미해결 이슈를 표시하는 라이브 표를 만들고 이슈가 생성, 수정 또는 종료될 때 자동으로 업데이트합니다.

### 계획 대시보드 예제 {#planning-dashboard-examples}

위키 페이지에서 직접 포괄적인 계획 대시보드를 만듭니다.

> [!note]
> 이 섹션의 예제에서 `project = "group/project"`을(를) 실제 프로젝트 경로(예: `project = "gitlab-org/gitlab"` 또는 `project = "my-team/my-project"`)로 바꿉니다.

사전 요구 사항:

- 쿼리된 이슈 및 작업 항목을 볼 수 있는 권한이 있어야 합니다.

스프린트 개요 대시보드:

````yaml
```glql
display: table
title: Sprint Overview
description: All work for the current sprint
fields: title, assignee, state, labels("priority::*") as "Priority", health, due
limit: 30
sort: due asc
query: project = "group/project" and milestone = "Current Sprint" and opened = true
```
````

중요한 버그 추적:

````yaml
```glql
display: table
title: Critical Bugs
description: High-priority bugs requiring immediate attention
fields: title, assignee, labels, created, updated
limit: 10
query: project = "group/project" and label = "bug" and label = "severity::1" and opened = true
```
````

팀 워크로드 보기:

````yaml
```glql
display: list
title: Team Work In Progress
description: Active work items by team member
fields: title, assignee, milestone, due
limit: 15
sort: assignee asc
query: project = "group/project" and assignee in (alice, bob, charlie) and label = "workflow::in dev"
```
````

개인 작업 목록:

````yaml
```glql
display: orderedList
title: My Tasks
description: Tasks assigned to me, sorted by priority
fields: title, labels("priority::*") as "Priority", due
limit: 10
sort: due asc
query: type = Task and assignee = currentUser() and opened = true
```
````

임베드된 보기는 다음을 지원합니다:

- 다중 표시 형식: `table`, `list`, 또는 `orderedList`
- 사용자 정의 필드: 표시할 필드를 선택합니다
- 정렬: 모든 필드를 오름차순 또는 내림차순으로 정렬합니다
- 필터링: 여러 조건을 포함하는 복잡한 쿼리를 사용합니다
- 페이지 매김: **더 보기**로 추가 결과를 로드합니다
- 동적 함수: `currentUser()`을 개인화된 보기로 사용하고 `today()`를 날짜 기반 쿼리로 사용합니다

## 위키를 사용한 계획 워크플로우 {#planning-workflows-with-wiki}

### 스프린트 계획 및 실행 {#sprint-planning-and-execution}

스프린트 전체에서 연결된 설명서 흐름을 만듭니다:

#### 스프린트 전 계획 {#pre-sprint-planning}

1. 요구 사항 수집: 위키에서 자세한 요구 사항을 문서화합니다.
1. 에픽 생성: 위키 사양을 참조하는 에픽을 만듭니다.
1. 스토리 분석: 이슈를 관련 위키 설명서에 링크합니다.
1. 예상 노트: 위키에서 예상 추론을 문서화합니다.

#### 스프린트 중 {#during-sprint}

- 일일 스탠드업: 차단된 이슈에 대한 링크를 포함한 일일 위키 페이지를 만듭니다.
- 기술적 결정: 구현 이슈에 대한 링크를 포함한 설계 결정을 문서화합니다.
- 장애물: 이슈 참조와 함께 위키에서 차단기를 추적합니다.

#### 스프린트 후 {#post-sprint}

- 회고: 다음을 참조하는 위키 회고 페이지를 만듭니다:
  - 종료된 이슈
  - 속도 지표
  - 실행 항목(새 이슈로)
  - 교훈

### 장기 계획 설명서 {#long-term-planning-documentation}

로드맵에 연결되는 전략적 설명서를 유지합니다:

#### 로드맵 설명서 구조 {#roadmap-documentation-structure}

```plaintext
roadmap/
├── 2025-strategy
├── q1-okrs
├── q2-okrs
├── architecture-decisions/
│   ├── adr-001-microservices
│   ├── adr-002-authentication
└── technical-debt-registry
```

각 페이지는 관련 에픽에 링크하고 이슈 참조를 통해 진행 상황을 추적합니다.

#### 아키텍처 결정 기록 {#architecture-decision-records}

추적 기능을 포함한 기술 결정을 문서화합니다. 다음과 같은 템플릿을 사용할 수 있습니다:

```markdown
# ADR-001: Adopt microservices architecture

## Status

Accepted

## Context

[Detailed context...]

## Decision

[Decision details...]

## Consequences

[Impact analysis...]

## Implementation

- Infrastructure epic: &50
- Service extraction: #2001, #2002, #2003
- Monitoring setup: #2004
```

### 기능 간 협업 {#cross-functional-collaboration}

위키를 기능 간 팀의 협업 허브로 사용합니다:

#### 설계 설명서 {#design-documentation}

- 설계 사양을 구현 이슈에 링크합니다
- 사용 예제를 포함한 컴포넌트 라이브러리 유지
- 에픽 참조를 포함한 설계 결정을 문서화합니다

#### API 설명서 {#api-documentation}

- 구현 이슈에 링크되는 API 설명서 생성
- 마일스톤 참조를 포함한 버전 정보 유지
- 테스트 이슈에 링크된 예제 코드 포함

#### QA 테스트 계획 {#qa-test-plans}

- 에픽 요구 사항에 링크된 테스트 전략
- 이슈 추적 가능성을 포함한 테스트 케이스 리포지토리
- 이슈 예제를 포함한 버그 패턴 설명서

## 탐색 및 검색 패턴 {#navigation-and-discovery-patterns}

### 이슈 및 보드에서 위키를 검색 가능하게 만들기 {#make-wiki-discoverable-from-issues-and-boards}

#### 이슈 및 에픽 템플릿 {#issue-and-epic-templates}

템플릿에 위키 참조를 포함합니다:

```markdown
## Prerequisites

- [ ] Review [[contribution-guidelines]]
- [ ] Check [[security-checklist]]
- [ ] Read relevant documentation in [[project-wiki-home]]

## Implementation

- [ ] Follow [[coding-standards]]
- [ ] Update [[api-documentation]] if needed
- [ ] Add tests per [[testing-guidelines]]
```

#### 마일스톤 설명 {#milestone-descriptions}

위키 계획 문서에 링크합니다:

```markdown
## Milestone 18.5

Sprint dates: 2025-02-01 to 2025-02-14

- [[Sprint 18.5 Goals|sprint-18-5-goals]]
- [[Sprint 18.5 Capacity|sprint-18-5-capacity]]
- [[Known Issues|known-issues-and-workarounds]]
```

#### 보드 설명 {#board-descriptions}

위키 워크플로우 설명서를 참조합니다:

```markdown
This board follows our [[Kanban Workflow Guide|kanban-workflow-guide]].

For column definitions, see [[Board Column Definitions|board-column-definitions]].
```

### 위키에서 작업 항목 표시 {#surface-work-items-in-wiki}

#### 인덱스 페이지 만들기 {#create-index-pages}

관련 이슈를 수집하는 위키 페이지를 만듭니다:

```markdown
# Open bugs dashboard

## Critical (P1)

- #1001 - Database connection timeout
- #1002 - Authentication bypass

## High (P2)

- #1003 - Performance degradation
- #1004 - UI rendering issue

## By component

### Authentication

- #1001, #1005, #1009

### API

- #1002, #1006, #1010
```

#### 계층형 위키 구조 사용 {#use-hierarchical-wiki-structure}

폴더 및 상대 링크를 사용하여 위키 페이지를 구성합니다:

```markdown
# Team handbook

## Processes

- [Sprint Planning](processes/sprint-planning) - How we plan sprints
- [Code Review](processes/code-review) - Review standards and SLAs
- [Incident Response](processes/incident-response) - On-call procedures

## Go up to parent page

[Back to Documentation](../documentation)
```

## 실용적인 예제 {#practical-examples}

### 예제 1: 기능 개발 워크플로우 {#example-1-feature-development-workflow}

위키 통합을 사용한 완전한 기능 개발 주기:

1. 제품 관리자:

   - `feature-x-prd` 위키 페이지를 시장 조사와 함께 만듭니다.
   - 링크를 포함하는 에픽 &100을 만듭니다: `[[Feature X PRD|feature-x-prd]]`.
   - 위키에 수용 기준을 추가합니다.

1. 엔지니어링 담당자:

   - `feature-x-technical-design` 위키 페이지를 만듭니다.
   - 설계 문서를 에픽 &100에 링크합니다.
   - 위키 참조를 포함하는 구현 이슈 #201-205를 만듭니다.

1. 엔지니어:

   - MR 설명에서 위키 설계 문서를 참조합니다.
   - 결정 변경으로 위키를 업데이트합니다.
   - 이슈를 위키 문제 해결 가이드에 링크합니다.

1. QA 엔지니어:

   - `feature-x-test-plan` 위키 페이지를 만듭니다.
   - 테스트 이슈 #301-305를 테스트 계획에 링크합니다.
   - 이슈 참조를 포함하는 위키에서 테스트 결과를 문서화합니다.

1. 기술 작성자:

   - 위키에서 사용자 설명서를 업데이트합니다.
   - 설명서 이슈 #401을 만듭니다.
   - 위키 변경사항을 기능 에픽에 링크합니다.

### 예제 2: 라이브 대시보드를 포함한 팀 지식 기반 {#example-2-team-knowledge-base-with-live-dashboards}

실시간 인사이트를 위해 임베드된 보기를 사용하여 팀 핸드북을 구성합니다:

````markdown
# Engineering team handbook

## Current sprint status

```glql
display: table
title: Sprint Progress
fields: title, assignee, state, labels("workflow::*") as "Status"
limit: 20
query: project = "team/project" and milestone = "Sprint 23" and opened = true
```

## Processes

- [[Sprint Planning Process|sprint-planning-process]] - How we plan sprints
- [[Code Review Guidelines|code-review-guidelines]] - Review standards and SLAs
- [[Incident Response|incident-response]] - On-call procedures

## Technical standards

- [[API Design Standards|API-design-standards]] - REST API conventions
- [[Database Schema Guide|database-schema-guide]] - Schema design rules
- [[Security Checklist|security-checklist]] - Security requirements

## Work management

- [Issue board](https://gitlab.example.com/group/project/-/boards/123)
- [Current milestone](https://gitlab.example.com/group/project/-/milestones/45)
- Label taxonomy: [[Label Definitions|label-definitions]]

## Onboarding

- [[New Developer Setup|new-developer-setup]] - Environment setup
- [[First Week Issues|first-week-issues]] - Good first issues: #101, #102, #103
- [[Team Contacts|team-contacts]] - Who to ask for what
````

## 빠른 참조 {#quick-reference}

### 위키 링크 구문 {#wiki-linking-syntax}

| 목적                          | 문법                                    | 예제 |
| -------------------------------- | ----------------------------------------- | ------- |
| 위키 페이지(동일 프로젝트)에 링크 | `[[page-slug]]`                           | `[[api-standards]]` |
| 사용자 정의 텍스트로 링크            | `[[Display Text\|page-slug]]`             | `[[our API guide\|api-standards]]` |
| 교차 프로젝트 위키 링크          | `[[group/project:page-slug]]`             | `[[backend/api:rest-guide]]` |
| 대체 위키 구문          | `[wiki_page:page-slug]`                   | `[wiki_page:home]` |
| 교차 프로젝트 대체        | `[wiki_page:namespace/project:page-slug]` | `[wiki_page:backend/api:home]` |
| 계층형 링크(동일 수준)   | `[Link text](page-slug)`                  | `[Related](related-page)` |
| 계층형 링크(상위)       | `[Link text](../parent-page)`             | `[Up](../main)` |
| 계층형 링크(하위)        | `[Link text](child-page)`                 | `[Details](details)` |
| 루트 링크                        | `[Link text](/page-from-root)`            | `[Home](/home)` |
| 전체 URL                         | 표준 Markdown                         | `[API Guide](https://gitlab.example.com/.../wikis/api-standards)` |

<!-- The `page-from-root` example is added as exception in `doc/.vale/gitlab_docs/InternalLinkFormat.yml` -->

### 작업 항목 참조 {#referencing-work-items}

| 항목 유형                 | 문법              | 예제 |
| ------------------------- | ------------------- | ------- |
| 이슈(동일 프로젝트)      | `#123`              | `#123`  |
| 이슈(다른 프로젝트) | `group/project#123` | `gitlab-org/gitlab#123` |
| 병합 요청             | `!123`              | `!123`  |
| 에픽                      | `&123`              | `&123`  |
| 마일스톤                 | `%"Milestone Name"` | `%"18.5"` |

### 위키에서 이슈 생성 {#creating-issues-from-wiki}

이슈로 변환할 수 있는 위키에서 작업 목록을 사용합니다:

```markdown
## Action items from retrospective

- [ ] Improve CI pipeline performance
- [ ] Update documentation
- [ ] Add monitoring for API endpoints
```

체크박스를 선택하고 **이슈 생성**을 사용하여 작업을 추적된 이슈로 변환합니다.

## 효과적인 통합 팁 {#tips-for-effective-integration}

### 페이지 슬러그를 올바르게 사용 {#use-page-slugs-correctly}

- 위키 링크는 페이지 슬러그(URL 친화적 버전)를 사용합니다: `api-standards` 아님 `API Standards`.
- 페이지가 없으면 링크를 선택하여 만들 수 있습니다.
- 붙여넣은 위키 URL은 자동으로 읽을 수 있는 텍스트로 변환됩니다(하이픈이 공백이 됨).

### 양방향 링크 유지 {#maintain-bidirectional-links}

- 위키에서 이슈로 링크할 때 이슈를 업데이트하여 위키 페이지를 참조합니다.
- 더 쉬운 검색을 위해 일관된 명명 규칙을 사용합니다.
- 웹후크 또는 CI/CD를 사용하여 링크 생성을 자동화하는 것을 고려합니다.

### 검색 가능하도록 구성 {#organize-for-discovery}

- 모든 계획 설명서를 색인하는 위키 홈 페이지를 만듭니다.
- 일관된 페이지 명명을 사용합니다: `sprint-2025-01`, `adr-001`, `feature-name`.
- 대규모 위키의 경우 폴더를 포함한 계층형 구조를 사용합니다.
- 레이블 분류법과 일치하는 범주로 위키 페이지에 태그를 지정합니다.

### 설명서를 최신 상태로 유지 {#keep-documentation-current}

- 완료 정의에 설명서 업데이트를 포함합니다.
- 스프린트 계획 중에 위키 페이지를 검토합니다.
- 오래된 페이지를 `archive/` 폴더에 보관합니다.

### 템플릿 사용 {#use-templates}

일반적인 문서에 대한 위키 템플릿을 만듭니다:

- 스프린트 계획 템플릿
- 회고 템플릿
- 기능 사양 템플릿
- 아키텍처 결정 기록 템플릿

## 관련 항목 {#related-topics}

- [위키](_index.md)
- [이슈](../issues/_index.md)
- [이슈 보드](../issue_board.md)
- [에픽](../../group/epics/_index.md)
- [GitLab Query Language](../../glql/_index.md)
- [GitLab Flavored Markdown](../../markdown.md)
