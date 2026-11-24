---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GLQL 데이터 소스
---

GLQL은 다음 데이터 소스를 쿼리할 수 있습니다:

| 데이터 소스 | 표준 모드 | [분석 모드](../_index.md#analytics-mode) | `type` 값 | 설명 |
|---|---|---|---|---|
| 작업 항목 | {{< yes >}} | {{< no >}} | `Issue`, `Incident`, `TestCase`, `Requirement`, `Task`, `Ticket`, `Objective`, `KeyResult`, `Epic` | 이슈, 에픽 및 기타 작업 항목 유형입니다. `type`이(가) 생략되었을 때의 기본값입니다. |
| 병합 요청 | {{< yes >}} | {{< yes >}} | `MergeRequest` | 코드 검토 및 머지 워크플로입니다. |
| 파이프라인 | {{< yes >}} | {{< yes >}} | `Pipeline` | CI/CD 파이프라인입니다. |
| 작업 | {{< yes >}} | {{< no >}} | `Job` | 파이프라인 내 CI/CD 작업입니다. |
| 프로젝트 | {{< yes >}} | {{< no >}} | `Project` | 네임스페이스 내 프로젝트입니다. |
| 에이전트 플랫폼 세션 | {{< no >}} | {{< yes >}} | `AgentPlatformSession` | 집계된 GitLab Duo 에이전트 플랫폼 세션 분석입니다. |
| AI 사용 이벤트 | {{< no >}} | {{< yes >}} | `AiUsageEvent` | 집계된 GitLab Duo 사용 이벤트 분석입니다. |
| 코드 제안 | {{< no >}} | {{< yes >}} | `CodeSuggestion` | 집계된 GitLab Duo 코드 제안 분석입니다. |
| 기여 | {{< no >}} | {{< yes >}} | `Contribution` | 집계된 기여 활동 분석입니다. |
| Duo 워크플로우 | {{< no >}} | {{< yes >}} | `DuoWorkflow` | 집계된 GitLab Duo 에이전트 플랫폼 플로우 분석(사용한 크레딧 포함)입니다. |

각 데이터 소스는 필터링, 표시 및 정렬을 위한 자체 지원 필드 집합을 가집니다.

`type` 필드를 사용하여 쿼리에서 데이터 소스를 지정합니다. 예를 들어 `type = Issue` 또는 `type = MergeRequest`입니다. 여러 유형을 지원하는 데이터 소스의 경우 `in` 연산자를 사용하여 유형 전체에서 쿼리합니다. 예를 들어, `type in (Issue, Task)`입니다.

## 범위 {#scopes}

각 데이터 소스는 데이터를 쿼리할 위치를 정의하는 범위가 필요합니다. 허용되는 범위는 데이터 소스에 따라 다르며 각 데이터 소스 페이지에 설명되어 있습니다.

쿼리에서 범위를 정의합니다. 예를 들어:

```yaml
query: type = issue and project = "gitlab-org/gitlab"
```

범위를 지정하지 않으면 GLQL은 쿼리가 삽입된 위치에서 이를 유추합니다:

- 프로젝트 컨텍스트(이슈 또는 병합 요청 설명)에서 GLQL은 현재 프로젝트를 사용합니다.
- 그룹 컨텍스트(예: 에픽 설명)에서 GLQL은 현재 그룹을 사용합니다.

### 여러 그룹 및 프로젝트 {#multiple-groups-and-projects}

{{< history >}}

- GitLab 19.5에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/628101).

{{< /history >}}

[분석 모드](../_index.md#analytics-mode)에서 `group` 및 `project` 필터는 목록을 허용하므로 단일 쿼리로 여러 그룹 또는 프로젝트 전체에서 데이터를 집계할 수 있습니다. `in` 연산자를 전체 경로와 함께 사용합니다:

````yaml
```glql
display: table
mode: analytics
query: type = MergeRequest and group in ("gitlab-org", "gitlab-com") and merged > -30d
dimensions: merged(weekly) as "Week"
metrics: totalCount as "Total", throughputCount as "Merged"
sort: merged desc
```
````

그룹, 프로젝트 또는 둘 다 나열할 수 있습니다:

- `group in ("gitlab-org", "gitlab-com")`은(는) 서브그룹을 포함하여 나열된 그룹의 모든 프로젝트를 집계합니다.
- `project in ("gitlab-org/gitlab", "gitlab-org/gitaly")`은(는) 나열된 프로젝트만 집계합니다.
- `group in ("gitlab-org") and project in ("gitlab-com/www-gitlab-com")`은(는) 두 목록의 합집합을 집계합니다.
- `group = "gitlab-org" and project in ("gitlab-org/gitlab", "gitlab-org/gitaly")`은(는) 그룹에 속해야 하는 나열된 프로젝트만 집계합니다.

예를 들어, 다른 그룹의 프로젝트를 나란히 비교하려면:

````yaml
```glql
display: table
mode: analytics
query: type = Pipeline and project in ("gitlab-org/gitlab", "gitlab-org/gitaly", "gitlab-com/www-gitlab-com") and finished > -30d
dimensions: project as "Project"
metrics: totalCount as "Total", successRate as "Success rate"
sort: totalCount desc
```
````

목록을 사용할 때:

- 최대 20개의 그룹 및 프로젝트를 함께 나열할 수 있습니다.
- 나열된 모든 그룹 및 프로젝트에 대한 액세스 권한이 있어야 합니다. 그 중 하나라도 누락되었거나 액세스할 수 없으면 읽을 수 없는 경로의 이름을 지정하는 오류로 쿼리가 실패합니다.
- 단일 경로가 있는 목록은 `group = "..."` 또는 `project = "..."`처럼 작동합니다.
- 프로젝트 또는 그룹에 쿼리를 삽입할 때 GLQL은 해당 프로젝트 또는 그룹 대신 나열된 경로를 범위로 사용합니다.

표준 모드에서는 목록이 지원되지 않습니다. 작업 항목 및 작업과 같은 데이터 소스는 단일 `group` 또는 `project` 값을 허용하며, 목록은 컴파일 오류를 발생시킵니다.
