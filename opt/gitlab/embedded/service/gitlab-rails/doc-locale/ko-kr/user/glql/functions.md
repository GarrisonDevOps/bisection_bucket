---
stage: Analytics
group: Platform Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GLQL 함수
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- `glql_integration`라는 이름의 [기능 플래그](../../administration/feature_flags/_index.md)와 함께 GitLab 17.4에 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/14767)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.4에서 일부 그룹 및 프로젝트를 위해 GitLab.com에서 활성화되었습니다.
- [GitLab 17.10에서 실험에서](https://gitlab.com/gitlab-org/gitlab/-/issues/476990) [베타](../../policy/development_stages_support.md#beta)로 변경되었습니다.
- GitLab 17.10의 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/work_items/476990)되었습니다.
- GitLab 18.3에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/554870)입니다. 기능 플래그 `glql_integration`이 제거되었습니다.

{{< /history >}}

[GitLab Query Language(GLQL)](_index.md)과 함께 함수를 사용하여 동적 쿼리를 생성합니다.

## 쿼리 내 함수 {#functions-inside-query}

쿼리를 컨텍스트별로 만들려면 [쿼리](_index.md#query-syntax) 내에서 함수를 사용합니다. 예를 들어 현재 사용자 또는 날짜로 필터링하여 만들 수 있습니다.

### 현재 사용자 {#current-user}

**함수 이름**: `currentUser`

**파라매터**: 없음

**구문**: `currentUser()`

**Description (설명)**: 현재 인증된 사용자로 평가됩니다.

**추가 세부 정보**:

- 쿼리에서 이 함수를 사용하면 인증되지 않은 사용자의 경우 쿼리가 실패합니다.

**예시**:

- 현재 인증된 사용자가 담당자인 모든 이슈를 나열합니다:

  ```plaintext
  assignee = currentUser()
  ```

- 현재 인증된 사용자가 담당자이지만 작성자가 아닌 모든 머지 리퀘스트를 나열합니다:

  ```plaintext
  type = MergeRequest and assignee = currentUser() and author != currentUser()
  ```

### 오늘 {#today}

**함수 이름**: `today`

**파라매터**: 없음

**구문**: `today()`

**Description (설명)**: 사용자의 시간대에서 오늘 날짜 00:00으로 평가됩니다.

**추가 세부 정보**:

- `=` 연산자와 함께 사용하면 시간 범위는 사용자의 시간대에서 00:00부터 23:59까지로 간주됩니다.

**예시**:

- 오늘 생성된 모든 이슈를 나열합니다:

  ```plaintext
  created = today()
  ```

- 오늘 병합된 모든 머지 리퀘스트를 나열합니다:

  ```plaintext
  type = MergeRequest and merged = today()
  ```

## 포함된 뷰의 함수 {#functions-in-embedded-views}

[포함된 뷰](_index.md#embedded-views)의 기존 필드에서 새 열을 파생하려면 `fields` 파라매터에 함수를 포함합니다.

### 레이블을 새 열로 추출 {#extract-labels-into-a-new-column}

**함수 이름**: `labels`

**파라매터**: 하나 이상의 `String` 값

**구문**: `labels("field1", "field2")`

**Description (설명)**:

`labels` 함수는 하나 이상의 레이블 이름 문자열 값을 파라매터로 사용하며, 이슈에 대해 해당 레이블만 포함된 필터링된 열을 생성합니다. 함수는 추출기로도 작동하므로 레이블이 추출되면 일반 `labels` 열에 더 이상 표시되지 않습니다. 해당 열을 표시하기로 선택한 경우입니다.

**추가 세부 정보**:

- 기본적으로 이 함수는 레이블 이름과 정확히 일치하는 항목을 찾습니다. 문자열에 와일드카드 문자 (`*`)를 사용하여 모든 문자와 일치합니다.
- 최소 1개에서 최대 100개의 레이블 이름을 `labels` 함수에 전달할 수 있습니다.
- 이 함수에 전달된 레이블 이름은 대소문자를 구분하지 않습니다. 예를 들어 `Deliverable`과(와) `deliverable`는 동일합니다.

**예시**:

- 열에 모든 `workflow` 범위 지정 레이블을 포함합니다:

  ```plaintext
  labels("workflow::*")
  ```

- 레이블 `Deliverable`, `Stretch`, `Spike`을(를) 포함합니다:

  ```plaintext
  labels("Deliverable", "Stretch", "Spike")
  ```

- `backend`, `frontend`과(와) 같은 모든 레이블을 포함하며, `end`으로 끝나는 다른 레이블들도 포함합니다:

  ```plaintext
  labels("*end")
  ```

포함된 뷰에 `labels` 함수를 포함하려면:

````markdown
```glql
display: list
fields: title, health, due, labels("workflow::*"), labels
limit: 5
query: project = "gitlab-org/gitlab" AND assignee = currentUser() AND state = opened
```
````
