---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 시간 추적
description: "예상 시간, 소요 시간 및 보고."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 작업에 대한 시간 추적이 GitLab 17.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/438577)되었습니다.
- 에픽에 대한 시간 추적이 GitLab 17.5에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/12396)되었습니다. [에픽의 새로운 모양](../group/epics/_index.md#epics-as-work-items)을 켜야 합니다.
- 예상 시간을 추가, 편집 및 제거하기 위한 최소 역할이 GitLab 17.7에서 보고자에서 계획자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/169256)되었습니다.
- 에픽에 대한 시간 추적이 GitLab 18.1에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/468310)되었습니다.
- 지원되는 총 소요 시간은 GitLab 18.10에서 1년에서 4년으로 증가했습니다.

{{< /history >}}

시간 추적은 GitLab 작업 항목에 투자한 시간을 기록하고 관리하는 데 도움이 됩니다. 시간 추적:

- 이슈, 병합 요청, 에픽 및 작업에 실제 소요 시간을 기록합니다.
- 완료에 필요한 총 시간을 예상합니다.
- 시간 엔트리에 대한 자세한 보고서를 제공합니다.
- 표준화된 시간 단위를 사용하여 합계를 계산합니다.
- 빠른 작업 및 UI를 통해 기록을 추적합니다.

작업 항목의 오른쪽 사이드바에서 시간 추적 정보를 볼 수 있습니다:

![작업 항목의 오른쪽 사이드바에 있는 시간 추적 섹션.](img/time_tracking_sidebar_v18_3.png)

[빠른 작업](quick_actions.md) 또는 사용자 인터페이스를 사용하여 시간 추적 데이터를 입력하고 제거합니다. 빠른 작업을 자신의 라인에 입력합니다. 단일 주석에서 빠른 작업을 두 번 이상 사용하는 경우 마지막 항목만 적용됩니다.

## 권한 {#permissions}

서로 다른 시간 추적 기능은 역할에 따라 사용 가능합니다:

- 예상 시간을 추가, 편집 및 제거하려면 이슈 및 작업에 대해 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 하거나 병합 요청에 대해 개발자 역할이 있어야 합니다.
- 소요 시간을 추가하고 편집하려면 프로젝트에 대해 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 시간 엔트리를 삭제하려면 작성자이거나 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

## 예상 시간 {#estimates}

예상 시간은 항목을 완료하는 데 필요한 총 시간을 표시하도록 설계되었습니다.

오른쪽 사이드바의 시간 추적 정보 위에 마우스를 올렸을 때 남은 예상 시간을 볼 수 있습니다.

![시간 추적 섹션 위에 마우스를 올렸을 때의 남은 예상 시간 툴팁.](img/remaining_time_v18_3.png)

### 예상 시간 추가 {#add-an-estimate}

사전 요구 사항:

- 이슈에서는 프로젝트에 대해 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 작업에서는 프로젝트에 대해 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 병합 요청에서는 프로젝트에 대해 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

예상 시간을 입력하려면 [`/estimate` 빠른 작업](quick_actions.md#estimate)을 사용한 후 시간을 입력합니다.

예를 들어 1개월, 2주, 3일, 4시간, 5분의 예상 시간을 입력해야 하는 경우 `/estimate 1mo 2w 3d 4h 5m`을 입력합니다. [사용할 수 있는 시간 단위](#available-time-units)를 확인합니다.

항목은 하나의 예상 시간만 가질 수 있습니다. 새 예상 시간을 입력할 때마다 이전 값을 덮어씁니다.

### 예상 시간 제거 {#remove-an-estimate}

사전 요구 사항:

- 이슈에서는 프로젝트에 대해 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 작업에서는 프로젝트에 대해 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 병합 요청에서는 프로젝트에 대해 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

예상 시간을 완전히 제거하려면 [`/remove_estimate` 빠른 작업](quick_actions.md#remove_estimate)을 사용합니다.

## 소요 시간 {#time-spent}

작업하면서 소요한 시간을 기록할 수 있습니다.

새로운 소요 시간 엔트리는 이슈, 작업 또는 병합 요청의 현재 총 소요 시간에 추가됩니다.

이슈, 작업 또는 병합 요청에 대한 총 소요 시간은 4년을 초과할 수 없습니다.

### 소요 시간 추가 {#add-time-spent}

사전 요구 사항:

- 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

#### 사용자 인터페이스 사용 {#using-the-user-interface}

{{< history >}}

- GitLab 17.0에서 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/150564)되었습니다. 소요한 시점을 지정하지 않으면 현재 시간이 사용됩니다.

{{< /history >}}

사용자 인터페이스를 사용하여 시간 엔트리를 추가하려면:

1. 사이드바의 **시간 추적** 섹션에서 **시간 엔트리 추가** ({{< icon name="plus" >}})를 선택합니다. 대화 상자가 열립니다.
1. 다음을 입력합니다:

   - 소요한 시간.
   - 선택 사항. 소요한 시점. 비어 있으면 현재 시간을 사용합니다.
   - 선택 사항. 요약.

1. **저장**을 선택합니다.

사이드바의 **소비됨** 합계가 업데이트되고 [시간 추적 보고서](#view-an-items-time-tracking-report)에서 모든 엔트리를 볼 수 있습니다.

#### 빠른 작업 사용 {#using-a-quick-action}

소요 시간을 입력하려면 [`/spend` 빠른 작업](quick_actions.md#spend)을 사용한 후 시간을 입력합니다.

예를 들어 1개월, 2주, 3일, 4시간, 5분을 기록해야 하는 경우 `/spend 1mo 2w 3d 4h 5m`을 입력합니다. [사용할 수 있는 시간 단위](#available-time-units)를 확인합니다.

설명 및 빠른 작업이 포함된 주석을 작성하여 메모가 포함된 [시간 추적 보고서](#view-an-items-time-tracking-report) 엔트리를 추가합니다. 그 후 시간 추적 보고서 **요약/메모** 열에 표시됩니다. 예를 들어:

```plaintext
Draft MR and respond to initial comments

/spend 30m
```

소요 시간을 언제 기록했는지 기록하려면 시간 뒤에 `YYYY-MM-DD` 형식으로 날짜를 입력합니다.

예를 들어 2021년 1월 31일에 1시간의 소요 시간을 기록하려면 `/spend 1h 2021-01-31`을 입력합니다.

미래 날짜를 입력하면 시간이 기록되지 않습니다.

#### 커밋 메시지 사용 {#using-commit-messages}

{{< history >}}

- GitLab 18.3에서 `commit_time_tracking`라는 플래그가 있는 상태로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/16543)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.7에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/215244/)합니다. 기능 플래그 `commit_time_tracking`이 제거되었습니다.

{{< /history >}}

커밋 메시지에서 직접 이슈에 대한 소요 시간을 기록할 수 있습니다. 이 방법을 사용하여 이슈를 별도로 업데이트하지 않고 작업할 때 시간을 추적합니다.

커밋 메시지에 소요 시간을 추가하려면 이슈 참조와 `@<time>` 형식의 시간 추적 마커를 포함하되 시간 단위 사이에 공백이 없어야 합니다.

예를 들어:

```plaintext
Fix a bug in the login form #123 @1mo2d3h15m
```

이 커밋 메시지는 이슈 #123에 1개월, 2일, 3시간, 15분의 소요 시간을 추가합니다.

시간 추적 마커는 다음을 수행해야 합니다:

- `@` 기호로 시작합니다.
- 시간 단위가 바로 뒤따르며 사이에 공백이 없어야 합니다.
- 다음 시간 단위를 지원합니다: 월 (`mo`), 일 (`d`), 시간 (`h`), 분 (`m`) 및 초 (`s`).
- 일반 시간 추적과 동일한 [시간 단위](#available-time-units)를 사용합니다.

시간 추적 정보가 포함된 커밋을 푸시할 때:

1. GitLab은 커밋 메시지에서 소요 시간을 추출합니다.
1. 시간이 동일한 커밋 메시지에서 참조된 모든 이슈에 추가됩니다.
1. 커밋에서 시간이 추가되었음을 나타내는 시스템 노트가 이슈에 추가됩니다.
1. 시간 추적 엔트리는 커밋 SHA 및 제목을 설명으로 포함합니다.

##### 커밋 작성자 권한 {#commit-author-permissions}

시간이 커밋 메시지에서 이슈로 추가되는 것은 커밋 작성자가 이슈를 업데이트할 권한이 있는 경우에만 가능합니다:

- 커밋 작성자는 이슈가 존재하는 프로젝트에 대해 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 작성자에게 충분한 권한이 없으면 해당 커밋의 시간 추적 정보가 무시됩니다.
- 권한 검사는 일반 시간 추적과 동일한 규칙을 사용합니다.

##### 알려진 이슈 {#known-issues}

**한 커밋에서 여러 시간 양**

커밋 메시지가 서로 다른 시간 양으로 여러 이슈를 참조하는 경우 첫 번째 시간 양만 참조된 모든 이슈에 적용됩니다.

예를 들어 이 커밋 메시지:

```plaintext
Fixes #41 @1h30m and fixes #40 @2h
```

이슈 #41과 이슈 #40 모두에 1h30m을 추가합니다. 두 번째 시간 양 (`@2h`)은 무시됩니다.

**커밋 SHA 변경으로 인한 중복 시간 엔트리**

커밋의 SHA가 변경되면 (예: 리베이스 또는 수정 후) GitLab은 이를 시간 추적을 위한 새 커밋으로 취급합니다. 원본 및 새 커밋이 모두 이슈에서 참조되면 중복 시간 엔트리가 생성될 수 있습니다.

커밋 SHA가 변경될 수 있을 때 중복 시간 엔트리를 방지하려면:

- 커밋 메시지 대신 UI 또는 빠른 작업을 사용하여 이슈에 직접 시간을 추가합니다.
- 커밋 메시지를 시간 추적에 사용해야 하는 경우 브랜치의 기록이 완료된 후에만 시간을 추가합니다.
- 병합하기 전에 이슈의 시간 추적 보고서를 확인하여 잠재적인 중복을 식별하고 제거합니다.

### 병합 요청에서 중복 시간 추적 방지 {#prevent-duplicate-time-tracking-in-merge-requests}

시간 추적 정보가 포함된 커밋이 있는 병합 요청을 병합할 때 GitLab은 중복 시간 추적을 방지합니다:

- 시간은 커밋당 한 번만 추적되며, 동일한 커밋 메시지가 리포지토리 기록에 여러 번 나타나도 마찬가지입니다.
- GitLab은 동일한 커밋 제목 및 ID를 가진 시간 엔트리가 이슈에 이미 존재하는지 확인하여 중복 시간 추적을 방지합니다.
- 커밋이 병합되면 추가 시간이 추적되지 않습니다. 이는 기능 브랜치가 기본 브랜치로 병합될 때 시간 이중 계산을 방지합니다.

### 소요 시간 빼기 {#subtract-time-spent}

사전 요구 사항:

- 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

시간을 빼려면 음수 값을 입력합니다. 예를 들어 `/spend -3d`은 총 소요 시간에서 3일을 제거합니다. 소요 시간을 0분 아래로 내릴 수 없으므로 입력된 시간보다 더 많은 시간을 제거하면 GitLab은 빼기를 무시합니다.

### 소요 시간 삭제 {#delete-time-spent}

타임로그는 양수 또는 음수의 단일 소요 시간 엔트리입니다.

사전 요구 사항:

- 타임로그의 작성자이거나 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

타임로그를 삭제하려면:

- 시간 추적 보고서에서 타임로그 엔트리의 오른쪽에 **소요 시간 삭제** ({{< icon name="remove" >}})를 선택합니다.
- [GraphQL API](../../api/graphql/reference/_index.md#mutationtimelogdelete)를 사용합니다.

### 모든 소요 시간 삭제 {#delete-all-the-time-spent}

사전 요구 사항:

- 프로젝트의 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

모든 소요 시간을 한 번에 삭제하려면 [`/remove_time_spent` 빠른 작업](quick_actions.md#remove_time_spent)을 사용합니다.

## 항목의 시간 추적 보고서 보기 {#view-an-items-time-tracking-report}

항목에 대한 소요 시간의 시간 추적 보고서를 보려면:

- 오른쪽 사이드바에서 **소비됨** 옆에 시간을 선택합니다.

![소요 시간에 대한 개별 엔트리를 보여주는 시간 추적 보고서.](img/time_tracking_report_v18_3.png)

표시된 소요 시간의 분석은 최대 100개 엔트리로 제한됩니다.

## 전역 시간 추적 보고서 {#global-time-tracking-report}

{{< details >}}

- 상태:  실험적 기능

{{< /details >}}

{{< history >}}

- GitLab 15.11에서 [기능 플래그](../../administration/feature_flags/_index.md)가 있는 상태로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/344002)되었고 `global_time_tracking_report`라는 이름입니다. 기본적으로 비활성화되었습니다.
- GitLab.com에서 GitLab 16.5로 활성화되었습니다.

{{< /history >}}

> [!flag]
> GitLab Self-Managed에서 기본적으로 이 기능은 사용할 수 없습니다. 사용 가능하게 하려면 관리자가 `global_time_tracking_report`라는 [기능 플래그를 사용으로 설정](../../administration/feature_flags/_index.md)할 수 있습니다. GitLab.com에서 이 기능을 사용할 수 있습니다. GitLab Dedicated에서 이 기능을 사용할 수 없습니다. 이 기능은 프로덕션 사용을 위해 준비되지 않았습니다.

GitLab 전체에서 이슈, 작업 및 병합 요청에 소요된 시간의 보고서를 봅니다.

이 기능은 [실험](../../policy/development_stages_support.md)입니다. 버그를 발견하면 [피드백 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/435222)에 추가합니다.

전역 시간 추적 보고서를 보려면:

1. 브라우저에서 전역 보고서의 URL을 입력합니다:
   - GitLab Self-Managed의 경우 기본 URL에 `/-/timelogs`을 추가합니다. 예를 들어, `https://gitlab.example.com/-/timelogs`입니다.
   - GitLab.com의 경우 <https://gitlab.com/-/timelogs>로 이동합니다.
1. 선택 사항. 특정 사용자로 필터링하려면 `@` 기호 없이 사용자 이름을 입력합니다.
1. 시작 및 종료 날짜를 선택합니다.
1. **보고서 실행**을 선택합니다.

![여러 항목에 대한 필터 및 결과를 보여주는 전역 시간 추적 보고서 페이지.](img/global_time_report_v16_5.png)

## 사용 가능한 시간 단위 {#available-time-units}

다음 시간 단위를 사용할 수 있습니다:

| 시간 단위 | 입력할 내용                | 변환율 |
| --------- | --------------------------- | --------------- |
| 월     | `mo`, `month` 또는 `months`  | 4주 (160시간)     |
| 주      | `w`, `week` 또는 `weeks`     | 5일 (40시간)      |
| 일       | `d`, `day` 또는 `days`       | 8시간             |
| 시간      | `h`, `hour` 또는 `hours`     | 60분            |
| 분    | `m`, `minute` 또는 `minutes` |                 |

### 시간으로 표시 단위 제한 {#limit-displayed-units-to-hours}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab 관리자는 시간 단위의 표시를 시간으로 제한할 수 있습니다. 다음을 수행합니다:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **환경설정**을 선택합니다.
1. **현지화**를 확장합니다.
1. **시간 추적** 아래에서 **시간 추적 단위 표시를 시간으로 제한** 체크박스를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

이 옵션을 켜면 `1w 4d 3h` 대신 `75h`이 표시됩니다.

## 관련 항목 {#related-topics}

- 시간 추적 GraphQL 참조:
  - [연결](../../api/graphql/reference/_index.md#timelogconnection)
  - [에지](../../api/graphql/reference/_index.md#timelogedge)
  - [필드](../../api/graphql/reference/_index.md#timelog)
  - [타임로그](../../api/graphql/reference/_index.md#querytimelogs)
  - [그룹 타임로그](../../api/graphql/reference/_index.md#grouptimelogs)
  - [프로젝트 타임로그](../../api/graphql/reference/_index.md#projecttimelogs)
  - [사용자 타임로그](../../api/graphql/reference/_index.md#usertimelogs)
