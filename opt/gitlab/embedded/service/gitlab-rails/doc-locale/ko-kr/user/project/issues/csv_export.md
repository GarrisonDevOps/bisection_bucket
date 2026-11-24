---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 이슈를 CSV로 내보내기
description: "이슈를 CSV 파일로 내보내면 오프라인 분석, 보고 또는 다른 시스템으로의 가져오기를 위해 메일로 전송됩니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- `IID`, `Type`, `Start Date`, 및 `Parent IID` 열이 GitLab 18.4에서 [추가](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/199945)되었습니다.

{{< /history >}}

GitLab에서 이슈를 일반 텍스트 CSV([쉼표로 구분된 값](https://en.wikipedia.org/wiki/Comma-separated_values)) 파일로 내보낼 수 있습니다. CSV 파일은 이메일에 첨부되어 기본 알림 이메일 주소로 전송됩니다.

<!-- vale gitlab_base.Spelling = NO -->

CSV 파일은 Microsoft Excel, OpenOffice Calc 또는 Google Sheets와 같은 모든 플로터 또는 스프레드시트 기반 프로그램에서 사용할 수 있습니다. 이슈의 CSV 목록을 다음과 같이 사용할 수 있습니다:

<!-- vale gitlab_base.Spelling = YES -->

- 오프라인 분석을 위해 이슈의 스냅샷을 만들거나 GitLab에 있지 않을 수 있는 다른 팀과 공유합니다.
- CSV 데이터에서 다이어그램, 그래프 및 차트를 만듭니다.
- 감사 또는 공유를 위해 데이터를 다른 형식으로 변환합니다.
- 이슈를 GitLab 외부의 시스템으로 가져옵니다.
- 시간에 따라 생성된 여러 스냅샷으로 장기 추세를 분석합니다.
- 장기 데이터를 사용하여 이슈에서 제공한 관련 피드백을 수집하고 실제 지표를 기반으로 제품을 개선합니다.

## 내보낼 이슈 선택 {#select-issues-to-export}

개별 프로젝트에서는 이슈를 내보낼 수 있지만 그룹에서는 내보낼 수 없습니다.

사전 요구 사항:

- 게스트, 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할이 있어야 합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **Plan** > **Work items**을 선택한 다음, **Type** = **Issue**로 필터링합니다.
1. 선택 사항. 추가 필터, 연산자 및 값을 선택하여 이슈의 부분 집합을 내보냅니다. 자세한 내용은 [이슈 목록 필터링](managing_issues.md#filter-the-list-of-issues)을 참조하세요.
1. 오른쪽 위 모서리에서 **조치**({{< icon name="ellipsis_v" >}}) > **CSV로 내보내기**를 선택합니다.
1. 대화 상자에서 이메일 주소가 올바른지 확인한 후 **이슈 내보내기**를 선택합니다.

첫 페이지에 표시되지 않은 이슈를 포함하여 모든 일치하는 이슈가 내보내집니다. 내보낸 CSV에는 이슈의 첨부 파일이 포함되지 않습니다.

## 형식 {#format}

CSV 파일의 형식은 다음과 같습니다:

- 정렬은 제목별입니다.
- 열은 쉼표로 구분됩니다.
- 필드는 필요한 경우 큰따옴표(`"`)로 인용됩니다.
- 줄 바꿈 문자는 행을 분리합니다.

> [!note]
> CSV 구문 분석 요구 사항에 대한 정보는 [CSV 구문 분석 고려 사항](../repository/files/csv.md#csv-parsing-considerations)을 참조하세요.

## 열 {#columns}

CSV 파일에 포함된 열은 다음과 같습니다.

| 열            | 설명 |
| ----------------- | ----------- |
| ID                | 이슈 `id`  |
| IID               | 이슈 `iid` |
| 제목             | 이슈 `title` |
| 설명       | 이슈 `description` |
| 형식              | 이슈 `type` |
| URL               | GitLab의 이슈로 연결되는 링크 |
| 상태             | `Open` 또는 `Closed` |
| 기밀      | `Yes` 또는 `No` |
| Locked (잠김)            | `Yes` 또는 `No` |
| 마일스톤         | 이슈 마일스톤의 제목 |
| 레이블            | 쉼표로 구분된 레이블 |
| 작성자            | 이슈 작성자의 전체 이름 |
| 작성자 사용자명   | `@` 기호를 생략한 작성자의 사용자명 |
| 담당자          | 이슈 담당자의 전체 이름 |
| 담당자 사용자명 | `@` 기호를 생략한 담당자의 사용자명 |
| Created At(UTC)  | `YYYY-MM-DD HH:MM:SS`로 형식화됨 |
| 업데이트 시간(UTC)  | `YYYY-MM-DD HH:MM:SS`로 형식화됨 |
| 종료 시간(UTC)   | `YYYY-MM-DD HH:MM:SS`로 형식화됨 |
| 기한          | `YYYY-MM-DD`로 형식화됨 |
| 시작 날짜        | `YYYY-MM-DD`로 형식화됨 |
| 상위 항목 ID         | 상위 항목의 ID |
| 상위 항목 IID        | 상위 항목의 IID |
| 상위 항목 제목      | 상위 항목의 제목 |
| 시간 예상     | [시간 예상](../time_tracking.md#estimates)(초) |
| 시간 소요        | [시간 소요](../time_tracking.md#time-spent)(초) |
| 가중치            | 이슈 가중치 |

## 문제 해결 {#troubleshooting}

내보낸 이슈를 사용할 때 다음과 같은 문제가 발생할 수 있습니다.

### 내보내기 크기 {#size-of-export}

이슈는 다양한 이메일 제공자 간에 성공적으로 전달하도록 15 MB 내보내기 제한으로 이메일 첨부 파일로 전송됩니다. 제한에 도달하면 내보내기 전에 검색을 좁히세요. 예를 들어 공개 이슈와 종료된 이슈를 별도로 내보내는 것을 고려하세요.
