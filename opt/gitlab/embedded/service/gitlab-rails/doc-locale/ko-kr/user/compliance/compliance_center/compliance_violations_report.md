---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab 규정 준수 위반 보고서를 살펴보고 프로젝트 및 그룹 전체에서 규정 비준수 이슈를 보고 관리합니다.
title: 규정 준수 위반 보고서
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 동적 규정 준수 위반 보고서
  - [도입](https://gitlab.com/groups/gitlab-org/-/epics/12774)되었습니다 GitLab 18.2 [기능 플래그](../../../administration/feature_flags/_index.md) `compliance_violations_report` 및 `enable_project_compliance_violations`와 함께. 기본적으로 비활성화되었습니다.
  - [GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/201027)되었습니다 GitLab 18.3.
  - GitLab 18.5에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/201027)합니다. 기능 플래그 `compliance_violations_report` 및 `enable_project_compliance_violations`이 제거되었습니다.

{{< /history >}}

규정 준수 위반 보고서를 사용하여 그룹의 모든 프로젝트 전체에 규정 준수 위반을 포괄적으로 볼 수 있습니다. 이 보고서는 위반된 컨트롤, 관련 감사 이벤트에 대한 자세한 정보를 제공하고 위반 상태를 관리할 수 있게 해줍니다.

## 규정 준수 위반 보고서 활성화 {#enable-compliance-violations-report}

규정 준수 위반 보고서에 위반이 나타나기 전에 다음을 수행해야 합니다:

1. [컨트롤이 있는 규정 준수 프레임워크 만들기](../compliance_frameworks/_index.md).
1. [프로젝트에 프레임워크 적용](../compliance_frameworks/_index.md#apply-a-compliance-framework-to-a-project).

이 단계를 완료하면 규정 준수 위반 보고서에 검출되는 위반이 표시됩니다.

감사 이벤트가 프레임워크에 정의된 컨트롤을 위반할 때 위반이 자동으로 검출됩니다. 시스템은 지속적으로 감사 이벤트를 모니터링하고 규정 비준수를 식별하기 위해 프레임워크의 컨트롤 정의와 비교합니다.

### 지원되는 컨트롤 {#supported-controls}

다음의 규정 준수 컨트롤이 위반 검출을 지원합니다:

- `minimum_approvals_required_1`
- `minimum_approvals_required_2`
- `merge_request_prevent_author_approval`
- `merge_request_prevent_committers_approval`

규정 준수 컨트롤에 대한 자세한 정보는 [규정 준수 프레임워크](../compliance_frameworks/_index.md)를 참조하세요.

## 규정 준수 위반 보고서 보기 {#view-the-compliance-violations-report}

사전 요구 사항:

- 관리자이거나 프로젝트 또는 그룹에 대한 보안 관리자 또는 소유자 역할이 있어야 합니다.

규정 준수 위반 보고서를 보려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **안전함** > **규정준수 센터**를 선택합니다.

규정 준수 위반 보고서는 다음을 표시합니다:

- **상태**: 위반의 현재 상태. 예: 검토 필요, 해결됨 또는 기각됨.
- **위반 컨트롤과 프레임워크**: 위반된 특정 규정 준수 컨트롤과 그 관련 프레임워크.
- **이벤트 감사**: 위반을 트리거한 이벤트에 대한 세부 정보.
- **프로젝트**: 위반이 발생한 프로젝트.
- **날짜 검출됨**: 위반이 식별되었을 때.
- **조치**: 위반에 대한 상세 정보를 보는 링크.

이 보고서에서 다음을 수행할 수 있습니다:

- 열 헤더를 선택하여 보고서를 정렬합니다.
- 상태 드롭다운 목록을 사용하여 위반의 상태를 변경합니다.
- 페이지 매김을 사용하여 여러 위반 페이지를 탐색합니다.
- 각 위반에 대한 상세 정보를 봅니다.
- 보고서를 CSV 파일로 내보냅니다.

### 규정 준수 위반 필터링 {#filter-compliance-violations}

{{< history >}}

- GitLab 18.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/555541)되었습니다.
- **이전 검출됨** 및 **이후 검출됨** 필터가 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/582497)되었습니다 GitLab 19.1.

{{< /history >}}

규정 준수 위반 보고서를 필터링하여 특정 위반에 집중할 수 있습니다:

1. 규정 준수 위반 보고서에서 페이지 상단의 필터 옵션을 사용합니다.
1. 하나 이상의 필터를 선택합니다:
   - **상태**: 위반 상태별로 필터링합니다(검출됨, 기각됨, 검토 중 또는 해결됨).
   - **프로젝트**: 그룹의 특정 프로젝트별로 필터링합니다.
   - **컨트롤**: 규정 준수 컨트롤별로 필터링합니다.
   - **이전 검출됨**: 특정 날짜 이전에 검출된 위반을 표시합니다.
   - **이후 검출됨**: 특정 날짜 이후에 검출된 위반을 표시합니다.

**이전 검출됨** 및 **이후 검출됨**을 결합하여 보고서를 날짜 범위로 제한합니다.

이 보고서는 선택한 필터와 일치하는 위반만 표시하도록 자동으로 업데이트됩니다.

필터를 지우려면 필터 옵션을 지우거나 **지우기**를 선택합니다.

## 위반 세부 정보 {#violation-details}

특정 위반에 대해 **상세정보**를 선택하면 다음을 볼 수 있습니다:

- 위반 ID 및 상태.
- 위반이 발생한 위치(프로젝트).
- 다음을 포함한 포괄적인 감사 이벤트 정보:
  - 이벤트 작성자.
  - 이벤트 대상.
  - 이벤트 세부 정보.
  - IP 주소.
  - 대상 유형.
- 다음을 포함한 위반된 컨트롤 정보:
  - 컨트롤 이름 및 설명.
  - 관련 규정 준수 프레임워크.
  - 요구 사항.
- 위반을 해결하기 위한 링크가 있는 수정 제안.
- 위반과 관련된 댓글 및 토론 스레드.

### 위반에 댓글 추가 {#add-comments-to-violations}

{{< history >}}

- GitLab 18.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/541095)되었습니다.

{{< /history >}}

수정 작업에 대해 팀과 협력하기 위해 위반에 댓글을 추가할 수 있습니다:

1. 위반 세부 정보 보기에서 댓글 섹션으로 스크롤합니다.
1. 텍스트 필드에 댓글을 입력합니다.
1. **댓글**를 선택하여 댓글을 게시합니다.

댓글이 위반에 추가되고 규정 준수 위반 보고서에 액세스할 수 있는 모든 사용자에게 표시됩니다.

## 위반 상태 관리 {#manage-violation-statuses}

규정 준수 위반의 상태를 업데이트하여 수정 진행 상황을 추적할 수 있습니다. 사용 가능한 상태는 다음과 같습니다:

- **검토 필요**: 새로운 위반의 기본 상태
- **진행 중**: 위반이 해결되는 중입니다
- **해결됨**: 위반이 수정되었습니다
- **해제됨**: 위반이 검토되고 기각되었습니다

위반 상태를 변경하려면:

1. 규정 준수 위반 보고서에서 업데이트하려는 위반을 찾습니다.
1. **상태** 열에서 현재 상태 드롭다운 목록을 선택합니다.
1. 드롭다운 목록 메뉴에서 새로운 상태를 선택합니다.

상태가 즉시 업데이트되고 보고서에 반영됩니다.

## 규정 준수 위반 보고서 내보내기 {#export-compliance-violations-report}

{{< history >}}

- GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/551244)되었습니다.

{{< /history >}}

그룹의 모든 프로젝트에 대한 규정 준수 위반의 CSV 보고서를 내보냅니다. 내보낸 보고서는 다음을 포함합니다:

- 검출 시간(가장 최근 먼저 DateTime)
- 위반 ID
- 상태
- 프레임워크
- 규정 준수 컨트롤
- 규정 준수 요구 사항
- 이벤트 감사 작성자
- 이벤트 감사 유형
- 이벤트 감사 이름
- 이벤트 감사 메시지
- 프로젝트 ID

보고서:

- 이메일 첨부 파일이 너무 커지지 않도록 15MB에서 잘립니다.
- 웹 인터페이스에 적용된 현재 필터에 관계없이 모든 위반을 포함합니다.

사전 요구 사항:

- 그룹의 관리자이거나 보안 관리자 또는 소유자 역할이 있어야 합니다.

규정 준수 위반 보고서를 내보내려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **안전함** > **규정준수 센터**를 선택합니다.
1. 오른쪽 위 모서리에서 **내보내기**를 선택하세요.
1. **위반 보고서 내보내기**를 선택합니다.

보고서가 컴파일되어 첨부 파일로 이메일 받은 편지함에 전달됩니다.

## 정적 규정 준수 위반 보고서 {#static-compliance-violations-report}

> [!warning]
> 이 기능은 GitLab 18.2에서 [지원 중단](https://gitlab.com/gitlab-org/gitlab/-/issues/551236)되었으며 18.8에서 제거될 예정입니다.

정적 규정 준수 위반 보고서는 그룹의 모든 프로젝트에 대한 머지 리퀘스트 활동의 상위 수준 보기를 제공합니다.

정적 규정 준수 위반 보고서의 행을 선택하면 다음을 제공하는 드로어가 나타납니다:

- 프로젝트 이름 및 [규정 준수 프레임워크 레이블](../../project/working_with_projects.md#add-a-compliance-framework-to-a-project)(프로젝트에 할당된 경우).
- 위반을 도입한 머지 리퀘스트로의 링크.
- 머지 리퀘스트의 브랜치 경로는 `[source] into [target]` 형식입니다.
- 머지 리퀘스트에 변경 사항을 커밋한 사용자의 목록.
- 머지 리퀘스트에 댓글을 단 사용자의 목록.
- 머지 리퀘스트를 승인한 사용자의 목록.
- 머지 리퀘스트를 병합한 사용자.

### 정적 규정 준수 위반 보고서 보기 {#view-the-static-compliance-violations-report}

사전 요구 사항:

- 관리자이거나 프로젝트 또는 그룹에 대한 보안 관리자 또는 소유자 역할이 있어야 합니다.

정적 규정 준수 위반 보고서를 보려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **안전함** > **규정준수 센터**를 선택합니다.

규정 준수 보고서를 다음 항목으로 정렬할 수 있습니다:

- 심각도 수준.
- 위반의 유형.
- 머지 리퀘스트 제목입니다.

규정 준수 위반 보고서를 다음 항목으로 필터링할 수 있습니다:

- 위반이 발견된 프로젝트.
- 위반의 날짜 범위.
- 위반의 대상 브랜치.

규정 준수 위반의 세부 정보를 보려면 행을 선택합니다.

### 심각도 수준 {#severity-levels}

각 규정 준수 위반에는 다음 심각도 중 하나가 있습니다.

<!-- vale gitlab_base.SubstitutionWarning = NO -->

| 아이콘                                  | 심각도 수준 |
|:--------------------------------------|:---------------|
| {{< icon name="severity-critical" >}} | 긴급       |
| {{< icon name="severity-high" >}}     | 높음           |
| {{< icon name="severity-medium" >}}   | 중간         |
| {{< icon name="severity-low" >}}      | 낮음            |
| {{< icon name="severity-info" >}}     | 정보           |

<!-- vale gitlab_base.SubstitutionWarning = YES -->

### 위반 유형 {#violation-types}

| 위반                         | 심각도 수준 | 범주                                      | 설명                                                                                                                                                                                                                                            |
|:----------------------------------|:---------------|:----------------------------------------------|:-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 작성자 승인 머지 리퀘스트     | 높음           | [직무 분리](#separation-of-duties) | 머지 리퀘스트의 작성자가 자신의 머지 리퀘스트를 승인했습니다. 자세한 정보는 [머지 리퀘스트 작성자의 승인 방지](../../project/merge_requests/approvals/settings.md#prevent-approval-by-merge-request-creator)를 참조하세요.                     |
| 커미터 승인 머지 리퀘스트 | 높음           | [직무 분리](#separation-of-duties) | 머지 리퀘스트의 커미터가 자신이 기여한 머지 리퀘스트를 승인했습니다. 자세한 정보는 [커밋을 추가하는 사용자의 승인 방지](../../project/merge_requests/approvals/settings.md#prevent-approvals-by-users-who-add-commits)를 참조하세요. |
| 2개 미만의 승인          | 높음           | [직무 분리](#separation-of-duties) | 머지 리퀘스트가 2개 미만의 승인으로 병합되었습니다. 자세한 정보는 [머지 리퀘스트 승인 규칙](../../project/merge_requests/approvals/rules.md)을 참조하세요.                                                                                     |

#### 직무 분리 {#separation-of-duties}

GitLab은 머지 리퀘스트를 생성하고 승인하는 사용자 간의 직무 분리 정책을 지원합니다. 직무 분리 기준은 다음과 같습니다:

- [머지 리퀘스트 작성자는 자신의 머지 리퀘스트를 승인할 수 없습니다](../../project/merge_requests/approvals/settings.md#prevent-approval-by-merge-request-creator).
- [머지 리퀘스트 커미터는 커밋을 추가한 머지 리퀘스트를 승인할 수 없습니다](../../project/merge_requests/approvals/settings.md#prevent-approvals-by-users-who-add-commits).
- [머지 리퀘스트를 병합하는 데 필요한 최소 승인 수는 최소 2개입니다](../../project/merge_requests/approvals/rules.md).

### 그룹의 프로젝트에 대한 머지 리퀘스트 규정 준수 위반 보고서 내보내기 {#export-a-report-of-merge-request-compliance-violations-on-projects-in-a-group}

그룹의 프로젝트에 속하는 머지 리퀘스트에 대한 머지 리퀘스트 규정 준수 위반 보고서를 내보냅니다. 보고서:

- 위반 보고서에 필터를 사용하지 마세요.
- 이메일 첨부 파일이 너무 커지지 않도록 15MB에서 잘립니다.

사전 요구 사항:

- 그룹의 관리자이거나 보안 관리자 또는 소유자 역할이 있어야 합니다.

그룹의 프로젝트에 대한 머지 리퀘스트 규정 준수 위반 보고서를 내보내려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **안전함** > **규정준수 센터**를 선택합니다.
1. 오른쪽 위 모서리에서 **내보내기**를 선택하세요.
1. **위반 보고서 내보내기**를 선택합니다.

보고서가 컴파일되어 첨부 파일로 이메일 받은 편지함에 전달됩니다.
