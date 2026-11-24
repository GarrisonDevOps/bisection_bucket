---
stage: Plan
group: Portfolio Planning
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 연결된 이슈
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [변경됨](https://gitlab.com/groups/gitlab-org/-/work_items/10267) \- 최소 필수 역할이 Reporter에서 GitLab 17.0에서 게스트로 변경되었습니다.

{{< /history >}}

연결된 이슈는 두 이슈 간의 양방향 관계이며 이슈 설명 아래 블록에 표시됩니다. 다른 프로젝트의 이슈를 연결할 수 있습니다.

사용자가 두 이슈를 모두 볼 수 있을 경우에만 관계가 UI에 표시됩니다. 열린 차단자가 있는 이슈를 닫으려고 하면 경고가 표시됩니다.

> [!note]
> API를 통해 연결된 이슈를 관리하려면 [이슈 링크 API](../../../api/issue_links.md)를 참조하세요.

## 연결된 이슈 추가 {#add-a-linked-issue}

사전 요구 사항:

- 두 프로젝트 모두에서 게스트, 플래너, 리포터, 개발자, 유지보수자 또는 소유자 역할이 있어야 합니다.

한 이슈를 다른 이슈에 연결하려면:

1. 이슈의 **링크된 항목** 섹션에서 연결된 이슈 추가 버튼({{< icon name="plus" >}})을 선택합니다.
1. 두 이슈 간의 관계를 선택합니다. 다음 중 하나를 선택합니다.
   - **다음과 관련됨**
   - [**차단**](#blocking-issues)
   - [**다음에 의해 차단됨**](#blocking-issues)
1. 이슈 번호를 입력하거나 이슈의 전체 URL을 붙여넣으세요.

   ![현재 이슈와 관련 이슈 연결](img/related_issues_add_v15_3.png)

   같은 프로젝트의 이슈는 참조 번호로만 지정할 수 있습니다. 다른 프로젝트의 이슈는 그룹 및 프로젝트 이름과 같은 추가 정보가 필요합니다. 예를 들어:

   - 같은 프로젝트: `#44`
   - 같은 그룹: `project#44`
   - 다른 그룹: `group/project#44`

   유효한 참조는 검토할 수 있는 임시 목록에 추가됩니다.

1. 모든 연결된 이슈를 추가한 경우 **추가**를 선택합니다.

모든 연결된 이슈 추가를 완료한 후에는 관계를 시각적으로 더 잘 이해할 수 있도록 분류된 항목을 볼 수 있습니다.

![관련 이슈를 보거나 관리하는 섹션](img/related_issue_block_v15_3.png)

커밋 메시지 또는 다른 이슈 또는 MR의 설명에서 연결된 이슈를 추가할 수도 있습니다. 자세한 내용은 [이슈 교차 연결](crosslinking_issues.md)을 참조하세요.

## 연결된 이슈 제거 {#remove-a-linked-issue}

이슈의 **링크된 항목** 섹션에서 제거할 각 이슈 토큰의 오른쪽에 있는 제거 버튼({{< icon name="close" >}})을 선택합니다.

양방향 관계로 인해 관계는 더 이상 두 이슈 중 어느 쪽에도 표시되지 않습니다.

![현재 이슈에서 관련 이슈 연결 해제](img/related_issues_remove_v15_3.png)

자세한 내용은 [권한](../../permissions.md) 페이지를 참조하세요.

## 차단하는 이슈 {#blocking-issues}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[연결된 이슈를 추가](#add-a-linked-issue)할 때, 이슈가 **차단**하거나 **다음에 의해 차단됨**을 다른 이슈에 표시할 수 있습니다.

다른 이슈에 의해 차단된 이슈는 이슈 목록과 [보드](../issue_board.md)에 표시되는 제목 옆에 아이콘({{< icon name="entity-blocked" >}})을 가집니다. 차단 이슈가 닫히거나 관계가 변경되거나 [제거](#remove-a-linked-issue)되면 아이콘이 사라집니다.

"이슈 닫기" 버튼을 사용하여 차단된 이슈를 닫으려고 하면 확인 메시지가 나타납니다.
