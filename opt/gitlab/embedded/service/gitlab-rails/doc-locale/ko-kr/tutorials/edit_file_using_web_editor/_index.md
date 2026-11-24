---
stage: Tutorials
group: Tutorials
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: '자습서: 웹 편집기를 사용하여 파일 편집'
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[프로젝트](../../user/project/organize_work_with_projects.md) 파일은 [적절한 액세스 권한](../../user/project/members/_index.md)이 있는 팀원이 편집할 수 있습니다.

간단한 웹 편집기를 사용하여 GitLab UI에서 개별 파일을 직접 편집하는 방법을 알아봅니다.

## 편집할 파일 선택 {#select-the-file-you-wish-to-edit}

먼저 프로젝트 홈 페이지로 이동하여 프로젝트의 파일 목록을 확인합니다.

![프로젝트 홈 페이지의 파일 목록입니다. "break-room.md"와 같은 파일이 있는 "Company Handbook"이라는 프로젝트를 보여줍니다.](img/project_file_listing_v18_9.png)

파일을 선택하여 세부 정보를 확인합니다.

!["break-room.md" 파일이 자세히 표시됩니다. 카드, 비디오 게임, 당구대 등의 편의 시설을 보여줍니다.](img/file_in_detail_v18_9.png)

## 파일 편집 {#edit-the-file}

**편집** 드롭다운 목록을 선택한 후 **단일 파일 편집**을 선택합니다.

![편집 버튼이 확장되어 드롭다운 목록 옵션인 "웹 IDE에서 열기"와 "단일 파일 편집"을 표시합니다.](img/edit_dropdown_v18_9.png)

편집기에서 필요에 따라 파일을 편집합니다.

![파일이 편집 가능한 텍스트 필드에 다시 표시되어 뷰어가 내용을 변경할 수 있습니다.](img/edit_file_v18_9.png)

## 변경 사항 커밋 및 머지 리퀘스트 생성 {#commit-your-changes-and-create-a-merge-request}

변경 사항을 파일에 직접 커밋(저장)할 수 있습니다. 그러나 대부분의 팀에서는 권장되지 않습니다. 팀원이 먼저 변경 사항을 검토하도록 하는 것이 좋은 관행이기 때문입니다. 이 단계에서는 새 변경 사항으로 브랜치와 머지 리퀘스트를 생성합니다.

편집을 완료한 후:

1. **변경 사항 커밋**을 선택합니다.
1. **커밋 메시지** 텍스트 상자에 변경 사항에 대한 설명을 입력합니다.
1. **브랜치**에서 **새 브랜치로 커밋**을 선택합니다.
1. **새 브랜치로 커밋**에서 새 브랜치의 이름을 입력하거나 자동으로 생성된 이름을 그대로 두세요.
1. **이 변경 사항에 대한 머지 리퀘스트를 만듭니다.**가 선택되어 있는지 확인합니다.

![예제 값이 포함된 변경 사항 커밋 양식입니다. 커밋 메시지는 "Remove mention of the ping-pong table"이고, "new branch로 commit"이 선택되었으며, 브랜치는 "ping-pong-table-removal"입니다.](img/commit_changes_v18_9.png)

마지막으로 **변경 사항 커밋**을 선택하여 변경 사항을 새 브랜치에 커밋합니다. 새 머지 리퀘스트 양식이 나타납니다. 요청을 생성하려면 다음을 수행하세요:

1. **제목**을 변경 사항에 대한 적절한 요약으로 설정합니다.
1. 변경 사항에 대한 자세한 정보를 **설명** 필드에 입력합니다.
1. **담당자**를 자신으로 설정합니다.
1. 변경 사항을 검토해야 할 사람을 알고 있다면 **검토자**를 설정합니다.
1. 선택사항. 머지 리퀘스트의 [마일스톤](../../user/project/milestones/_index.md)을 설정합니다.
1. 선택사항. 머지 리퀘스트의 레이블을 설정하여 더 잘 분류합니다.
1. **머지 리퀘스트 생성**를 선택하여 머지 리퀘스트를 생성합니다.

![새 머지 리퀘스트 양식은 제목이 "Remove mention of the ping-pong table"로 설정되고, 설명이 "This merge request removes the ping-pong table from the break room page since we no longer have one."으로 표시됩니다.](img/merge_request_v18_9.png)

편집 내용이 이제 머지 리퀘스트에 있으며 다른 기여자의 검토를 받을 준비가 되었습니다.

## 다음 단계 {#next-steps}

다음을 수행할 수 있습니다:

- 다른 사람의 머지 리퀘스트 검토
- [기존 프로젝트에 이슈 생성](../create_issue_in_existing_project/_index.md)
