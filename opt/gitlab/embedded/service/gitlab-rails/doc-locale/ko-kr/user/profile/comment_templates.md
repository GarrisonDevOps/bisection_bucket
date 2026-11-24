---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 댓글에서 자주 사용되는 텍스트의 템플릿을 만들고 프로젝트 또는 그룹과 그 템플릿을 공유합니다.
title: 댓글 템플릿
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 그룹의 저장된 답변:
  - [GitLab 16.11에서 도입됨](https://gitlab.com/groups/gitlab-org/-/work_items/12669) [기능 플래그](../../administration/feature_flags/_index.md) `group_saved_replies_flag`로 명명됨. 기본적으로 사용 중지됩니다.
  - [GitLab 17.8에서 일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/504028). 기능 플래그 `group_saved_replies_flag`이 제거되었습니다.
- 프로젝트의 저장된 답변:
  - [GitLab 17.0에서 도입됨](https://gitlab.com/groups/gitlab-org/-/work_items/12669) [기능 플래그](../../administration/feature_flags/_index.md) `project_saved_replies_flag`로 명명됨. 기본적으로 활성화됩니다.
  - [GitLab 17.8에서 일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/504028). 기능 플래그 `project_saved_replies_flag`이 제거되었습니다.

{{< /history >}}

댓글 템플릿을 사용하여 다음의 모든 텍스트 영역에서 텍스트를 만들고 재사용합니다:

- 차이점을 포함한 머지 리퀘스트
- 디자인 관리 댓글을 포함한 이슈
- 에픽.
- 작업 항목

댓글 템플릿은 머지 리퀘스트를 승인하고 자신을 할당 해제하는 것처럼 작을 수도 있고, 자주 사용하는 보일러플레이트 텍스트의 청크처럼 클 수도 있습니다:

![댓글 템플릿 드롭다운 목록](img/group_comment_templates_v16_11.png)

## 텍스트 영역에서 댓글 템플릿 사용 {#use-comment-templates-in-a-text-area}

댓글에 댓글 템플릿의 텍스트를 포함하려면:

1. 댓글의 편집기 도구 모음에서 **댓글 템플릿**({{< icon name="comment-lines" >}})을 선택합니다.
1. 원하는 댓글 템플릿을 선택합니다.

## 댓글 템플릿 만들기 {#create-comment-templates}

자신의 사용을 위해 댓글 템플릿을 만들거나 그룹의 모든 멤버와 공유할 수 있습니다.

자신의 사용을 위해 댓글 템플릿을 만들려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. 드롭다운 목록에서 **환경설정**을 선택합니다.
1. 왼쪽 사이드바에서 **댓글 템플릿**({{< icon name="comment-lines" >}})을 선택합니다.
1. **신규 추가**를 선택합니다.
1. 댓글 템플릿의 **이름**을 입력합니다.
1. 답변의 **내용**를 입력합니다. 다른 GitLab 텍스트 영역에서 사용하는 모든 형식을 사용할 수 있습니다.
1. **저장**을 선택하면 댓글 템플릿이 표시된 페이지가 다시 로드됩니다.

### 그룹의 경우 {#for-a-group}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

그룹의 모든 멤버와 공유되는 댓글 템플릿을 만들려면:

1. 댓글의 편집기 도구 모음에서 **댓글 템플릿**({{< icon name="comment-lines" >}})을 선택하고 **그룹 댓글 템플릿 관리**를 선택합니다.
1. **신규 추가**를 선택합니다.
1. 댓글 템플릿의 **이름**을 입력합니다.
1. 답변의 **내용**를 입력합니다. 다른 GitLab 텍스트 영역에서 사용하는 모든 형식을 사용할 수 있습니다.
1. **저장**을 선택하면 댓글 템플릿이 표시된 페이지가 다시 로드됩니다.

### 프로젝트의 경우 {#for-a-project}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

프로젝트의 모든 멤버와 공유되는 댓글 템플릿을 만들려면:

1. 댓글의 편집기 도구 모음에서 **댓글 템플릿**({{< icon name="comment-lines" >}})을 선택하고 **프로젝트 댓글 템플릿 관리**를 선택합니다.
1. **신규 추가**를 선택합니다.
1. 댓글 템플릿의 **이름**을 입력합니다.
1. 답변의 **내용**를 입력합니다. 다른 GitLab 텍스트 영역에서 사용하는 모든 형식을 사용할 수 있습니다.
1. **저장**을 선택하면 댓글 템플릿이 표시된 페이지가 다시 로드됩니다.

## 댓글 템플릿 보기 {#view-comment-templates}

기존 댓글 템플릿을 보려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. 드롭다운 목록에서 **환경설정**을 선택합니다.
1. 왼쪽 사이드바에서 **댓글 템플릿**({{< icon name="comment-lines" >}})을 선택합니다.
1. **댓글 템플릿**까지 스크롤합니다.

### 그룹의 경우 {#for-a-group-1}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

1. 댓글의 편집기 도구 모음에서 **댓글 템플릿**({{< icon name="comment-lines" >}})을 선택합니다.
1. **그룹 댓글 템플릿 관리**를 선택합니다.

### 프로젝트의 경우 {#for-a-project-1}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

1. 댓글의 편집기 도구 모음에서 **댓글 템플릿**({{< icon name="comment-lines" >}})을 선택합니다.
1. **프로젝트 댓글 템플릿 관리**를 선택합니다.

## 댓글 템플릿 편집 또는 삭제 {#edit-or-delete-comment-templates}

기존 댓글 템플릿을 편집하거나 삭제하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. 드롭다운 목록에서 **환경설정**을 선택합니다.
1. 왼쪽 사이드바에서 **댓글 템플릿**({{< icon name="comment-lines" >}})을 선택합니다.
1. **댓글 템플릿**까지 스크롤하고 편집할 댓글 템플릿을 식별합니다.
1. 편집하려면 **편집**({{< icon name="pencil" >}})을 선택합니다.
1. 삭제하려면 **삭제**({{< icon name="remove" >}})를 선택한 후 대화 상자에서 **삭제**를 다시 선택합니다.

### 그룹의 경우 {#for-a-group-2}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

1. 댓글의 편집기 도구 모음에서 **댓글 템플릿**({{< icon name="comment-lines" >}})을 선택하고 **그룹 댓글 템플릿 관리**를 선택합니다.
1. 편집하려면 **편집**({{< icon name="pencil" >}})을 선택합니다.
1. 삭제하려면 **삭제**({{< icon name="remove" >}})를 선택한 후 대화 상자에서 **삭제**를 다시 선택합니다.

### 프로젝트의 경우 {#for-a-project-2}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

1. 댓글의 편집기 도구 모음에서 **댓글 템플릿**({{< icon name="comment-lines" >}})을 선택하고 **프로젝트 댓글 템플릿 관리**를 선택합니다.
1. 편집하려면 **편집**({{< icon name="pencil" >}})을 선택합니다.
1. 삭제하려면 **삭제**({{< icon name="remove" >}})를 선택한 후 대화 상자에서 **삭제**를 다시 선택합니다.
