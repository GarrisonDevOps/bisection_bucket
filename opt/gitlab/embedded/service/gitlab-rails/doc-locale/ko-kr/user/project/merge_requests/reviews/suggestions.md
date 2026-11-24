---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 병합 요청에서 코드를 개선하고 이러한 개선 사항을 브라우저에서 직접 병합 요청에 커밋합니다.
title: 변경 사항 제안
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

검토자는 병합 요청 diff 스레드에서 Markdown 구문을 사용하여 코드 변경 사항을 제안할 수 있습니다. 병합 요청 작성자(또는 적절한 역할을 가진 다른 사용자)는 GitLab UI에서 모든 제안을 적용할 수 있습니다. 제안을 적용하면 변경 사항을 제안한 사용자가 작성한 커밋이 병합 요청에 추가됩니다.

## 제안 생성 {#create-suggestions}

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**를 선택하고 병합 요청을 찾습니다.
1. 보조 메뉴에서 **변경사항**을 선택합니다.
1. 변경할 코드 줄을 찾습니다.
   - 단일 줄을 선택하려면 줄 번호 위에 마우스를 올리고 **이 라인에 댓글 추가** ({{< icon name="comment" >}})를 선택합니다.
   - 더 많은 줄을 선택하려면:
     1. 줄 번호 위에 마우스를 올리고 **이 라인에 댓글 추가** ({{< icon name="comment" >}})를 선택합니다:

        ![줄 번호 위에 마우스를 올렸을 때 표시되는 댓글 추가 아이콘입니다.](img/comment_on_any_diff_line_v16_6.png)

     1. 선택을 끌어서 원하는 모든 줄을 포함하도록 합니다. 자세한 내용은 [여러 줄 제안](#multi-line-suggestions)을 참조하세요.
   - 특정 줄 대신 파일 전체에 댓글을 달려면 파일 헤더에서 **이 파일에 댓글 달기** ({{< icon name="comment" >}})를 선택합니다.
1. 댓글 도구 모음에서 **제안 삽입** ({{< icon name="doc-code" >}})을 선택합니다. GitLab은 댓글에 미리 입력된 코드 블록을 삽입합니다:

   ````markdown
   ```suggestion:-0+0
   The content of the line you selected is shown here.
   ```
   ````

1. 미리 입력된 코드 블록을 편집하여 제안을 추가합니다.
1. 댓글을 즉시 추가하려면 **댓글 추가**를 선택하거나 다음 키보드 단축키를 사용합니다:
   - macOS: <kbd>Shift</kbd>+<kbd>Command</kbd>+<kbd>Enter</kbd>
   - 기타 OS: <kbd>Shift</kbd>+<kbd>Control</kbd>+<kbd>Enter</kbd>
1. [리뷰](_index.md)를 완료할 때까지 댓글을 공개하지 않으려면 **리뷰 시작**을 선택하거나 다음 키보드 단축키를 사용합니다:
   - macOS: <kbd>Command</kbd>+<kbd>Enter</kbd>
   - 기타 OS: <kbd>Control</kbd>+<kbd>Enter</kbd>

### 여러 줄 제안 {#multi-line-suggestions}

{{< history >}}

- 여러 줄 제안이 GitLab 17.7에서 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/172981/)되어 제안에 코드 블록이 포함된 경우 렌더링을 지원합니다.

{{< /history >}}

병합 요청 diff를 검토할 때 다음 중 하나의 방법으로 단일 제안에서 최대 200개의 여러 줄에 대한 변경을 제안할 수 있습니다:

- [제안 생성](#create-suggestions)에 설명된 대로 선택하고 끕니다. GitLab이 제안 블록을 만듭니다.
- 단일 줄을 선택한 다음 제안 블록의 범위 오프셋을 수동으로 편집합니다.

제안의 첫 줄에서 범위 오프셋은 선택한 줄에 상대적인 줄 번호를 설명합니다. 오프셋은 제안이 바꾸려는 줄을 지정합니다. 예를 들어 이 제안은 주석이 달린 줄 위에 2줄, 아래에 2줄을 포함합니다:

````markdown
```suggestion:-2+2
## Prevent approval by author

By default, the author of a merge request cannot approve it. To change this setting:
```
````

적용하면 제안이 주석이 달린 줄 위의 2줄부터 아래의 2줄까지 바뀝니다:

![여러 줄에 걸친 제안의 미리보기입니다.](img/multi-line-suggestion-preview_v16_6.png)

GitLab은 여러 줄 제안을 주석이 달린 diff 줄 위에 100줄, 아래에 100줄로 제한합니다. 이를 통해 제안당 최대 201개의 변경 줄이 가능합니다.

여러 줄 댓글은 댓글 본문 위에 댓글의 줄 번호를 표시합니다:

![여러 줄 댓글의 범위를 나타내는 줄 번호입니다.](img/multiline-comment-saved_v17_5.png)

#### 리치 텍스트 편집기 사용 {#using-the-rich-text-editor}

제안을 삽입할 때 WYSIWYG [리치 텍스트 편집기](../../../rich_text_editor.md)를 사용하여 소스 파일의 줄 번호를 UI에서 위아래로 이동합니다.

변경된 줄을 추가하거나 빼려면 **시작 줄** 옆의 **+** 또는 **-**를 선택합니다.

![여러 줄 제안의 범위를 조정하기 위한 리치 텍스트 편집기 컨트롤입니다.](img/suggest_changes_v16_2.png)

## 제안 적용 {#apply-suggestions}

사전 요구 사항:

- 병합 요청의 작성자이거나 프로젝트에 대한 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

병합 요청에서 직접 제안된 변경을 적용하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**를 선택하고 병합 요청을 찾습니다.
1. 적용하려는 제안을 포함하는 댓글을 찾습니다.
   - 제안을 개별적으로 적용하려면 **제안 적용**을 선택합니다.
   - 단일 커밋에서 여러 제안을 적용하려면 **일괄 처리에 제안 추가**를 선택합니다.
1. 선택 사항. 변경을 설명하기 위한 사용자 지정 커밋 메시지를 제공합니다. 사용자 지정 메시지를 제공하지 않으면 기본 커밋 메시지를 사용합니다.
1. **적용**을 선택합니다.

제안을 적용한 후 GitLab은:

- 제안을 **적용됨**으로 표시합니다.
- 댓글 스레드를 해결합니다.
- 변경 사항이 포함된 새 커밋을 만듭니다.
- (사용자가 개발자 역할을 가진 경우) 제안된 변경을 병합 요청의 브랜치의 코드베이스에 직접 푸시합니다.

## 제안 거부 {#reject-suggestions}

사전 요구 사항:

- 병합 요청의 작성자이거나 프로젝트에 대한 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

병합 요청에서 직접 제안된 변경을 거부하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**를 선택하고 병합 요청을 찾습니다.
1. 거부하려는 제안을 포함하는 댓글을 찾습니다.
1. 선택 사항. 제안을 거부하는 이유를 설명하는 답글을 추가합니다.
1. **스레드 해결**을 선택합니다.

## 적용된 제안의 커밋 메시지 구성 {#configure-the-commit-message-for-applied-suggestions}

GitLab은 제안을 적용할 때 기본 커밋 메시지를 사용하지만 변경할 수 있습니다. 이 메시지는 자리 표시자를 지원합니다. 예를 들어 기본 메시지 `Apply %{suggestions_count} suggestion(s) to %{files_count} file(s)`는 3개의 제안을 2개의 다른 파일에 적용하면 다음과 같이 렌더링됩니다:

```plaintext
Apply 3 suggestion(s) to 2 file(s)
```

포크에서 생성된 병합 요청은 대상 프로젝트에 정의된 템플릿을 사용합니다. 프로젝트의 필요에 맞게 이러한 메시지를 사용자 지정하고 다른 자리 표시자 변수를 포함합니다.

사전 요구 사항:

- 유지 관리자 역할이 있어야 합니다.

다음과 같이 설정합니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **병합 요청**을 선택합니다.
1. **머지 제안**으로 스크롤하고 텍스트를 필요에 맞게 변경합니다. 이 메시지에서 사용할 수 있는 자리 표시자 목록은 [지원되는 변수](#supported-variables)를 참조하세요.

### 지원되는 변수 {#supported-variables}

적용된 제안의 커밋 메시지 템플릿은 다음 변수를 지원합니다:

| 변수               | 설명 | 출력 예시 |
|------------------------|-------------|----------------|
| `%{branch_name}`       | 제안이 적용된 브랜치의 이름입니다. | `my-feature-branch` |
| `%{files_count}`       | 제안이 적용된 파일의 수입니다.| `2` |
| `%{file_paths}`        | 제안이 적용된 파일의 경로입니다. 경로는 쉼표로 구분됩니다.| `docs/index.md, docs/about.md` |
| `%{project_path}`      | 프로젝트 경로입니다. | `my-group/my-project` |
| `%{project_name}`      | 프로젝트의 인간 친화적 이름입니다. | `My Project` |
| `%{suggestions_count}` | 적용된 제안의 수입니다.| `3` |
| `%{username}`          | 제안을 적용하는 사용자의 사용자 이름입니다. | `user_1` |
| `%{user_full_name}`    | 제안을 적용하는 사용자의 전체 이름입니다. | `User 1` |
| `%{co_authored_by}`    | `Co-authored-by` Git 커밋 트레일러 형식의 제안 작성자 이름 및 이메일입니다. | `Co-authored-by: Zane Doe <zdoe@example.com>` <br> `Co-authored-by: Blake Smith <bsmith@example.com>` |

예를 들어 커밋 메시지를 `Addresses user_1's review`로 출력하도록 사용자 지정하려면 사용자 지정 텍스트를 `Addresses %{username}'s review`로 설정합니다.

## 일괄 제안 {#batch-suggestions}

사전 요구 사항:

- 소스 브랜치에 커밋할 수 있는 프로젝트에 대한 역할이 있어야 합니다.

브랜치에 추가된 커밋 수를 줄이려면 여러 제안을 단일 커밋에 적용합니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**를 선택하고 병합 요청을 찾습니다.
1. 적용하려는 각 제안에 대해 **일괄 처리에 제안 추가**를 선택합니다.
1. 선택 사항. 제안을 제거하려면 **배치에서 제거**를 선택합니다.
1. 원하는 제안을 추가한 후 **제안 적용**을 선택합니다.

   > [!warning]
   > 여러 작성자의 변경 사항이 포함된 제안 배치를 적용하면 결과 커밋은 당신을 작성자로 표시합니다. 프로젝트를 [커밋을 추가하는 사용자의 승인 방지](../approvals/settings.md#prevent-approvals-by-users-who-add-commits)로 구성하면 이 병합 요청에 대한 적격 승인자가 더 이상 아닙니다.

1. 선택 사항. [일괄 제안](#batch-suggestions)의 변경을 설명하기 위한 사용자 지정 커밋 메시지를 제공합니다. 지정하지 않으면 기본 커밋 메시지를 사용합니다.

## 관련 항목 {#related-topics}

- [제안 API](../../../../api/suggestions.md)
