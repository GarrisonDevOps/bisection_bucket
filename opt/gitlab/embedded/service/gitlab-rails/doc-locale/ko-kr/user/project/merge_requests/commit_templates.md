---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 커밋 메시지 템플릿을 사용하여 GitLab 프로젝트의 커밋에 모든 필요한 정보가 포함되고 올바른 형식으로 지정되었는지 확인하세요.
title: 커밋 메시지 템플릿
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab은 커밋 템플릿을 사용하여 특정 유형의 커밋에 대한 기본 메시지를 만듭니다. 이러한 템플릿은 커밋 메시지가 특정 형식을 따르거나 특정 정보를 포함하도록 권장합니다. 사용자는 머지 리퀘스트를 병합할 때 이러한 템플릿을 무시할 수 있습니다.

커밋 템플릿 구문은 [검토 제안](reviews/suggestions.md#configure-the-commit-message-for-applied-suggestions)의 구문과 같습니다.

GitLab Duo는 템플릿을 구성하지 않아도 [머지 커밋 메시지](duo_in_merge_requests.md#generate-a-merge-commit-message)를 생성하는 데 도움이 될 수 있습니다.

## 커밋 템플릿 구성 {#configure-commit-templates}

기본 템플릿에 필요한 정보가 포함되지 않으면 프로젝트의 커밋 템플릿을 변경하세요.

사전 요구 사항:

- 프로젝트에 대한 유지 관리자 역할 이상이 필요합니다.

다음과 같이 설정합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **머지 리퀘스트**를 선택합니다.
1. 생성할 템플릿 유형에 따라 [**머지 커밋 메시지 템플릿**](#default-template-for-merge-commits) 또는 [**스쿼시 커밋 메시지 템플릿**](#default-template-for-squash-commits)까지 스크롤합니다.
1. 원하는 커밋 유형에 대해 기본 메시지를 입력하세요. 정적 텍스트와 [변수](#supported-variables-in-commit-templates)를 모두 사용할 수 있습니다. 각 템플릿은 500자로 제한되지만, 템플릿을 데이터로 바꾼 후 최종 메시지는 더 길 수 있습니다.
1. **변경 사항 저장**을 선택합니다.

## 머지 커밋을 위한 기본 템플릿 {#default-template-for-merge-commits}

머지 커밋 메시지의 기본 템플릿은 다음과 같습니다:

```plaintext
Merge branch '%{source_branch}' into '%{target_branch}'

%{title}

%{issues}

See merge request %{reference}
```

## 스쿼시 커밋을 위한 기본 템플릿 {#default-template-for-squash-commits}

프로젝트를 [병합 시 커밋 스쿼시](squash_and_merge.md)하도록 구성한 경우 GitLab은 이 템플릿을 사용하여 스쿼시 커밋 메시지를 만듭니다:

```plaintext
%{title}
```

## 커밋 템플릿에서 지원되는 변수 {#supported-variables-in-commit-templates}

{{< history >}}

- `merge_request_author` 변수가 GitLab 17.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/152510)되었습니다.
- `commits_count` 변수가 GitLab 19.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/383062)되었습니다.

{{< /history >}}

커밋 메시지 템플릿은 다음 변수를 지원합니다:

| 변수                                | 설명                                                                                                                                                                                                                                   | 출력 예시                                                                                                                                                                                   |
|-----------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `%{source_branch}`                      | 병합할 브랜치의 이름입니다.                                                                                                                                                                                                              | `my-feature-branch`                                                                                                                                                                              |
| `%{target_branch}`                      | 변경 사항을 적용할 브랜치의 이름입니다.                                                                                                                                                                                               | `main`                                                                                                                                                                                           |
| `%{title}`                              | 머지 리퀘스트의 제목입니다.                                                                                                                                                                                                                   | `Fix tests and translations`                                                                                                                                                                     |
| `%{issues}`                             | `Closes <issue numbers>`이 있는 문자열입니다. 머지 리퀘스트 설명에 언급된 모든 이슈를 포함하며, [이슈 마감 패턴](../issues/managing_issues.md#closing-issues-automatically)과 일치합니다. 이슈를 언급하지 않으면 비어 있습니다. | `Closes #465, #190 and #400`                                                                                                                                                                     |
| `%{description}`                        | 머지 리퀘스트의 설명입니다.                                                                                                                                                                                                             | `Merge request description.`<br>`Can be multiline.`                                                                                                                                              |
| `%{reference}`                          | 머지 리퀘스트에 대한 참조입니다.                                                                                                                                                                                                               | `group-name/project-name!72359`                                                                                                                                                                  |
| `%{local_reference}`                    | 머지 리퀘스트에 대한 로컬 참조입니다.                                                                                                                                                                                                         | `!72359`                                                                                                                                                                                         |
| `%{source_project_id}`                  | 머지 리퀘스트의 소스 프로젝트 ID입니다.                                                                                                                                                                                                     | `123`                                                                                                                                                                                            |
| `%{first_commit}`                       | 머지 리퀘스트 diff의 첫 번째 커밋의 전체 메시지입니다.                                                                                                                                                                                       | `Update README.md`                                                                                                                                                                               |
| `%{first_multiline_commit}`             | 머지 커밋이 아니며 메시지 본문에 두 줄 이상이 있는 첫 번째 커밋의 전체 메시지입니다. 모든 커밋이 여러 줄이 아닌 경우 머지 리퀘스트 제목입니다.                                                                                   | `Update README.md`<br><br>`Improved project description in readme file.`                                                                                                                         |
| `%{first_multiline_commit_description}` | 머지 커밋이 아니며 메시지 본문에 두 줄 이상이 있는 첫 번째 커밋의 설명(첫 번째 줄/제목 제외)입니다.                                                                                                          | `Improved project description in readme file.`                                                                                                                                                   |
| `%{url}`                                | 머지 리퀘스트의 전체 URL입니다.                                                                                                                                                                                                                | `https://gitlab.com/gitlab-org/gitlab/-/merge_requests/1`                                                                                                                                        |
| `%{reviewed_by}`                        | 일괄 주석을 사용하여 검토를 제출한 사용자를 기반으로 하는 머지 리퀘스트 검토자의 줄 분리 목록이며, `Reviewed-by` Git 커밋 트레일러 형식입니다.                                                                                 | `Reviewed-by: Sidney Jones <sjones@example.com>` <br> `Reviewed-by: Zhang Wei <zwei@example.com>`                                                                                                |
| `%{approved_by}`                        | 머지 리퀘스트 승인자의 줄 분리 목록이며, `Approved-by` Git 커밋 트레일러 형식입니다.                                                                                                                                              | `Approved-by: Sidney Jones <sjones@example.com>` <br> `Approved-by: Zhang Wei <zwei@example.com>`                                                                                                |
| `%{merged_by}`                          | 머지 리퀘스트를 병합한 사용자입니다.                                                                                                                                                                                                            | `Alex Garcia <agarcia@example.com>`                                                                                                                                                              |
| `%{merge_request_author}`               | 머지 리퀘스트 작성자의 이름과 이메일입니다.                                                                                                                                                                                                   | `Zane Doe <zdoe@example.com>`                                                                                                                                                                    |
| `%{co_authored_by}`                     | 커밋 작성자의 이름과 이메일이며, `Co-authored-by` Git 커밋 트레일러 형식입니다. 머지 리퀘스트의 100개 최근 커밋의 작성자로 제한됩니다.                                                                                           | `Co-authored-by: Zane Doe <zdoe@example.com>` <br> `Co-authored-by: Blake Smith <bsmith@example.com>`                                                                                            |
| `%{all_commits}`                        | 머지 리퀘스트의 모든 커밋의 메시지입니다. 100개 최근 커밋으로 제한됩니다. 100KiB를 초과하는 커밋 본문과 머지 커밋 메시지를 건너뜁니다.                                                                                          | `* Feature introduced` <br><br> `This commit implements feature` <br> `Changelog:added` <br><br> `* Bug fixed` <br><br> `* Documentation improved` <br><br>`This commit introduced better docs.` |
| `%{commits_count}`                      | 머지 리퀘스트의 커밋 수입니다.                                                                                                                                                                                                       | `3`                                                                                                                                                                                              |

빈 변수만 포함하는 모든 줄이 제거됩니다. 제거된 줄이 빈 줄로 앞뒤로 되어 있으면, 앞의 빈 줄도 제거됩니다.

열린 머지 리퀘스트에서 커밋 메시지를 편집한 후 GitLab은 자동으로 커밋 메시지를 다시 업데이트합니다. 커밋 메시지를 프로젝트 템플릿으로 복원하려면 페이지를 다시 로드하세요.

## 관련 항목 {#related-topics}

- [머지 리퀘스트 제목 템플릿](title_templates.md)
- [스쿼시 및 머지](squash_and_merge.md)
