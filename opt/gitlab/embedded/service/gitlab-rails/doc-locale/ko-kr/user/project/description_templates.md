---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 설명 템플릿
description: "이슈 템플릿, 머지 리퀘스트 템플릿, 인스턴스 템플릿 및 그룹 템플릿입니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [작업 항목 지원](https://gitlab.com/gitlab-org/gitlab/-/issues/512208)은(는) GitLab 17.10에서 도입되었습니다.
- 에픽에 대한 지원이 GitLab 17.10에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/16088)되었으며 [기능 플래그](../../administration/feature_flags/_index.md)는 `work_item_epics`로 명명됩니다. 기본적으로 활성화됩니다. [베타](../../policy/development_stages_support.md#beta)에서 도입되었습니다.
- 에픽 지원이 GitLab 18.1에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/468310)되었습니다. `work_item_epics` 기능 플래그가 제거되었습니다.

{{< /history >}}

설명 템플릿은 GitLab에서 이슈 및 머지 리퀘스트를 생성하는 방식을 표준화하고 자동화합니다.

설명 템플릿:

- 프로젝트 전반에 걸쳐 이슈 및 머지 리퀘스트에 대한 일관된 레이아웃을 생성합니다.
- 다양한 워크플로우 스테이지 및 목적에 대한 전문화된 템플릿을 제공합니다.
- 프로젝트, 그룹 및 전체 인스턴스에 대한 사용자 지정 템플릿을 지원합니다.
- 변수 및 빠른 작업으로 필드를 자동 채웁니다.
- 버그, 기능 및 기타 작업 항목을 적절히 추적합니다.
- [Service Desk 이메일 응답](service_desk/configure.md#use-a-custom-template-for-service-desk-tickets)의 형식을 지정합니다.

다음에 대한 설명으로 사용할 템플릿을 정의할 수 있습니다:

- [이슈](issues/_index.md)
- [에픽](../group/epics/_index.md)([그룹 수준 설명 템플릿](#set-group-level-description-templates) 필요)
- [태스크](../tasks.md)
- [목표 및 핵심 결과(OKR)](../okrs.md)
- [인시던트](../../operations/incident_management/manage_incidents.md)
- [Service Desk 티켓](service_desk/_index.md)
- [머지 리퀘스트](merge_requests/_index.md)

프로젝트는 해당 그룹 및 인스턴스에서 템플릿을 상속받습니다.

템플릿은 다음이어야 합니다:

- `.md` 확장자로 저장됩니다.
- 프로젝트의 리포지토리에서 `.gitlab/issue_templates` 또는 `.gitlab/merge_request_templates` 디렉터리에 저장됩니다.
- 기본 브랜치에 있습니다.

## 설명 템플릿 생성 {#create-a-description-template}

리포지토리의 `.gitlab/issue_templates/` 디렉터리 내에서 Markdown(`.md`) 파일로 새로운 설명 템플릿을 생성합니다.

작업 항목 설명 템플릿을 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **리포지토리**를 선택합니다.
1. 기본 브랜치 옆에서 {{< icon name="plus" >}}를 선택합니다.
1. **새 파일**을 선택합니다.
1. 기본 브랜치 옆의 **파일 이름** 텍스트 상자에 `.gitlab/issue_templates/mytemplate.md`를 입력합니다. 여기서 `mytemplate`는 템플릿의 이름입니다.
1. 기본 브랜치에 커밋합니다.

이것이 제대로 작동했는지 확인하려면:

1. [새 이슈 생성](issues/create_issues.md) 또는 [새 에픽 생성](../group/epics/manage_epics.md#create-an-epic)을 수행합니다.
1. **템플릿 선택** 드롭다운 목록에서 설명 템플릿을 찾을 수 있는지 확인합니다.

## 머지 리퀘스트 템플릿 생성 {#create-a-merge-request-template}

이슈 템플릿과 유사하게 리포지토리의 `.gitlab/merge_request_templates/` 디렉터리 내에서 Markdown(`.md`) 파일을 새로 생성합니다. 이슈 템플릿과는 다르게 머지 리퀘스트는 커밋 메시지 및 브랜치 이름의 내용에 따라 달라지는 추가 상속 규칙이 있습니다. 자세한 내용은 [머지 리퀘스트 생성](merge_requests/creating_merge_requests.md)을 참조하세요.

프로젝트에 대한 머지 리퀘스트 설명 템플릿을 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **리포지토리**를 선택합니다.
1. 기본 브랜치 옆에서 {{< icon name="plus" >}}를 선택합니다.
1. **새 파일**을 선택합니다.
1. 기본 브랜치 옆의 **파일 이름** 텍스트 상자에 `.gitlab/merge_request_templates/mytemplate.md`를 입력합니다. 여기서 `mytemplate`는 머지 리퀘스트 템플릿의 이름입니다.
1. 기본 브랜치에 커밋합니다.

이것이 제대로 작동했는지 확인하려면 [새 머지 리퀘스트를 생성](merge_requests/creating_merge_requests.md)하고 **템플릿 선택** 드롭다운 목록에서 설명 템플릿을 찾을 수 있는지 확인합니다.

## 템플릿 사용 {#use-the-templates}

이슈 또는 머지 리퀘스트를 생성하거나 편집할 때 **템플릿 선택** 드롭다운 목록에 표시됩니다.

템플릿을 적용하려면:

1. 이슈, 작업 항목 또는 머지 리퀘스트를 생성하거나 편집합니다.
1. **템플릿 선택** 드롭다운 목록을 선택합니다.
1. **설명** 텍스트 상자가 비어있지 않으면 **템플릿 적용**을 선택하여 확인합니다.
1. **변경 사항 저장**을 선택합니다.

설명 템플릿을 선택하면 해당 내용이 설명 텍스트 상자로 복사됩니다.

템플릿을 선택한 후 설명에 대해 수행한 모든 변경 사항을 취소하려면 **템플릿 선택** 드롭다운 목록을 확장하고 **템플릿 재설정**을 선택합니다.

![이슈에서 설명 템플릿 선택합니다.](img/description_templates_v17_10.png)

> [!note]
> 지정된 템플릿을 사용하여 이슈를 생성하는 바로가기 링크를 생성할 수 있습니다. 예: `https://gitlab.com/gitlab-org/gitlab/-/work_items/new?description_template=Feature%20proposal`. [미리 채워진 값을 사용하여 URL에서 이슈 생성](issues/create_issues.md#using-a-url-with-prefilled-values)에 대해 자세히 알아보세요.

### 머지 리퀘스트 템플릿에서 지원되는 변수 {#supported-variables-in-merge-request-templates}

> [!note]
> 이 기능은 [기본 템플릿](#set-a-default-template-for-merge-requests-and-issues)에만 사용할 수 있습니다.

머지 리퀘스트를 처음 저장할 때 GitLab은 머지 리퀘스트 템플릿의 이 변수를 해당 값으로 바꿉니다:

| 변수                                | 설명                                                                                                                                                 | 출력 예시                                                                                                                                                                                   |
|-----------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `%{all_commits}`                        | 머지 리퀘스트의 모든 커밋의 메시지입니다. 가장 최근의 100개 커밋으로 제한됩니다. 100 KiB를 초과하는 커밋 본문 및 머지 커밋 메시지는 건너뜁니다.        | `* Feature introduced` <br><br> `This commit implements feature` <br> `Changelog:added` <br><br> `* Bug fixed` <br><br> `* Documentation improved` <br><br>`This commit introduced better docs.` |
| `%{closes_issue}`                       | 소스 브랜치 이름에서 추론되는 이슈에 대한 참조입니다(있는 경우). 프로젝트에 자동 이슈 마감이 해제된 경우 `Closes` 대신 `Related to`를 사용합니다. 템플릿이 이 변수를 사용하면 참조가 설명 끝에 추가되지 않습니다. | `Closes #123`                                                                                                                                                                    |
| `%{co_authored_by}`                     | `Co-authored-by` Git 커밋 트레일러 형식의 커밋 작성자 이름 및 이메일입니다. 머지 리퀘스트의 가장 최근의 100개 커밋의 작성자로 제한됩니다.         | `Co-authored-by: Zane Doe <zdoe@example.com>` <br> `Co-authored-by: Blake Smith <bsmith@example.com>`                                                                                            |
| `%{first_commit}`                       | 머지 리퀘스트 diff의 첫 번째 커밋의 전체 메시지입니다.                                                                                                     | `Update README.md`                                                                                                                                                                               |
| `%{first_multiline_commit}`             | 머지 커밋이 아니면서 메시지 본문에 두 개 이상의 줄이 있는 첫 번째 커밋의 전체 메시지입니다. 모든 커밋이 여러 줄이 아닌 경우 머지 리퀘스트 제목입니다. | `Update README.md` <br><br> `Improved project description in readme file.`                                                                                                                       |
| `%{first_multiline_commit_description}` | 머지 커밋이 아니면서 메시지 본문에 두 개 이상의 줄이 있는 첫 번째 커밋의 설명(첫 번째 줄/제목 제외)입니다.                        | `Improved project description in readme file.`                                                                                                                                                   |
| `%{source_branch}`                      | 병합되는 브랜치의 이름입니다.                                                                                                                        | `my-feature-branch`                                                                                                                                                                              |
| `%{target_branch}`                      | 변경 사항이 적용되는 브랜치의 이름입니다.                                                                                                     | `main`                                                                                                                                                                                           |

### 인스턴스 수준 설명 템플릿 설정 {#set-instance-level-description-templates}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이슈 및 머지 리퀘스트의 경우 [인스턴스 템플릿 리포지토리](../../administration/settings/instance_template_repository.md)를 사용하여 전체 인스턴스에 대한 설명 템플릿을 설정할 수 있습니다. 인스턴스 템플릿 리포지토리를 파일 템플릿에도 사용할 수 있습니다.

인스턴스에서 새 프로젝트를 생성할 때 사용할 수 있는 [프로젝트 템플릿](../../administration/project_templates.md)에도 관심이 있을 수 있습니다.

### 그룹 수준 설명 템플릿 설정 {#set-group-level-description-templates}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹의 설명 템플릿을 사용하면 템플릿을 저장할 그룹의 프로젝트를 선택할 수 있습니다. 그런 다음 그룹의 다른 프로젝트에서 이 템플릿에 액세스할 수 있습니다. 결과적으로 그룹의 모든 프로젝트의 이슈 및 머지 리퀘스트에 동일한 템플릿을 사용할 수 있습니다.

사전 요구 사항:

- 그룹의 Owner 역할이 있어야 합니다.
- 프로젝트는 그룹의 직계 자식이어야 합니다.

[생성한](#create-a-description-template) 템플릿을 다시 사용하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **텝플릿**을 확장합니다.
1. 드롭다운 목록에서 템플릿 프로젝트를 그룹의 템플릿 리포지토리로 선택합니다.
1. **변경 사항 저장**을 선택합니다.

![그룹 템플릿 설정입니다.](img/group_file_template_settings_v11_5.png)

그룹의 다양한 [파일 유형에 대한 템플릿](../group/manage.md#group-file-templates)에도 관심이 있을 수 있습니다.

### 머지 리퀘스트 및 이슈에 대한 기본 템플릿 설정 {#set-a-default-template-for-merge-requests-and-issues}

프로젝트에서 새로운 이슈 및 머지 리퀘스트에 대한 기본 설명 템플릿을 선택할 수 있습니다. 결과적으로 새로운 머지 리퀘스트 또는 이슈가 생성될 때마다 템플릿에 입력한 텍스트로 미리 채워집니다.

사전 요구 사항:

- 프로젝트의 왼쪽 사이드바에서 **설정** > **일반**을 선택하고 **표시 여부, 프로젝트 기능, 권한**을 확장합니다. 이슈 또는 머지 리퀘스트가 **모든 사용자(액세스 권한 있음)** 또는 **프로젝트 멤버만**으로 설정되어 있는지 확인합니다.

머지 리퀘스트에 대한 기본 설명 템플릿을 설정하려면 다음 중 하나를 수행합니다:

- [머지 리퀘스트 템플릿 생성](#create-a-merge-request-template)(대소문자 구분 안 함)을 `Default.md` 이름으로 하여 `.gitlab/merge_request_templates/`에 저장합니다. `Default.md` 템플릿은 프로젝트 설정에서 설정된 기본 템플릿보다 우선하지 않습니다. 자세한 내용은 [기본 설명 템플릿의 우선순위](#priority-of-default-description-templates)를 참조하세요.
- GitLab Premium 및 Ultimate 사용자: 프로젝트 설정에서 기본 템플릿을 설정합니다:

  1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
  1. **설정** > **머지 리퀘스트**를 선택합니다.
  1. **머지 리퀘스트에 대한 기본 설명 템플릿** 섹션에서 텍스트 영역을 채웁니다.
  1. **변경 사항 저장**을 선택합니다.

작업 항목에 대한 기본 설명을 설정하려면 다음 중 하나를 수행합니다:

- [설명 템플릿 생성](#create-a-description-template)(대소문자 구분 안 함)을 `Default.md` 이름으로 하여 `.gitlab/issue_templates/`에 저장합니다. `Default.md` 템플릿은 프로젝트 설정에서 설정된 기본 설명보다 우선하지 않습니다. 자세한 내용은 [기본 설명 템플릿의 우선순위](#priority-of-default-description-templates)를 참조하세요.
- GitLab Premium 및 Ultimate 사용자: 프로젝트 설정에서 기본 템플릿을 설정합니다:

  1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
  1. **설정** > **일반**을 선택합니다.
  1. **작업 항목에 대한 설명 기본값**을 확장합니다.
  1. 텍스트 영역을 채웁니다.
  1. **변경 사항 저장**을 선택합니다.

GitLab 머지 리퀘스트 및 이슈는 [Markdown](../markdown.md)을 지원하므로 이를 사용하여 제목 및 목록과 같은 텍스트 형식을 지정할 수 있습니다.

[Projects REST API](../../api/projects.md)에서 `issues_template` 및 `merge_requests_template` 속성을 제공하여 기본 이슈 및 머지 리퀘스트 템플릿을 최신 상태로 유지할 수 있습니다.

#### 기본 설명 템플릿의 우선순위 {#priority-of-default-description-templates}

다양한 위치에서 [이슈 설명 템플릿](#set-a-default-template-for-merge-requests-and-issues)을 설정할 때 프로젝트에서 다음 우선순위를 갖습니다. 높은 위치의 항목이 낮은 위치의 항목을 재정의합니다:

1. 프로젝트 설정에서 설정된 템플릿입니다.
1. 상위 그룹의 `Default.md`(대소문자 구분 안 함)입니다.
1. 프로젝트 리포지토리의 `Default.md`(대소문자 구분 안 함)입니다.

머지 리퀘스트에는 커밋 메시지 및 브랜치 이름의 내용에 따라 달라지는 [추가 상속 규칙](merge_requests/creating_merge_requests.md)이 있습니다.

## 예제 설명 템플릿 {#example-description-template}

예제를 보려면 GitLab 프로젝트의 [`.gitlab` 폴더](https://gitlab.com/gitlab-org/gitlab/-/tree/master/.gitlab)에서 이슈 및 머지 리퀘스트의 설명 템플릿을 참조하세요.

> [!note]
> 설명 템플릿에서 [빠른 작업](quick_actions.md)을 사용하여 레이블, 담당자 및 마일스톤을 빠르게 추가할 수 있습니다. 빠른 작업은 이슈 또는 머지 리퀘스트를 제출하는 사용자가 관련 작업을 수행할 수 있는 권한이 있는 경우에만 실행됩니다.

다음은 버그 보고서 템플릿의 예입니다:

```markdown
## Summary

<!-- HTML comments are not displayed -->
(Summarize the bug encountered concisely)

## Steps to reproduce

(How one can reproduce the issue - this is very important)

## Example Project

(If possible, create an example project here on GitLab.com that exhibits the problematic
behavior, and link to it here in the bug report.
If you are using an older version of GitLab, this will also determine whether the bug has been fixed
in a more recent version)

## What is the current bug behavior?

(What actually happens)

## What is the expected correct behavior?

(What you should see instead)

## Relevant logs and/or screenshots

(Paste any relevant logs - use code blocks (```) to format console output, logs, and code, as
it's very hard to read otherwise.)

## Possible fixes

(If you can, link to the line of code that might be responsible for the problem)

/label ~bug ~reproduced ~needs-investigation
/cc @project-manager
/assign @qa-tester
```
