---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Confluence 작업공간
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Confluence Cloud 워크스페이스를 프로젝트 위키로 사용합니다.

이 통합은 [GitLab 위키](../wiki/_index.md) 대신 Confluence 위키에 대한 링크를 추가합니다. GitLab은 Confluence 콘텐츠를 표시하지 않습니다.

통합을 설정하면:

- 왼쪽 사이드바에 새로운 메뉴 항목이 추가됩니다: **계획** > **Confluence**. Confluence 위키에 연결됩니다.
- **계획** > **위키** 메뉴 항목이 숨겨집니다.

  프로젝트의 GitLab 위키에 액세스하려면 해당 URL을 사용합니다: `<example_project_URL>/-/wikis/home`. **계획** > **위키** 메뉴 항목을 다시 표시하려면 이 통합을 해제합니다.

Confluence Cloud와의 보다 포괄적인 통합은 [에픽 3629](https://gitlab.com/groups/gitlab-org/-/epics/3629)에서 추적됩니다.

## 통합 설정 {#set-up-the-integration}

이 통합은 프로젝트나 그룹 또는 인스턴스의 모든 프로젝트에서 활성화할 수 있습니다.

### 프로젝트 또는 그룹의 모든 프로젝트 {#for-your-project-or-all-projects-in-a-group}

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.
- Confluence Cloud URL(`https://example.atlassian.net/wiki/`)을 사용해야 합니다.

프로젝트 또는 그룹에 대한 통합을 설정하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Confluence 작업공간** 옆에서 **구성**을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. **Confluence 작업 공간 URL**에 Confluence 워크스페이스 URL을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

그룹에 대해 통합이 활성화된 경우에도 개별 프로젝트에 대해 해제할 수 있습니다.

### 인스턴스의 모든 프로젝트 {#for-all-projects-on-the-instance}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

사전 요구 사항:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.
- Confluence Cloud URL(`https://example.atlassian.net/wiki/`)을 사용해야 합니다.

인스턴스에 대한 통합을 설정하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Confluence 작업공간** 옆에서 **구성**을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. **Confluence 작업 공간 URL**에 Confluence 워크스페이스 URL을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

## GitLab에서 Confluence 작업공간에 액세스 {#access-your-confluence-workspace-from-gitlab}

사전 요구 사항:

- [프로젝트 또는 그룹](#for-your-project-or-all-projects-in-a-group)이나 [인스턴스](#for-all-projects-on-the-instance)에 대해 통합을 설정해야 합니다.

GitLab 프로젝트에서 Confluence 작업공간에 액세스하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **계획** > **Confluence**를 선택합니다.
1. **Confluence로 이동**을 선택합니다.
