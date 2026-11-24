---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 이슈
description: "작업, 버그 보고서, 기능 요청 및 추적."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이슈를 통해 팀과 협력하여 GitLab에서 작업을 계획, 추적 및 전달할 수 있습니다. 이슈:

- 기능 제안, 작업, 지원 요청 및 버그 보고서를 추적합니다.
- 담당자, 마감일 및 상태를 통해 작업을 구성하고 우선순위를 정합니다.
- 댓글 및 스레드 토론을 통해 팀 토론 및 의사 결정을 촉진합니다.
- 템플릿, 레이블, 에픽 및 보드를 통해 사용자 지정 워크플로우를 지원합니다.
- Zoom, Jira 및 이메일 서비스와 같은 외부 도구와 통합합니다.

이슈는 항상 특정 프로젝트와 연결됩니다. 그룹에 여러 프로젝트가 있으면 모든 프로젝트의 이슈를 한 번에 볼 수 있습니다.

<div class="video-fallback">
  동영상 보기:  <a href="https://www.youtube.com/watch?v=Mt1EzlKToig">이슈 - GitLab으로 조직 설정하기</a>.
</div>
<figure class="video-container">
  <iframe src="https://www.youtube-nocookie.com/embed/Mt1EzlKToig" frameborder="0" allowfullscreen> </iframe>
</figure>
<!-- Video published on 2023-10-30 -->

<i class="fa-youtube-play" aria-hidden="true"></i> GitLab 전략 마케팅 부서가 [레이블](../labels.md) 및 [이슈 보드](../issue_board.md)로 GitLab 이슈를 사용하는 방법을 알아보려면 [이슈로 약속 관리](https://www.youtube.com/watch?v=cuIHNintg1o&t=3) 동영상을 참조하세요.
<!-- Video published on 2020-04-10 -->

## 작업 항목으로서의 이슈 {#issues-as-work-items}

{{< history >}}

- GitLab 17.5에서 `work_items_view_preference`라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/groups/gitlab-org/-/epics/9584)되었습니다. 기본적으로 비활성화되었습니다. 이 기능은 [베타](../../../policy/development_stages_support.md#beta) 단계입니다.
- 기능 플래그 `work_items_view_preference`이 GitLab 17.9에서 사용자 집단을 위해 GitLab.com에서 활성화되었습니다.
- 기능 플래그 `work_items_view_preference`이 17.10에서 GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 [활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/184496)되었습니다.
- [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/482931) (GitLab 17.11).
- GitLab 18.1에서 기능 플래그 `work_item_view_for_issues`로 [이동](https://gitlab.com/gitlab-org/gitlab/-/issues/482931)되었습니다. GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화되었습니다. `work_items_view_preference` 기능 플래그가 제거되었습니다.
- 프로젝트의 이슈 페이지에 추가 필터가 GitLab 18.4에서 [소개](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/198544)되었습니다. [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 사용으로 설정되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/204139).
- 그룹의 이슈 페이지에 추가 필터가 GitLab 18.5에서 [소개](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/202089)되었습니다. [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 사용으로 설정되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/205308).
- GitLab 18.7에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/520791)합니다. `work_item_view_for_issues` 기능 플래그가 제거되었습니다.

{{< /history >}}

이슈는 GitLab Agile Planning 제공 서비스의 제품 요구 사항을 더 잘 충족하기 위해 작업 항목을 위한 통합 프레임워크로 이동되었습니다.

자세한 내용은 [에픽 9290](https://gitlab.com/groups/gitlab-org/-/work_items/9290) 및 [GitLab의 새로운 애자일 계획 환경](https://about.gitlab.com/blog/first-look-the-new-agile-planning-experience-in-gitlab/) 블로그 게시물(2024년 6월)을 참조하세요.

이 변경을 시도하는 동안 문제가 발생하면 [피드백 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/523713)를 사용하여 자세한 내용을 제공할 수 있습니다.

### 작업 항목 마크다운 참조 {#work-item-markdown-reference}

{{< history >}}

- GitLab 18.1에서 `extensible_reference_filters` [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/352861)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.2에서 [정식 출시](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197052)되었습니다. `extensible_reference_filters` 기능 플래그가 제거되었습니다.

{{< /history >}}

GitLab Flavored Markdown 필드에서 `[work_item:123]`으로 작업 항목을 참조할 수 있습니다. 자세한 내용은 [GitLab 특정 참조](../../markdown.md#gitlab-specific-references)를 참조하세요.

## 관련 항목 {#related-topics}

- [이슈 생성](create_issues.md)
- [템플릿에서 이슈 생성](../description_templates.md#use-the-templates)
- [이슈 편집](managing_issues.md#edit-an-issue)
- [이슈 이동](managing_issues.md#move-an-issue)
- [이슈 닫기](managing_issues.md#close-an-issue)
- [이슈 삭제](managing_issues.md#delete-an-issue)
- [이슈를 에픽으로 승격](managing_issues.md#promote-an-issue-to-an-epic)
- [마감일 설정](due_dates.md)
- [이슈 가져오기](csv_import.md)
- [이슈 내보내기](csv_export.md)
- [이슈에 디자인 업로드](design_management.md)
- [연결된 이슈](related_issues.md)
- [유사한 이슈](managing_issues.md#similar-issues)
- [상태](managing_issues.md#health-status)
- [이슈 상호 연결](crosslinking_issues.md)
- [이슈 목록 정렬](sorting_issue_lists.md)
- [이슈 검색](managing_issues.md#filter-the-list-of-issues)
- [에픽](../../group/epics/_index.md)
- [이슈 보드](../issue_board.md)
- [이슈 API](../../../api/issues.md)
- [외부 이슈 추적기 구성](../../../integration/external-issue-tracker.md)
- [태스크](../../tasks.md)
- [이슈에서 작업의 개수 및 가중치 보기](../../tasks.md#view-count-and-weight-of-tasks-in-the-parent-issue)
- [하위 작업이 있는 이슈의 진행률 보기](../../tasks.md#view-progress-of-the-parent-issue)
- [외부 참여자](../service_desk/external_participants.md)
