---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Engineering Workflow Management (EWM)
description: 머지 리퀘스트 및 커밋 메시지에서 언급된 EWM 작업 항목을 연결하도록 Engineering Workflow Management (EWM) 통합을 구성합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

EWM 통합을 사용하면 머지 리퀘스트 설명 및 커밋 메시지에서 언급된 EWM 작업 항목으로 GitLab에서 이동할 수 있습니다. 각 작업 항목 참조는 자동으로 작업 항목에 대한 링크로 변환됩니다.

이 IBM 제품은 [이전에 Rational Team Concert (RTC)로 명명되었습니다](https://jazz.net/blog/index.php/2019/04/23/renaming-the-ibm-continuous-engineering-portfolio/). 이 통합은 RTC 및 EWM의 모든 버전과 호환됩니다.

프로젝트에서 EWM 통합을 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **EWM**을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. 필수 필드를 입력합니다:

   - **프로젝트 URL**: EWM 프로젝트 영역의 URL입니다.

     프로젝트 영역 URL을 얻으려면 `/ccm/web/projects` 경로로 이동하여 나열된 프로젝트의 URL을 복사합니다. 예를 들어, `https://example.com/ccm/web/Example%20Project`입니다.
   - **이슈 URL**: EWM 프로젝트 영역의 작업 항목 편집기로의 URL입니다.

     형식은 `<your-server-url>/resource/itemName/com.ibm.team.workitem.WorkItem/:id`입니다. GitLab은 `:id`를 이슈 번호로 바꿉니다 (예: `https://example.com/ccm/resource/itemName/com.ibm.team.workitem.WorkItem/:id`, 이는 `https://example.com/ccm/resource/itemName/com.ibm.team.workitem.WorkItem/123`가 됩니다).
   - **새 이슈 URL**: EWM 프로젝트 영역에서 새 작업 항목을 생성하는 URL입니다.

     프로젝트 영역 URL에 다음 조각을 추가합니다: `#action=com.ibm.team.workitem.newWorkItem`. 예를 들어, `https://example.com/ccm/web/projects/JKE%20Banking#action=com.ibm.team.workitem.newWorkItem`입니다.

1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 커밋 메시지에서 EWM 작업 항목 참조 {#reference-ewm-work-items-in-commit-messages}

작업 항목을 참조하려면 EWM Git Integration Toolkit에서 지원하는 모든 키워드를 사용할 수 있습니다. 다음 형식을 사용합니다: `<keyword> <id>`.

다음 키워드를 사용할 수 있습니다:

- `bug`
- `defect`
- `rtcwi`
- `task`
- `work item`
- `workitem`

키워드 `#`를 사용하지 마세요. 자세한 내용은 [커밋 메모에서 링크 생성](https://www.ibm.com/docs/en/elm/7.0.0?topic=commits-creating-links-from-commit-comments)을 참조하세요.
