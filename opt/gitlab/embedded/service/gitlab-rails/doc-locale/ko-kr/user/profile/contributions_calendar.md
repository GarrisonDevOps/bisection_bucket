---
stage: Software Supply Chain Security
group: Authentication
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 기여도 달력
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

기여도 달력에는 지난 12개월 동안의 [사용자 이벤트](#user-contribution-events)가 표시됩니다. 여기에는 포크된 리포지토리 및 [비공개](#show-private-contributions-on-your-user-profile-page) 리포지토리에서 수행한 기여가 포함됩니다.

![기여도 달력](img/contributions_calendar_v15_6.png)

타일의 그래디언트 색상은 하루에 수행한 기여도의 수를 나타냅니다. 그래디언트는 공백(기여도 0)에서 진파란색(기여도 30개 이상)까지입니다.

> [!note]
> 기여도 달력에는 지난 12개월의 기여만 표시되지만, 이슈 [24264](https://gitlab.com/gitlab-org/gitlab/-/issues/24264)에서는 이를 12개월 이상으로 변경할 것을 제안합니다. 사용자 프로필에 대한 일반적인 개선 사항은 이슈 [8488](https://gitlab.com/groups/gitlab-org/-/epics/8488)에서 제안됩니다.

모든 그룹 멤버의 기여 이벤트에 대한 포괄적인 보기를 보려면 [기여도 분석](../group/contribution_analytics/_index.md)을 사용할 수 있습니다.

## 사용자 기여 이벤트 {#user-contribution-events}

GitLab은 다음 기여 이벤트를 추적합니다:

| 이벤트 | 기여 |
| ----- | ------------ |
| `approved` | 머지 리퀘스트 |
| `closed` | [에픽](../group/epics/_index.md), 이슈, 머지 리퀘스트, 마일스톤, 작업 항목 |
| `commented` 모든 `Noteable` 레코드에서. | 경고, 커밋, 디자인, 이슈, 머지 리퀘스트, 스니펫 |
| `created` | 디자인, 에픽, 이슈, 머지 리퀘스트, 마일스톤, 프로젝트, 위키 페이지, 작업 항목 |
| `destroyed` | 디자인, 마일스톤, 위키 페이지 |
| `expired` | 프로젝트 멤버십 |
| `joined` | 프로젝트 멤버십 |
| `left` | 프로젝트 멤버십 |
| `merged` | 머지 리퀘스트 |
| 리포지토리에 `pushed` 커밋을 개별적으로 또는 일괄적으로 수행합니다. | 프로젝트 |
| `reopened` | 에픽, 이슈, 머지 리퀘스트, 마일스톤 |
| `updated` | 디자인, 위키 페이지 |

### 일일 기여도 보기 {#view-daily-contributions}

일일 기여도를 보려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. 드롭다운 목록에서 이름을 선택합니다.
1. 기여도 달력에서:
   - 특정 날짜의 기여도 수를 보려면 타일 위로 마우스를 이동합니다.
   - 특정 날짜의 모든 기여를 보려면 타일을 선택합니다. 목록에는 모든 기여와 작성된 시간이 표시됩니다.

### 사용자 프로필 페이지에 비공개 기여 표시 {#show-private-contributions-on-your-user-profile-page}

기여도 달력 그래프 및 최근 활동 목록에는 비공개 프로젝트에 대한 [기여 작업](#user-contribution-events)이 표시됩니다.

비공개 기여를 보려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. **주요 설정** 섹션에서 **내 프로필에 비공개 기여 포함** 확인란을 선택합니다.
1. **프로필 설정 업데이트**를 선택합니다.

## 사용자 활동 {#user-activity}

### 사용자의 활동 팔로우 {#follow-a-users-activity}

관심 있는 사용자의 활동을 팔로우할 수 있습니다. 팔로우할 수 있는 최대 사용자 수는 300명입니다.

사용자를 팔로우하려면 다음 중 하나를 수행합니다:

- 사용자의 프로필에서 **팔로우**를 선택합니다.
- 사용자 이름을 마우스로 가리킨 다음 **팔로우**를 선택합니다.

팔로우하는 사용자의 활동을 보려면:

1. GitLab 메뉴에서 **활동**을 선택합니다.
1. **팔로우한 사용자** 탭을 선택합니다.

### 사용자 활동을 피드로 검색 {#retrieve-user-activity-as-a-feed}

GitLab은 사용자 활동의 RSS 피드를 제공합니다. 사용자의 활동 RSS 피드를 구독하려면:

1. [사용자 프로필](_index.md#access-your-user-profile)로 이동합니다.
1. 오른쪽 위 모서리에서 피드 기호({{< icon name="rss" >}})를 선택합니다.

결과의 URL에는 피드 토큰과 보기 권한이 있는 사용자의 활동이 포함됩니다. 이 URL을 피드 리더에 추가할 수 있습니다.

### 사용자 활동 피드 토큰 재설정 {#reset-the-user-activity-feed-token}

피드 토큰은 민감하며 기밀 이슈의 정보를 공개할 수 있습니다. 피드 토큰이 노출되었다고 생각되면 재설정해야 합니다.

피드 토큰을 재설정하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **개인 액세스 토큰**을 선택합니다.
1. 아래로 스크롤합니다. **피드 토큰** 섹션에서 **이 토큰 재설정** 링크를 선택합니다.
1. 확인 대화 상자에서 **확인**을 선택합니다.

새 토큰이 생성됩니다.

### 이벤트 시간 기간 제한 {#event-time-period-limit}

GitLab은 성능상의 이유로 이벤트 테이블에서 3년 이상 된 사용자 활동 이벤트를 제거합니다.
