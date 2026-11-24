---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 이슈와 Zoom 회의를 연결하기
description: /zoom 빠른 작업을 사용하여 이슈와 Zoom 회의를 연결하면 팀 구성원이 신속하게 통화에 참여할 수 있습니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

장애 관리를 위해 실시간으로 통신하려면 이슈와 Zoom 회의를 연결할 수 있습니다. 긴급 상황 대응을 위해 Zoom 통화를 시작한 후에는 해당 통화를 이슈와 연결하는 방법이 필요합니다. 이렇게 하면 팀 구성원이 링크를 요청하지 않고 신속하게 참여할 수 있습니다.

## 이슈에 Zoom 회의 추가 {#adding-a-zoom-meeting-to-an-issue}

이슈와 Zoom 회의를 연결하려면 [`/zoom` 빠른 작업](../quick_actions.md#zoom)을 사용할 수 있습니다.

이슈에서 `/zoom` 빠른 작업을 사용하여 댓글을 남기고 유효한 Zoom 링크를 입력하세요:

```shell
/zoom https://zoom.us/j/123456789
```

Zoom 회의 URL이 유효하고 Reporter, Developer, Maintainer 또는 Owner 역할이 있으면 시스템 알림이 성공적으로 추가되었음을 알려줍니다. 이슈의 설명이 자동으로 수정되어 Zoom 링크가 포함되며, 이슈 제목 바로 아래에 버튼이 나타납니다.

![Zoom 회의 참여 버튼을 표시하는 GitLab 이슈 보기.](img/zoom_quickaction_button_v16_6.png)

이슈에는 하나의 Zoom 회의만 첨부할 수 있습니다. `/zoom` 빠른 작업을 사용하여 두 번째 Zoom 회의를 추가하려고 하면 작동하지 않습니다. 먼저 [제거](#removing-an-existing-zoom-meeting-from-an-issue)해야 합니다.

GitLab Premium 및 Ultimate 사용자는 [incident에 여러 Zoom 링크를 추가](../../../operations/incident_management/linked_resources.md#link-zoom-meetings-from-an-incident)할 수도 있습니다.

## 이슈에서 기존 Zoom 회의 제거 {#removing-an-existing-zoom-meeting-from-an-issue}

Zoom 회의를 추가하는 것과 마찬가지로 빠른 작업으로 제거할 수 있습니다:

```shell
/remove_zoom
```

[`/remove_zoom` 빠른 작업](../quick_actions.md#remove_zoom)을 사용할 수도 있습니다.

Reporter, Developer, Maintainer 또는 Owner 역할이 있으면 시스템 알림이 회의 URL이 성공적으로 제거되었음을 알려줍니다.
