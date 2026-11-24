---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Unify Circuit
description: "Unify Circuit 대화로 이벤트 알림을 보내도록 GitLab을 구성합니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Unify Circuit 통합은 GitLab에서 Circuit 대화로 알림을 보냅니다.

## Unify Circuit 설정 {#set-up-unify-circuit}

Unify Circuit에서 [웹후크 추가](https://www.circuit.com/unifyportalfaqdetail?articleId=164448)를 한 다음 URL을 복사합니다.

GitLab에서:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Unify Circuit**을 선택합니다.
1. **활성** 토글을 켭니다.
1. Unify Circuit에서 받고 싶은 GitLab 이벤트에 해당하는 체크박스를 선택합니다.
1. Unify Circuit 구성 단계에서 복사한 **Webhook URL**을 붙여 넣습니다.
1. **잘못된 파이프라인만 알림 받기** 체크박스를 선택하여 실패 시에만 알림을 받습니다.
1. **상태 변경 시에만 알림** 체크박스를 선택하여 ref의 파이프라인 상태가 변경될 때만 알림을 보냅니다.
1. **알림을 보내야 할 브랜치** 드롭다운 목록에서 알림을 보낼 브랜치 유형을 선택합니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

이제 Unify Circuit 대화가 GitLab 이벤트 알림을 받기 시작합니다.
