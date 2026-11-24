---
stage: Growth
group: Engagement
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Matrix
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 17.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/)되었습니다.

{{< /history >}}

GitLab을 구성하여 Matrix 룸으로 알림을 보낼 수 있습니다.

## GitLab에서 Matrix 통합 설정 {#set-up-the-matrix-integration-in-gitlab}

사전 요구 사항:

- 인스턴스 활성화를 위한 관리자 액세스입니다.
- 그룹 활성화를 위한 소유자 역할입니다.
- 프로젝트 활성화를 위한 유지 관리자 또는 소유자 역할입니다.

Matrix 방에 참여한 후 GitLab을 구성하여 알림을 보낼 수 있습니다:

1. 통합을 활성화하려면:
   - **그룹 또는 프로젝트**:
     1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
     1. **설정** > **연동**을 선택합니다.
   - **인스턴스**:
     1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
     1. **설정** > **연동**을 선택합니다.
1. **Matrix**를 선택하세요.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. 선택 사항. **호스트 이름**에 서버의 호스트 이름을 입력하세요.
1. **토큰**에 Matrix 사용자의 토큰 값을 붙여 넣으세요.
1. **트리거** 섹션에서 Matrix에서 받을 GitLab 이벤트에 대한 체크박스를 선택하세요.
1. **알림 설정** 섹션:
   - **방 식별자**에 Matrix 방 식별자를 붙여 넣으세요.
   - 선택 사항. **잘못된 파이프라인만 알림 받기** 체크박스를 선택하여 실패한 파이프라인에 대한 알림만 받으세요.
   - 선택 사항. **상태 변경 시에만 알림** 체크박스를 선택하여 ref에 대한 파이프라인 상태가 변경될 때만 알림을 받으세요.
   - 선택 사항. **알림을 보내야 할 브랜치** 드롭다운 목록에서 알림을 받을 브랜치를 선택하세요.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

이제 Matrix 방이 선택한 모든 GitLab 이벤트를 받을 수 있습니다.
