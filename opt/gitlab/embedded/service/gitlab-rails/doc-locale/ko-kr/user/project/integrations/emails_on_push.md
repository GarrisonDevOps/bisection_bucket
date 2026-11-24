---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 푸시에 이메일 알림
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

푸시에 이메일 알림을 사용하여 GitLab 프로젝트에 푸시된 변경 사항에 대한 이메일 알림을 받으세요. 이러한 알림을 트리거하는 푸시 이벤트를 선택할 수 있습니다.

푸시에 이메일 알림을 사용하면 각 푸시에 대해 커밋과 비교 사항을 받을 이메일 주소 목록을 지정할 수 있습니다.

## 통합 설정 {#set-up-the-integration}

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

푸시에 이메일 알림을 설정하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **푸시에 이메일 알림**을 선택하세요.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. **수신자**에 공백 또는 줄 바꿈으로 구분된 이메일 주소 목록을 입력하세요. 유효하지 않은 이메일 주소는 자동으로 필터링되며 알림을 받지 않습니다.
1. 다음 옵션을 구성하세요:

   - **푸시 이벤트** \- 푸시 이벤트가 수신되면 이메일이 발송됩니다.
   - **태그 푸시 이벤트** \- 태그가 생성되어 푸시될 때 이메일이 발송됩니다.
   - **커미터가 보냄** \- GitLab 인스턴스에서 사용하는 도메인과 도메인이 일치하는 경우 커미터의 이메일 주소에서 알림을 보냅니다. (예: `user@gitlab.com`)
   - **코드 비교(diff) 비활성화** \- 알림 본문에 민감한 코드 비교 사항을 포함하지 않습니다.
