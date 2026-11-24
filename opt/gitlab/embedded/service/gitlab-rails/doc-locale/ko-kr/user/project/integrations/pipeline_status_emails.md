---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 파이프라인 상태 이메일
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹 또는 프로젝트의 파이프라인 상태 변경 사항에 대한 알림을 이메일 주소 목록으로 전송할 수 있습니다.

차단된 사용자로 인해 트리거되는 파이프라인 알림은 전달되지 않습니다.

## 파이프라인 상태 이메일 알림 활성화 {#enable-pipeline-status-email-notifications}

사전 요구 사항:

- 프로젝트의 Maintainer 또는 Owner 역할이거나 그룹의 Owner 역할이 필요합니다.

파이프라인 상태 이메일을 활성화하려면:

1. 프로젝트 또는 그룹의 왼쪽 사이드바에서 **설정** > **연동**을 선택하세요.
1. **파이프라인 상태 이메일**을 선택하세요.
1. **활성** 체크박스가 선택되어 있는지 확인하세요.
1. **수신자**에 쉼표로 구분된 이메일 주소 목록을 입력하세요. 유효하지 않은 이메일 주소는 자동으로 필터링되며 알림을 받지 않습니다.
1. 선택 사항. 잘못된 파이프라인만 알림을 받으려면 **잘못된 파이프라인만 알림 받기**를 선택하세요.
1. 선택 사항. 파이프라인 상태가 변경될 때만 알림을 받으려면 **상태가 변경될 때만 알림**을 선택하세요.
1. 선택 사항. 상위 및 하위 파이프라인에 대한 알림을 받으려면 **하위 파이프라인 알림**을 선택하세요.
1. 알림을 보낼 브랜치를 선택하세요.
1. **변경 사항 저장**을 선택합니다.
