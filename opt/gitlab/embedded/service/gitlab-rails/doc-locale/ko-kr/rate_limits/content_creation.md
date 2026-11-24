---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "이슈, 에픽, 노트 생성에 대한 속도 제한을 구성합니다."
title: 콘텐츠 생성 속도 제한
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

속도 제한은 사용자가 이슈, 에픽, 노트를 생성할 수 있는 속도를 제어합니다.

## 이슈 및 에픽 생성 {#issue-and-epic-creation}

[에픽](../user/group/epics/_index.md) 생성의 제한은 이슈 생성에 적용되는 제한과 동일합니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

이슈 및 에픽 생성 엔드포인트에 대한 요청 수를 제한하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **Issues Rate Limits**를 확장합니다.
1. **Max requests per minute** 아래에 새 값을 입력합니다.
1. **변경 사항 저장**을 선택합니다.

속도 제한:

- 프로젝트당 및 사용자당 독립적으로 적용됩니다.
- IP 주소당 적용되지 않습니다.
- 기본적으로 비활성화됩니다.
- 속도 제한을 비활성화하려면 `0`로 설정할 수 있습니다.

속도 제한을 초과하는 요청은 `auth.log` 파일에 기록됩니다.

예를 들어 제한을 `300`로 설정하면 분당 300을 초과하는 요청이 차단됩니다. 엔드포인트에 대한 액세스는 1분 후에 사용 가능합니다.

## 노트 생성 {#note-creation}

노트 생성 엔드포인트에 대한 요청의 속도 제한을 구성할 수 있습니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

노트 생성 속도 제한을 변경하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **Notes rate limit**을 확장합니다.
1. **분당 최대 요청** 상자에 새 값을 입력합니다.
1. 선택사항. **속도 제한에서 제외할 사용자** 상자에 제한을 초과할 수 있도록 허용된 사용자를 나열합니다.
1. **변경 사항 저장**을 선택합니다.

속도 제한:

- 사용자당 독립적으로 적용됩니다.
- IP 주소당 적용되지 않습니다.
- 기본값은 `300`입니다.

속도 제한을 초과하는 요청은 `auth.log` 파일에 기록됩니다.

예를 들어 제한을 `300`로 설정하면 분당 300을 초과하는 요청이 차단됩니다. 엔드포인트에 대한 액세스는 1분 후에 사용 가능합니다.

## 관련 항목 {#related-topics}

- [속도 제한](_index.md)
- [구성 불가능한 속도 제한](non_configurable.md)
