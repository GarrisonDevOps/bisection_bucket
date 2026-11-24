---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 감사 이벤트 API의 속도 제한
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 19.4에서 인스턴스 감사 이벤트 API를 위해 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/248055).
- GitLab 19.5에서 프로젝트 감사 이벤트 API를 위해 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253781).
- GitLab 19.5에서 그룹 감사 이벤트 API를 위해 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/255336).

{{< /history >}}

3개의 API에 대한 요청의 속도 제한을 구성할 수 있습니다:

- [인스턴스 감사 이벤트 API](../../api/audit_events.md#instance-audit-events). 속도 제한은 분당 사용자당입니다. 기본값은 200입니다.
- [그룹 감사 이벤트 API](../../api/audit_events.md#group-audit-events). 속도 제한은 분당 사용자당 그룹당입니다. 기본값은 200입니다.
- [프로젝트 감사 이벤트 API](../../api/audit_events.md#project-audit-events). 속도 제한은 분당 사용자당 프로젝트당입니다. 기본값은 200입니다.

이러한 속도 제한을 초과하는 요청은 `429 Too Many Requests` 상태 코드를 반환하며 `auth.log` 파일에 기록됩니다.

- 인스턴스 감사 이벤트 API 속도 제한은 `GET /audit_events`과 `GET /audit_events/:id` 모두에 적용됩니다.
- 그룹 감사 이벤트 API 속도 제한은 `GET /groups/:id/audit_events`과 `GET /groups/:id/audit_events/:audit_event_id` 모두에 적용됩니다.
- 프로젝트 감사 이벤트 API 속도 제한은 `GET /projects/:id/audit_events`과 `GET /projects/:id/audit_events/:audit_event_id` 모두에 적용됩니다.

예를 들어 200의 제한을 설정하면, 1분 내에 200의 속도를 초과하는 이러한 엔드포인트에 대한 요청이 차단됩니다. 1분 후 액세스가 복구됩니다.

## 속도 제한 변경 {#change-the-rate-limits}

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

속도 제한을 변경하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **감사 이벤트 API 속도 제한**을 펼칩니다.
1. 업데이트하려는 속도 제한의 값을 변경합니다. 속도 제한을 비활성화하려면 값을 `0`로 설정합니다.
1. **변경 사항 저장**을 선택합니다.
