---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab에서 더 이상 사용되지 않는 API에 대한 제한을 정의합니다.
gitlab_dedicated: yes
title: 더 이상 사용되지 않는 API 속도 제한
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

더 이상 사용되지 않는 API 엔드포인트는 대체 기능으로 바뀌었지만 이전 버전과의 호환성을 손상시키지 않고는 제거할 수 없습니다. 사용자가 대체 기능으로 전환하도록 유도하려면 더 이상 사용되지 않는 엔드포인트에 제한적인 속도 제한을 설정합니다.

## 더 이상 사용되지 않는 API 엔드포인트 {#deprecated-api-endpoints}

이 속도 제한은 모든 더 이상 사용되지 않는 API 엔드포인트를 포함하지는 않으며, 성능에 영향을 미칠 가능성이 있는 엔드포인트만 포함합니다:

- [`GET /groups/:id`](../../api/groups.md#retrieve-a-group) - `with_projects=0` 쿼리 매개변수 제외.

## 더 이상 사용되지 않는 API 속도 제한 정의 {#define-deprecated-api-rate-limits}

더 이상 사용되지 않는 API 엔드포인트에 대한 속도 제한은 기본적으로 비활성화됩니다. 활성화되면 더 이상 사용되지 않는 엔드포인트에 대한 요청의 일반 사용자 및 IP 속도 제한을 재정의합니다. 기존의 일반 사용자 및 IP 속도 제한을 유지하면서 더 이상 사용되지 않는 API 엔드포인트에 대한 속도 제한을 증가하거나 감소시킬 수 있습니다. 이 재정의로 인해 다른 새로운 기능은 제공되지 않습니다.

전제 조건:

- 인스턴스에 대한 관리자 액세스 권한이 있어야 합니다.

더 이상 사용되지 않는 API 엔드포인트에 대한 요청의 일반 사용자 및 IP 속도 제한을 재정의하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **네트워크**를 선택합니다.
1. **더 이상 사용되지 않는 API 속도 제한**을 확장합니다.
1. 활성화할 속도 제한 유형에 대한 확인란을 선택합니다:
   - **인증되지 않은 API 요청 속도 제한**
   - **인증된 API 요청 속도 제한**
1. **인증되지 않은**을 선택한 경우:
   1. **IP당 기간당 최대 인증되지 않은 API 요청**을 선택합니다.
   1. **인증되지 않은 API 속도 제한 기간(초)**을 선택합니다.
1. **인증된**을 선택한 경우:
   1. **사용자당 기간당 최대 인증된 API 요청**을 선택합니다.
   1. **인증된 API 속도 제한 기간(초)**을 선택합니다.

## 관련 항목 {#related-topics}

- [속도 제한](../_index.md)
- [사용자 및 IP 속도 제한](../../administration/settings/user_and_ip_rate_limits.md)
