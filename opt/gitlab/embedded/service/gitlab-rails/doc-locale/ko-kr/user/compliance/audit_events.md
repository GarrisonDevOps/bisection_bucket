---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 감사 이벤트
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

보안 감사는 인프라를 심층 분석하고 검토하는 것으로, 우려 영역과 잠재적으로 위험한 관행을 파악하는 데 사용됩니다. 감사 프로세스를 지원하기 위해 GitLab은 GitLab 내에서 다양한 작업을 추적할 수 있는 감사 이벤트를 제공합니다. GitLab은 포괄적인 보고서를 생성하여 소유자와 관리자가 감사자에게 대응하도록 도와줄 수 있습니다. 이러한 감사 보고서는 필요에 따라 범위가 다릅니다.

예를 들어, 감사 이벤트를 사용하여 다음을 추적할 수 있습니다:

- GitLab 프로젝트의 특정 사용자의 권한 수준을 변경한 사람과 시간.
- 새 사용자를 추가하거나 사용자를 제거한 사람과 시간.

이러한 이벤트는 감사에서 위험을 평가하고, 보안 조치를 강화하며, 인시던트에 대응하고, 규정 준수를 준수하는 데 사용할 수 있습니다. GitLab이 제공하는 감사 이벤트의 전체 목록은 [감사 이벤트 유형](audit_event_types.md)을 참조하세요. 예를 들어:

- 특정 로깅 기능에 대한 증명을 요청하는 외부 감사자에게 제공할 감사 이벤트 보고서를 생성합니다.
- 분기별 액세스 검토를 위해 모든 사용자와 그들의 그룹 및 프로젝트 멤버십을 표시하는 보고서를 제공하여 감사자가 조직의 액세스 관리 정책 준수를 확인할 수 있도록 합니다.

감사 이벤트는 무기한 보관됩니다. 보관 기간이 없으므로 모든 감사 이벤트를 사용할 수 있습니다.

## 사전 요구 사항 {#prerequisites}

특정 유형의 감사 이벤트를 보려면 최소 역할이 필요합니다.

- 그룹의 모든 사용자의 그룹 감사 이벤트를 보려면 그룹에 대한 [소유자 역할](../permissions.md#roles)이 있어야 합니다.
- 프로젝트의 모든 사용자의 프로젝트 감사 이벤트를 보려면 프로젝트에 대한 [유지관리자 역할](../permissions.md#roles) 이상이 있어야 합니다.
- 그룹 또는 프로젝트의 자신의 작업을 기반으로 그룹 및 프로젝트 감사 이벤트를 보려면 그룹 또는 프로젝트에 대한 [개발자 역할](../permissions.md#roles) 이상이 있어야 합니다.

[감사자 액세스 수준](../../administration/auditor_users.md)을 가진 사용자는 모든 사용자의 그룹 및 프로젝트 이벤트를 볼 수 있습니다.

## 감사 이벤트 보기 {#viewing-audit-events}

감사 이벤트는 그룹, 프로젝트, 인스턴스 및 로그인 수준에서 볼 수 있습니다. 각 수준에는 로깅하는 다른 감사 이벤트가 있습니다.

### 로그인 감사 이벤트 {#sign-in-audit-events}

성공한 로그인 이벤트는 모든 티어에서 사용 가능한 유일한 감사 이벤트입니다. 성공한 로그인 이벤트를 보려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **인증 로그**를 선택합니다.

유료 티어로 업그레이드한 후 감사 이벤트 페이지에서 성공한 로그인 이벤트도 볼 수 있습니다.

### 그룹 감사 이벤트 {#group-audit-events}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹의 감사 이벤트를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **보안** > **감사 이벤트**를 선택합니다.
1. 작업을 수행한 프로젝트의 멤버(사용자)와 날짜 범위별로 감사 이벤트를 필터링합니다.

그룹 감사 이벤트는 [그룹 감사 이벤트 API](../../api/audit_events.md#group-audit-events)를 사용하여 액세스할 수도 있습니다. 그룹 감사 이벤트 쿼리 `created_after` 및 `created_before` 매개변수는 날짜 간 최대 30일 차이로 제한됩니다.

### 프로젝트 감사 이벤트 {#project-audit-events}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **보안** > **감사 이벤트**를 선택합니다.
1. 작업을 수행한 프로젝트의 멤버(사용자)와 날짜 범위별로 감사 이벤트를 필터링합니다.

프로젝트 감사 이벤트는 [프로젝트 감사 이벤트 API](../../api/audit_events.md#project-audit-events)를 사용하여 액세스할 수도 있습니다. 프로젝트 감사 이벤트 쿼리 `created_after` 및 `created_before` 매개변수는 날짜 간 최대 30일 차이로 제한됩니다.

## 시간대 {#time-zones}

감사 이벤트에 사용되는 시간대는 보는 위치에 따라 다릅니다:

- GitLab UI에서는 로컬 시간대를 사용합니다.
- [감사 이벤트 API](../../api/audit_events.md)는 기본적으로 UTC로 날짜와 시간을 반환하거나 GitLab Self-Managed에서 [구성된 시간대](../../administration/timezone.md)를 반환합니다.
- CSV 내보내기에서는 UTC를 사용합니다.

## 알려진 이슈 {#known-issues}

감사 이벤트 인터페이스의 검색 기능은 제한적입니다. 감사 이벤트 세부 정보의 텍스트 기반 검색은 지원되지 않습니다. 감사 이벤트를 다음 기준으로만 필터링할 수 있습니다:

- 멤버 이벤트: 작업을 수행한 작성자.
- 날짜 범위: 최대 30일 기간.

감사 이벤트 보고서 사용성 확장은 [에픽 418](https://gitlab.com/groups/gitlab-org/-/epics/418)에서 제안됩니다.

고급 검색 및 감사 이벤트 분석을 위해 [감사 이벤트 스트리밍](audit_event_streaming.md)을 외부 대상으로 고려하여 포괄적인 텍스트 검색 및 분석을 수행할 수 있습니다.

## 감사 이벤트에 기여 {#contribute-to-audit-events}

에픽에서 원하는 이벤트를 찾을 수 없으면 다음 중 하나를 수행할 수 있습니다:

- 감사 이벤트 제안 이슈 템플릿을 사용하여 [이슈를 생성](https://gitlab.com/gitlab-org/gitlab/-/work_items/new?description_template=Audit%20Event%20Proposal)하여 요청합니다.
- GitLab에 기여하고 이벤트를 추가합니다.

## AI 감사 이벤트 {#ai-audit-events}

GitLab Duo 에이전트 세션은 각 세션에 대한 입력, 모델 컨텍스트, 이벤트 타임라인 및 출력을 캡처하는 AI 감사 이벤트를 생성합니다. **감사 이벤트** 탭에서 **거버넌스** 페이지에서 이러한 이벤트를 탐색하고, 필터링하고, 다운로드할 수 있습니다.

자세한 내용은 [AI 감사 이벤트 보고서](../ai-governance/ai-audit-events.md)를 참조하세요.

## 토픽 관리 {#administer-topics}

인스턴스 관리자는 **운영자** 영역에서 [감사 이벤트를 관리](../../administration/compliance/audit_event_reports.md)할 수 있습니다.
