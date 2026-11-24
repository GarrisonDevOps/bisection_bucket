---
stage: Security Governance
Group: AI Control Plane
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "그룹, 프로젝트 및 인스턴스에 대한 GitLab Duo 에이전트 플랫폼 가용성을 제어합니다."
title: GitLab Duo Agent Platform 가용성 제어
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Duo 에이전트 플랫폼은 기본적으로 켜져 있습니다. 에이전트 플랫폼에는 [기능 모음](_index.md)이 포함됩니다.

에이전트 플랫폼을 사용하려면 [GitLab Credits](../../subscriptions/gitlab_credits.md)가 필요합니다.

에이전트 플랫폼을 켜거나 끌 수 있습니다:

- GitLab.com:  최상위 그룹의 경우.
- GitLab Self-Managed:  인스턴스의 경우.

[에이전트 도구 거버넌스](../ai-governance/tool-governance.md)에 대한 도구 거버넌스를 구성하려면 참조하세요.

## GitLab Duo 에이전트 플랫폼 켜기 또는 끄기 {#turn-gitlab-duo-agent-platform-on-or-off}

### GitLab.com {#on-gitlabcom}

{{< details >}}

- 티어: [Free](../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate

{{< /details >}}

{{< history >}}

- GitLab 18.10부터 GitLab.com의 Free 티어에서 GitLab Credits를 사용하여 이용 가능합니다.

{{< /history >}}

사전 요구 사항:

- 최상위 그룹의 소유자 역할이 있습니다.

최상위 그룹에 대해 에이전트 플랫폼을 켜거나 끄려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 최상위 그룹을 찾습니다.
1. **설정** > **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **GitLab Duo 에이전트 플랫폼** 아래에서 **GitLab Duo 에이전트 채팅, 에이전트, 플로우를 켜기** 확인란을 선택하거나 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

에이전트 플랫폼 가용성이 모든 하위 그룹 및 프로젝트에 대해 변경됩니다.

에이전트 플랫폼이 꺼지면 다음 기능이 숨겨집니다:

- 플로우 및 [기본 에이전트](agents/foundational_agents/_index.md#turn-foundational-agents-on-or-off)에 대한 관련 설정.
- AI 카탈로그.

### GitLab Self-Managed {#on-gitlab-self-managed}

사전 요구 사항:

- 관리자 액세스 권한이 있어야 합니다.
- 다음 중 하나를 포함하는 인스턴스:
  - 유료 라이선스가 포함된 활성 GitLab Duo Pro, Enterprise 또는 Self-Hosted 추가 기능.
  - 활성 GitLab Credits.

인스턴스에 대해 에이전트 플랫폼을 켜거나 끄려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **GitLab Duo 에이전트 플랫폼** 아래에서 **GitLab Duo 에이전트 채팅, 에이전트, 플로우를 켜기** 확인란을 선택하거나 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

에이전트 플랫폼이 꺼지면 다음 기능이 숨겨집니다:

- 플로우, [기본 에이전트](agents/foundational_agents/_index.md#turn-foundational-agents-on-or-off) 및 GitLab Duo CLI에 대한 관련 설정.
- AI 카탈로그.

## GitLab Duo 켜짐 잠금 {#lock-gitlab-duo-on}

{{< history >}}

- GitLab 19.1에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/21844)되었습니다.

{{< /history >}}

그룹 또는 프로젝트 설정에 관계없이 모든 사용자에 대해 GitLab Duo를 켭니다.

GitLab Duo 가용성을 **항상 켜짐**으로 설정하면 실험적 기능과 베타 기능이 자동으로 켜지지 않습니다. 실험적 기능과 베타 기능을 사용하려면 [별도로 켜야 합니다](#turn-on-beta-and-experimental-features).

{{< tabs >}}

{{< tab title="GitLab.com" >}}

사전 요구 사항:

- 최상위 그룹의 소유자 역할이 있습니다.

최상위 그룹에 대해 GitLab Duo를 켜짐으로 잠그려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 최상위 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **GitLab Duo 가용성** 아래에서 **항상 켜짐**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

GitLab Duo는 모든 하위 그룹 및 프로젝트에 대해 켜짐으로 잠깁니다. 하위 그룹 또는 프로젝트의 소유자 역할을 가진 사용자는 GitLab Duo를 끌 수 없습니다.

{{< /tab >}}

{{< tab title="GitLab Self-Managed" >}}

사전 요구 사항:

- 관리자 액세스 권한이 있어야 합니다.
- 다음 중 하나를 포함하는 인스턴스:
  - 유료 라이선스가 포함된 활성 GitLab Duo Pro, Enterprise 또는 Self-Hosted 추가 기능.
  - 활성 GitLab Credits.

인스턴스에 대해 GitLab Duo를 켜짐으로 잠그려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **GitLab Duo 가용성** 아래에서 **항상 켜짐**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

GitLab Duo는 모든 그룹, 하위 그룹 및 프로젝트에 대해 켜짐으로 잠깁니다. 그룹, 하위 그룹 또는 프로젝트의 소유자 역할을 가진 사용자는 GitLab Duo를 끌 수 없습니다.

{{< /tab >}}

{{< /tabs >}}

## GitLab Duo 켜기 또는 끄기 {#turn-gitlab-duo-on-or-off}

GitLab Duo는 기본적으로 켜져 있습니다. GitLab Duo를 켜거나 끌 수 있습니다.

- GitLab.com:  최상위 그룹, 기타 그룹 또는 하위 그룹 및 프로젝트의 경우.
- GitLab Self-Managed:  인스턴스, 그룹 또는 하위 그룹 및 프로젝트의 경우.

### GitLab.com {#on-gitlabcom-1}

{{< details >}}

- 티어: [Free](../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate

{{< /details >}}

{{< history >}}

- GitLab 18.10부터 GitLab.com의 Free 티어에서 GitLab Credits를 사용하여 이용 가능합니다.

{{< /history >}}

#### 최상위 그룹의 경우 {#for-a-top-level-group}

사전 요구 사항:

- 최상위 그룹의 소유자 역할이 있습니다.

최상위 그룹에 대한 GitLab Duo 가용성을 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 최상위 그룹을 찾습니다.
1. **설정** > **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **GitLab Duo 가용성** 아래에서 옵션을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

GitLab Duo 가용성이 모든 하위 그룹 및 프로젝트에 대해 변경됩니다.

#### 그룹 또는 하위 그룹의 경우 {#for-a-group-or-subgroup}

사전 요구 사항:

- 그룹 또는 하위 그룹의 소유자 역할.

그룹 또는 하위 그룹에 대한 GitLab Duo 가용성을 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹 또는 하위 그룹을 찾습니다.
1. **설정** > **일반**을 선택합니다.
1. **GitLab Duo 기능**을 확장합니다.
1. **GitLab Duo 가용성** 아래에서 옵션을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

GitLab Duo 가용성이 모든 하위 그룹 및 프로젝트에 대해 변경됩니다.

#### 프로젝트의 경우 {#for-a-project}

사전 요구 사항:

- 프로젝트에 대한 유지 관리자 또는 소유자 역할.

프로젝트에 대한 GitLab Duo 가용성을 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **GitLab Duo**를 확장합니다.
1. **GitLab Duo** 토글을 켜거나 끕니다.
1. **변경 사항 저장**을 선택합니다.

### GitLab Self-Managed {#on-gitlab-self-managed-1}

#### 인스턴스의 경우 {#for-an-instance}

사전 요구 사항:

- 관리자 액세스 권한이 있어야 합니다.
- 다음 중 하나를 포함하는 인스턴스:
  - 유료 라이선스가 포함된 활성 GitLab Duo Pro, Enterprise 또는 Self-Hosted 추가 기능.
  - 활성 GitLab Credits.

인스턴스에 대한 GitLab Duo 가용성을 변경하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **GitLab Duo 가용성** 아래에서 옵션을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

#### 그룹 또는 하위 그룹의 경우 {#for-a-group-or-subgroup-1}

사전 요구 사항:

- 그룹 또는 하위 그룹의 소유자 역할.

그룹 또는 하위 그룹에 대한 GitLab Duo 가용성을 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹 또는 하위 그룹을 찾습니다.
1. **설정** > **일반**을 선택합니다.
1. **GitLab Duo 기능**을 확장합니다.
1. **GitLab Duo 가용성** 아래에서 옵션을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

GitLab Duo 가용성이 모든 하위 그룹 및 프로젝트에 대해 변경됩니다.

#### 프로젝트의 경우 {#for-a-project-1}

사전 요구 사항:

- 프로젝트에 대한 유지 관리자 또는 소유자 역할.

프로젝트에 대한 GitLab Duo 가용성을 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **GitLab Duo**를 확장합니다.
1. **GitLab Duo** 토글을 켜거나 끕니다.
1. **변경 사항 저장**을 선택합니다.

## GitLab Duo Core 켜기 또는 끄기 {#turn-gitlab-duo-core-on-or-off}

GitLab Duo Core는 Premium 및 Ultimate 구독에 포함되어 있습니다.

- GitLab 17.11 이전의 기존 고객인 경우 GitLab Duo Core에 대한 기능을 켜야 합니다.
- GitLab 18.0 이상의 신규 고객인 경우 GitLab Duo Core가 자동으로 켜져 있으며 추가 작업이 필요하지 않습니다.

2025년 5월 15일 이전에 Premium 또는 Ultimate 구독이 있는 기존 고객이었다면, GitLab 18.0 이상으로 업그레이드할 때 GitLab Duo Core를 사용하려면 이를 켜야 합니다.

### GitLab.com {#on-gitlabcom-2}

{{< details >}}

- 티어: [Free](../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate

{{< /details >}}

{{< history >}}

- GitLab 18.10부터 GitLab.com의 Free 티어에서 GitLab Credits를 사용하여 이용 가능합니다.

{{< /history >}}

사전 요구 사항:

- 최상위 그룹의 소유자 역할이 있습니다.

최상위 그룹에 대한 GitLab Duo Core 가용성을 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 최상위 그룹을 찾습니다.
1. **설정** > **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **GitLab Duo 가용성** 아래에서 옵션을 선택합니다.
1. **GitLab Duo 코어** 아래에서 **GitLab Duo Core를 위한 기능 켜기** 체크박스를 선택하거나 선택 해제합니다. GitLab Duo 가용성에 대해 **항상 꺼짐**을 선택한 경우 이 설정에 액세스할 수 없습니다.
1. **변경 사항 저장**을 선택합니다.

변경 사항이 적용되는 데 최대 10분이 소요될 수 있습니다.

### GitLab Self-Managed {#on-gitlab-self-managed-2}

사전 요구 사항:

- 관리자 액세스 권한이 있어야 합니다.
- 다음 중 하나를 포함하는 인스턴스:
  - 유료 라이선스가 포함된 활성 GitLab Duo Pro, Enterprise 또는 Self-Hosted 추가 기능.
  - 활성 GitLab Credits.

인스턴스에 대한 GitLab Duo Core 가용성을 변경하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **GitLab Duo 가용성** 아래에서 옵션을 선택합니다.
1. **GitLab Duo 코어** 아래에서 **GitLab Duo Core를 위한 기능 켜기** 체크박스를 선택하거나 선택 해제합니다. GitLab Duo 가용성에 대해 **항상 꺼짐**을 선택한 경우 이 설정에 액세스할 수 없습니다.
1. **변경 사항 저장**을 선택합니다.

## 베타 및 실험적 기능 켜기 {#turn-on-beta-and-experimental-features}

실험적 기능 및 베타 단계인 GitLab Duo 기능은 기본적으로 꺼져 있습니다. 이 기능들은 [테스팅 계약](https://handbook.gitlab.com/handbook/legal/testing-agreement/)의 적용을 받습니다.

### GitLab.com {#on-gitlabcom-3}

{{< details >}}

- 티어: [Free](../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate

{{< /details >}}

{{< history >}}

- GitLab 18.10부터 GitLab.com의 Free 티어에서 GitLab Credits를 사용하여 이용 가능합니다.

{{< /history >}}

사전 요구 사항:

- 최상위 그룹의 소유자 역할이 있습니다.

최상위 그룹에 대한 GitLab Duo 실험적 기능 및 베타 기능을 켜려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **기능 미리보기** 아래에서 **실험적 기능과 베타 GitLab Duo 기능 활성화**를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

이 설정은 그룹에 속한 [모든 프로젝트에 적용됨](../project/merge_requests/approvals/settings.md#cascade-settings-from-the-instance-or-top-level-group).

### GitLab Self-Managed {#on-gitlab-self-managed-3}

{{< tabs >}}

{{< tab title="17.4 이상" >}}

GitLab 17.4 이상에서는 이 지침을 따라 GitLab Self-Managed 인스턴스에 대한 GitLab Duo 실험적 기능 및 베타 기능을 켭니다.

사전 요구 사항:

- 관리자 액세스 권한이 있어야 합니다.
- 다음 중 하나를 포함하는 인스턴스:
  - 유료 라이선스가 포함된 활성 GitLab Duo Pro, Enterprise 또는 Self-Hosted 추가 기능.
  - 활성 GitLab Credits.

인스턴스에 대한 GitLab Duo 실험적 기능 및 베타 기능을 켜려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **GitLab Duo**를 선택합니다.
1. **구성 변경**을 확장합니다.
1. **기능 미리보기** 아래에서 **실험적 기능과 베타 GitLab Duo 기능 사용**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

{{< /tab >}}

{{< tab title="17.3 이전" >}}

사전 요구 사항:

- 관리자 액세스 권한이 있어야 합니다.
- 다음 중 하나를 포함하는 인스턴스:
  - 유료 라이선스가 포함된 활성 GitLab Duo Pro, Enterprise 또는 Self-Hosted 추가 기능.
  - 활성 GitLab Credits.
- [네트워크 연결](../../administration/gitlab_duo/configure/_index.md)이 활성화되었습니다.
- [자동 모드](../../administration/silent_mode/_index.md) 꺼짐.

인스턴스에 대한 GitLab Duo 실험적 기능 및 베타 기능을 켜려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **GitLab Duo**를 선택합니다.
1. **구성 변경**을 확장합니다.
1. **기능 미리보기** 아래에서 **실험적 기능과 베타 GitLab Duo 기능 사용**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.
1. GitLab Duo Chat가 즉시 작동하려면 [수동으로 구독을 동기화](../../subscriptions/manage_subscription.md#manually-synchronize-subscription-data)합니다.

   구독을 수동으로 동기화하지 않으면 인스턴스에서 GitLab Duo Chat을 활성화하는 데 최대 24시간이 소요될 수 있습니다.

{{< /tab >}}

{{< /tabs >}}
