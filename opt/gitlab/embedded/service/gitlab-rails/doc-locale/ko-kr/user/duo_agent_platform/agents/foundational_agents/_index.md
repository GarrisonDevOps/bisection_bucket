---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 기본 에이전트
---

{{< details >}}

- 티어: [Free](../../../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [GitLab 18.6에서 베타로 소개](https://gitlab.com/gitlab-org/gitlab/-/issues/576618)되었습니다.
- GitLab 18.8에서 [정식 출시(GA)](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273)되었습니다.
- GitLab 18.10부터 GitLab.com의 Free 티어에서 GitLab Credits를 사용하여 이용 가능합니다.

{{< /history >}}

기본 에이전트는 영역별 전문 지식과 상황 인식으로 GitLab Duo Chat의 기능을 확장하는 특화된 AI 어시스턴트입니다.

일반 목적의 GitLab Duo 에이전트와 달리 기본 에이전트는 각각의 특화된 영역의 독특한 워크플로우, 프레임워크 및 모범 사례를 이해합니다. 각 에이전트는 GitLab 기능에 대한 깊이 있는 지식을 역할별 추론과 결합하여 실무자의 실제 업무 방식에 맞춘 목표 지향적인 지원을 제공합니다.

기본 에이전트는 GitLab에서 빌드하고 유지 관리하며 GitLab 유지 관리 배지({{< icon name="tanuki-verified" >}})를 표시합니다.

## 사전 요구 사항 {#prerequisites}

- [GitLab Duo Agent Platform 사전 요구 사항](../../_index.md#prerequisites)을 충족합니다.
- [기본 에이전트가 켜져](#turn-foundational-agents-on-or-off) 있어야 합니다.

## 사용 가능한 기본 에이전트 {#available-foundational-agents}

다음의 기본 에이전트는 GitLab UI, VS Code 및 JetBrains IDE에서 사용할 수 있습니다. 티어 가용성은 에이전트에 따라 다릅니다. 자세한 내용은 각 에이전트의 페이지를 참조하세요.

| 에이전트 | 설명 |
|-------|-------------|
| [CI Expert](ci_expert_agent.md) | GitLab CI/CD 파이프라인을 만들고, 디버깅하고, 최적화합니다. |
| [Data Analyst](data_analyst.md) | 플랫폼 데이터를 분석하고 시각화합니다. |
| [Flow Creator](flow_creator.md) | Chat에서 AI 카탈로그용 사용자 지정 플로우를 생성합니다. |
| [Onboarding Agent](onboarding_guide.md) | 첫 리포지토리 가져오기부터 보안 및 규정 준수 성숙도까지 GitLab DevSecOps 플랫폼을 도입합니다. |
| [Permissions Assistant](permissions_assistant.md) | 세분화된 개인 액세스 토큰에 대한 올바른 권한을 선택합니다. |
| [Planner](planner.md) | 제품 관리 및 계획 워크플로우에 대한 지원을 받습니다. |
| [Security Analyst](security_analyst_agent.md) | 보안 분석 및 취약성 관리에 대한 지원을 받습니다. |
| [지원 도우미](support_assistant.md) | GitLab 제품 문제를 진단하고 해결합니다. |

## 에이전트 복제 {#duplicate-an-agent}

기본 에이전트를 변경하려면 복사본을 만듭니다.

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

에이전트를 복제하려면 다음을 수행합니다.

1. 상단 표시줄에서 **검색 또는 이동** > **탐색**을 선택합니다.
1. **AI 카탈로그**를 선택한 다음 **에이전트** 탭을 선택합니다.
1. 복제하려는 에이전트를 선택합니다.
1. 오른쪽 위 모서리에서 **조치**({{< icon name="ellipsis_v" >}}) > **복제**를 선택합니다.
1. **공개범위 및 액세스** 아래:
   1. **관리** 드롭다운 목록에서 에이전트의 프로젝트를 선택합니다.
   1. **공개범위**에 대해 **비공개** 또는 **공개**를 선택합니다.
1. 선택 사항. 변경할 필드를 편집합니다.
1. **에이전트 만들기**를 선택합니다.

사용자 지정 에이전트가 생성됩니다. 이를 사용하려면 [이를 활성화](../custom.md#enable-an-agent)해야 합니다.

## 기본 에이전트를 켜거나 끄기 {#turn-foundational-agents-on-or-off}

기본적으로 기본 에이전트는 켜져 있습니다. 최상위 그룹(네임스페이스) 또는 인스턴스에 대해 기본 에이전트를 켜거나 끌 수 있습니다.

기본 에이전트를 기본적으로 끄면:

- 새로 릴리스된 에이전트를 포함하여 기본 구성을 사용하는 기본 에이전트가 꺼집니다.
- 기본 GitLab Duo Agent를 계속 사용할 수 있습니다.

{{< tabs >}}

{{< tab title="GitLab.com" >}}

사전 요구 사항:

- 그룹의 소유자 역할이 있어야 합니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **파운데이션 에이전트**에서 **기본 가용성**에 대해 다음 중 하나를 선택합니다:
   - **활성**
   - **끄기**
1. **가용성 설정**에서 각 에이전트에 대해 다음 중 하나를 선택합니다:
   - **활성**
   - **끄기**
   - **기본값 사용 (On)** 또는 **기본값 사용 (Off)**
1. **변경 사항 저장**을 선택합니다.

이러한 설정은 다음에 적용됩니다:

- [기본 GitLab Duo 네임스페이스](../../../profile/preferences.md#set-a-default-gitlab-duo-namespace)로 최상위 그룹을 보유한 사용자입니다.
- 기본 네임스페이스가 없으며 최상위 그룹에 속하는 네임스페이스를 방문하는 사용자입니다.

최상위 그룹에 대해 기본 에이전트를 끄면 해당 그룹을 기본 GitLab Duo 네임스페이스로 설정한 사용자는 어떤 네임스페이스에서도 기본 에이전트에 액세스할 수 없습니다.

{{< /tab >}}

{{< tab title="인스턴스" >}}

사전 요구 사항:

- 관리자여야 합니다.

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **파운데이션 에이전트**에서 **기본 가용성**에 대해 다음 중 하나를 선택합니다:
   - **활성**
   - **끄기**
1. **가용성 설정**에서 각 에이전트에 대해 다음 중 하나를 선택합니다:
   - **활성**
   - **끄기**
   - **기본값 사용 (On)** 또는 **기본값 사용 (Off)**
1. **변경 사항 저장**을 선택합니다.

{{< /tab >}}

{{< /tabs >}}
