---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 여러 에이전트와 함께 기본 플로우 및 사용자 지정 플로우를 사용하여 복잡한 개발 작업을 자동화합니다.
title: 플로우
---

{{< details >}}

- 티어: [Free](../../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< collapsible title="모델 정보" >}}

- LLM: Anthropic [Claude Sonnet 4](https://www.anthropic.com/claude/sonnet)

{{< /collapsible >}}

{{< history >}}

- GitLab 18.4에서 `ai_catalog_flows` [기능 플래그](../../../administration/feature_flags/_index.md)의 [실험적 기능](../../../policy/development_stages_support.md)으로 도입되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.7에서 [베타](../../../policy/development_stages_support.md)로 변경되었습니다.
- GitLab 18.7의 [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/569060)되었습니다.
- GitLab 18.8의 [GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/569060)되었습니다.
- GitLab 18.8에서 `ai_catalog_flows` 기능 플래그가 [기본적으로 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/216969)되었습니다.
- 기본 플로우에는 추가 플래그가 필요합니다.
- 기본 플로우가 GitLab 18.8에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273)으로 변경되었습니다.
- 사용자 지정 플로우가 GitLab 18.8에서 [베타](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273)로 변경되었습니다.
- GitLab 19.2에서 `ai_catalog_flows` 기능 플래그가 [제거](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/239459)되었습니다.
- 사용자 지정 플로우가 GitLab 19.2에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/work_items/602415)으로 변경되었습니다.

{{< /history >}}

플로우는 복잡한 문제를 해결하기 위해 함께 작동하는 하나 이상의 에이전트의 조합입니다.

GitLab은 두 가지 유형의 플로우를 제공합니다:

- [기본 플로우](foundational_flows/_index.md)는 일반적인 개발 작업을 위해 GitLab에서 만든 사전 구축되고 프로덕션 준비가 완료된 워크플로우입니다.
- [사용자 지정 플로우](custom.md)는 팀의 특정 프로세스를 자동화하기 위해 생성하는 워크플로우입니다. 워크플로우 단계와 에이전트를 정의하고 플로우가 실행되는 시기를 제어하는 트리거를 정의합니다.

플로우는 IDE 및 GitLab UI에서 사용 가능합니다.

- UI에서는 GitLab CI/CD에서 직접 실행되어 브라우저를 떠나지 않고도 일반적인 개발 작업을 자동화하는 데 도움이 됩니다.
- IDE에서는 VS Code, Visual Studio, JetBrains에서 소프트웨어 개발 플로우를 사용할 수 있습니다. 다른 플로우에 대한 지원이 제안 중입니다.

플로우가 CI/CD에서 어떻게 실행되는지에 대한 자세한 내용은 [플로우 실행 설명서](execution/_index.md)를 참조하세요. 플로우 보안에 대한 정보는 [복합 ID 설명서](../composite_identity.md)를 참조하세요.

## 사전 요구 사항 {#prerequisites}

<!-- Note: These prerequisites are duplicated on each flow sub-page. Update all pages when editing. -->

- [GitLab Duo Agent Platform 사전 요구 사항](../_index.md#prerequisites)을 충족합니다.
- **파운데이셔널 플로우 허용**을 [최상위 그룹](foundational_flows/_index.md#turn-foundational-flows-on-or-off)에 대해 켜세요.
- [서비스 계정을 허용하도록 푸시 규칙을 해야 합니다](../troubleshooting.md#configure-push-rules-to-allow-a-service-account).
- 프로젝트를 위해 [자체 러너를 구성](execution/_index.md#configure-runners-to-execute-flows)하거나 [GitLab 호스팅 러너](../../../ci/runners/hosted_runners/_index.md)를 활성화해야 합니다.
- 권장하는 방식입니다. CI/CD의 플로우가 프로젝트의 도구 체인 및 종속성에 액세스할 수 있도록 [에이전트 구성 파일](execution/_index.md#create-the-agent-configuration-file)을 생성합니다.

## GitLab UI에서 실행 중인 플로우 모니터링 {#monitor-running-flows-in-the-gitlab-ui}

프로젝트에서 실행 중인 플로우를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **AI** > **세션**을 선택합니다.

## IDE에서 플로우 기록 보기 {#view-flow-history-in-the-ides}

프로젝트에서 실행한 플로우의 기록을 보려면:

- **플로우** 탭에서 아래로 스크롤하여 **최근 에이전트 세션**을 봅니다.

## `AGENTS.md`으로 플로우 사용자 지정 {#customize-flows-with-agentsmd}

`AGENTS.md` 파일을 사용하여 기본 플로우 및 사용자 지정 플로우를 실행하는 동안 GitLab Duo가 따를 컨텍스트 및 지침을 제공합니다.

자세한 내용은 [`AGENTS.md` 사용자 지정 파일](../customize/agents_md.md)을 참조하세요.

## 피드백 제공 {#give-feedback}

플로우는 GitLab AI 지원 개발 플랫폼의 일부입니다. 의견은 이러한 워크플로우를 개선하는 데 도움이 됩니다. 플로우에 대한 문제를 보고하거나 개선 사항을 제안하려면 [이 설문을 완료](https://gitlab.fra1.qualtrics.com/jfe/form/SV_9GmCPTV7oH9KNuu)하세요.

## 관련 항목 {#related-topics}

- [플로우가 실행되는 위치 구성](execution/_index.md)
- [기본 플로우](foundational_flows/_index.md)
- [웹후크 콜백](webhook_callbacks.md)
