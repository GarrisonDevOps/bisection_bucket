---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "GitLab Duo 에이전트 플랫폼에서 사용 가능한 기본 에이전트, 사용자 지정 에이전트, 외부 에이전트에 대해 알아봅니다."
title: 에이전트
---

{{< details >}}

- 티어: [Free](../../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< collapsible title="모델 정보" >}}

- [기본 LLM](../model_selection.md#default-models)

{{< /collapsible >}}

{{< history >}}

- GitLab 18.5에서 `global_ai_catalog`라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/549914)되었습니다. GitLab.com에서 사용으로 설정되었습니다.
- 기본 에이전트와 사용자 지정 에이전트는 GitLab 18.7에서 [베타](https://gitlab.com/gitlab-org/gitlab/-/issues/568176)로 변경되었습니다.
- 기본 에이전트, 외부 에이전트, 사용자 지정 에이전트는 GitLab 18.8에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273)되었습니다.
- GitLab 18.10에서 `global_ai_catalog` 기능 플래그가 [제거](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/223135)되었습니다.
- GitLab 18.10부터 GitLab.com의 Free 티어에서 GitLab Credits를 사용하여 이용 가능합니다.

{{< /history >}}

에이전트는 특정 작업을 완료하고 복잡한 질문에 답변하는 데 도움이 되는 AI 기반 어시스턴트입니다.

GitLab은 세 가지 유형의 에이전트를 제공합니다:

- [기본 에이전트](foundational_agents/_index.md)는 일반적인 워크플로우를 위해 GitLab에서 만든 사전 구축된 프로덕션 준비 에이전트입니다. 이러한 에이전트는 특정 도메인을 위한 전문 지식과 도구를 갖추고 있습니다. 기본 에이전트는 기본적으로 켜져 있으므로 GitLab Duo Chat에서 사용을 시작할 수 있습니다.
- [사용자 지정 에이전트](custom.md)는 팀의 특정 필요를 충족하도록 생성하고 구성하는 에이전트입니다. 시스템 프롬프트를 통해 동작을 정의하고 액세스할 수 있는 도구를 선택합니다. 사용자 지정 에이전트는 기본 에이전트에서 다루지 않는 특화된 워크플로우가 필요할 때 이상적입니다. 사용자 지정 에이전트와 상호 작용하려면 그룹이나 프로젝트에서 이를 활성화하여 Chat과 함께 사용합니다.
- [외부 에이전트](external.md)는 GitLab 외부의 AI 모델 공급자와 통합됩니다. 외부 에이전트를 사용하여 Claude와 같은 모델 공급자가 GitLab에서 작동하도록 허용합니다. 토론, 이슈 또는 병합 요청에서 직접 외부 에이전트를 트리거할 수 있습니다.
