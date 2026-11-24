---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 권한 어시스턴트
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [도입됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/592230) \- GitLab 18.11에서 [베타](../../policy/development_stages_support.md#beta) 기능으로 제공됨.
- GitLab 19.2에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/work_items/596613)합니다.

{{< /history >}}

권한 어시스턴트는 개인 액세스 토큰을 생성할 때 올바른 [세분화된 권한](fine_grained_access_tokens.md)을 선택하는 데 도움을 주는 GitLab Duo 에이전트입니다.

토큰이 수행해야 할 작업을 설명하면, 권한 어시스턴트가 생성 양식에서 적절한 권한을 선택합니다. 선택 사항이 필요에 맞을 때까지 후속 질문을 하거나 요청을 수정할 수 있습니다.

## 전제 조건 {#prerequisites}

- [GitLab Duo Agent Platform 사전 요구 사항](../../user/duo_agent_platform/_index.md#prerequisites)을 충족합니다.
- [기본 에이전트를 활성화](../../user/duo_agent_platform/agents/foundational_agents/_index.md#turn-foundational-agents-on-or-off)했습니다.
- 세분화된 개인 액세스 토큰을 활성화했습니다. 이 기능은 기본적으로 활성화되어 있는 `granular_personal_access_tokens` 기능 플래그로 제어됩니다.

## 권한 어시스턴트 사용 {#use-the-permissions-assistant}

권한 어시스턴트는 GitLab UI의 세분화된 개인 액세스 토큰 생성 페이지에서 사용할 수 있습니다.

권한 어시스턴트를 사용하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **개인 액세스 토큰**을 선택합니다.
1. **토큰 생성** 드롭다운 목록에서 **상세조정 토큰**을 선택합니다.
1. **Duo로 권한 추가**를 선택합니다.

   권한 어시스턴트가 미리 선택된 상태로 Duo Chat 패널이 열립니다.
1. 토큰이 수행해야 할 작업을 설명하거나 제안된 프롬프트 중 하나를 선택합니다.

   권한 어시스턴트가 양식에서 적절한 권한을 선택합니다.
1. 선택된 권한을 검토하고 필요하면 요청을 수정합니다.
1. 나머지 토큰 필드를 완료하고 **토큰 생성**을 선택합니다.

### 최상의 결과를 위한 팁 {#tips-for-best-results}

- 사용 사례를 구체적으로 설명하세요. 예를 들어, "단일 프로젝트에서 이슈를 읽고 머지 리퀘스트를 생성해야 합니다"는 "API 액세스가 필요합니다"보다 더 나은 결과를 제공합니다.
- 초기 선택이 너무 광범위하거나 좁으면 조정을 요청하세요.
- 필요사항을 설명하는 방법이 확실하지 않으면 제안된 프롬프트를 시작점으로 사용하세요.
- 제안은 관련 액세스 수준(그룹 및 프로젝트, 사용자 또는 전역)에 적용되므로 요청이 여러 섹션에 걸칠 때 동일한 권한을 두 개 이상의 섹션에서 추가할 수 있습니다.

## 프롬프트 예시 {#example-prompts}

- "API를 통해 리포지토리에 읽고 쓰고 싶습니다."
- "CI/CD 파이프라인을 관리하고 작업 로그를 읽어야 합니다."
- "이슈 및 머지 리퀘스트 관리를 자동화하고 싶습니다."
- "프로젝트 및 그룹에 대한 읽기 전용 액세스가 필요합니다."
- "모든 스니펫을 읽고 싶습니다. 내 것만이 아니라."
