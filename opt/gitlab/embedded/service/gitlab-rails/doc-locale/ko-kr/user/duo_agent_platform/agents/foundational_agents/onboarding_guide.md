---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments
gitlab_dedicated: no
title: 온보딩 에이전트
---

{{< details >}}

- 티어: Premium, Ultimate
- 추가 기능: GitLab Duo
- 제공 서비스: GitLab.com, GitLab Self-Managed
- 상태:  실험적 기능

{{< /details >}}

{{< history >}}

- [GitLab 19.4에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/245452), [실험](../../../../policy/development_stages_support.md#experiment) [기능 플래그](../../../../administration/feature_flags/_index.md) `onboarding_guide_agent`로 제공됩니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

온보딩 에이전트는 GitLab DevSecOps 플랫폼을 설정하는 데 도움이 됩니다. 이 에이전트는 프로젝트 컨텍스트와 구독 티어를 읽고 기능을 설명하며 다음 도입 단계를 권장하고 구성 예제(예: `.gitlab-ci.yml`)를 제공합니다.

온보딩 에이전트는 GitLab Duo Chat에서만 응답을 제공합니다. 파일, 파이프라인 또는 프로젝트 설정을 수정하지 않습니다. 에이전트는 작업 항목, 이슈 및 에픽을 생성 및 업데이트하고, 이슈 및 작업 항목에 댓글을 추가할 수 있습니다. 각 작업 전에 에이전트가 정확한 내용을 표시하고 승인 대기합니다.

다음이 필요한 경우 온보딩 에이전트를 사용합니다:

- 처음으로 팀 또는 프로젝트를 설정합니다.
- GitHub, Bitbucket 또는 Jenkins에서 마이그레이션하고 기존 워크플로를 GitLab에 매핑합니다.
- 보안 스캔, 규정 준수 또는 에이전트 워크플로와 같은 플랫폼의 더 많은 기능을 도입합니다.
- 티어에 포함된 기능이나 다음으로 구성할 사항을 확인합니다.

## 사전 요구 사항 {#prerequisites}

온보딩 에이전트를 사용하기 전에:

- 기본 에이전트를 [활성화](_index.md#turn-foundational-agents-on-or-off)합니다.
- [베타 및 실험 기능 활성화](../../turn_on_off.md#turn-on-beta-and-experimental-features)

## 온보딩 에이전트 사용 {#use-the-onboarding-agent}

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. GitLab Duo 사이드바에서 **새 채팅 추가**({{< icon name="pencil-square" >}})를 선택합니다.
1. 드롭다운 목록에서 **온보딩 에이전트**를 선택합니다.

   화면 오른쪽의 GitLab Duo 사이드바에서 Chat 대화창이 열립니다.
1. 도움이 필요한 내용을 설명합니다. 최적의 결과를 얻으려면 다음을 수행합니다.
   - 같은 대화에서 후속 질문을 합니다. 에이전트는 세션의 컨텍스트를 기억하고 이를 사용하여 지침을 제공합니다.
   - 특정 단계(예: 보안 또는 규정 준수)를 탐색하려는지에 대해 명확히 합니다.
   - 자신의 프로젝트에 적용하기 전에 에이전트의 구성 제안을 검토합니다.

에이전트는 응답하기 전에 현재 프로젝트 및 티어에서 컨텍스트를 수집하고 컨텍스트별 지침을 제공합니다.

## 프롬프트 예시 {#example-prompts}

시작하기 위해 다음 프롬프트를 사용합니다:

- `Help me get started with GitLab.`
- `I'm migrating from GitHub — where should I begin?`
- `Set up security scanning for this project.`
- `What should I do next to get more value out of GitLab?`
- `What features am I missing on my current tier?`
- `Help me convert my Jenkins pipeline to GitLab CI/CD.`
- `Help me get started with compliance frameworks.` (GitLab Ultimate)

## 알려진 이슈 {#known-issues}

- 에이전트는 GitLab Duo Chat UI 및 IDE에서만 실행됩니다. 이 에이전트의 [트리거](../../triggers/_index.md)를 만들 수 없습니다.
- 에이전트는 파일을 생성, 편집 또는 커밋하거나, 파이프라인을 수정하거나, 프로젝트 설정을 변경하지 않습니다. 각 작업을 승인한 후 작업 항목, 이슈 및 에픽을 생성 및 업데이트하고, 이슈 및 작업 항목에 댓글을 추가할 수 있습니다.
- 에이전트는 취약점, 보안 결과, 파이프라인 오류 또는 작업 로그를 읽을 수 없습니다. 관련 결과를 요청하고 Security Analyst 에이전트 또는 CI Expert 에이전트로 안내할 수 있습니다. 다른 에이전트에 위임할 수 없습니다.
- 에이전트는 프로젝트 및 페이지 컨텍스트를 사용하지만 특정 기능이 프로젝트에 대해 활성화되었는지 항상 감지할 수 없습니다.
- 에이전트 플랫폼 사용량은 [GitLab Duo 및 SDLC 트렌드 대시보드](../../../analytics/duo_and_sdlc_trends.md)에서 집계되어 보고됩니다. 개별 에이전트의 사용량을 아직 볼 수 없습니다.

## 피드백 제공 {#give-feedback}

이 에이전트는 실험이며 사용자의 피드백은 개선에 도움이 됩니다. 경험을 공유하거나 문제를 보고하려면 [이슈 606350](https://gitlab.com/gitlab-org/gitlab/-/issues/606350)에 댓글을 추가합니다.

## 관련 항목 {#related-topics}

- [기본 에이전트](_index.md)
- [GitLab Duo Agent Platform](../../_index.md)
