---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments
title: 지원 도우미
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  베타

{{< /details >}}

{{< history >}}

- [GitLab 19.2](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/237380)에서 [베타](../../../../policy/development_stages_support.md#beta)로 도입되었습니다.

{{< /history >}}

지원 도우미는 다음을 도와주는 전문화된 에이전트입니다:

- 시작 위치를 확실하지 않을 때 GitLab 제품 문제를 진단합니다.
- 특정 기능 영역에 대한 문제 해결 설명서를 찾습니다.
- 문제가 알려진 이슈인지 확인합니다.
- 담당자에게 escalate해야 할 때 관련 진단 정보가 포함된 지원 티켓을 준비합니다.

지원 도우미는 GitLab 문제를 진단하는 데 도움이 됩니다. 다른 이슈의 경우, 지원 도우미는 올바른 팀으로 안내하려고 합니다.

지원 도우미에 대한 자세한 내용은 [에이전트 구성 YAML 파일](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/blob/main/duo_workflow_service/agent_platform/v1/flows/configs/support_assistant/1.0.0.yml)을 참조하세요.

## 지원 도우미 사용 {#use-the-support-assistant}

사전 요구 사항:

- [기본 에이전트 설정](_index.md#turn-foundational-agents-on-or-off).
- [베타 및 실험 기능 설정](../../turn_on_off.md#turn-on-beta-and-experimental-features).

지원 도우미를 사용하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. GitLab Duo 사이드바에서 **새 채팅 추가**({{< icon name="pencil-square" >}})를 선택합니다.
1. 드롭다운 목록에서 **지원 도우미**를 선택합니다.

   화면 오른쪽의 GitLab Duo 사이드바에서 Chat 대화창이 열립니다.
1. GitLab 문제를 자신의 말로 설명한 다음, 에이전트가 원인을 진단할 때 후속 질문에 답합니다. 요청에서 최상의 결과를 얻으려면:

   - 증상과 영향으로 시작합니다. 예를 들어 "빌드가 이번 아침부터 실패했으며 모든 병합을 차단하고 있습니다"는 "CI가 손상됨"보다 더 많은 작업을 제공합니다.
   - 정확한 오류 메시지(모든 비밀은 삭제됨)와 오류 코드(있는 경우)를 포함합니다.
   - 이미 시도한 것을 설명하여 에이전트가 동일한 항목을 다시 제안하지 않도록 합니다.
   - 환경을 일찍 언급합니다: GitLab.com SaaS, GitLab Self-Managed(Linux 패키지 또는 Helm 차트 등의 설치 유형 포함) 또는 GitLab Dedicated 및 버전입니다.
   - 긴급도를 표시합니다. 프로덕션 중단이면 그렇게 말씀하면 에이전트가 즉시 긴급 티켓 준비로 이동합니다.
   - 대화당 하나의 문제를 유지하여 진단이 초점을 맞추도록 합니다.

### 프롬프트 예시 {#example-prompts}

- "파이프라인이 명확한 오류 없이 간헐적으로 실패하고 있습니다. 시작은 어디서 해야 합니까?"
- "종속성 검사가 내 프로젝트에 대한 취약점을 보고하지 않습니다."
- "개인 액세스 토큰으로 API를 호출할 때 403 오류가 발생합니다."
- "우리의 Geo 보조가 주 사이트보다 훨씬 뒤떨어져 있습니다. 이것이 알려진 이슈입니까?"
- "느린 Gitaly 성능에 대해 지원 티켓을 열어야 합니다. 무엇을 포함해야 합니까?"
- "Helm 기반 GitLab Self-Managed 설치를 위해 수집해야 할 진단 아카이브는 무엇입니까?"
