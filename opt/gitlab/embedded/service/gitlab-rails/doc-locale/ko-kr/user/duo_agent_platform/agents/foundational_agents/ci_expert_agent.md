---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments
title: CI Expert 에이전트
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.10에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/587460)되었으며 [베타](../../../../policy/development_stages_support.md#beta) 버전이고 [기능 플래그](../../../../administration/feature_flags/_index.md) `foundational_pipeline_authoring_agent`로 제공됩니다. 기본적으로 사용 중지됩니다.
- 기능 플래그가 GitLab 19.0에서 [제거](https://gitlab.com/gitlab-org/gitlab/-/issues/588564)되었습니다.
- GitLab 19.2에서 [일반 공급](https://gitlab.com/groups/gitlab-org/-/work_items/21405)입니다.

{{< /history >}}

CI Expert 에이전트는 GitLab CI/CD 파이프라인을 만들고 디버깅하며 최적화하는 데 도움을 주는 특화된 에이전트입니다. 다음을 결합합니다:

- GitLab CI/CD 구문 및 구성에 대한 깊은 전문 지식.
- 파이프라인 최적화 전략 및 모범 사례 지식.

다음 작업에 도움이 필요할 때 CI Expert 에이전트를 사용합니다:

- 파이프라인 생성: 프로젝트 요구 사항을 기반으로 `.gitlab-ci.yml` 구성을 처음부터 생성합니다.
- 구문 설명: CI/CD 키워드 및 구성 옵션을 이해합니다.
- 디버깅: 작업 로그를 분석하고 파이프라인 오류를 해결합니다.
- 최적화: 캐싱, 병렬 처리 및 `needs` 키워드를 사용하여 파이프라인 성능을 개선하고 작업을 더 빨리 시작할 수 있습니다.
- `rules`, `artifacts`, `services`, `environments`를 포함하여 CI/CD 키워드의 올바른 사용을 구현합니다.

## CI Expert 에이전트 액세스 {#access-the-ci-expert-agent}

사전 요구 사항:

- 기본 에이전트는 [켜져 있어야](_index.md#turn-foundational-agents-on-or-off) 합니다.

CI Expert 에이전트에 액세스하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. GitLab Duo 사이드바에서 **새 채팅 추가** ({{< icon name="pencil-square" >}})를 선택합니다.
1. 드롭다운 목록에서 **CI Expert**를 선택합니다.

   화면 오른쪽의 GitLab Duo 사이드바에서 Chat 대화창이 열립니다.
1. CI/CD 관련 질문이나 요청을 입력합니다. 요청에서 최적의 결과를 얻으려면:

   - 프로젝트 유형과 기술 스택을 설명합니다.
   - 기존 `.gitlab-ci.yml`을 공유합니다(있는 경우).
   - 목표를 지정합니다. 예를 들어 더 빠른 빌드, Kubernetes로의 배포 또는 병렬 테스트 실행입니다.

### 프롬프트 예시 {#example-prompts}

- "내 Node.js 프로젝트용 테스트 및 Docker 빌드를 포함한 CI/CD 파이프라인을 만드세요."
- "빌드 속도를 높이기 위해 종속 항목을 캐시하려면 어떻게 해야 하나요?"
- "Kubernetes 파이프라인에 배포 스테이지를 추가하세요."
- "`cache`과 `artifacts` 사이의 차이점은 무엇인가요?"
- "내 테스트 스위트에 대한 병렬 테스트를 설정하도록 도와주세요."
- "`needs`을 사용하여 작업을 더 빨리 시작하려면 어떻게 해야 하나요?"
- "이 CI/CD 구성이 수행하는 작업을 설명하세요: (구성 붙여넣기)"
- "다중 프로젝트 파이프라인을 설정하려면 어떻게 해야 하나요?"
- "파이프라인에서 시크릿을 처리하는 가장 좋은 방법은 무엇인가요?"
- "빌드 시간을 단축하기 위해 파이프라인을 최적화하도록 도와주세요."
- "머지 리퀘스트에서만 작업을 실행하려면 어떻게 해야 하나요?"
- "내 Python 프로젝트용 `.gitlab-ci.yml`을 pytest 및 linting과 함께 만드세요."
- "아티팩트를 사용하여 작업 간 데이터를 전달하려면 어떻게 해야 하나요?"
