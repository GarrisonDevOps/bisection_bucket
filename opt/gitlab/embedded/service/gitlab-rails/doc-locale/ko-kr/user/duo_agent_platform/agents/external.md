---
stage: Agent Foundations
group: AI Catalog
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 외부 에이전트
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< collapsible title="모델 정보" >}}

- 자체 호스팅된 모델에서는 GitLab Duo를 사용할 수 없습니다

{{< /collapsible >}}

{{< history >}}

- GitLab 18.3에서 GitLab.com에 도입되었으며 [기능 플래그](../../../administration/feature_flags/_index.md)의 이름은 `ai_flow_triggers`입니다. 기본적으로 활성화됩니다.
- GitLab 18.6에서 CLI 에이전트에서 이름이 변경되었습니다
- Claude Code Agent 및 Codex Agent는 GitLab 18.6에서 GitLab Self-Managed 및 GitLab Dedicated에서 활성화되었습니다.
- GitLab 18.7에서 그룹에서 활성화 기능이 `ai_catalog_agents` [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/578318)되었습니다. GitLab.com에서 사용으로 설정되었습니다.
- GitLab 18.10에서 유지 관리자로 프로젝트에서 직접 사용으로 설정하는 기능이 `ai_catalog_project_level_enablement`라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/20743)되었습니다. GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 기본적으로 사용으로 설정되었습니다.
- GitLab 18.11에서 `ai_catalog_project_level_enablement` 기능 플래그가 제거되었습니다.
- GitLab 19.0에서 **머지 리퀘스트 준비** 트리거 이벤트 유형이 `merge_request_ready_flow_trigger` [플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/592454)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 19.1에서 **머지 리퀘스트 코드 충돌** 트리거 이벤트 유형이 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/592455)되었습니다.
- GitLab 19.1에서 **머지 리퀘스트** 트리거 이벤트 유형과 **승인됨** 작업이 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/237081)되었습니다.
- GitLab 19.1에서 **작업 항목 생성됨** 트리거 이벤트 유형이 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/599985)되었습니다.
- GitLab 19.1에서 **머지 리퀘스트 준비** 트리거 이벤트 유형이 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/work_items/598421)하게 되었습니다. 기능 플래그 `merge_request_ready_flow_trigger`이 제거되었습니다.
- GitLab 19.2에서 **작업 항목 상태 변경됨** 트리거 이벤트 유형이 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/599983)되었습니다.
- **머지 리퀘스트** 트리거 이벤트 유형과 **생성됨** 작업이 GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/242698)되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어되며 확인된 고객에 대해 활성화됩니다. 고객 네임스페이스 또는 GitLab 인스턴스에서 외부 에이전트를 활성화하려면 GitLab 지원팀에 문의하세요.

GitLab Duo 에이전트는 코드를 작성하고, 연구 결과를 얻고, 작업을 동시에 수행하도록 병렬로 작동합니다.

외부 AI 모델 제공자와 에이전트를 통합하여 조직의 요구에 맞게 사용자 정의할 수 있습니다. 그런 다음 프로젝트 이슈, 에픽 또는 머지 리퀘스트에서 댓글이나 토론에 외부 에이전트를 언급하고 에이전트에 작업을 완료하도록 요청할 수 있습니다.

외부 에이전트:

- 주변 컨텍스트와 리포지토리 코드를 읽고 분석합니다.
- 프로젝트 권한을 준수하면서 적절한 작업을 결정하고 감사 추적을 유지합니다.
- CI/CD 파이프라인을 실행하고 머지 가능한 변경 또는 인라인 댓글로 GitLab 내에서 응답합니다.

## 사전 요구 사항 {#prerequisites}

- [GitLab Duo Agent Platform 사전 요구 사항](../_index.md#prerequisites)을 충족합니다.
- [플로우 실행이 켜져](../flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off) 있습니다.
- [외부 에이전트가 켜져](#turn-external-agents-on-or-off) 있습니다.

## 보안 고려 사항 {#security-considerations}

외부 에이전트는 타사 AI 모델 제공자와 통합되며 GitLab 기본 제공 에이전트 및 플로우와는 다른 보안 특성을 가집니다. 외부 에이전트를 사용하면 다음과 같은 위험을 수락합니다:

- **프롬프트 인젝션 취약점**: GitLab은 프롬프트 인젝션 위험을 낮추기 위해 타사 프롬프트 스캔을 구현합니다. 이 스캔은 외부 에이전트에서 사용할 수 없습니다.
- **타사 제공자 의존성**: 외부 AI 모델 제공자는 GitLab이 아닌 모든 보안 제어(프롬프트 스캔, 모니터링 및 알림 포함)를 관리합니다.
- **네트워크 액세스**: 외부 에이전트는 타사 AI 제공자에 네트워크 호출을 합니다. 이러한 제공자에게 전송된 데이터는 해당 보안 정책 및 데이터 처리 관행을 따릅니다.
- **제한된 격리**: 외부 에이전트는 GitLab 기본 에이전트 및 플로우에 적용되는 것과 동일한 수준의 네트워크 격리 및 보안 제한을 갖지 않습니다.

조직에서 외부 에이전트를 활성화하기 전에 보안 요구 사항과 선택한 AI 모델 제공자가 제공하는 보안 문서를 검토하세요.

Duo Agent Platform의 보안 위협 및 완화에 대한 광범위한 개요는 [Duo Agent Platform 보안 위협 문서](../security_threats.md)를 참조하세요.

## GitLab-관리 외부 에이전트용 빠른 시작 {#quickstart-for-gitlab-managed-external-agents}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

{{< history >}}

- GitLab 18.8에서 GitLab.com에 도입되었습니다.

{{< /history >}}

다음 통합은 GitLab에서 테스트되었으며 사용 가능합니다:

- [Claude Code](https://code.claude.com/docs/en/overview)
- [OpenAI Codex](https://help.openai.com/en/articles/11096431-openai-codex-cli-getting-started)
- [Amazon Q](https://aws.amazon.com/q/)
- [Gemini](https://gemini.google.com/)

외부 AI 모델 제공자와 에이전트를 통합할 수 있으려면 [GitLab Duo Agent Platform의 사전 조건](../_index.md#prerequisites)을 충족해야 합니다.

관리형 외부 에이전트는 GitLab-관리 자격 증명을 사용할 수 있으며 추가 에이전트 구성 없이 그룹에서 활성화할 수 있습니다.

관리형 에이전트를 활성화 및 사용하기 위한 필수 단계:

1. AI 카탈로그에서 에이전트에 액세스합니다. 에이전트 이름을 검색하거나 직접 URL을 사용합니다.

   GitLab-관리 외부 에이전트는 GitLab에서 유지 관리하는 배지({{< icon name="tanuki-verified" >}})를 표시합니다.

1. [에이전트 활성화](#enable-the-agent).
1. [외부 에이전트 사용](#use-an-external-agent) (이슈, 에픽 또는 머지 리퀘스트에서).

### Claude Code Agent {#claude-code-agent}

[GitLab의 Claude Code Agent](https://gitlab.com/explore/ai-catalog/agents/2337/)는 GitLab-관리 자격 증명을 사용하며 추가 구성이 필요하지 않습니다.

### Codex Agent {#codex-agent}

[GitLab의 Codex Agent](https://gitlab.com/explore/ai-catalog/agents/2334/)는 GitLab-관리 자격 증명을 사용하며 추가 구성이 필요하지 않습니다.

### Amazon Q Developer Agent {#amazon-q-developer-agent}

{{< details >}}

- 제공 서비스: GitLab.com

{{< /details >}}

[Amazon Q Developer Agent](https://gitlab.com/explore/ai-catalog/agents/2332/)는 GitLab-관리 자격 증명을 사용하지 않습니다. 이 에이전트를 사용하려면 자신의 자격 증명을 제공해야 합니다.

Amazon Q Developer Agent를 사용하려면:

- 프로젝트의 CI/CD 설정에 다음 환경 변수를 추가합니다:

  - `AWS_ACCESS_KEY_ID`
  - `AWS_SECRET_ACCESS_KEY`
  - `AWS_REGION_NAME`
  - `AMAZON_Q_SIGV4`

### Gemini Agent로 개발 {#develop-with-gemini-agent}

{{< details >}}

- 제공 서비스: GitLab.com

{{< /details >}}

[Gemini Agent로 개발](https://gitlab.com/explore/ai-catalog/agents/2331/)은 GitLab-관리 자격 증명을 사용하지 않습니다. 이 에이전트를 사용하려면 자신의 자격 증명을 제공해야 합니다.

Gemini Agent로 개발을 사용하려면:

- 프로젝트의 CI/CD 설정에 다음 환경 변수를 추가합니다:

  - `GOOGLE_CREDENTIALS` - Google 자격 증명 JSON 파일의 위치를 추가합니다. 자세한 내용은 [`GOOGLE_APPLICATION_CREDENTIALS` 환경 변수](https://docs.cloud.google.com/docs/authentication/application-default-credentials#GAC)를 참조하세요.
  - `GOOGLE_CLOUD_PROJECT`
  - `GOOGLE_CLOUD_LOCATION`

### 다른 인스턴스에 GitLab-관리 에이전트 추가 {#add-gitlab-managed-agents-to-other-instances}

{{< details >}}

- 제공 서비스: GitLab Self-Managed, GitLab Dedicated
- 상태:  실험적 기능

{{< /details >}}

{{< history >}}

- GitLab 18.8에서 실험으로 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/221986)되었습니다.

{{< /history >}}

관리자는 Claude Agent 및 Codex Agent를 GitLab 인스턴스에 추가할 수 있습니다.

사전 요구 사항:

- 관리자여야 합니다.

인스턴스에 외부 에이전트를 추가하려면:

{{< tabs >}}

{{< tab title="GitLab UI" >}}

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **GitLab Duo**를 선택합니다.
1. **GitLab-관리 외부 에이전트**에서 **AI 카탈로그에 추가**를 선택합니다.

{{< /tab >}}

{{< tab title="Rake 작업" >}}

Linux 패키지(Omnibus)의 경우:

```shell
sudo gitlab-rake gitlab:ai_catalog:seed_external_agents
```

자체 컴파일(소스)의 경우:

```shell
bundle exec rake gitlab:ai_catalog:seed_external_agents
```

{{< /tab >}}

{{< /tabs >}}

[API](../../../api/admin/ai_catalog.md)를 사용하여 외부 에이전트를 추가할 수도 있습니다.

### 자격 증명 액세스 {#access-credentials}

{{< history >}}

- GitLab 18.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/567791)되었습니다.

{{< /history >}}

외부 에이전트는 AI Gateway를 통해 GitLab-관리 자격 증명을 사용합니다.

GitLab-관리 자격 증명을 사용하는 경우:

- 외부 에이전트 구성에서 `injectGatewayToken: true`을 설정합니다.
- 외부 에이전트를 GitLab AI Gateway 프록시 엔드포인트를 사용하도록 구성합니다.

`injectGatewayToken`이 `true`일 때 다음 환경 변수가 자동으로 주입됩니다:

- `AI_FLOW_AI_GATEWAY_TOKEN`: AI Gateway용 인증 토큰
- `AI_FLOW_AI_GATEWAY_HEADERS`: API 요청용 형식이 지정된 헤더

GitLab-관리 자격 증명은 Anthropic Claude 및 OpenAI Codex에만 사용 가능합니다.

GitLab API에 대해 에이전트를 인증하려면 [GitLab API에 인증](#authenticate-to-the-gitlab-api)을 참조하세요.

### 지원 모델 {#supported-models}

GitLab-관리 자격 증명의 경우 다음 AI 모델이 지원됩니다:

Anthropic Claude:

- `claude-haiku-4-5-20251001`
- `claude-opus-4-5-20251101`
- `claude-opus-4-6`
- `claude-sonnet-4-20250514`
- `claude-sonnet-4-5-20250929`
- `claude-sonnet-4-6`

OpenAI Codex:

- `gpt-5`
- `gpt-5-mini-2025-08-07`
- `gpt-5.1`
- `gpt-5.1-2025-11-13`
- `gpt-5.2-2025-12-11`
- `gpt-5.3-codex`
- `gpt-5.4-2026-03-05`
- `gpt-5.4-mini`
- `gpt-5.4-nano`

## CI/CD 변수 구성 {#configure-cicd-variables}

변수를 프로젝트에 추가하여 GitLab이 타사 제공자에 연결하는 방식을 결정합니다.

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

프로젝트 설정에서 변수를 추가하거나 업데이트하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **변수**를 펼칩니다.
1. **변수 추가**를 선택하고 필드를 완성합니다:
   - **유형**: **변수 (기본값)**를 선택합니다.
   - **Environments (환경)**: **모두 (기본값)**를 선택합니다.
   - **공개범위**: 원하는 가시성을 선택합니다.

     API 키 및 개인 액세스 토큰 변수의 경우 **마스킹됨** 또는 **마스킹 및 숨김**을 선택합니다.
   - **보호 변수** 확인란을 선택 해제합니다.
   - **변수 참조 펼침** 확인란을 선택 해제합니다.
   - **설명 (옵션)**: 변수 설명을 입력합니다.
   - **키**: CI/CD 변수의 환경 변수 이름(예: `GITLAB_HOST`)을 입력합니다.
   - **값**: API 키, 개인 액세스 토큰 또는 호스트의 값입니다.
1. **변수 추가**를 선택합니다.

자세한 내용은 [프로젝트 설정에 CI/CD 변수 추가](../../../ci/variables/_index.md#define-a-cicd-variable-in-the-ui) 방법을 참조하세요.

### 외부 에이전트용 CI/CD 변수 {#cicd-variables-for-external-agents}

다음 CI/CD 변수가 사용 가능합니다:

| 통합                | 환경 변수         | 설명 |
|----------------------------|------------------------------|-------------|
| 모두                        | `GITLAB_TOKEN_<integration>` | 서비스 계정 사용자의 개인 액세스 토큰입니다. |
| 모두                        | `GITLAB_HOST`                | GitLab 인스턴스 호스트 이름(예: `gitlab.com`)입니다. |
| 모두                        | `ADDITIONAL_INSTRUCTIONS`    | 에이전트가 프롬프트에 포함하는 추가 지침입니다. |
| Amazon Q                   | `AWS_SECRET_NAME`            | AWS Secrets Manager 보안 이름입니다. |
| Amazon Q                   | `AWS_REGION_NAME`            | AWS 지역 이름입니다. |
| Amazon Q                   | `AMAZON_Q_SIGV4`             | Amazon Q Sig V4 자격 증명입니다. |
| Google Gemini CLI          | `GOOGLE_CREDENTIALS`         | JSON 자격 증명 파일 내용입니다. |
| Google Gemini CLI          | `GOOGLE_CLOUD_PROJECT`       | Google Cloud 프로젝트 ID입니다. |
| Google Gemini CLI          | `GOOGLE_CLOUD_LOCATION`      | Google Cloud 프로젝트 위치입니다. |

## GitLab API에 인증 {#authenticate-to-the-gitlab-api}

모든 외부 에이전트는 환경 변수 `AI_FLOW_GITLAB_TOKEN`로 설정된 GitLab OAuth 토큰을 받습니다. 이 토큰은 부여된 범위로 제한됩니다. [`ai_workflows` 범위의 GitLab API 엔드포인트](../flows/foundational_flows/software_development.md#apis-that-the-flow-has-access-to)에만 액세스할 수 있습니다. 토큰이 올바르게 전송되더라도 해당 범위를 벗어난 엔드포인트는 거부됩니다.

외부 에이전트에서 GitLab API를 호출하려면 `AI_FLOW_GITLAB_TOKEN`을 `Authorization: Bearer` 토큰으로 보냅니다. `PRIVATE-TOKEN` 헤더를 사용하여 토큰을 보내면 API는 `401 Unauthorized`를 반환합니다.

```shell
curl --header "Authorization: Bearer $AI_FLOW_GITLAB_TOKEN" \
  "https://$AI_FLOW_GITLAB_HOSTNAME/api/v4/user"
```

에이전트에서 `glab` CLI를 사용하려면 토큰을 `~/.config/glab-cli/config.yml`에 쓰고 `is_oauth2: "true"`을 설정하여 `glab`이 토큰을 올바르게 보내도록 합니다:

```yaml
hosts:
  $AI_FLOW_GITLAB_HOSTNAME:
    token: $AI_FLOW_GITLAB_TOKEN
    is_oauth2: "true"
```

GitLab-관리 Claude 및 Codex 에이전트는 이 동일한 패턴을 사용합니다. 작동 예제는 [외부 에이전트 구성 예제](external_examples.md)를 참조하세요.

## ID 토큰으로 인증 {#authenticate-with-id-tokens}

{{< history >}}

- GitLab 19.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/224940)되었습니다.

{{< /history >}}

사용자 정의 외부 에이전트를 타사 OpenID Connect(OIDC) 서비스로 인증하려면 에이전트 구성에서 [ID 토큰](../../../ci/secrets/id_token_authentication.md)을 선언합니다. GitLab CI/CD는 서명된 JSON 웹 토큰(JWT)을 생성하고 에이전트 작업에 주입합니다.

오래 지속되는 자격 증명을 저장하지 않고 인증하려면 ID 토큰을 사용합니다. 예를 들어, 보안 관리자에서 보안을 검색하거나 아티팩트에 서명할 수 있습니다.

ID 토큰을 구성하려면 외부 에이전트 구성에 `id_tokens` 블록을 추가합니다. 각 토큰은 `aud`(대상) 클레임이 필요합니다.

```yaml
injectGatewayToken: true
image: node:22-slim
commands:
  - my-authentication-script.sh "$VAULT_ID_TOKEN"
id_tokens:
  VAULT_ID_TOKEN:
    aud: https://vault.example.com
```

`aud` 클레임은 단일 문자열 또는 문자열 목록일 수 있습니다. 각 토큰은 토큰의 이름을 사용하는 환경 변수로 에이전트 작업에서 사용 가능합니다.

> [!warning]
> ID 토큰은 `aud` 클레임을 신뢰하는 모든 서비스에 액세스 권한을 부여하는 자격증명입니다. 각 토큰에 대해 가장 좁은 가능한 `aud` 값을 설정합니다.

토큰 페이로드에 대한 자세한 내용은 [OpenID Connect(OIDC) 인증을 사용한 ID 토큰](../../../ci/secrets/id_token_authentication.md)을 참조하세요.

## 에이전트 활성화 {#enable-the-agent}

{{< history >}}

- GitLab 19.2에서 여러 프로젝트에 대한 공개 에이전트를 활성화하는 기능이 `ai_catalog_bulk_item_consumer_create` [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/600526)되었습니다. 기본적으로 활성화됩니다.
- 기능 플래그 `ai_catalog_bulk_item_consumer_create`은 GitLab 19.4에서 제거되었습니다.

{{< /history >}}

이슈, 머지 리퀘스트 또는 토론에서 트리거하도록 에이전트를 활성화합니다.

프로젝트에서 에이전트를 사용 가능하도록 설정하면 동시에 해당 프로젝트의 최상위 그룹에서 사용 가능하도록 설정됩니다.

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

{{< tabs >}}

{{< tab title="관리 프로젝트에서" >}}

외부 에이전트를 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **AI** > **에이전트**를 선택합니다.
1. **관리됨** 탭을 선택한 다음 사용 가능하도록 설정할 에이전트를 선택합니다.
1. 오른쪽 위 모서리에서 **사용**을 선택합니다.
1. **프로젝트** 아래에서 에이전트를 사용 가능하도록 설정할 프로젝트를 선택합니다.
1. **트리거 추가**에서 다음을 선택합니다.
   - 하나 이상의 [트리거 이벤트 유형](../triggers/_index.md#trigger-event-types).
   - 트리거 이벤트 유형에 필요한 경우 트리거 이벤트 작업.
1. **활성화**를 선택합니다.

{{< /tab >}}

{{< tab title="AI 카탈로그에서" >}}

외부 에이전트를 활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동** > **탐색**을 선택합니다.
1. **AI 카탈로그**를 선택한 다음 **에이전트** 탭을 선택합니다.
1. 사용 가능하도록 설정할 에이전트를 선택합니다.
1. 오른쪽 위 모서리에서 **사용**을 선택합니다.
1. **프로젝트** 아래에서 에이전트를 사용 가능하도록 설정할 프로젝트를 선택합니다.

   여러 프로젝트에 공개된 또는 제한된 에이전트를 활성화하려면 **프로젝트** 드롭다운 목록에서 관련 프로젝트를 선택합니다. 최대 100개 프로젝트를 선택할 수 있습니다.

1. **트리거 추가**에서 다음을 선택합니다.
   - 하나 이상의 [트리거 이벤트 유형](../triggers/_index.md#trigger-event-types).
   - 트리거 이벤트 유형에 필요한 경우 트리거 이벤트 작업.
1. **활성화**를 선택합니다.

{{< /tab >}}

{{< /tabs >}}

외부 에이전트는 그룹 및 프로젝트 **AI** > **에이전트** 페이지에 나타납니다. 최상위 그룹의 모든 프로젝트의 구성원은 이제 자신의 프로젝트에서 에이전트를 사용으로 설정할 수 있습니다.

서비스 계정이 그룹에 생성됩니다. 계정의 이름은 다음 명명 규칙을 따릅니다. `ai-<agent>-<group>`.

## 프로젝트에서 사용으로 설정 {#enable-in-a-project}

외부 에이전트가 이미 최상위 그룹에서 활성화되어 있으면 그룹의 프로젝트에서 활성화할 수 있습니다.

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 에이전트가 프로젝트의 최상위 그룹에서 사용 가능하도록 설정되어 있어야 합니다.

프로젝트에서 외부 에이전트를 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **AI** > **에이전트**를 선택합니다.
1. 오른쪽 위 모서리에서 **그룹에서 에이전트 사용으로 설정**를 선택합니다.
1. 드롭다운 목록에서 활성화하려는 외부 에이전트를 선택합니다.
1. **트리거 추가**에서 다음을 선택합니다.
   - 하나 이상의 [트리거 이벤트 유형](../triggers/_index.md#trigger-event-types).
   - 트리거 이벤트 유형에 필요한 경우 트리거 이벤트 작업.
1. **활성화**를 선택합니다.

외부 에이전트는 프로젝트의 **AI** > **에이전트** 목록에 나타납니다.

최상위 그룹의 서비스 계정이 프로젝트에 추가됩니다. 이 계정에는 Developer 역할이 할당됩니다.

## 외부 에이전트 사용 {#use-an-external-agent}

사전 요구 사항:

- 프로젝트에 대해 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.
- GitLab-관리 외부 에이전트 및 AI 카탈로그에서 생성된 사용자 정의 외부 에이전트의 경우 외부 에이전트를 프로젝트에서 활성화해야 합니다.
- 에이전트가 에이전트가 생성한 브랜치(^duo/(fix\|feature\|refactor\|docs/).\*\`로 시작하는 브랜치)에 푸시하도록 허용하려면 [브랜치 규칙](../../project/repository/branches/branch_rules.md)을 생성해야 할 수도 있습니다.

1. 프로젝트에서 이슈, 머지 리퀘스트 또는 에픽을 엽니다.
1. 서비스 계정 사용자에게 언급, 할당 또는 검토 요청을 합니다. 예를 들어:

   ```plaintext
   @service-account-username Can you help analyze this code change?
   ```

1. 외부 에이전트가 작업을 완료한 후 확인과 머지 가능한 변경 또는 인라인 댓글이 표시됩니다.

## 사용자 정의 외부 에이전트 만들기 {#create-a-custom-external-agent}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

{{< history >}}

- GitLab 18.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/207610)된 이름이 `ai_catalog_third_party_flows`인 플래그가 있습니다. GitLab.com에서 사용으로 설정되었습니다.
- GitLab 18.8의 [GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/218840)되었습니다.
- GitLab 18.8에서 추가 `ai_catalog_create_third_party_flows` [플래그](../../../administration/feature_flags/_index.md)를 요구하도록 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/217634)되었습니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

GitLab Self-Managed에서 `ai_catalog_create_third_party_flows` 기능 플래그가 활성화되면 AI 카탈로그로 외부 에이전트를 만들고 환경에서 실행하도록 구성할 수 있습니다.

GitLab.com에서는 사용자 정의 외부 에이전트를 만들 수 없습니다. 대신 [GitLab-관리 외부 에이전트](#quickstart-for-gitlab-managed-external-agents)를 사용합니다.

권장되는 워크플로우는:

1. AI 카탈로그에 에이전트를 만듭니다.
1. 프로젝트에 대해 에이전트를 활성화하고 에이전트를 호출하는 방법을 결정하는 트리거를 지정합니다.

이 경우 서비스 계정이 자동으로 생성됩니다. 에이전트가 실행되면 사용자의 멤버십과 서비스 계정 멤버십의 조합을 사용합니다. 이 조합을 [복합 ID](../composite_identity.md)라고 합니다.

선호하는 경우 [외부 에이전트를 수동으로 만들기](#create-an-external-agent-manually)할 수 있습니다.

### 에이전트 가시성 {#agent-visibility}

{{< history >}}

- 비공개 에이전트를 볼 수 있는 역할이 GitLab 18.7에서 [확장되었습니다](https://gitlab.com/gitlab-org/gitlab/-/work_items/582507).
- GitLab 19.3에서 `ai_catalog_internal_visibility`라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 제한된 표시 여부가 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/603253)되었습니다. 기본적으로 활성화됩니다.
- GitLab 19.4에서 일반적으로 사용 가능합니다. 기능 플래그 `ai_catalog_internal_visibility`이 제거되었습니다.

{{< /history >}}

사용자 정의 외부 에이전트를 만들 때 관리할 프로젝트를 선택하고 에이전트가 공개, 비공개 또는 제한인지 선택합니다.

공개 에이전트:

- 모든 사용자가 볼 수 있으며 사전 요구 사항을 충족하는 모든 프로젝트에서 사용으로 설정할 수 있습니다.

제한된 에이전트:

- 관리 프로젝트의 최상위 그룹에 있는 모든 프로젝트의 구성원이 볼 수 있고 사용할 수 있습니다.
- 동일한 최상위 수준 그룹의 다른 프로젝트에 사용으로 설정할 수 있습니다.
- 해당 최상위 그룹 외부에서 보거나 활성화할 수 없습니다.
- 탐색의 AI 카탈로그에서 볼 수 없습니다.
- 프로젝트에서만 만들 수 있으며 탐색의 AI 카탈로그에서는 만들 수 없습니다.

해당 최상위 그룹 외부의 프로젝트에서 에이전트가 활성화된 경우 공개 에이전트를 제한됨으로 설정할 수 없습니다.

비공개 에이전트:

- 게스트, 계획자, 보고자, 개발자, 유지 관리자 또는 소유자 역할이 있는 관리 프로젝트의 구성원만 볼 수 있습니다.
- 관리 프로젝트 이외의 프로젝트에서는 사용 가능하도록 설정할 수 없습니다.

관리 프로젝트 이외의 프로젝트에서 에이전트가 활성화된 경우 공개 또는 제한된 에이전트를 비공개로 설정할 수 없습니다.

### AI 카탈로그에서 에이전트 만들기 {#create-the-agent-in-the-ai-catalog}

{{< history >}}

- GitLab 19.3에서 `ai_catalog_internal_visibility`라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 제한된 표시 여부가 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/603253)되었습니다. 기본적으로 활성화됩니다.
- GitLab 19.4에서 일반적으로 사용 가능합니다. 기능 플래그 `ai_catalog_internal_visibility`이 제거되었습니다.

{{< /history >}}

AI 카탈로그에서 외부 에이전트를 만들기로 시작합니다.

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

외부 에이전트를 만들려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **AI** > **에이전트**를 선택합니다.
1. **새 에이전트**를 선택합니다.
1. **기본 정보** 아래:
   1. **이름 표시**에서 이름을 입력합니다.
   1. **설명**에서 설명을 입력합니다.
1. **표시 여부 및 액세스** 아래에 **표시 여부**에서 **비공개**, **제한됨** 또는 **공개**를 선택합니다.
1. **구성** 아래:
   1. **외부**를 선택합니다.
   1. 외부 에이전트 구성을 입력합니다. 자신의 YAML을 작성하거나 예제 구성을 편집할 수 있습니다.
1. **에이전트 만들기**를 선택합니다.

외부 에이전트가 AI 카탈로그에 나타납니다.

YAML 구성의 최대 크기가 있습니다. 자세한 내용은 [구성 크기 제한](../ai_catalog.md#configuration-size-limits)을 참조하세요.

### 외부 에이전트를 수동으로 만들기 {#create-an-external-agent-manually}

UI 플로우를 따르지 않으려면 외부 에이전트를 수동으로 만들 수 있습니다:

1. 프로젝트에 구성 파일을 만듭니다.
1. 서비스 계정을 만듭니다.
1. 에이전트를 호출하는 방법을 결정하는 트리거를 만듭니다.
1. 에이전트를 사용합니다.

이 경우 에이전트를 실행하는 데 사용되는 서비스 계정을 수동으로 만듭니다.

#### 구성 파일 만들기 {#create-a-configuration-file}

구성 파일을 수동으로 추가하여 외부 에이전트를 만드는 경우 각 외부 에이전트에 대해 다른 구성 파일을 만들어야 합니다.

사전 요구 사항:

- 프로젝트에 대해 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.

구성 파일을 만들려면:

1. 프로젝트에서 YAML 파일을 만듭니다(예: `.gitlab/duo/flows/claude.yaml`).
1. [구성 파일 예제 중 하나](external_examples.md)를 사용하여 파일을 채웁니다.

#### 서비스 계정 만들기 {#create-a-service-account}

외부 에이전트를 사용할 것으로 예상되는 프로젝트에 액세스할 수 있는 [서비스 계정](../../profile/service_accounts.md)을 만들어야 합니다.

에이전트가 실행되면 사용자의 멤버십과 서비스 계정 멤버십의 조합을 사용합니다. 이 조합을 [복합 ID](../composite_identity.md)라고 합니다.

사전 요구 사항:

- GitLab Self-Managed에서는 다음 중 하나가 있어야 합니다:
  - 인스턴스에 대한 관리자 액세스
  - 최상위 그룹의 소유자 역할 및 [서비스 계정을 만들 수 있는 권한](../../../administration/settings/account_and_limit_settings.md#allow-top-level-group-owners-to-create-service-accounts).

외부 에이전트를 언급하는 각 프로젝트는 고유한 [그룹 서비스 계정](../../profile/service_accounts.md)을 가져야 합니다. 외부 에이전트에 작업을 할당할 때 서비스 계정 사용자 이름을 언급합니다.

AI 카탈로그에서 외부 에이전트를 만들고 최상위 그룹에서 활성화하면 `ai-<agent>-<group>` 이름의 서비스 계정이 자동으로 생성됩니다. 예를 들어 `Claude code agent` 그룹에서 `GitLab Duo` 에이전트를 활성화하면 서비스 계정 이름은 `ai-claude-code-agent-gitlab-duo`입니다.

> [!warning]
> 같은 서비스 계정을 여러 프로젝트에서 사용하면 해당 서비스 계정에 연결된 외부 에이전트가 모든 해당 프로젝트에 액세스할 수 있습니다.

서비스 계정을 설정하려면 다음 작업을 수행합니다. 충분한 권한이 없으면 인스턴스 관리자 또는 최상위 그룹 소유자에게 도움을 요청합니다.

1. 최상위 그룹의 경우 [서비스 계정을 만듭니다](../../profile/service_accounts.md#create-a-service-account). 인스턴스에 대해 생성된 서비스 계정은 지원되지 않습니다.

   > [!note]
   > 외부 에이전트로 기존 서비스 계정을 구성하는 경우 해당 계정과 연결할 수 있는 개인 액세스 토큰이 없습니다. 이 동작은 서비스 계정을 보호하기 위한 것입니다.

1. [서비스 계정의 개인 액세스 토큰 만들기](../../profile/service_accounts.md#create-a-personal-access-token-for-a-service-account) (다음 [범위](../../../security/tokens/access_token_scopes.md) 포함):
   - `write_repository`
   - `api`
   - `ai_features`
1. [프로젝트에 서비스 계정 추가](../../project/members/_index.md#add-users-to-a-project) (개발자 역할 포함). 이는 서비스 계정이 필요한 최소 권한을 갖도록 합니다.

서비스 계정을 프로젝트에 추가할 때 서비스 계정의 정확한 이름을 입력해야 합니다. 잘못된 이름을 입력하면 외부 에이전트가 작동하지 않습니다.

#### 트리거 생성 {#create-a-trigger}

이제 [트리거를 만들어야](../triggers/_index.md) 하며, 이는 외부 에이전트가 실행되는 시기를 결정합니다.

예를 들어, 토론에서 서비스 계정을 언급하거나 서비스 계정을 검토자로 할당할 때 에이전트를 트리거하도록 지정할 수 있습니다.

## 외부 에이전트 켜기 또는 끄기 {#turn-external-agents-on-or-off}

{{< history >}}

- GitLab 19.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/594615)되었습니다.

{{< /history >}}

기본적으로 외부 에이전트는 켜져 있습니다. 최상위 그룹 또는 인스턴스에 대해 활성화 또는 비활성화할 수 있습니다.

외부 에이전트가 꺼져 있을 때:

- 사용자는 외부 에이전트를 만들거나, 활성화하거나, 비활성화하거나, 수정하거나, 실행할 수 없습니다. 여기에는 GitLab-관리 외부 에이전트와 사용자 정의 외부 에이전트가 모두 포함됩니다.
- 기존 외부 에이전트는 더 이상 프로젝트의 **AI** > **에이전트** > **활성화**에서 표시되지 않습니다.
- 프로젝트에서 만든 외부 에이전트는 **AI** > **에이전트** > **관리됨** 아래에 나타나지만 수정하거나 실행할 수 없습니다.
- [사용자 정의 에이전트](custom.md) 및 [기본 에이전트](foundational_agents/_index.md)는 계속 사용 가능합니다.

{{< tabs >}}

{{< tab title="GitLab.com" >}}

사전 요구 사항:

- 그룹에 대한 소유자 역할이 있어야 합니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **커스텀 외부 에이전트와 플로우**에서 **외부 에이전트 허용** 확인란을 선택하거나 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

이 설정은 그룹의 모든 하위 그룹으로 계단식으로 진행됩니다.

{{< /tab >}}

{{< tab title="GitLab Self-Managed" >}}

사전 요구 사항:

- 관리자여야 합니다.

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **GitLab Duo**를 선택합니다.
1. **구성 변경**을 선택합니다.
1. **커스텀 외부 에이전트와 플로우**에서 **외부 에이전트 허용** 확인란을 선택하거나 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

인스턴스 수준 설정이 꺼져 있으면 그룹 수준 설정은 이를 재정의할 수 없습니다.

{{< /tab >}}

{{< /tabs >}}
