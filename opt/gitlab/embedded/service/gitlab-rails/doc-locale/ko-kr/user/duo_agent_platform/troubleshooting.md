---
stage: Agent Foundations
group: Agent Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "GitLab Duo Agent Platform의 플로우, 권한 및 푸시 규칙 구성을 포함한 일반적인 문제를 해결합니다."
title: GitLab Duo Agent Platform 문제 해결
---

GitLab Duo Agent Platform으로 작업할 때 다음과 같은 문제가 발생할 수 있습니다.

## 로그 보기 {#view-logs}

플로우를 생성한 후 **AI** > **세션**으로 이동하여 플로우의 세션을 볼 수 있습니다.

**상세정보** 탭에는 CI/CD 작업 로그로의 링크가 표시됩니다. 이러한 로그에는 문제 해결 정보가 포함될 수 있습니다.

## UI에서 보이지 않는 플로우 {#flows-not-visible-in-the-ui}

플로우를 실행하려고 하지만 GitLab UI에 표시되지 않으면:

1. 프로젝트에서 최소한 개발자 역할이 있는지 확인하세요.
1. GitLab Duo가 [켜져 있고 플로우가 실행되도록 허용되었는지](../gitlab_duo/turn_on_off.md) 확인하세요.
1. 당신이 속한 그룹이 [플로우 사용](../../administration/gitlab_duo/configure/access_control.md) 권한을 받았는지 확인하세요.
1. 최상위 그룹이 올바르게 구성되었지만 개별 프로젝트에 플로우가 표시되지 않으면:
   1. 프로젝트로 이동하세요.
   1. **AI** > **플로우**를 선택합니다.
   1. 오른쪽 위 모서리에서 **그룹에서 플로우 활성화**를 선택합니다.
   1. 플로우를 선택한 후 **활성화**을 선택하세요.

1. 여전히 작동하지 않으면:
   1. 최상위 그룹에서 영향을 받는 플로우를 비활성화하고 구성을 저장합니다.
   1. 최상위 그룹에서 영향을 받는 플로우를 활성화하고 구성을 저장합니다.
   1. 설정이 그룹 전체에 전파될 때까지 몇 분 기다립니다.

## 가져온 프로젝트의 새로운 파이프라인을 만들 권한 부족 {#insufficient-permissions-to-create-a-new-pipeline-for-imported-projects}

가져온 프로젝트 또는 템플릿에서 생성된 프로젝트에서 기본 플로우를 실행하려고 하면 다음 오류가 발생할 수 있습니다: `Error in creating workload: Insufficient permissions to create a new pipeline`.

이 문제를 해결하려면:

1. 최상위 그룹으로 이동하세요.
1. **설정** > **일반**을 선택합니다.
1. **GitLab Duo 기능**을 확장합니다.
1. **플로우 실행**에서 활성화할 기본 플로우를 확인합니다.
1. 최상위 그룹에서 플로우를 비활성화하고 구성을 저장합니다.
1. 최상위 그룹에서 동일한 플로우를 활성화하고 구성을 저장합니다.
1. 설정이 그룹의 프로젝트 전체에 전파될 때까지 몇 분 기다립니다.

## 오류: `Your request was valid but Workflow failed to complete it` {#error-your-request-was-valid-but-workflow-failed-to-complete-it}

플로우는 프로젝트 리포지토리에 최소 하나 이상의 커밋이 있어야 합니다. 커밋이 없는 프로젝트에서 플로우를 실행하면 다음 오류가 발생합니다: `Your request was valid but Workflow failed to complete it. Please try again.`

이 오류는 플로우가 커밋이 없는 리포지토리의 기본 브랜치를 찾을 수 없기 때문에 발생합니다.

이 문제를 해결하려면 플로우를 실행하기 전에 프로젝트에 초기 커밋을 푸시하세요. 예를 들어 `README.md` 파일을 추가합니다.

## 세션이 생성된 상태에서 멈춤 {#session-is-stuck-in-created-state}

플로우의 세션이 시작되지 않으면:

- 푸시 규칙이 구성되어 있는지 확인하세요.

### 서비스 계정을 허용하도록 푸시 규칙 구성 {#configure-push-rules-to-allow-a-service-account}

GitLab UI에서 기본 플로우는 다음을 수행하는 서비스 계정을 사용합니다:

- 자신의 이메일 주소로 커밋을 생성합니다.
- [워크로드 파이프라인](../../ci/pipelines/pipeline_types.md#workload-pipeline)을 생성합니다.

사전 요구 사항:

- 관리자 액세스 권한이 있어야 합니다.

프로젝트의 푸시 규칙을 구성하려면:

1. 서비스 계정과 연결된 이메일 주소를 찾습니다:
   1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
   1. **개요** > **사용자**을 선택하고 플로우와 연결된 계정을 검색합니다. 계정은 `duo-[flow-name]-[top-level-group-name]` 패턴을 따릅니다.
   1. 서비스 계정 사용자를 찾고 이메일 주소를 복사합니다.

1. 프로젝트에 푸시할 이메일 주소를 허용합니다:
   1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
   1. **설정** > **리포지토리**를 선택합니다.
   1. **푸시 규칙**을 확장합니다.
   1. **작성자의 이메일 커밋**에서 방금 복사한 이메일 주소를 허용하는 정규식을 추가합니다.
   1. **푸시 규칙 저장**을 선택합니다.

1. `duo/feature/` 브랜치 접두사를 허용합니다:
   1. **푸시 규칙** 섹션에서 **브랜치 이름**을 찾습니다.
   1. ^duo/(fix\|feature\|refactor\|docs/).\*로 시작하는 브랜치를 허용하는 정규식을 추가합니다. 예를 들어: `^(duo/feature)/.*$`
   1. **푸시 규칙 저장**을 선택합니다.

인스턴스에 대한 푸시 규칙을 생성하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **푸시 규칙**을 선택합니다.
1. 이전 단계를 따라 **작성자의 이메일 커밋**과 **브랜치 이름**을 허용합니다.
1. **푸시 규칙 저장**을 선택합니다.

## 플로우의 작업 또는 세션이 시작되지 않음 {#a-flows-job-or-session-fails-to-start}

플로우의 작업이 시작되지 않거나 작업이 `Starting job`에서 멈춘 경우 작업을 선택할 러너가 없습니다. 세션 페이지 (**AI** > **세션**)에 `Session failed to start` 알림이 나타납니다.

플로우는 다음 요구사항을 충족하는 러너에서 실행됩니다:

- 러너에는 `gitlab--duo` 태그가 있습니다.
- 러너는 Docker 이미지를 지원하는 실행기(예: `docker`, `docker-autoscaler` 또는 `kubernetes`)를 사용합니다. `shell` 실행기는 지원되지 않습니다.
- 러너는 인스턴스 러너이거나 최상위 그룹에 할당된 그룹 러너입니다. 하위 그룹 또는 프로젝트 범위의 러너는 `duo_runner_restrictions` 기능 플래그가 해제되지 않으면 플로우 작업을 선택하지 않습니다.

이 이슈를 해결하려면:

1. GitLab.com에서 프로젝트에 대해 [호스팅되는 러너](../../ci/runners/hosted_runners/_index.md)가 켜져 있는지 확인합니다. 호스팅되는 러너는 기본적으로 모든 요구사항을 충족합니다.
1. 자신의 러너를 사용하는 경우 최소한 하나의 러너가 요구사항을 충족하는지 확인하세요:
   1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트 또는 최상위 그룹을 찾습니다.
   1. 왼쪽 사이드바에서 **빌드** > **러너**를 선택합니다.
   1. `gitlab--duo` 태그가 있는 러너가 온라인 상태인지 확인합니다.
1. 선택 사항. 프로젝트 설정에서 [러너 구성 확인](flows/execution/_index.md#verify-the-runner-configuration)을 수행합니다. 이는 태그, 실행기 및 범위를 함께 확인합니다.
1. 어떤 러너도 요구사항을 충족하지 않으면 [플로우를 실행하도록 러너 구성](flows/execution/_index.md#configure-runners-to-execute-flows)을 수행합니다.

러너가 모든 요구사항을 충족하지만 작업이 시작되지 않으면 다음을 확인하세요:

- 네임스페이스가 [컴퓨팅 분](../../ci/pipelines/instance_runner_compute_minutes.md#enforcement)을 모두 사용했으며, 이는 호스팅되는 러너에 대한 액세스도 제거합니다. 할당량 부족은 러너 가용성 문제처럼 보일 수 있습니다.
- 최상위 그룹이 [IP 주소로 액세스 제한](../group/access_and_permissions.md#restrict-group-access-by-ip-address)합니다. 호스팅되는 러너는 동적 IP 주소를 사용하므로 허용 목록에 추가할 수 없으므로 해당 그룹의 플로우를 실행할 수 없습니다. 대신 최상위 그룹에서 자신의 러너를 구성합니다.

## 오류: `Something went wrong while requesting a review from GitLab Duo` {#error-something-went-wrong-while-requesting-a-review-from-gitlab-duo}

GitLab 18.8 이전에는 이 오류 메시지가 Code Review 플로우 실패에 대해 나타납니다. 다음은 일반적인 근본 원인입니다:

- 기본 플로우 서비스 계정이 생성되지 않았습니다.
- 그룹 멤버십 잠금이 서비스 계정이 프로젝트에 추가되는 것을 방지하고 있습니다.
- 당신은 여러 GitLab Duo 네임스페이스에 속하고 기본 네임스페이스가 설정되지 않았습니다.

GitLab 18.9 이상에서는 더 구체적인 오류 메시지가 대신 나타납니다. 자세한 내용은 [Code Review 플로우 문제 해결](flows/foundational_flows/code_review/troubleshooting.md)을 참조하세요.

### 기본 플로우 서비스 계정이 생성되지 않음 {#foundational-flow-service-account-not-created}

기본 플로우가 켜져 있지만 작동하지 않으면 최상위 그룹의 서비스 계정이 성공적으로 생성되지 않았을 수 있습니다.

서비스 계정이 있는지 확인하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 최상위 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **Service Accounts**를 선택합니다.
1. `duo-[flow-name]-[top-level-group-name]` 라는 계정을 찾습니다.

계정이 없으면 `CascadeSyncFoundationalFlowsWorker`이 생성하지 못했을 수 있습니다. 계정이 없는지 확인하려면 다음 오류의 Sidekiq 로그를 확인하세요:

```json
{
  "severity": "ERROR",
  "meta.caller_id": "Ai::Catalog::Flows::CascadeSyncFoundationalFlowsWorker",
  "message": "Cannot obtain an exclusive lease. There must be another instance already in execution.",
  "lease_key": "sidekiq:concurrency_limit:{ai/catalog/flows/cascade_sync_foundational_flows_worker}",
  "lease_timeout": 600
}
```

이 문제를 해결하려면 [기본 플로우를 해제](flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off)하고 10분 후에 다시 활성화합니다.

### 그룹 멤버십 잠금 {#group-membership-locked}

최상위 그룹에 대해 [멤버십이 잠긴](../group/access_and_permissions.md#prevent-members-from-being-added-to-projects-in-a-group) 경우 서비스 계정을 필요한 프로젝트에 추가할 수 없기 때문에 기본 플로우가 조용히 실패합니다.

이 이슈를 해결하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 최상위 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **권한 및 그룹 기능**을 확장합니다.
1. **이 그룹의 프로젝트에 사용자를 추가할 수 없습니다.** 확인란을 선택 취소한 후 **변경사항 저장**을 선택합니다.
1. [기본 플로우를 해제](flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off)한 후 **변경사항 저장**을 선택합니다.
1. 기본 플로우를 다시 활성화한 후 **변경사항 저장**을 선택합니다.
1. **이 그룹의 프로젝트에 사용자를 추가할 수 없습니다.** 확인란을 선택한 후 **변경사항 저장**을 선택합니다.

### 기본 GitLab Duo 네임스페이스가 설정되지 않음 {#default-gitlab-duo-namespace-not-set}

GitLab 18.3 이상에서 여러 GitLab Duo 네임스페이스에 속하고 기본 네임스페이스가 설정되지 않으면 GitLab Duo Agent Platform이 해제됩니다.

GitLab 18.8 이전에는 다음 오류 메시지가 표시될 수 있습니다:

```plaintext
Something went wrong while requesting a review from GitLab Duo.
```

GitLab 18.9 이상에서는 네임스페이스 관련 오류가 발생할 수 있습니다.

이 문제를 해결하려면 [기본 GitLab Duo 네임스페이스를 설정](../profile/preferences.md#set-a-default-gitlab-duo-namespace)합니다.

## 오류: `SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)` {#error-ssl-certificate-openssl-verify-result-unable-to-get-local-issuer-certificate-20}

GitLab Self-Managed 인스턴스에서 사용자 지정 또는 자체 서명된 CA 인증서를 사용하는 경우 GitLab Duo Agent Platform 작업이 초기 `git clone` (the `get_sources` 단계) 중에 실패할 때 이 메시지가 표시될 수 있습니다.

GitLab Duo Agent Platform 작업이 `GIT_CONFIG_GLOBAL=/dev/null` 및 `GIT_CONFIG_NOSYSTEM=1`을 설정하여 에이전트 샌드박스를 강화하기 때문에 발생합니다. 이러한 변수는 Git이 시스템 및 전역 구성 파일을 읽는 것을 방지합니다. 이는 `get_sources` 중에 CA 인증서 경로를 삽입하는 러너의 메커니즘을 깨뜨립니다.

플로우를 실행하지 않는 CI/CD 작업은 영향을 받지 않습니다. 이 문제는 GitLab Duo Agent Platform의 워크로드 파이프라인에만 해당됩니다.

이 문제를 해결하려면 [`config.toml`](https://docs.gitlab.com/runner/configuration/advanced-configuration/) 파일에서 `GIT_SSL_CAINFO` 환경 변수를 러너 수준에서 설정하고 CA 인증서를 컨테이너에 마운트합니다:

```toml
[[runners]]
  environment = ["GIT_SSL_CAINFO=/etc/gitlab-runner/certs/ca.crt"]
  [runners.docker]
    volumes = ["/path/to/your/ca-bundle.crt:/etc/gitlab-runner/certs/ca.crt:ro"]
```

`/path/to/your/ca-bundle.crt`을(를) 러너 호스트의 CA 인증서 번들 경로로 바꿉니다. 파일은 PEM 형식의 CA 번들이어야 하며 루트 CA 및 모든 중간 인증서를 포함해야 합니다.

이를 CI/CD 변수로 설정하려고 할 수 있지만 사용자 지정 CI/CD 변수는 GitLab Duo Agent Platform 작업에서 [사용할 수 없습니다](flows/execution/execution-variables.md#custom-cicd-variables). 대신 러너의 `config.toml` `environment` 지시어를 사용해야 합니다.

GitLab Duo CLI를 사용자 지정 CA를 통해 GitLab 인스턴스에 연결하려면 `NODE_EXTRA_CA_CERTS`을(를) 동일한 `environment` 라인에 추가합니다:

```toml
[[runners]]
  environment = [
    "GIT_SSL_CAINFO=/etc/gitlab-runner/certs/ca.crt",
    "NODE_EXTRA_CA_CERTS=/etc/gitlab-runner/certs/ca.crt"
  ]
  [runners.docker]
    volumes = ["/path/to/your/ca-bundle.crt:/etc/gitlab-runner/certs/ca.crt:ro"]
```

GitLab Duo CLI는 빈 환경으로 시작하는 Anthropic Sandbox Runtime (SRT) 내에서 실행됩니다. 작업에서 다음 인증서 및 프록시 변수를 설정하면 샌드박스로 전달됩니다:

- `NODE_EXTRA_CA_CERTS`
- `HTTP_PROXY`, `HTTPS_PROXY` 및 `NO_PROXY`
- 소문자로 된 `http_proxy`, `https_proxy` 및 `no_proxy`

러너의 `environment` 지시어에서 이러한 변수를 설정하거나 `agent-config.yml` 파일의 `setup_script`에서 내보냅니다. 다른 변수는 전달되지 않습니다.

이러한 변수는 GitLab 인스턴스에 대한 연결뿐 아니라 샌드박스의 모든 Node.js 네트워크 트래픽에 적용됩니다. `NODE_EXTRA_CA_CERTS`은 파일을 가리키므로 앞에서 표시한 대로 CA 인증서를 컨테이너에 마운트합니다.

`NODE_TLS_REJECT_UNAUTHORIZED`은 전달되지 않습니다. `0`로 설정하면 TLS 검증이 꺼지기 때문입니다. 대신 `NODE_EXTRA_CA_CERTS`을 사용합니다.

`GIT_SSL_CAINFO` 변수는 GitLab Duo CLI가 시작되기 전에 발생하는 Git 작업을 처리합니다. GitLab Duo CLI 인증서 구성의 경우 [인증서 오류](../gitlab_duo_cli/use.md#certificate-errors)를 참조하세요.

## WebSocket 오류 `1006` 또는 `404` 로 인한 연결 실패 {#connection-fails-with-websocket-error-1006-or-404}

GitLab Duo CLI, GitLab 언어 서버 및 IDE 클라이언트 (GitLab for VS Code, GitLab Duo plugin for JetBrains IDEs 및 GitLab for Visual Studio)는 WebSocket 연결을 통해 GitLab Duo Agent Platform에 연결합니다. 이 연결이 실패하면 클라이언트는 다음 오류 중 하나를 기록합니다:

- `1006`: WebSocket이 비정상적으로 종료되어 종료 핸드셰이크가 없습니다.
- `404`: 클라이언트는 다음 WebSocket 엔드포인트에 도달할 수 없습니다:
  - GitLab Duo Non-Agentic의 경우: `/-/cable`.
  - GitLab Duo Agent Platform의 경우: `wss://\<instance\>/api/v4/ai/duo_workflows/ws`.

이러한 오류는 일반적으로 사용자 지정 인증 기관 (CA), HTTP 프록시, TLS 검사 프록시 또는 네트워크의 상호 TLS (mTLS) 프록시가 연결을 방해할 때 발생합니다. 이 문제를 해결하려면 다음 원인을 확인하세요.

### 사용자 지정 CA 인증서 {#custom-ca-certificate}

네트워크에서 사용자 지정 또는 자체 서명된 CA 인증서를 사용하면 클라이언트가 GitLab 인스턴스에 대한 연결을 확인할 수 없습니다. 클라이언트에 대한 인증서를 구성합니다:

- GitLab Duo CLI의 경우 `NODE_EXTRA_CA_CERTS` 환경 변수를 CA 인증서의 경로로 설정합니다.
- IDE 클라이언트의 경우 GitLab 언어 서버가 인증서를 관리합니다. JetBrains IDE의 경우 [인증서 오류](../../editor_extensions/jetbrains_ide/jetbrains_troubleshooting.md#certificate-errors)를 참조하세요. VS Code의 경우 [사용자 지정 인증서의 오류](../../editor_extensions/visual_studio_code/troubleshooting.md#errors-with-custom-certificates)를 참조하세요.

### HTTP 프록시 {#http-proxy}

네트워크에 HTTP 프록시가 필요한 경우 클라이언트에 대한 프록시를 구성합니다:

- GitLab Duo CLI의 경우 `HTTP_PROXY`, `HTTPS_PROXY` 및 `NO_PROXY` 환경 변수를 설정합니다.
- IDE 클라이언트의 경우 [프록시를 사용하도록 언어 서버 구성](../../editor_extensions/language_server/_index.md#configure-the-language-server-to-use-a-proxy)합니다.

### WebSocket 트래픽 차단 {#websocket-traffic-blocked}

`404` 오류 또는 로그에 `/-/cable` WebSocket 엔드포인트 대신 `HTTP/1.1` 응답이 보이면 GitLab 인스턴스가 인바운드 WebSocket 연결을 차단할 수 있습니다. 관리자에게 [GitLab 인스턴스로의 WebSocket 트래픽 허용](../../administration/gitlab_duo/configure/_index.md#allow-inbound-connections-from-clients-to-the-gitlab-instance)을 요청합니다.

### mTLS 또는 TLS 검사 프록시 {#mtls-or-tls-inspection-proxy}

네트워크가 TLS 검사 (SSL 가로채기) 프록시를 통해 트래픽을 라우팅하는 경우 다음을 모두 구성합니다:

- `HTTPS_PROXY` 환경 변수를 프록시 URL로 설정합니다.
- 프록시의 [CA 인증서](#custom-ca-certificate)를 추가합니다.

GitLab Duo CLI, GitLab Duo plugin for JetBrains IDEs 및 GitLab for Visual Studio에는 하나의 알려진 문제가 있습니다. 프록시 URL이 `https://`을 사용하면 WebSocket 연결이 실패합니다. 가능하면 `http://` 프록시 URL을 사용합니다.

GitLab for VS Code는 영향을 받지 않습니다.

## IDE에서 문제 해결 {#troubleshooting-in-your-ide}

IDE에서 GitLab Duo Agent Platform으로 작업하는 동안 문제가 발생하면 먼저 GitLab Duo가 켜져 있고 제대로 연결되어 있는지 확인합니다.

- 당신은 GitLab Duo Agent Platform [사전 조건](_index.md#prerequisites)을 충족합니다.
- 관리 모드가 [비활성화](../../administration/settings/sign_in_restrictions.md#turn-off-admin-mode-for-your-session)되었습니다.
- 당신의 프로젝트는 [그룹 네임스페이스](../namespace/_index.md)에 있습니다.
- 당신은 [기본 GitLab Duo 네임스페이스](../profile/preferences.md#namespace-resolution-in-your-local-environment)를 설정했거나 GitLab Duo 액세스가 있는 프로젝트를 열었습니다.

추가 지원을 보려면 확장 및 IDE의 문제 해결 페이지를 참조하세요:

- [GitLab for VS Code](../../editor_extensions/visual_studio_code/troubleshooting.md#gitlab-duo)
- [GitLab Duo plugin for JetBrains IDEs](../../editor_extensions/jetbrains_ide/jetbrains_troubleshooting.md)
- [GitLab for Visual Studio](../../editor_extensions/visual_studio/visual_studio_troubleshooting.md)

## 구성 진단 스크립트 실행 {#run-the-configuration-diagnostic-script}

관련 기능 설명서에서 GitLab Duo Agent Platform 문제의 원인을 파악할 수 없으면 진단 스크립트를 실행하여 구성을 확인합니다.

스크립트는 GitLab Duo Agent Platform 기능에 필요한 전체 구성 체인을 확인합니다:

- 라이선스 유효성 및 계획.
- 인스턴스 수준 GitLab Duo 설정.
- `gitlab--duo` 태그가 있는 CI/CD 러너.
- 네임스페이스 및 프로젝트 GitLab Duo 설정.
- 기본 플로우 및 해당 서비스 계정.
- Code Review Flow 가용성 및 자동 검토 설정과 같은 기능 가용성.

> [!warning]
> 이 스크립트는 구성 데이터만 읽으며 설정을 수정하지 않습니다. 출력에는 내부 구성 세부정보가 포함될 수 있습니다. 지원과 공유하기 전에 출력을 정제합니다.

사전 요구 사항:

- GitLab 18.8 이상

GitLab 19.0 이상에서 진단 스크립트를 실행하려면:

- 내장된 `gitlab:duo:verify_setup` [Rake 작업](../../administration/raketasks/_index.md)을 실행합니다. `<group/project>`을(를) 프로젝트의 전체 경로 (예: `gitlab-org/gitlab`)로 바꿉니다.

  예를 들어:

  ```shell
  sudo gitlab-rake "gitlab:duo:verify_setup[<group/project>]"
  ```

GitLab 18.8에서 GitLab 18.11까지 진단 스크립트를 실행하려면:

{{< tabs >}}

{{< tab title="Linux 패키지(Omnibus)" >}}

1. [`verify_setup.rb`](https://gitlab.com/gitlab-org/gitlab/-/raw/master/ee/lib/gitlab/duo/administration/verify_setup.rb)를 다운로드합니다.
1. `verify_setup.rb` 파일을 GitLab 서버로 복사합니다.
1. 스크립트를 실행합니다. `<group/project>`을(를) 프로젝트의 전체 경로 (예: `gitlab-org/gitlab`)로 바꿉니다.

   ```shell
   sudo gitlab-rails runner "load '/tmp/verify_setup.rb'; Gitlab::Duo::Administration::VerifySetup.new('<group/project>').execute"
   ```

{{< /tab >}}

{{< tab title="Docker" >}}

1. [`verify_setup.rb`](https://gitlab.com/gitlab-org/gitlab/-/raw/master/ee/lib/gitlab/duo/administration/verify_setup.rb)를 다운로드합니다.
1. `verify_setup.rb` 파일을 컨테이너로 복사합니다.
1. 스크립트를 실행합니다. `<group/project>`을(를) 프로젝트의 전체 경로 (예: `gitlab-org/gitlab`)로 바꿉니다.

   ```shell
   docker cp verify_setup.rb <container-id>:/tmp/verify_setup.rb
   docker exec -it <container-id> gitlab-rails runner \
   "load '/tmp/verify_setup.rb'; Gitlab::Duo::Administration::VerifySetup.new('<group/project>').execute"
   ```

{{< /tab >}}

{{< tab title="Self-compiled(source)" >}}

1. [`verify_setup.rb`](https://gitlab.com/gitlab-org/gitlab/-/raw/master/ee/lib/gitlab/duo/administration/verify_setup.rb)를 다운로드합니다.
1. `verify_setup.rb` 파일을 GitLab 서버로 복사합니다.
1. GitLab 애플리케이션 디렉토리에서 스크립트를 실행합니다. `<group/project>`을(를) 프로젝트의 전체 경로 (예: `gitlab-org/gitlab`)로 바꿉니다.

   ```shell
   sudo -u git bundle exec rails runner \
   "load '/tmp/verify_setup.rb'; Gitlab::Duo::Administration::VerifySetup.new('<group/project>').execute"
   ```

{{< /tab >}}

{{< tab title="Helm 차트(Kubernetes)" >}}

1. [`verify_setup.rb`](https://gitlab.com/gitlab-org/gitlab/-/raw/master/ee/lib/gitlab/duo/administration/verify_setup.rb)를 다운로드합니다.
1. `verify_setup.rb` 파일을 toolbox pod로 복사합니다.
1. 스크립트를 실행합니다. `<group/project>`을(를) 프로젝트의 전체 경로 (예: `gitlab-org/gitlab`)로 바꿉니다.

   ```shell
   # Find the toolbox pod
   kubectl get pods --namespace <namespace> -lapp=toolbox

   kubectl cp verify_setup.rb <namespace>/<toolbox-pod-name>:/tmp/verify_setup.rb
   kubectl exec -it <toolbox-pod-name> -- gitlab-rails runner \
   "load '/tmp/verify_setup.rb'; Gitlab::Duo::Administration::VerifySetup.new('<group/project>').execute"
   ```

{{< /tab >}}

{{< /tabs >}}

## 관련 항목 {#related-topics}

- [GitLab Duo Agentic Chat 문제 해결](../gitlab_duo_chat/troubleshooting.md)
- [Code Review 플로우 문제 해결](flows/foundational_flows/code_review/troubleshooting.md)
- [GitLab MCP 클라이언트 문제 해결](../gitlab_duo/model_context_protocol/mcp_clients.md#troubleshooting)
- [GitLab MCP 서버 문제 해결](../model_context_protocol/mcp_server_troubleshooting.md)
