---
stage: Create
group: Remote Development
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 클러스터의 작업 영역을 인증하고 권한을 부여하기 위해 GitLab 작업 영역 프록시를 만듭니다.
title: 작업 영역 문제 해결
---

GitLab 작업 영역으로 작업할 때 다음 문제가 발생할 수 있습니다.

## 오류: `Failed to renew lease` {#error-failed-to-renew-lease}

작업 영역을 만들 때 에이전트 로그에서 다음 오류 메시지가 나타날 수 있습니다:

```plaintext
{"level":"info","time":"2023-01-01T00:00:00.000Z","msg":"failed to renew lease gitlab-agent-remote-dev-dev/agent-123XX-lock: timed out waiting for the condition\n","agent_id":XXXX}
```

이 오류는 GitLab 에이전트의 Kubernetes에서 알려진 문제로 인해 발생합니다. 이 오류는 에이전트 인스턴스가 리더십 리스를 갱신할 수 없을 때 발생하며, `remote_development`와 같은 리더 전용 모듈이 종료됩니다.

이 이슈를 해결하려면:

1. 에이전트 인스턴스를 다시 시작합니다.
1. 문제가 계속되면 Kubernetes 클러스터의 상태와 연결을 확인합니다.

## 오류: `Workspace create failed: Expiration date must be before <date>` {#error-workspace-create-failed-expiration-date-must-be-before-date}

작업 영역을 만들 때 UI에서 이 오류가 나타날 수 있습니다:

```plaintext
Workspace create failed: Expiration date must be before <date>
```

이 오류는 새로 만든 작업 영역에 대한 [인증을 위해 만든 개인 액세스 토큰](_index.md#personal-access-token)의 만료 날짜가 토큰 만료에 대한 인스턴스 설정을 초과할 때 발생합니다.

이 문제를 해결하려면 [인스턴스의 액세스 토큰 만료 제한](../../administration/settings/account_and_limit_settings.md#limit-the-lifetime-of-access-tokens)을 비활성화합니다. [이슈 579331](https://gitlab.com/gitlab-org/gitlab/-/work_items/579331)은 이 제한을 해결하기 위해 작업 영역 관련 토큰에 대한 구성 가능한 제한을 제안합니다.

## 오류: `No agents available to create workspaces` {#error-no-agents-available-to-create-workspaces}

프로젝트에서 작업 영역을 만들 때 다음 오류가 나타날 수 있습니다:

```plaintext
No agents available to create workspaces. Please consult Workspaces documentation for troubleshooting.
```

이 오류는 여러 가지 이유로 발생할 수 있습니다. 다음 문제 해결 단계를 수행합니다.

### 권한 확인 {#check-permissions}

1. 작업 영역 프로젝트와 에이전트 프로젝트 모두에 대해 개발자, 유지 관리자 또는 소유자 역할이 있는지 확인합니다.
1. 에이전트가 작업 영역 프로젝트의 상위 그룹에서 허용되는지 확인합니다.

자세한 내용은 [에이전트 허용](gitlab_agent_configuration.md#allow-a-cluster-agent-for-workspaces-in-a-group)을 참조하세요.

### 에이전트 구성 확인 {#check-agent-configuration}

에이전트 구성에서 `remote_development` 모듈이 활성화되어 있는지 확인합니다:

   ```yaml
   remote_development:
     enabled: true
   ```

GitLab 에이전트의 Kubernetes에 대해 `remote_development` 모듈이 비활성화되어 있으면 [`enabled`](settings.md#enabled)을 `true`로 설정합니다.

### 에이전트 이름 불일치 확인 {#check-agent-name-mismatch}

[Kubernetes 토큰에 대한 GitLab 에이전트 만들기](set_up_infrastructure.md#create-a-gitlab-agent-for-kubernetes-token) 단계에서 만든 에이전트 이름이 `.gitlab/agents/FOLDER_NAME/`의 폴더 이름과 일치하는지 확인합니다.

이름이 다르면 폴더의 이름을 바꿔 에이전트 이름과 정확히 일치하도록 합니다.

### 에이전트 연결 상태 확인 {#check-agent-connection-status}

에이전트가 GitLab에 연결되어 있는지 확인합니다:

1. 그룹으로 이동합니다.
1. **운영** > **Kubernetes 클러스터**를 선택합니다.
1. **연결 상태**가 **연결됨**인지 확인합니다. 연결되지 않았다면 에이전트 로그를 확인합니다:

   ```shell
   kubectl logs -f -l app=gitlab-agent -n gitlab-workspaces
   ```

## 오류: `unsupported scheme in kas address` {#error-unsupported-scheme-in-kas-address}

이 오류는 GitLab Relay(KAS) 주소에 필요한 프로토콜 체계가 없을 때 발생합니다.

이 이슈를 해결하려면:

1. `grpcs://` 또는 `wss://` 접두사를 `TF_VAR_kas_address` 변수에 추가합니다. 예: `grpcs://kas.gitlab.com`.
1. 구성을 업데이트하고 에이전트를 다시 배포합니다.

## 오류: 오프라인 환경에서 작업 영역을 시작할 때 `ImagePullBackOff` {#error-imagepullbackoff-when-starting-workspace-in-offline-environment}

오프라인 환경에서 작업 영역을 만들 때 이 오류가 나타날 수 있습니다:

```plaintext
workspace-example-abc123-def456   0/1   Init:ImagePullBackOff   0
```

이 오류는 작업 영역이 `registry.gitlab.com`에서 초기화 컨테이너 이미지를 끌어올 수 없을 때 발생합니다. 오프라인 환경에서 초기화 컨테이너 이미지는 하드코딩되어 있으며 devfile에서 재정의할 수 없습니다.

> [!warning]
> 다음 해결 방법은 지원되지 않으며 임시입니다. [이슈 509983](https://gitlab.com/gitlab-org/gitlab/-/issues/509983)이 지원되는 솔루션을 제공할 때까지 자신의 책임하에 사용합니다.

해결 방법은 다음과 같습니다:

1. [Kubernetes 뮤테이팅 웹훅](https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/)을 배포하여 초기화 컨테이너 이미지 참조를 수정합니다.
1. `MutatingWebhookConfiguration`을 만들고, 업데이트하거나, 삭제할 수 있는 클러스터 관리자 권한이 있는지 확인합니다.

구현 예는 [간단한 Kubernetes 승인 웹훅](https://slack.engineering/simple-kubernetes-webhook/)을 참조하세요.

## 오류: `redirect URI included is not valid` {#error-redirect-uri-included-is-not-valid}

작업 영역에 액세스할 때 잘못된 리디렉션 URI에 대한 OAuth 오류가 나타날 수 있습니다.

이 오류는 다음 이유로 발생할 수 있습니다:

- OAuth 애플리케이션이 올바르게 구성되지 않았습니다. 이 이슈를 해결하려면:
  1. GitLab의 OAuth 애플리케이션 리디렉션 URI가 도메인과 일치하는지 확인합니다.
  1. OAuth 애플리케이션 리디렉션 URI를 업데이트합니다. 예: `https://YOUR_DOMAIN/auth/callback`.
- 작업 영역 프록시가 오래된 OAuth 자격 증명을 사용 중입니다. 이 이슈를 해결하려면:
  1. 프록시가 최신 OAuth 자격 증명을 사용하고 있는지 확인합니다.
  1. 작업 영역 프록시를 다시 시작합니다:

     ```shell
     kubectl rollout restart deployment -n gitlab-workspaces gitlab-workspaces-proxy
     ```

## 오류: `Workspace does not exist` {#error-workspace-does-not-exist}

VS Code에서 다음 오류가 나타날 수 있습니다.

```plaintext
Workspace does not exist

Please select another workspace to open.
```

이 문제는 작업 영역이 성공적으로 시작되지만 Git 복제 작업이 실패했기 때문에 예상되는 프로젝트 디렉터리가 없을 때 발생합니다. Git 복제 작업은 네트워크 문제, 인프라 문제 또는 취소된 리포지토리 권한으로 인해 실패합니다.

이 이슈를 해결하려면:

1. 오류 대화 상자에서 다른 작업 영역을 선택하라는 메시지가 표시되면 **취소**를 선택합니다.
1. VS Code 메뉴에서 **파일** > **폴더 열기**를 선택합니다.
1. `/projects` 디렉터리로 이동한 후 **확인**을 선택합니다.
1. **탐색기** 패널에서 프로젝트와 같은 이름의 디렉터리를 확인합니다.
   - 디렉터리가 없으면 Git 복제 작업이 완전히 실패한 것입니다.
   - 디렉터리가 있지만 비어 있으면 복제 작업이 시작되었으나 완료되지 않았습니다.
1. 터미널을 엽니다. 메뉴에서 **터미널** > **새 터미널**을 선택합니다.
1. 작업 영역 로그 디렉터리로 이동합니다:

   ```shell
   cd /tmp/workspace-logs/
   ```

1. Git 복제가 실패한 이유를 나타낼 수 있는 오류 출력을 로그에서 확인합니다:

   ```shell
   less poststart-stderr.log
   ```

1. 식별된 문제를 해결하고 작업 영역을 다시 시작합니다.

문제가 계속되면 Git이 포함된 작동하는 컨테이너 이미지를 사용하여 새 작업 영역을 만듭니다.

## `postStart` 이벤트 디버깅 {#debug-poststart-events}

사용자 지정 `postStart` 이벤트가 실패하거나 예상대로 작동하지 않을 때 작업 영역 로그 디렉터리를 사용하여 문제를 디버깅할 수 있습니다.

일반적인 `postStart` 디버깅 시나리오 및 해결 방법:

- `Command not found`: `poststart-stderr.log`에서 컨테이너 이미지의 누락된 종속성을 나타내는 오류를 확인합니다.
- `Permission denied`: `poststart-stderr.log`에서 파일 권한 또는 사용자 구성을 조정해야 할 수 있는 권한 오류를 확인합니다.
- `Network issues`: 사용자 `postStart` 이벤트가 종속성을 다운로드하거나 외부 리소스에 액세스할 때 연결 시간 초과 또는 DNS 확인 실패를 확인합니다.
- `Long-running commands`: `postStart` 이벤트가 중단되면 `poststart-stdout.log`을 확인하여 명령이 여전히 실행 중인지 또는 성공적으로 완료되었는지 확인합니다.

`postStart` 명령 실행 로그를 확인하려면:

1. 작업 영역에서 터미널을 엽니다.
1. 작업 영역 로그 디렉터리로 이동합니다:

   ```shell
   cd /tmp/workspace-logs/
   ```

1. 로그 파일을 봅니다:

   ```shell
   # Monitor postStart execution output in real-time
   tail -f poststart-stdout.log

   # Check postStart errors
   cat poststart-stderr.log

   # Check VS Code server startup
   cat start-vscode.log
   ```

1. 오류를 확인합니다:

   ```shell
   # Search for error messages across all logs
   grep -i error *.log

   # Search for specific command output
   grep "your-command-name" poststart-stdout.log
   ```

1. 식별된 문제를 해결하고 작업 영역을 다시 시작합니다.

자세한 내용은 [작업 영역 로그 디렉터리](_index.md#workspace-logs-directory) 및 [사용 가능한 로그 파일](_index.md#available-log-files)을 참조하세요.

<!--- Other suggested topics:

## DNS configuration

## Workspace stops unexpectedly

## Workspace creation fails due to quotas

## Network connectivity

## SSH connection failures

### Network policy restrictions

-->
