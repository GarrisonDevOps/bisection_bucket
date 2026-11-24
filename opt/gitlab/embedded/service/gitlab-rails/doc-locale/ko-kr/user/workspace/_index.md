---
stage: Create
group: Remote Development
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 작업 영역은 GitLab 개발 환경을 생성하고 관리하기 위한 가상 샌드박스 환경입니다.
title: 작업 영역
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

작업 영역은 GitLab의 코드를 위한 가상 샌드박스 환경입니다. 작업 영역을 사용하여 GitLab 프로젝트를 위한 격리된 개발 환경을 생성하고 관리할 수 있습니다. 이러한 환경은 다양한 프로젝트가 서로 방해하지 않도록 보장합니다.

각 작업 영역은 자체 종속성, 라이브러리 및 도구 세트를 포함하며, 각 프로젝트의 특정 요구 사항을 충족하도록 사용자 정의할 수 있습니다.

작업 영역은 최대 약 1년(달력), `8760` 시간 동안 존재할 수 있습니다. 그 이후에는 자동으로 종료됩니다.

클릭스루 데모는 [GitLab 작업 영역](https://tech-marketing.gitlab.io/static-demos/workspaces/ws_html.html)을 참고하세요.

> [!note]
> 작업 영역은 GitLab Kubernetes 에이전트(`agentk`)를 지원하는 모든 `linux/amd64` Kubernetes 클러스터에서 실행됩니다. `sudo` 명령을 실행하거나 작업 영역에서 컨테이너를 빌드 및 실행해야 하는 경우 플랫폼별 요구 사항이 있을 수 있습니다.
>
> 자세한 내용은 [플랫폼 호환성](configuration.md#platform-compatibility)을 참고하세요.

## 작업 영역 및 프로젝트 {#workspaces-and-projects}

작업 영역은 프로젝트로 범위가 지정됩니다. 작업 영역을 생성할 때 다음을 수행해야 합니다:

- 작업 영역을 특정 프로젝트에 할당합니다.
- [devfile](#devfile)이 있는 프로젝트를 선택합니다.

작업 영역은 현재 사용자 권한으로 정의된 액세스 수준을 통해 GitLab API와 상호 작용할 수 있습니다. 실행 중인 작업 영역은 사용자 권한이 나중에 취소되는 경우에도 사용자가 계속 액세스할 수 있습니다.

### 프로젝트에서 작업 영역 관리 {#manage-workspaces-from-a-project}

프로젝트에서 작업 영역을 관리하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 오른쪽 위에서 **코드**를 선택합니다.
1. 드롭다운 목록에서 **당신의 작업공간** 아래에서 다음을 수행할 수 있습니다:
   - 기존 작업 영역을 다시 시작, 중지 또는 종료합니다.
   - 새 작업 영역을 생성합니다.

> [!warning]
> 작업 영역을 종료하면 GitLab이 해당 작업 영역의 저장되지 않은 또는 커밋되지 않은 데이터를 모두 삭제합니다. 데이터를 복구할 수 없습니다.

### 작업 영역과 연결된 리소스 삭제 {#deleting-resources-associated-with-a-workspace}

작업 영역을 종료하면 작업 영역와 연결된 모든 리소스를 삭제합니다. 프로젝트, `agentk`, 사용자 또는 실행 중인 작업 영역과 연결된 토큰을 삭제하면:

- 작업 영역이 사용자 인터페이스에서 삭제됩니다.
- Kubernetes 클러스터에서 실행 중인 작업 영역 리소스는 고아 상태가 되어 자동으로 삭제되지 않습니다.

고아 리소스를 정리하려면 관리자가 Kubernetes에서 작업 영역을 수동으로 삭제해야 합니다.

[에픽 11452](https://gitlab.com/groups/gitlab-org/-/work_items/11452)에서 이 동작을 변경하도록 제안합니다.

## 에이전트 수준에서 작업 영역 관리 {#manage-workspaces-at-the-agent-level}

`agentk`과 연결된 모든 작업 영역을 관리하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **운영** > **Kubernetes 클러스터**를 선택합니다.
1. 원격 개발을 위해 구성된 에이전트를 선택합니다.
1. **작업공간** 탭을 선택합니다.
1. 목록에서 기존 작업 영역을 다시 시작, 중지 또는 종료할 수 있습니다.

> [!warning]
> 작업 영역을 종료하면 GitLab이 해당 작업 영역의 저장되지 않은 또는 커밋되지 않은 데이터를 모두 삭제합니다. 데이터를 복구할 수 없습니다.

### 실행 중인 작업 영역에서 에이전트 식별 {#identify-an-agent-from-a-running-workspace}

여러 `agentk` 설치가 포함된 배포에서는 실행 중인 작업 영역에서 에이전트를 식별하려고 할 수 있습니다.

실행 중인 작업 영역과 연결된 에이전트를 식별하려면 다음 GraphQL 엔드포인트 중 하나를 사용합니다:

- `agent-id`은 에이전트가 속한 프로젝트를 반환합니다.
- `Query.workspaces`을 반환하려면:
  - 작업 영역과 연결된 클러스터 에이전트입니다.
  - 에이전트가 속한 프로젝트입니다.

## Devfile {#devfile}

작업 영역은 devfile을 위한 기본 제공 지원을 제공합니다. Devfile은 GitLab 프로젝트에 필요한 도구, 언어, 런타임 및 기타 구성 요소를 지정하여 개발 환경을 정의하는 파일입니다. 이를 사용하여 정의된 사양으로 개발 환경을 자동으로 구성합니다. 사용하는 머신이나 플랫폼에 관계없이 일관성 있고 재현 가능한 개발 환경을 만듭니다.

작업 영역은 GitLab 기본 devfile과 사용자 정의 devfile을 모두 지원합니다.

### GitLab 기본 devfile {#gitlab-default-devfile}

{{< history >}}

- GitLab 17.8에서 [Go로 도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/171230).
- GitLab 17.9에서 [Node, Ruby 및 Rust에 대한 지원 추가됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/185393).
- GitLab 18.0에서 [Python, PHP, Java 및 GCC에 대한 지원 추가됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/188199).

{{< /history >}}

GitLab 기본 devfile은 작업 영역을 생성할 때 모든 프로젝트에 사용 가능합니다. 이 devfile에는 다음이 포함됩니다:

```yaml
schemaVersion: 2.2.0
components:
  - name: development-environment
    attributes:
      gl/inject-editor: true
    container:
      image: "registry.gitlab.com/gitlab-org/gitlab-build-images/workspaces/ubuntu-24.04:[VERSION_TAG]"
```

> [!note]
> 이 컨테이너 `image`는 정기적으로 업데이트됩니다. `[VERSION_TAG]`은 자리 표시자일 뿐입니다. 최신 버전을 보려면 [기본 `default_devfile.yaml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/lib/remote_development/settings/default_devfile.yaml)을 참고하세요.

작업 영역 기본 이미지에는 Ruby, Node.js, Rust, Go, Python, Java, PHP, GCC 및 해당 패키지 관리자와 같은 개발 도구가 포함됩니다. 이러한 도구는 정기적으로 업데이트됩니다.

GitLab 기본 devfile은 모든 개발 환경 구성에 적합하지 않을 수 있습니다. 이 경우 [사용자 정의 devfile](#custom-devfile)을 생성할 수 있습니다.

### 사용자 정의 devfile {#custom-devfile}

특정 개발 환경 구성이 필요한 경우 사용자 정의 devfile을 생성합니다. 프로젝트의 루트 디렉터리에 상대적으로 다음 위치에서 devfile을 정의할 수 있습니다:

```plaintext
- /.devfile.yaml
- /.devfile.yml
- /.devfile/{devfile_name}.yaml
- /.devfile/{devfile_name}.yml
```

> [!note]
> Devfile은 `.devfile` 폴더에 직접 배치해야 합니다. 중첩된 하위 폴더는 지원되지 않습니다. 예를 들어 `.devfile/subfolder/devfile.yaml`은 인식되지 않습니다.

### 유효성 검사 규칙 {#validation-rules}

- devfile 크기는 3 MB를 초과하면 안 됩니다.

| 속성        | 명시적 규칙                                                                                                                                                                                                                                                                                                          |
|-----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `schemaVersion` | [`2.2.0`](https://devfile.io/docs/2.2.0/devfile-schema)이어야 합니다.                                                                                                                                                                                                                                                       |
| `components`    | \- devfile에는 최소 1개의 구성 요소가 있어야 합니다.<br/>\- 이름은 `gl-`로 시작하면 안 됩니다.<br/>- `container`과 `volume`만 지원됩니다.<br/>- `mountSources`과 `sourceMapping`은 지원되지 않습니다.                                                                                                                  |
| `commands`      | \- ID는 `gl-`로 시작하면 안 됩니다.<br/>- `exec` 및 `apply` 명령 유형만 지원됩니다.<br/>- `exec` 명령의 경우 다음 옵션만 지원됩니다: `commandLine`, `component`, `label` 및 `hotReloadCapable`.<br/>- `hotReloadCapable`이 `exec` 명령에 대해 지정된 경우 `false`로 설정해야 합니다. |
| `events`        | \- 이름은 `gl-`로 시작하면 안 됩니다.<br/>- `preStart`과 `postStart`만 지원됩니다.<br/>\- Devfile 표준은 실행 명령이 `postStart` 이벤트에만 연결되도록 허용합니다. 적용 명령을 원하는 경우 `preStart` 이벤트를 사용해야 합니다.                                                                        |
| `parent`        | 지원되지 않습니다.                                                                                                                                                                                                                                                                                                      |
| `projects`           | 지원되지 않습니다.                                                                                                                                                                                                                                                                                                      |
| `starterProjects`     | 지원되지 않습니다.                                                                                                                                                                                                                                                                                                      |
| `variables`  | 키는 `gl-`, `gl_`, `GL-` 또는 `GL_`로 시작하면 안 됩니다.                                                                                                                                                                                                                                                                |
| `attributes`       | - `pod-overrides`은 루트 수준 또는 `components`에서 설정하면 안 됩니다.<br/>- `container-overrides`을 `components`에서 설정하면 안 됩니다.                                                                                                                                                                                   |

### `container` 구성 요소 유형 {#container-component-type}

`container` 구성 요소 유형을 사용하여 컨테이너 이미지를 작업 영역의 실행 환경으로 정의합니다. 기본 이미지, 종속성 및 기타 설정을 지정할 수 있습니다.

`container` 구성 요소 유형은 다음 스키마 속성만 지원합니다:

| 속성             | 설명 |
|----------------------|-------------|
| `image`[^create-custom-container] | 작업 영역에 사용할 컨테이너 이미지의 이름입니다. |
| `memoryRequest`      | 컨테이너가 사용할 수 있는 최소 메모리 양입니다. |
| `memoryLimit`        | 컨테이너가 사용할 수 있는 최대 메모리 양입니다. |
| `cpuRequest`         | 컨테이너가 사용할 수 있는 최소 CPU 양입니다. |
| `cpuLimit`           | 컨테이너가 사용할 수 있는 최대 CPU 양입니다. |
| `env`                | 컨테이너에서 사용할 환경 변수입니다. 이름은 `gl-`로 시작하면 안 됩니다. |
| `endpoints`          | 컨테이너에서 노출할 포트 매핑입니다. 이름은 `gl-`로 시작하면 안 됩니다. |
| `volumeMounts`       | 컨테이너에 마운트할 스토리지 볼륨입니다. |
| `command`            | 컨테이너 진입점을 재정의할 명령입니다. [`overrideCommand` 특성](#overridecommand-attribute)을 참고하세요. |
| `args`               | 컨테이너 명령의 인수입니다. [`overrideCommand` 특성](#overridecommand-attribute)을 참고하세요. |

[^create-custom-container]: `image` 속성의 사용자 정의 컨테이너 이미지를 생성할 때 [작업 영역 기본 이미지](#workspace-base-image)를 기반으로 사용할 수 있습니다. SSH 액세스, 사용자 권한 및 작업 영역 호환성을 위한 중요한 구성이 포함되어 있습니다. 기본 이미지를 사용하지 않기로 선택한 경우 사용자 정의 이미지가 모든 작업 영역 요구 사항을 충족하는지 확인합니다.

#### `overrideCommand` 특성 {#overridecommand-attribute}

`overrideCommand` 특성은 작업 영역이 컨테이너 진입점을 처리하는 방식을 제어하는 부울입니다. 이 특성은 컨테이너의 원래 진입점을 유지할지 아니면 keep-alive 명령으로 바꿀지 여부를 결정합니다.

`overrideCommand`의 기본값은 구성 요소 유형에 따라 달라집니다:

- 특성 `gl/inject-editor: true`이 있는 주 구성 요소: 지정하지 않으면 `true`로 기본값이 설정됩니다.
- 다른 모든 구성 요소: 지정하지 않으면 `false`로 기본값이 설정됩니다.

`true`일 때 컨테이너 진입점이 `tail -f /dev/null`로 바뀌어 컨테이너가 계속 실행됩니다. `false`일 때 컨테이너는 devfile 구성 요소 `command`/`args` 또는 빌드된 컨테이너 이미지의 `Entrypoint`/`Cmd`을 사용합니다.

다음 표는 `overrideCommand`이 컨테이너 동작에 어떻게 영향을 미치는지 보여줍니다. 명확하게 하기 위해 표에서 다음 용어가 사용됩니다:

- Devfile 구성 요소: devfile 구성 요소 항목의 `command` 및 `args` 속성입니다.
- 컨테이너 이미지: OCI 컨테이너 이미지의 `Entrypoint` 및 `Cmd` 필드입니다.

| `overrideCommand` | Devfile 구성 요소 | 컨테이너 이미지 | 결과 |
|-------------------|-------------------|-----------------|--------|
| `true`            | 지정됨         | 지정됨       | 유효성 검사 오류: Devfile 구성 요소 `command`/`args`은 `overrideCommand`이 `true`일 때 지정할 수 없습니다. |
| `true`            | 지정됨         | 지정되지 않음   | 유효성 검사 오류: Devfile 구성 요소 `command`/`args`은 `overrideCommand`이 `true`일 때 지정할 수 없습니다. |
| `true`            | 지정되지 않음     | 지정됨       | 컨테이너 진입점이 `tail -f /dev/null`로 바뀝니다. |
| `true`            | 지정되지 않음     | 지정되지 않음   | 컨테이너 진입점이 `tail -f /dev/null`로 바뀝니다. |
| `false`           | 지정됨         | 지정됨       | Devfile 구성 요소 `command`/`args`을 진입점으로 사용합니다. |
| `false`           | 지정됨         | 지정되지 않음   | Devfile 구성 요소 `command`/`args`을 진입점으로 사용합니다. |
| `false`           | 지정되지 않음     | 지정됨       | 컨테이너 이미지 `Entrypoint`/`Cmd`을 사용합니다. |
| `false`           | 지정되지 않음     | 지정되지 않음   | 컨테이너가 조기에 종료됩니다(`CrashLoopBackOff`).[^create-workspace-cannot] |

[^create-workspace-cannot]: 작업 영역을 생성할 때 비공개 또는 내부 레지스트리의 컨테이너 이미지 세부 정보에 액세스할 수 없습니다. `overrideCommand`이 `false`이고 Devfile이 `command` 또는 `args`를 지정하지 않으면 GitLab이 컨테이너 이미지를 검증하거나 필수 `Entrypoint` 또는 `Cmd` 필드를 확인하지 않습니다. Devfile 또는 컨테이너가 이 필드를 지정하거나 컨테이너가 조기에 종료되고 작업 영역이 시작되지 않는지 확인해야 합니다.

### 사용자 정의 `postStart` 이벤트 {#user-defined-poststart-events}

devfile에서 사용자 정의 `postStart` 이벤트를 정의하여 작업 영역 시작 후 명령을 실행할 수 있습니다. 이러한 `postStart` 이벤트는 작업 영역 접근성을 차단하지 않습니다. 작업 영역은 내부 초기화가 완료되는 즉시 사용 가능하게 되며, 사용자 정의 `postStart` 명령이 여전히 실행 중이거나 실행을 기다리는 경우에도 사용 가능합니다.

이 이벤트 유형을 사용하여:

- 개발 종속성을 설정합니다.
- 작업 영역 환경을 구성합니다.
- 초기화 스크립트를 실행합니다.

`postStart` 이벤트 이름은 `gl-`로 시작하면 안 되며 `exec` 유형 명령만 참조할 수 있습니다.

`postStart` 이벤트를 구성하는 방법을 보여주는 예제는 [예제 구성](#example-configurations)을 참고하세요.

#### `postStart` 명령의 작업 디렉터리 {#working-directory-for-poststart-commands}

기본적으로 `postStart` 명령은 구성 요소에 따라 다른 작업 디렉터리에서 실행됩니다:

- 특성 `gl/inject-editor: true`이 있는 주 구성 요소: 명령은 프로젝트 디렉터리(`/projects/<project-path>`)에서 실행됩니다.
- 다른 구성 요소: 명령은 컨테이너의 기본 작업 디렉터리에서 실행됩니다.

명령 정의에서 `workingDir`을 지정하여 기본 동작을 재정의할 수 있습니다:

```yaml
commands:
  - id: install-dependencies
    exec:
      component: tooling-container
      commandLine: "npm install"
      workingDir: "/custom/path"
  - id: setup-project
    exec:
      component: tooling-container
      commandLine: "echo 'Setting up in project directory'"
      # Runs in project directory by default
```

#### `postStart` 이벤트 진행 상황 모니터링 {#monitor-poststart-event-progress}

작업 영역이 `postStart` 이벤트를 실행할 때 진행 상황을 모니터링하고 작업 영역 로그를 확인할 수 있습니다. `postStart` 스크립트의 진행 상황을 확인하려면:

1. 작업 영역에서 터미널을 엽니다.
1. 작업 영역 로그 디렉터리로 이동합니다:

   ```shell
   cd /tmp/workspace-logs/
   ```

1. 출력 로그를 확인하여 명령 결과를 봅니다:

   ```shell
   tail -f poststart-stdout.log
   ```

모든 `postStart` 명령 출력은 [작업 영역 로그 디렉터리](#workspace-logs-directory)에 위치한 로그 파일에 캡처됩니다.

### 예제 구성 {#example-configurations}

다음은 devfile 구성의 예입니다:

```yaml
schemaVersion: 2.2.0
variables:
  registry-root: registry.gitlab.com
components:
  - name: tooling-container
    attributes:
      gl/inject-editor: true
    container:
      image: "{{registry-root}}/gitlab-org/remote-development/gitlab-remote-development-docs/ubuntu:22.04"
      env:
        - name: KEY
          value: VALUE
      endpoints:
        - name: http-3000
          targetPort: 3000
  - name: database-container
    attributes:
      overrideCommand: false
    container:
      image: mysql
      command: ["echo"]
      args: ["-n", "user-defined entrypoint command"]
      env:
        - name: MYSQL_ROOT_PASSWORD
          value: "my-secret-pw"
commands:
  # Command 1: Container 1, no working directory (uses project directory)
  - id: install-dependencies
    exec:
      component: tooling-container
      commandLine: "npm install"

  # Command 2: Container 1, with working directory
  - id: setup-environment
    exec:
      component: tooling-container
      commandLine: "echo 'Setting up development environment'"
      workingDir: "/home/gitlab-workspaces"

  # Command 3: Container 2, no working directory (uses container default)
  - id: init-database
    exec:
      component: database-container
      commandLine: "echo 'Database initialized' > db-init.log"

  # Command 4: Container 2, with working directory
  - id: setup-database
    exec:
      component: database-container
      commandLine: "mkdir -p /var/lib/mysql/logs && echo 'DB setup complete' > setup.log"
      workingDir: "/var/lib/mysql"

events:
  postStart:
    - install-dependencies
    - setup-environment
    - init-database
    - setup-database
```

> [!note]
> 이 컨테이너 `image`는 시연용입니다.

다른 예제는 [`examples` 프로젝트](https://gitlab.com/gitlab-org/workspaces/examples)를 참고하세요.

## 작업 영역 컨테이너 요구 사항 {#workspace-container-requirements}

기본적으로 작업 영역은 devfile에 정의된 `gl/inject-editor` 특성이 있는 컨테이너에서 [GitLab VS Code 포크](https://gitlab.com/gitlab-org/gitlab-web-ide-vscode-fork)를 삽입하고 시작합니다. GitLab VS Code 포크가 삽입되는 작업 영역 컨테이너는 다음 시스템 요구 사항을 충족해야 합니다:

- 시스템 아키텍처: AMD64
- 시스템 라이브러리:
  - `glibc` 2.28 이상
  - `glibcxx` 3.4.25 이상

이 요구 사항은 Debian 10.13 및 Ubuntu 20.04에서 테스트되었습니다.

> [!note]
> GitLab은 항상 작업 영역 도구 주입기 이미지를 GitLab 레지스트리(`registry.gitlab.com`)에서 가져옵니다. 이 이미지는 재정의할 수 없습니다.
>
> 다른 이미지에 비공개 컨테이너 레지스트리를 사용하는 경우 GitLab이 GitLab 레지스트리에서 이 특정 이미지를 가져옵니다. 이 요구 사항은 오프라인 환경과 같이 엄격한 네트워크 제어가 있는 환경에 영향을 미칠 수 있습니다.

## 작업 영역 기본 이미지 {#workspace-base-image}

{{< history >}}

- GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/gitlab-build-images/-/merge_requests/983)되었습니다.

{{< /history >}}

GitLab은 모든 작업 영역 환경의 기초로 사용되는 작업 영역 기본 이미지(`registry.gitlab.com/gitlab-org/gitlab-build-images:workspaces-base`)를 제공합니다.

기본 이미지에 포함된 항목:

- 안정적인 Linux 운영 체제 기반.
- 작업 영역 작업을 위한 적절한 권한이 있는 미리 구성된 사용자입니다.
- 필수 개발 도구 및 시스템 라이브러리입니다.
- 프로그래밍 언어 및 도구를 위한 버전 관리입니다.
- 원격 액세스를 위한 SSH 서버 구성.
- 임의 사용자 ID 지원을 위한 보안 구성입니다.

작업 영역 기본 이미지를 사용하지 않으려면 사용자 정의 작업 영역 이미지를 생성할 수 있습니다. GitLab이 사용자 정의 이미지를 제대로 초기화하고 연결할 수 있도록 하려면 [기본 이미지 Dockerfile](https://gitlab.com/gitlab-org/gitlab-build-images/-/blob/master/Dockerfile.workspaces-base)에서 필요한 구성 명령을 자신의 Dockerfile로 복사합니다.

### 기본 이미지 확장 {#extend-the-base-image}

작업 영역 기본 이미지를 기반으로 사용자 정의 작업 영역 이미지를 생성할 수 있습니다. 예를 들어:

```dockerfile
FROM registry.gitlab.com/gitlab-org/gitlab-build-images:workspaces-base

# Install additional tools
RUN sudo apt-get update && sudo apt-get install -y \
    your-additional-package \
    && sudo rm -rf /var/lib/apt/lists/*

# Install specific language versions
RUN mise install python@3.11 && mise use python@3.11
```

## 작업 영역 추가 기능 {#workspace-add-ons}

{{< history >}}

- GitLab 17.2에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/385157).

{{< /history >}}

GitLab for VS Code 확장은 기본적으로 작업 영역에서 구성됩니다.

이 확장을 사용하면 이슈를 보고, 병합 요청을 생성하고, CI/CD 파이프라인을 관리할 수 있습니다. 이 확장은 GitLab Duo Code Suggestions 및 GitLab Duo Chat과 같은 AI 기능도 지원합니다.

## 확장 마켓플레이스 {#extension-marketplace}

{{< details >}}

- 상태:  베타

{{< /details >}}

{{< history >}}

- [GitLab 16.9에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/438491)([베타](../../policy/development_stages_support.md#beta)로 [기능 플래그](../../administration/feature_flags/_index.md) `allow_extensions_marketplace_in_workspace`로 명명됨). 기본적으로 비활성화되었습니다.
- 기능 플래그 `allow_extensions_marketplace_in_workspace`이 GitLab 17.6에서 [제거됨](https://gitlab.com/gitlab-org/gitlab/-/issues/454669).

{{< /history >}}

VS Code 확장 마켓플레이스는 Web IDE의 기능을 향상시키는 확장에 대한 액세스를 제공합니다. 기본적으로 GitLab Web IDE는 [Open VSX Registry](https://open-vsx.org/)에 연결됩니다.

자세한 내용은 [VS Code 확장 마켓플레이스 구성](../../administration/settings/vscode_extension_marketplace.md)을 참고하세요.

## 개인 액세스 토큰 {#personal-access-token}

{{< history >}}

- `api` 권한이 GitLab 17.2에서 [추가됨](https://gitlab.com/gitlab-org/gitlab/-/issues/385157).

{{< /history >}}

작업 영역을 생성할 때 365일 동안 유효하며 `write_repository` 및 `api` 권한이 있는 개인 액세스 토큰을 받습니다. 이 토큰은 처음에 프로젝트를 복제하고 작업 영역을 시작하며 GitLab for VS Code 확장을 구성하는 데 사용됩니다.

작업 영역에서 수행하는 모든 Git 작업은 인증 및 권한 부여를 위해 이 토큰을 사용합니다. 작업 영역을 종료하면 토큰이 취소됩니다.

작업 영역에서 Git 인증을 위해 `GIT_CONFIG_COUNT`, `GIT_CONFIG_KEY_n` 및 `GIT_CONFIG_VALUE_n` [환경 변수](https://git-scm.com/docs/git-config/#Documentation/git-config.txt-GITCONFIGCOUNT)를 사용합니다. 이 변수는 작업 영역 컨테이너에서 Git 2.31 이상을 필요로 합니다.

## 클러스터의 Pod 상호 작용 {#pod-interaction-in-a-cluster}

작업 영역은 Kubernetes 클러스터의 pod로 실행됩니다. GitLab은 pod가 서로 상호 작용하는 방식에 대한 제한을 두지 않습니다.

이 요구 사항으로 인해 이 기능을 클러스터의 다른 컨테이너로부터 격리하는 것을 고려합니다.

## 네트워크 액세스 및 작업 영역 권한 부여 {#network-access-and-workspace-authorization}

GitLab이 API에 대한 제어권이 없기 때문에 Kubernetes 제어 평면에 대한 네트워크 액세스를 제한하는 것은 클라이언트의 책임입니다.

작업 영역 작성자만 작업 영역 및 해당 작업 영역에 노출된 모든 엔드포인트에 액세스할 수 있습니다. 작업 영역 작성자는 OAuth를 통한 사용자 인증 후에만 작업 영역에 액세스할 수 있습니다.

## 리소스 및 볼륨 스토리지 계산 {#compute-resources-and-volume-storage}

작업 영역을 중지하면 GitLab이 해당 작업 영역의 리소스를 0으로 축소합니다. 그러나 작업 영역용으로 프로비전된 볼륨은 여전히 존재합니다.

프로비전된 볼륨을 삭제하려면 작업 영역을 종료해야 합니다.

## 자동 작업 영역 중지 및 종료 {#automatic-workspace-stop-and-termination}

{{< history >}}

- GitLab 17.6에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/14910)되었습니다.

{{< /history >}}

기본적으로 작업 영역은 자동으로:

- 작업 영역이 마지막으로 시작되거나 다시 시작된 후 36시간 후 중지됩니다.
- 작업 영역이 마지막으로 중지된 후 722시간 후 종료됩니다.

## 임의의 사용자 ID {#arbitrary-user-ids}

자신의 컨테이너 이미지를 제공할 수 있으며 모든 Linux 사용자 ID로 실행할 수 있습니다.

GitLab이 컨테이너 이미지의 Linux 사용자 ID를 예측할 수 없습니다. GitLab은 Linux `root` 그룹 ID 권한을 사용하여 컨테이너의 파일을 생성, 업데이트 또는 삭제합니다. Kubernetes 클러스터에서 사용하는 컨테이너 런타임은 모든 컨테이너의 기본 Linux 그룹 ID가 `0`인지 확인해야 합니다.

임의의 사용자 ID를 지원하지 않는 컨테이너 이미지가 있으면 작업 영역에서 파일을 생성, 업데이트 또는 삭제할 수 없습니다. 임의의 사용자 ID를 지원하는 사용자 정의 작업 영역 이미지를 생성하려면 [임의의 사용자 ID를 지원하는 사용자 정의 작업 영역 이미지 생성](create_image.md)을 참고하세요.

## 작업 영역 로그 디렉터리 {#workspace-logs-directory}

작업 영역이 시작되면 GitLab이 로그 디렉터리를 생성하여 다양한 초기화 및 시작 프로세스의 출력을 캡처합니다.

작업 영역 로그는 `/tmp/workspace-logs/`에 저장됩니다.

이 디렉터리는 작업 영역 시작 진행 상황을 모니터링하고 `postStart` 이벤트, 개발 도구 및 기타 작업 영역 구성 요소의 문제를 해결하는 데 도움이 됩니다. 자세한 내용은 [`postStart` 이벤트 디버그](workspaces_troubleshooting.md#debug-poststart-events)를 참고하세요.

### 사용 가능한 로그 파일 {#available-log-files}

로그 디렉터리에는 다음 로그 파일이 있습니다:

| 로그 파일               | 목적                    | 콘텐츠 |
|------------------------|----------------------------|---------|
| `poststart-stdout.log` | `postStart` 명령 출력 | 모든 `postStart` 명령의 표준 출력(사용자 정의 명령 및 내부 GitLab 시작 작업 포함). |
| `poststart-stderr.log` | `postStart` 명령 오류 | `stderr` 명령의 오류 출력 및 `postStart`. 이 로그를 사용하여 실패한 시작 스크립트를 해결할 수 있습니다. |
| `start-vscode.log`     | VS Code 서버 시작     | GitLab VS Code 포크 서버 초기화의 로그입니다. |
| `start-sshd.log`       | SSH 데몬 시작         | SSH 데몬 초기화의 출력(서버 시작 및 구성 세부 정보 포함). |
| `clone-unshallow.log`  | Git 리포지토리 변환  | 얕은 복제를 전체 복제로 변환하고 프로젝트의 전체 Git 기록을 검색하는 백그라운드 프로세스의 로그입니다. |

> [!note]
> 로그 파일은 작업 영역을 다시 시작할 때마다 다시 생성됩니다. 작업 영역을 중지했다가 다시 시작할 때 이전 로그 파일은 보존되지 않습니다.

## 얕은 복제 {#shallow-cloning}

{{< history >}}

- `workspaces_shallow_clone_project`라는 이름의 [기능 플래그](../../administration/feature_flags/_index.md)로 GitLab 18.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/543982)되었습니다. 기본적으로 비활성화되었습니다.
- [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/550330) GitLab 18.3에서
- GitLab 18.4에서 [정식 출시(GA)](https://gitlab.com/gitlab-org/gitlab/-/issues/558154). 기능 플래그 `workspaces_shallow_clone_project`이 제거되었습니다.

{{< /history >}}

작업 영역을 생성할 때 GitLab이 얕은 복제를 사용하여 성능을 개선합니다. 얕은 복제는 전체 Git 기록 대신 최신 커밋 기록만 다운로드하므로 큰 리포지토리의 초기 복제 시간을 크게 줄입니다.

작업 영역이 시작된 후 Git은 얕은 복제를 백그라운드에서 전체 복제로 변환합니다. 이 프로세스는 투명하며 개발 워크플로에 영향을 주지 않습니다.

## 관련 항목 {#related-topics}

- [작업 영역 생성](configuration.md#create-a-workspace)
- [작업 영역 설정](settings.md)
- [작업 영역 문제 해결](workspaces_troubleshooting.md)
- [GitLab Duo Code Suggestions](../duo_agent_platform/code_suggestions/_index.md)
- [GitLab Duo Agentic Chat](../gitlab_duo_chat/agentic_chat.md)
- [GraphQL API 참조](../../api/graphql/reference/_index.md)
- [Devfile 설명서](https://devfile.io/docs/2.2.0/devfile-schema)
- [임의의 사용자 ID에 대한 OpenShift 설명서](https://docs.openshift.com/container-platform/4.12/openshift_images/create-images.html#use-uid_create-images)
