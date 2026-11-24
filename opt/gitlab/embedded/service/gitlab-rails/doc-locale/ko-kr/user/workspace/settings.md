---
stage: Create
group: Remote Development
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 원격 개발 환경을 지원하도록 Kubernetes용 GitLab 에이전트를 구성합니다.
title: 워크스페이스 설정
---

워크스페이스 설정은 Kubernetes용 GitLab 에이전트가 Kubernetes 클러스터의 원격 개발 환경을 관리하는 방식을 구성합니다. 이러한 설정은 다음을 제어합니다:

- 리소스 할당
- 보안
- 네트워킹
- 수명 주기 관리

## 기본 워크스페이스 구성 설정 {#set-up-a-basic-workspace-configuration}

기본 워크스페이스 구성을 설정하려면 다음 작업을 수행합니다:

1. 구성 YAML 파일을 엽니다.
1. 다음의 최소 필수 설정을 추가합니다:

   ```yaml
   remote_development:
     enabled: true
     dns_zone: "<workspaces.example.dev>"
   ```

1. 변경 사항을 커밋합니다.

워크스페이스 구성이 작동하지 않는 경우 [워크스페이스 문제 해결](workspaces_troubleshooting.md)을 참조하세요.

> [!note]
> 설정에 잘못된 값이 있으면 해당 값을 수정할 때까지 다른 설정을 업데이트할 수 없습니다. `enabled`를 제외한 이러한 설정의 업데이트는 기존 워크스페이스에 영향을 주지 않습니다.

## 구성 참조 {#configuration-reference}

| 설정                                                                                   | 설명                                                                                   | 형식                                                      | 기본값                           | 필수 |
|-------------------------------------------------------------------------------------------|-----------------------------------------------------------------------------------------------|-------------------------------------------------------------|-----------------------------------------|----------|
| [`enabled`](#enabled)                                                                     | Kubernetes용 GitLab 에이전트에 대해 원격 개발이 활성화되어 있는지 여부를 나타냅니다.                         | 부울                                                     | `false`                                 | 예      |
| [`dns_zone`](#dns_zone)                                                                   | 워크스페이스를 사용할 수 있는 DNS 영역입니다.                                                      | 문자열입니다. 유효한 DNS 형식입니다.                                   | 없음                                    | 예      |
| [`gitlab_workspaces_proxy`](#gitlab_workspaces_proxy)                                     | [`gitlab-workspaces-proxy`](set_up_gitlab_agent_and_proxies.md)가 설치된 네임스페이스입니다. | 문자열입니다. 유효한 Kubernetes 네임스페이스 이름입니다.                    | `gitlab-workspaces`                     | 아니요       |
| [`network_policy`](#network_policy)                                                       | 워크스페이스의 방화벽 규칙입니다.                                                                | `enabled` 및 `egress` 필드를 포함하는 객체입니다.            | [`network_policy`](#network_policy)를 참조하세요. | 아니요       |
| [`default_resources_per_workspace_container`](#default_resources_per_workspace_container) | 워크스페이스 컨테이너당 CPU 및 메모리에 대한 기본 요청 및 제한입니다.                       | CPU 및 메모리를 위한 `requests` 및 `limits`가 있는 객체입니다.     | `{}`                                    | 아니요       |
| [`max_resources_per_workspace`](#max_resources_per_workspace)                             | 워크스페이스당 CPU 및 메모리에 대한 최대 요청 및 제한입니다.                                 | CPU 및 메모리를 위한 `requests` 및 `limits`가 있는 객체입니다.      | `{}`                                    | 아니요       |
| [`workspaces_quota`](#workspaces_quota)                                                   | Kubernetes용 GitLab 에이전트의 최대 워크스페이스 수입니다.                                            | 정수                                                     | `-1`                                    | 아니요       |
| [`workspaces_per_user_quota`](#workspaces_per_user_quota)                                 | 사용자당 최대 워크스페이스 수입니다.                                                        | 정수                                                     | `-1`                                    | 아니요       |
| [`use_kubernetes_user_namespaces`](#use_kubernetes_user_namespaces)                       | Kubernetes에서 사용자 네임스페이스를 사용할지 여부를 나타냅니다.                                       | 부울: `true` 또는 `false`                                  | `false`                                 | 아니요       |
| [`default_runtime_class`](#default_runtime_class)                                         | 기본 Kubernetes `RuntimeClass`입니다.                                                            | 문자열입니다. 유효한 `RuntimeClass` 이름입니다.                          | `""`                                    | 아니요       |
| [`allow_privilege_escalation`](#allow_privilege_escalation)                               | 권한 상승을 허용합니다.                                                                   | 부울                                                     | `false`                                 | 아니요       |
| [`image_pull_secrets`](#image_pull_secrets)                                               | 워크스페이스의 프라이빗 이미지를 가져오기 위해 필요한 기존 Kubernetes 시크릿입니다.                            | `name` 및 `namespace` 필드가 있는 객체 배열입니다.        | `[]`                                    | 아니요       |
| [`annotations`](#annotations)                                                             | Kubernetes 객체에 적용할 주석입니다.                                                   | 키-값 쌍의 맵입니다. 유효한 Kubernetes 주석 형식입니다. | `{}`                                    | 아니요       |
| [`labels`](#labels)                                                                       | Kubernetes 객체에 적용할 레이블입니다.                                                        | 키-값 쌍의 맵입니다. 유효한 Kubernetes 레이블 형식입니다.       | `{}`                                    | 아니요       |
| [`max_active_hours_before_stop`](#max_active_hours_before_stop)                           | 워크스페이스가 중지되기 전에 활성 상태로 있을 수 있는 최대 시간 수입니다.                       | 정수                                                     | `36`                                    | 아니요       |
| [`max_stopped_hours_before_termination`](#max_stopped_hours_before_termination)           | 워크스페이스가 종료되기 전에 중지된 상태로 있을 수 있는 최대 시간 수입니다.                   | 정수                                                     | `744`                                   | 아니요       |
| [`shared_namespace`](#shared_namespace)                                                   | 공유된 Kubernetes 네임스페이스를 사용할지 여부를 나타냅니다.                                    | 문자열                                                      | `""`                                    | 아니요       |

### `enabled` {#enabled}

이 설정을 사용하여 다음을 정의합니다:

- Kubernetes용 GitLab 에이전트가 GitLab 인스턴스와 통신할 수 있습니다.
- Kubernetes용 GitLab 에이전트를 사용하여 [워크스페이스를 생성](configuration.md#create-a-workspace)할 수 있습니다.

기본값은 `false`입니다.

에이전트 구성에서 원격 개발을 활성화하려면 `enabled`을 `true`로 설정합니다:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  enabled: true
```

> [!note]
> `enabled`이 활성 또는 중지된 워크스페이스가 있는 에이전트에 대해 `false`로 설정된 경우 해당 워크스페이스는 고아 상태가 되어 사용할 수 없게 됩니다.
>
> 에이전트에서 원격 개발을 비활성화하기 전에 다음 작업을 수행합니다:
>
> - 모든 관련 워크스페이스가 더 이상 필요하지 않음을 확인합니다.
> - 실행 중인 워크스페이스를 수동으로 삭제하여 Kubernetes 클러스터에서 제거합니다.

### `dns_zone` {#dns_zone}

이 설정을 사용하여 워크스페이스를 사용할 수 있는 URL의 DNS 영역을 정의합니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  dns_zone: "<workspaces.example.dev>"
```

### `gitlab_workspaces_proxy` {#gitlab_workspaces_proxy}

이 설정을 사용하여 [`gitlab-workspaces-proxy`](set_up_gitlab_agent_and_proxies.md)가 설치된 네임스페이스를 정의합니다. `gitlab_workspaces_proxy.namespace`의 기본값은 `gitlab-workspaces`입니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  gitlab_workspaces_proxy:
    namespace: "<custom-gitlab-workspaces-proxy-namespace>"
```

### `network_policy` {#network_policy}

이 설정을 사용하여 각 워크스페이스의 네트워크 정책을 정의합니다. 이 설정은 워크스페이스의 네트워크 트래픽을 제어합니다.

기본값은 다음과 같습니다:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  network_policy:
    enabled: true
    egress:
      - allow: "0.0.0.0/0"
        except:
          - "10.0.0.0/8"
          - "172.16.0.0/12"
          - "192.168.0.0/16"
```

이 구성에서:

- `enabled`이 `true`이므로 각 워크스페이스에 대해 네트워크 정책이 생성됩니다.
- 송신 규칙은 인터넷(`0.0.0.0/0`)으로의 모든 트래픽을 허용하지만 IP CIDR 범위 `10.0.0.0/8`, `172.16.0.0/12` 및 `192.168.0.0/16`는 제외합니다.

네트워크 정책의 동작은 Kubernetes 네트워크 플러그인에 따라 다릅니다. 자세한 내용은 [Kubernetes 설명서](https://kubernetes.io/docs/concepts/services-networking/network-policies/)를 참조하세요.

#### `network_policy.enabled` {#network_policyenabled}

이 설정을 사용하여 각 워크스페이스에 대해 네트워크 정책이 생성되는지 여부를 정의합니다. `network_policy.enabled`의 기본값은 `true`입니다.

#### `network_policy.egress` {#network_policyegress}

이 설정을 사용하여 워크스페이스에서 송신 대상으로 허용할 IP CIDR 범위의 목록을 정의합니다.

다음 경우에 송신 규칙을 정의합니다:

- GitLab 인스턴스가 프라이빗 IP 범위에 있습니다.
- 워크스페이스가 프라이빗 IP 범위의 클라우드 리소스에 액세스해야 합니다.

목록의 각 요소는 선택적 `except` 속성이 있는 `allow` 속성을 정의합니다. `allow`은 트래픽을 허용할 IP 범위를 정의합니다. `except`은 `allow` 범위에서 제외할 IP 범위를 나열합니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  network_policy:
    egress:
      - allow: "0.0.0.0/0"
        except:
          - "10.0.0.0/8"
          - "172.16.0.0/12"
          - "192.168.0.0/16"
      - allow: "172.16.123.1/32"
```

이 예에서는 다음의 경우 워크스페이스에서 트래픽이 허용됩니다:

- 대상 IP는 `10.0.0.0/8`, `172.16.0.0/12` 또는 `192.168.0.0/16`을 제외한 모든 범위입니다.
- 대상 IP는 `172.16.123.1/32`입니다.

### `default_resources_per_workspace_container` {#default_resources_per_workspace_container}

이 설정을 사용하여 워크스페이스 컨테이너당 CPU 및 메모리에 대한 기본 [요청 및 제한](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#requests-and-limits)을 정의합니다. [devfile](_index.md#devfile)에서 정의하는 모든 리소스는 이 설정을 재정의합니다.

`default_resources_per_workspace_container`의 경우 `requests` 및 `limits`이 필수입니다. 가능한 CPU 및 메모리 값에 대한 자세한 내용은 [Kubernetes의 리소스 단위](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#resource-units-in-kubernetes)를 참조하세요.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  default_resources_per_workspace_container:
    requests:
      cpu: "0.5"
      memory: "512Mi"
    limits:
      cpu: "1"
      memory: "1Gi"
```

### `max_resources_per_workspace` {#max_resources_per_workspace}

이 설정을 사용하여 워크스페이스당 CPU 및 메모리에 대한 최대 [요청 및 제한](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#requests-and-limits)을 정의합니다.

`max_resources_per_workspace`의 경우 `requests` 및 `limits`이 필수입니다. 가능한 CPU 및 메모리 값에 대한 자세한 내용은 다음을 참조하세요:

- [Kubernetes의 리소스 단위](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/#resource-units-in-kubernetes)
- [리소스 할당량](https://kubernetes.io/docs/concepts/policy/resource-quotas/)

워크스페이스는 `requests` 및 `limits`에 대해 설정한 값을 초과하면 실패합니다.

> [!note]
> [`shared_namespace`](#shared_namespace)이 설정되면 `max_resources_per_workspace`은 빈 해시여야 합니다. 사용자는 `shared_namespace`에서 Kubernetes [리소스 할당량](https://kubernetes.io/docs/concepts/policy/resource-quotas/)을 생성하여 여기에서 이 값을 지정하는 것과 동일한 결과를 얻을 수 있습니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  max_resources_per_workspace:
    requests:
      cpu: "1"
      memory: "1Gi"
    limits:
      cpu: "2"
      memory: "2Gi"
```

정의하는 최대 리소스에는 프로젝트 리포지토리 복제와 같은 부트스트래핑 작업을 수행하기 위해 초기화 컨테이너에 필요한 모든 리소스가 포함되어야 합니다.

### `workspaces_quota` {#workspaces_quota}

이 설정을 사용하여 Kubernetes용 GitLab 에이전트의 최대 워크스페이스 수를 설정합니다.

다음의 경우 에이전트에 대한 새 워크스페이스를 생성할 수 없습니다:

- 에이전트의 워크스페이스 수가 정의된 `workspaces_quota`에 도달했습니다.
- `workspaces_quota`이 `0`로 설정되었습니다.

`workspaces_quota`이 에이전트에 대한 종료되지 않은 워크스페이스 수보다 낮은 값으로 설정된 경우 에이전트의 워크스페이스는 자동으로 종료되지 않습니다.

기본값은 `-1`(무제한)입니다. 가능한 값은 `-1`보다 크거나 같습니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  workspaces_quota: 10
```

### `workspaces_per_user_quota` {#workspaces_per_user_quota}

이 설정을 사용하여 사용자당 최대 워크스페이스 수를 설정합니다.

다음의 경우 사용자에 대한 새 워크스페이스를 생성할 수 없습니다:

- 사용자의 워크스페이스 수가 정의된 `workspaces_per_user_quota`에 도달했습니다.
- `workspaces_per_user_quota`이 `0`로 설정되었습니다.

`workspaces_per_user_quota`이 사용자에 대한 종료되지 않은 워크스페이스 수보다 낮은 값으로 설정된 경우 사용자의 워크스페이스는 자동으로 종료되지 않습니다.

기본값은 `-1`(무제한)입니다. 가능한 값은 `-1`보다 크거나 같습니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  workspaces_per_user_quota: 3
```

### `use_kubernetes_user_namespaces` {#use_kubernetes_user_namespaces}

{{< history >}}

- GitLab 17.4에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/13983)되었습니다.

{{< /history >}}

이 설정을 사용하여 Kubernetes의 사용자 네임스페이스 기능을 사용할지 여부를 지정합니다.

[사용자 네임스페이스](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/)는 컨테이너 내부에서 실행 중인 사용자를 호스트의 사용자와 격리합니다.

기본값은 `false`입니다. 값을 `true`로 설정하기 전에 Kubernetes 클러스터가 사용자 네임스페이스를 지원하는지 확인합니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  use_kubernetes_user_namespaces: true
```

`use_kubernetes_user_namespaces`에 대한 자세한 내용은 [사용자 네임스페이스](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/)를 참조하세요.

### `default_runtime_class` {#default_runtime_class}

{{< history >}}

- GitLab 17.4에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/13983)되었습니다.

{{< /history >}}

이 설정을 사용하여 워크스페이스의 컨테이너를 실행하는 데 사용할 컨테이너 런타임 구성을 선택합니다.

기본값은 `""`(값이 없음을 나타냄)입니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  default_runtime_class: "example-runtime-class-name"
```

유효한 값:

- 253자 이하를 포함합니다.
- 소문자, 숫자, `-` 또는 `.`만 포함합니다.
- 영숫자로 시작합니다.
- 영숫자로 끝납니다.

`default_runtime_class`에 대한 자세한 내용은 [런타임 클래스](https://kubernetes.io/docs/concepts/containers/runtime-class/)를 참조하세요.

### `allow_privilege_escalation` {#allow_privilege_escalation}

{{< history >}}

- GitLab 17.4에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/13983)되었습니다.

{{< /history >}}

이 설정을 사용하여 프로세스가 부모 프로세스보다 더 많은 권한을 얻을 수 있는지 여부를 제어합니다.

이 설정은 [`no_new_privs`](https://www.kernel.org/doc/Documentation/prctl/no_new_privs.txt) 플래그가 컨테이너 프로세스에서 설정되는지 여부를 직접 제어합니다.

기본값은 `false`입니다. 값은 다음 중 하나인 경우에만 `true`로 설정할 수 있습니다:

- [`default_runtime_class`](#default_runtime_class)이 비어 있지 않은 값으로 설정되었습니다.
- [`use_kubernetes_user_namespaces`](#use_kubernetes_user_namespaces)이 `true`로 설정되었습니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  default_runtime_class: "example-runtime-class-name"
  allow_privilege_escalation: true
```

`allow_privilege_escalation`에 대한 자세한 내용은 [Pod 또는 컨테이너의 보안 컨텍스트 구성](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/)을 참조하세요.

### `image_pull_secrets` {#image_pull_secrets}

{{< history >}}

- GitLab 17.6에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/14664)되었습니다.

{{< /history >}}

이 설정을 사용하여 워크스페이스가 프라이빗 이미지를 가져오는 데 필요한 `kubernetes.io/dockercfg` 또는 `kubernetes.io/dockerconfigjson` 타입의 기존 Kubernetes 시크릿을 지정합니다.

기본값은 `[]`입니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  image_pull_secrets:
    - name: "image-pull-secret-name"
      namespace: "image-pull-secret-namespace"
```

이 예에서 `image-pull-secret-name`은 네임스페이스 `image-pull-secret-namespace`에서 워크스페이스의 네임스페이스로 동기화됩니다.

`image_pull_secrets`의 경우 `name` 및 `namespace` 속성이 필수입니다. 시크릿의 이름은 고유해야 합니다. [`shared_namespace`](#shared_namespace)이 설정되면 시크릿의 네임스페이스는 `shared_namespace`과 동일해야 합니다.

지정한 시크릿이 Kubernetes 클러스터에 없으면 시크릿이 무시됩니다. 시크릿을 삭제하거나 업데이트하면 시크릿이 참조되는 워크스페이스의 모든 네임스페이스에서 시크릿이 삭제되거나 업데이트됩니다.

### `annotations` {#annotations}

{{< history >}}

- GitLab 17.4에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/13983)되었습니다.

{{< /history >}}

이 설정을 사용하여 Kubernetes 객체에 임의의 비식별 메타데이터를 연결합니다.

기본값은 `{}`입니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  annotations:
    "example.com/key": "value"
```

유효한 주석 키는 두 부분으로 구성된 문자열입니다:

- 선택 사항. 접두사입니다. 접두사는 253자 이하이며 마침표로 구분된 DNS 레이블을 포함해야 합니다. 접두사는 슬래시(`/`)로 끝나야 합니다.
- 이름입니다. 이름은 63자 이하이며 영숫자 문자, 대시(`-`), 밑줄(`_`) 및 마침표(`.`)만 포함해야 합니다. 이름은 영숫자 문자로 시작하고 끝나야 합니다.

Kubernetes 핵심 구성 요소용으로 예약되어 있으므로 `kubernetes.io` 및 `k8s.io`로 끝나는 접두사를 사용하지 않아야 합니다. `gitlab.com`로 끝나는 접두사도 예약되어 있습니다.

유효한 주석 값은 문자열입니다.

`annotations`에 대한 자세한 내용은 [주석](https://kubernetes.io/docs/concepts/overview/working-with-objects/annotations/)을 참조하세요.

### `labels` {#labels}

{{< history >}}

- GitLab 17.4에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/13983)되었습니다.

{{< /history >}}

이 설정을 사용하여 Kubernetes 객체에 임의의 식별 메타데이터를 연결합니다.

기본값은 `{}`입니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  labels:
    "example.com/key": "value"
```

레이블 키는 두 부분으로 구성된 문자열입니다:

- 선택 사항. 접두사입니다. 접두사는 253자 이하이며 마침표로 구분된 DNS 레이블을 포함해야 합니다. 접두사는 슬래시(`/`)로 끝나야 합니다.
- 이름입니다. 이름은 63자 이하이며 영숫자 문자, 대시(`-`), 밑줄(`_`) 및 마침표(`.`)만 포함해야 합니다. 이름은 영숫자 문자로 시작하고 끝나야 합니다.

Kubernetes 핵심 구성 요소용으로 예약되어 있으므로 `kubernetes.io` 및 `k8s.io`로 끝나는 접두사를 사용하지 않아야 합니다. `gitlab.com`로 끝나는 접두사도 예약되어 있습니다.

유효한 레이블 값:

- 63자 이하를 포함합니다. 값은 비워둘 수 있습니다.
- 영숫자 문자로 시작하고 끝납니다.
- 대시(`-`), 밑줄(`_`) 및 마침표(`.`)를 포함할 수 있습니다.

`labels`에 대한 자세한 내용은 [레이블](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/)을 참조하세요.

### `max_active_hours_before_stop` {#max_active_hours_before_stop}

{{< history >}}

- GitLab 17.6에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/14910)되었습니다.

{{< /history >}}

이 설정은 에이전트의 워크스페이스가 지정된 시간 동안 활성 상태인 후 자동으로 중지합니다. 활성 상태는 중지되지 않거나 종료되지 않은 모든 상태입니다.

이 설정의 타이머는 워크스페이스를 생성할 때 시작되며 워크스페이스를 다시 시작할 때마다 재설정됩니다. 워크스페이스가 오류 또는 실패 상태에 있더라도 적용됩니다.

기본값은 `36`(1일 반)입니다. 사용자의 일반적인 근무 시간 동안 워크스페이스가 중지되는 것을 방지합니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  max_active_hours_before_stop: 60
```

유효한 값:

- 정수입니다.
- `1`보다 크거나 같습니다.
- `8760`(1년) 이하입니다.
- `max_active_hours_before_stop` + `max_stopped_hours_before_termination`은 `8760` 이하여야 합니다.

자동 중지는 1시간마다 발생하는 전체 재조정에서만 트리거됩니다. 이는 워크스페이스가 구성된 값보다 최대 1시간 더 활성 상태일 수 있음을 의미합니다.

### `max_stopped_hours_before_termination` {#max_stopped_hours_before_termination}

{{< history >}}

- GitLab 17.6에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/14910)되었습니다.

{{< /history >}}

이 설정을 사용하여 에이전트의 워크스페이스가 지정된 시간 동안 중지된 상태에 있은 후 자동으로 종료합니다.

기본값은 `722`(약 1개월)입니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  max_stopped_hours_before_termination: 4332
```

유효한 값:

- 정수입니다.
- `1`보다 크거나 같습니다.
- `8760`(1년) 이하입니다.
- `max_active_hours_before_stop` + `max_stopped_hours_before_termination`은 `8760` 이하여야 합니다.

자동 종료는 1시간마다 발생하는 전체 재조정에서만 트리거됩니다. 이는 워크스페이스가 구성된 값보다 최대 1시간 더 오래 중지될 수 있음을 의미합니다.

### `shared_namespace` {#shared_namespace}

{{< history >}}

- GitLab 18.0에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/12327)되었습니다.

{{< /history >}}

이 설정을 사용하여 모든 워크스페이스에 대한 공유된 Kubernetes 네임스페이스를 지정합니다.

기본값은 `""`(각각의 새 워크스페이스를 자체 별도 Kubernetes 네임스페이스에 생성)입니다.

값을 지정하면 모든 워크스페이스는 개별 네임스페이스 대신 해당 Kubernetes 네임스페이스에 있습니다.

`shared_namespace`의 값을 설정하면 [`image_pull_secrets`](#image_pull_secrets) 및 [`max_resources_per_workspace`](#max_resources_per_workspace)의 허용 가능한 값에 제한이 적용됩니다.

예 구성:

```yaml
remote_development:
  # NOTE: This is a partial example.
  # Some required fields are not included.
  shared_namespace: "example-shared-namespace"
```

유효한 값:

- 최대 63자를 포함합니다.
- 소문자 영숫자 문자 또는 '-'만 포함합니다.
- 영숫자로 시작합니다.
- 영숫자로 끝납니다.

Kubernetes 네임스페이스에 대한 자세한 내용은 [네임스페이스](https://kubernetes.io/docs/concepts/overview/working-with-objects/namespaces/)를 참조하세요.

## 완전한 예 구성 {#complete-example-configuration}

다음 구성은 완전한 예 구성입니다. [구성 참조](#configuration-reference)의 모든 사용 가능한 설정이 포함되어 있습니다:

```yaml
remote_development:
  enabled: true
  dns_zone: workspaces.dev.test
  gitlab_workspaces_proxy:
    namespace: "gitlab-workspaces"

  network_policy:
    enabled: true
    egress:
      - allow: "0.0.0.0/0"
        except:
          - "10.0.0.0/8"
          - "172.16.0.0/12"
          - "192.168.0.0/16"

  default_resources_per_workspace_container:
    requests:
      cpu: "0.5"
      memory: "512Mi"
    limits:
      cpu: "1"
      memory: "1Gi"

  max_resources_per_workspace:
    requests:
      cpu: "1"
      memory: "1Gi"
    limits:
      cpu: "2"
      memory: "4Gi"

  workspaces_quota: 10
  workspaces_per_user_quota: 3

  use_kubernetes_user_namespaces: false
  default_runtime_class: "standard"
  allow_privilege_escalation: false

  image_pull_secrets:
    - name: "registry-secret"
      namespace: "default"

  annotations:
    environment: "production"
    team: "engineering"

  labels:
    app: "workspace"
    tier: "development"

  max_active_hours_before_stop: 60
  max_stopped_hours_before_termination: 4332
  shared_namespace: ""
```
