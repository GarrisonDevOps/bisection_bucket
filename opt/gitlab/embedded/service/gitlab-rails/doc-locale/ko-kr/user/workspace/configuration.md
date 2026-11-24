---
stage: Create
group: Remote Development
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab 워크스페이스를 구성하여 GitLab 개발 환경을 관리하세요.
title: 워크스페이스 구성
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[워크스페이스](_index.md)를 사용하여 GitLab 프로젝트의 격리된 개발 환경을 생성하고 관리할 수 있습니다. 각 워크스페이스에는 자체 종속성 집합, 라이브러리 및 도구가 포함되어 있으며, 각 프로젝트의 특정 요구 사항을 충족하도록 사용자 지정할 수 있습니다.

## 워크스페이스 인프라 설정 {#set-up-workspace-infrastructure}

[워크스페이스를 생성](#create-a-workspace)하기 전에 인프라를 한 번만 설정해야 합니다. 클라우드 제공자와 관계없이 워크스페이스의 인프라를 설정하려면 다음을 수행해야 합니다:

1. [GitLab agent for Kubernetes](../clusters/agent/_index.md)가 지원하는 Kubernetes 클러스터를 설정합니다. [지원되는 Kubernetes 버전](../clusters/agent/_index.md#supported-kubernetes-versions-for-gitlab-features)을 참조하세요.
1. Kubernetes 클러스터에 대해 자동 크기 조정이 활성화되었는지 확인하세요.
1. Kubernetes 클러스터에서:
   1. [기본 저장소 클래스](https://kubernetes.io/docs/concepts/storage/storage-classes/)가 정의되어 있는지 확인하여 각 워크스페이스에 대해 볼륨을 동적으로 프로비저닝할 수 있습니다.
1. [GitLab agent for Kubernetes 튜토리얼 설정](set_up_gitlab_agent_and_proxies.md)의 모든 단계를 완료합니다.
1. 선택 사항. [워크스페이스에서 컨테이너 빌드 및 실행](#build-and-run-containers-in-a-workspace).
1. 선택 사항. [프라이빗 컨테이너 레지스트리 지원 구성](#configure-support-for-private-container-registries).
1. 선택 사항. [워크스페이스의 sudo 액세스 구성](#configure-sudo-access-for-a-workspace).

AWS를 사용하는 경우 OpenTofu 튜토리얼을 사용할 수 있습니다. 자세한 내용은 [AWS에서 워크스페이스 인프라 설정 튜토리얼](set_up_infrastructure.md)을 참조하세요.

## 워크스페이스 생성 {#create-a-workspace}

{{< history >}}

- **변수** [GitLab 17.1에 도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/issues/463514)
- **워크스페이스는 다음 시간 후에 자동으로 종료됩니다** [GitLab 17.6에서 제거되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/166065)
- **워크스페이스를 머지 리퀘스트 페이지에서 생성할 수 있습니다** [GitLab 18.0에 도입되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/187320)

{{< /history >}}

> [!warning]
> 신뢰할 수 있는 프로젝트에서만 워크스페이스를 생성하세요.

사전 요구 사항:

- [워크스페이스 인프라를 설정](#set-up-workspace-infrastructure)해야 합니다.
- 워크스페이스 및 에이전트 프로젝트에 대해 개발자, 관리자 또는 소유자 역할이 있어야 합니다.

{{< tabs >}}

{{< tab title="프로젝트에서" >}}

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 프로젝트 페이지에서 우측 상단의 **코드** 드롭다운을 선택한 다음, **작업공간** 섹션에서 **새 작업공간**을 선택하세요.
1. **클러스터 에이전트** 드롭다운 목록에서 프로젝트가 속한 그룹이 소유한 클러스터 에이전트를 선택하세요.
1. **Git 참조** 드롭다운 목록에서 GitLab이 워크스페이스를 생성하는 데 사용하는 브랜치, 태그 또는 커밋 해시를 선택하세요. 기본적으로 이는 현재 보고 있는 브랜치입니다.
1. **Devfile** 드롭다운 목록에서 다음 중 하나를 선택하세요:
   - [GitLab 기본 devfile](_index.md#gitlab-default-devfile).
   - [사용자 지정 devfile](_index.md#custom-devfile).
1. **변수**에서 워크스페이스에 주입하려는 환경 변수의 키와 값을 입력하세요. 새 변수를 추가하려면 **변수 추가**를 선택하세요.
1. **작업공간 생성**을 선택하세요.

{{< /tab >}}

{{< tab title="머지 리퀘스트에서" >}}

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **병합 요청**을 선택합니다.
1. 워크스페이스를 생성할 머지 리퀘스트를 선택하세요.
1. **코드** > **워크스페이스내에서 열기**를 선택하세요.
1. **클러스터 에이전트** 드롭다운 목록에서 프로젝트가 속한 그룹이 소유한 클러스터 에이전트를 선택하세요.
1. **Git 참조** 드롭다운 목록에서 GitLab이 워크스페이스를 생성하는 데 사용하는 브랜치, 태그 또는 커밋 해시를 선택하세요. 기본적으로 이는 머지 리퀘스트의 소스 브랜치입니다.
1. **Devfile** 드롭다운 목록에서 다음 중 하나를 선택하세요:
   - [GitLab 기본 devfile](_index.md#gitlab-default-devfile).
   - [사용자 지정 devfile](_index.md#custom-devfile).
1. **변수**에서 워크스페이스에 주입하려는 환경 변수의 키와 값을 입력하세요. 새 변수를 추가하려면 **변수 추가**를 선택하세요.
1. **작업공간 생성**을 선택하세요.

{{< /tab >}}

{{< /tabs >}}

워크스페이스가 시작되는 데 몇 분이 걸릴 수 있습니다. 워크스페이스를 열려면 **미리보기** 아래에서 워크스페이스를 선택하세요. 터미널에도 액세스할 수 있으며 필요한 종속성을 설치할 수 있습니다.

### 워크스페이스 시작 진행 상황 모니터링 {#monitor-workspace-startup-progress}

워크스페이스를 시작하면 `postStart` 이벤트의 초기화 작업 및 진행 상황을 모니터링하고 워크스페이스 로그를 확인할 수 있습니다. 자세한 내용은 [워크스페이스 로그 디렉터리](_index.md#workspace-logs-directory)를 참조하세요.

## 플랫폼 호환성 {#platform-compatibility}

워크스페이스의 플랫폼 요구 사항은 개발 요구 사항에 따라 달라집니다.

기본 워크스페이스 기능의 경우 워크스페이스는 기본 운영 체제와 관계없이 GitLab agent for Kubernetes를 지원하는 모든 `linux/amd64` Kubernetes 클러스터에서 실행됩니다.

플랫폼 요구 사항에 맞는 방법을 선택하려면 [워크스페이스의 sudo 액세스 구성](#configure-sudo-access-for-a-workspace)을 참조하세요.

## 워크스페이스에서 컨테이너 빌드 및 실행 {#build-and-run-containers-in-a-workspace}

{{< history >}}

- GitLab 17.4에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/13983)되었습니다.

{{< /history >}}

개발 환경은 런타임 중에 종속성을 관리하고 사용하기 위해 컨테이너를 빌드하고 실행해야 하는 경우가 많습니다. 워크스페이스에서 컨테이너를 빌드하고 실행하려면 [워크스페이스의 sudo 액세스 구성](#configure-sudo-access-for-a-workspace)을 참조하세요.

## 프라이빗 컨테이너 레지스트리 지원 구성 {#configure-support-for-private-container-registries}

{{< history >}}

- GitLab 17.6에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/14664)되었습니다.

{{< /history >}}

프라이빗 컨테이너 레지스트리의 이미지를 사용하려면:

1. [Kubernetes에서 이미지 가져오기 시크릿](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/)을 생성합니다.
1. 이 시크릿의 `name` 및 `namespace`을(를) [GitLab agent for Kubernetes 구성](gitlab_agent_configuration.md)에 추가합니다.

자세한 내용은 [`image_pull_secrets`](settings.md#image_pull_secrets)를 참조하세요.

## 워크스페이스의 sudo 액세스 구성 {#configure-sudo-access-for-a-workspace}

{{< history >}}

- GitLab 17.4에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/13983)되었습니다.

{{< /history >}}

개발 환경은 종종 런타임 중에 종속성을 설치, 구성 및 사용하기 위해 sudo 권한이 필요합니다. 플랫폼 요구 사항에 맞는 방법을 선택하세요:

| 메서드                                   | 플랫폼 요구 사항                                                                                                                                                                                                                                                                     | 용도 |
|------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------|
| [Sysbox](#with-sysbox)                   | 최신 정보는 [Sysbox 배포 호환성 매트릭스](https://github.com/nestybox/sysbox/blob/master/docs/distro-compat.md)를 참조하세요.                                                                                                                                     | 컨테이너 격리를 개선하고 컨테이너가 가상 머신과 동일한 워크로드를 실행할 수 있도록 합니다. |
| [Kata Containers](#with-kata-containers) | 최신 정보는 [Kata Containers 설치 가이드](https://github.com/kata-containers/kata-containers/tree/main/docs/install)를 참조하세요.                                                                                                                                     | 경량 VM은 컨테이너처럼 수행하지만 향상된 워크로드 격리 및 보안을 제공합니다. |
| [사용자 네임스페이스](#with-user-namespaces) | Kubernetes 버전 1.33 이상은 기본적으로 활성화된 Kubernetes 기능 게이트 뒤에서 사용자 네임스페이스를 활성화합니다. 최신 정보는 [Kubernetes 기능 게이트](https://kubernetes.io/docs/reference/command-line-tools-reference/feature-gates/)를 참조하세요. | 추가 런타임 설치가 필요하지 않습니다. 컨테이너 사용자를 호스트 사용자와 격리하여 보안을 개선합니다. |

사전 요구 사항:

- 컨테이너 이미지는 [임의 사용자 ID](_index.md#arbitrary-user-ids)를 지원해야 합니다. sudo 액세스가 구성된 경우에도 [devfile](_index.md#devfile)에서 사용되는 컨테이너 이미지는 사용자 ID `0`로 실행할 수 없습니다.

### Sysbox 사용 {#with-sysbox}

[Sysbox](https://github.com/nestybox/sysbox)는 컨테이너 격리를 개선하고 컨테이너가 가상 머신과 동일한 워크로드를 실행할 수 있도록 하는 컨테이너 런타임입니다.

Sysbox를 사용하여 sudo 액세스를 구성하려면:

1. Kubernetes 클러스터에서 [Sysbox를 설치](https://github.com/nestybox/sysbox#installation)합니다.
1. GitLab agent for Kubernetes를 구성합니다:

   - 기본 런타임 클래스를 설정합니다. [`default_runtime_class`](settings.md#default_runtime_class)에서 Sysbox의 런타임 클래스를 입력합니다. 예를 들어, `sysbox-runc`입니다.
   - 권한 상승을 활성화합니다. [`allow_privilege_escalation`](settings.md#allow_privilege_escalation)을(를) `true`로 설정합니다.
   - Sysbox에 필요한 주석을 구성합니다. [`annotations`](settings.md#annotations)을(를) `{"io.kubernetes.cri-o.userns-mode": "auto:size=65536"}`로 설정합니다.

### Kata Containers 사용 {#with-kata-containers}

[Kata Containers](https://github.com/kata-containers/kata-containers)는 컨테이너처럼 수행하지만 가상 머신의 워크로드 격리 및 보안을 제공하는 경량 가상 머신의 표준 구현입니다.

Kata Containers를 사용하여 sudo 액세스를 구성하려면:

1. Kubernetes 클러스터에서 [Kata Containers를 설치](https://github.com/kata-containers/kata-containers/tree/main/docs/install)합니다.
1. GitLab agent for Kubernetes를 구성합니다:

   - 기본 런타임 클래스를 설정합니다. [`default_runtime_class`](settings.md#default_runtime_class)에서 Kata Containers의 런타임 클래스를 입력합니다. 예를 들어, `kata-qemu`입니다.
   - 권한 상승을 활성화합니다. [`allow_privilege_escalation`](settings.md#allow_privilege_escalation)을(를) `true`로 설정합니다.

### 사용자 네임스페이스 사용 {#with-user-namespaces}

[사용자 네임스페이스](https://kubernetes.io/docs/concepts/workloads/pods/user-namespaces/)는 컨테이너 사용자를 호스트 사용자와 격리합니다.

사용자 네임스페이스를 사용하여 sudo 액세스를 구성하려면:

1. Kubernetes 클러스터에서 [사용자 네임스페이스를 구성](https://kubernetes.io/blog/2024/04/22/userns-beta/)합니다.
1. GitLab agent for Kubernetes를 구성합니다:

   - [`use_kubernetes_user_namespaces`](settings.md#use_kubernetes_user_namespaces)을(를) `true`로 설정합니다.
   - [`allow_privilege_escalation`](settings.md#allow_privilege_escalation)을(를) `true`로 설정합니다.

## SSH를 사용하여 워크스페이스에 연결 {#connect-to-a-workspace-with-ssh}

사전 요구 사항:

- [devfile](_index.md#devfile)에 지정된 이미지에 대해 SSH 액세스를 활성화해야 합니다. 자세한 내용은 [워크스페이스 컨테이너 이미지 업데이트](#update-your-workspace-container-image)를 참조하세요.
- GitLab 워크스페이스 프록시를 가리키는 TCP 로드 밸런서를 구성해야 합니다. 자세한 내용은 [DNS 레코드 업데이트](set_up_gitlab_agent_and_proxies.md#update-your-dns-records)를 참조하세요.

SSH 클라이언트를 사용하여 워크스페이스에 연결하려면:

1. `gitlab-workspaces-proxy-ssh` 서비스의 외부 IP 주소를 가져옵니다:

   ```shell
   kubectl -n gitlab-workspaces get service gitlab-workspaces-proxy-ssh
   ```

1. 워크스페이스의 이름을 가져옵니다:

   1. 상단 표시줄에서 **검색 또는 이동**을 선택합니다.
   1. **귀하의 작업**을 선택하세요.
   1. **작업공간**을 선택하세요.
   1. 연결하려는 워크스페이스의 이름을 복사합니다.

1. 이 명령을 실행하세요:

   ```shell
   ssh <workspace_name>@<ssh_proxy_IP_address>
   ```

1. 암호의 경우 최소한 `read_api` 범위가 있는 개인 액세스 토큰을 입력합니다.

`gitlab-workspaces-proxy`을(를)통해 TCP 로드 밸런서에 연결할 때 `gitlab-workspaces-proxy`는 사용자 이름(워크스페이스 이름)을 검사하고 GitLab과 상호 작용하여 다음을 확인합니다:

- 개인 액세스 토큰
- 워크스페이스에 대한 사용자 액세스

### 워크스페이스 컨테이너 이미지 업데이트 {#update-your-workspace-container-image}

두 가지 방법으로 사용자 지정 워크스페이스 이미지를 업데이트할 수 있습니다.

워크스페이스 이미지가 [워크스페이스 기본 이미지](_index.md#workspace-base-image)를 기반으로 하는 경우 SSH 지원이 이미 구성되고 사용할 준비가 되어 있습니다. 이 방법은 이미지에 필요한 모든 워크스페이스 구성이 있는지 확인합니다. 자세한 내용은 [사용자 지정 워크스페이스 이미지 생성](create_image.md)을 참조하세요.

워크스페이스 기본 이미지를 사용하지 않으려면 자신의 기본 이미지에서 빌드할 수 있습니다. 이렇게 하면 런타임 이미지에서 SSH 지원을 수동으로 구성합니다:

1. 런타임 이미지에 [`sshd`](https://man.openbsd.org/sshd.8)을(를) 설치합니다.
1. 암호 없이 컨테이너에 액세스할 수 있도록 `gitlab-workspaces`이라는 사용자를 생성합니다.

다음은 SSH 구성 예시입니다:

```dockerfile
FROM golang:1.20.5-bullseye

# Install `openssh-server` and other dependencies
RUN apt update \
    && apt upgrade -y \
    && apt install openssh-server sudo curl git wget software-properties-common apt-transport-https --yes \
    && rm -rf /var/lib/apt/lists/*

# Permit empty passwords
RUN sed -i 's/nullok_secure/nullok/' /etc/pam.d/common-auth
RUN echo "PermitEmptyPasswords yes" >> /etc/ssh/sshd_config

# Generate a workspace host key
RUN ssh-keygen -A
RUN chmod 775 /etc/ssh/ssh_host_rsa_key && \
    chmod 775 /etc/ssh/ssh_host_ecdsa_key && \
    chmod 775 /etc/ssh/ssh_host_ed25519_key

# Create a `gitlab-workspaces` user
RUN useradd -l -u 5001 -G sudo -md /home/gitlab-workspaces -s /bin/bash gitlab-workspaces
RUN passwd -d gitlab-workspaces
ENV HOME=/home/gitlab-workspaces
WORKDIR $HOME
RUN mkdir -p /home/gitlab-workspaces && chgrp -R 0 /home && chmod -R g=u /etc/passwd /etc/group /home

# Allow sign-in access to `/etc/shadow`
RUN chmod 775 /etc/shadow

USER gitlab-workspaces
```

## 관련 항목 {#related-topics}

- [튜토리얼: GitLab agent for Kubernetes 설정](set_up_gitlab_agent_and_proxies.md)
- [워크스페이스 설정](settings.md)
- [워크스페이스 문제 해결](workspaces_troubleshooting.md)
- [GitLab 원격 개발 워크스페이스 빠른 시작 가이드](https://go.gitlab.com/AVKFvy)
- [GitLab에서 온디맨드 클라우드 기반 개발 환경을 위한 인프라 설정](https://go.gitlab.com/dp75xo)
