---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 클러스터 관리 프로젝트로 cert-manager 설치
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[관리 프로젝트 템플릿](../../../../clusters/management_project_template.md)에서 생성한 프로젝트가 이미 있다면, cert-manager를 설치하려면 `helmfile.yaml`의 다음 줄의 주석을 제거해야 합니다:

```yaml
  - path: applications/cert-manager/helmfile.yaml
```

`applications/cert-manager/helmfile.yaml`을 유효한 이메일 주소로 업데이트합니다.

```yaml
  values:
    - letsEncryptClusterIssuer:
        #
        # IMPORTANT: This value MUST be set to a valid email.
        #
        email: example@example.com
```

> [!note]
> Kubernetes 버전이 1.20보다 이전이고 [GitLab Managed Apps에서 클러스터 관리 프로젝트로 마이그레이션](../../../../clusters/migrating_from_gma_to_project_template.md)하는 경우, 대신 `- path: applications/cert-manager-legacy/helmfile.yaml`을 사용하여 cert-manager v0.10의 기존 릴리스를 인수할 수 있습니다.

cert-manager:

- 기본적으로 클러스터의 `gitlab-managed-apps` 네임스페이스에 설치됩니다.
- [Let's Encrypt `ClusterIssuer`](https://cert-manager.io/docs/configuration/acme/)를 기본적으로 포함합니다. `certmanager-issuer` 릴리스에서 발급자는 `letsEncryptClusterIssuer.email`에 대한 유효한 이메일 주소가 필요합니다. Let's Encrypt는 이 이메일 주소를 사용하여 만료되는 인증서 및 계정 관련 문제에 대해 연락합니다.
- `applications/cert-manager/helmfile.yaml`에서 사용자 정의 `values`을 `certmanager` 릴리스에 전달하여 사용자 정의할 수 있습니다. 사용 가능한 구성 옵션은 [차트](https://github.com/cert-manager/cert-manager)를 참조하십시오.
