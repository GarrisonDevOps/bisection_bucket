---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 클러스터 관리 프로젝트를 사용하여 Ingress 설치
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[관리 프로젝트 템플릿](../../../../clusters/management_project_template.md)에서 생성한 프로젝트가 이미 있다고 가정하면 Ingress를 설치하기 위해 `helmfile.yaml`에서 이 줄의 주석을 제거해야 합니다:

```yaml
  - path: applications/ingress/helmfile.yaml
```

Ingress는 기본적으로 클러스터의 `gitlab-managed-apps` 네임스페이스에 설치됩니다.

클러스터 관리 프로젝트에서 `applications/ingress/values.yaml` 파일을 업데이트하여 Ingress 설치를 사용자 지정할 수 있습니다. 사용 가능한 구성 옵션은 [차트](https://github.com/kubernetes/ingress-nginx/tree/master/charts/ingress-nginx)를 참조하세요.
