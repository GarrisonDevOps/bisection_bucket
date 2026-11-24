---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 클러스터 관리 프로젝트를 사용하여 GitLab Runner 설치
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[관리 프로젝트 템플릿](../../../../clusters/management_project_template.md)에서 생성한 프로젝트가 이미 있다고 가정하고, GitLab Runner를 설치하려면 `helmfile.yaml`에서 다음 줄의 주석을 제거해야 합니다:

```yaml
  - path: applications/gitlab-runner/helmfile.yaml
```

GitLab Runner는 기본적으로 클러스터의 `gitlab-managed-apps` 네임스페이스에 설치됩니다.

## 필수 변수 {#required-variables}

GitLab Runner가 작동하려면 `applications/gitlab-runner/values.yaml.gotmpl` 파일에서 다음을 지정해야 합니다:

- `gitlabUrl`: 러너를 등록할 GitLab 서버 전체 URL(예: `https://gitlab.example.com`)입니다.
- 러너 토큰: 이는 GitLab 인스턴스에서 [검색](../../../../../ci/runners/_index.md)되어야 합니다. 다음 토큰 중 하나를 사용할 수 있습니다:

  - `runnerToken`: [GitLab UI에서 생성](../../../../../ci/runners/runners_scope.md)된 러너 구성의 러너 인증 토큰입니다.
  - `runnerRegistrationToken` (GitLab 15.6에서 [더 이상 사용되지 않음](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/102681)이며 GitLab 20.0에서 제거될 예정입니다.): GitLab에 새 러너를 추가하는 데 사용되는 등록 토큰입니다.

이러한 값은 [CI/CD 변수](../../../../../ci/variables/_index.md)를 사용하여 지정할 수 있습니다:

- `CI_SERVER_URL`은 `gitlabUrl`에 사용됩니다. GitLab.com을 사용하는 경우 이 변수를 설정할 필요가 없습니다.
- `GITLAB_RUNNER_TOKEN`은 `runnerToken`에 사용됩니다.
- `GITLAB_RUNNER_REGISTRATION_TOKEN`은 `runnerRegistrationToken`(더 이상 사용되지 않음)에 사용됩니다.

이러한 값을 지정하는 방법은 상호 배타적입니다. 다음 중 하나를 수행할 수 있습니다.

- 변수 `GITLAB_RUNNER_TOKEN`과 `CI_SERVER_URL`를 CI 변수로 지정합니다(권장).
- `runnerToken:`과 `gitlabUrl:`의 값을 `applications/gitlab-runner/values.yaml.gotmpl`에 입력합니다.

러너 등록 토큰은 러너를 통한 프로젝트 연결을 허용합니다. 악의적인 사용을 방지하고 러너를 통한 코드 유출을 방지하기 위해 이를 보안 정보로 취급하세요. 러너 등록 토큰을 [보호된 변수](../../../../../ci/variables/_index.md#protect-a-cicd-variable)와 [마스킹된 변수](../../../../../ci/variables/_index.md#mask-a-cicd-variable)로 지정하세요. 토큰을 Git 리포지토리의 `values.yaml.gotmpl` 파일에 커밋하지 마세요.

클러스터 관리 프로젝트에서 `applications/gitlab-runner/values.yaml.gotmpl` 파일을 정의하여 GitLab Runner 설치를 사용자 지정할 수 있습니다. 사용 가능한 구성 옵션은 [차트](https://gitlab.com/gitlab-org/charts/gitlab-runner)를 참고하세요.
