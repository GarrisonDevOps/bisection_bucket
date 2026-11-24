---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab Release CLI 도구(더 이상 사용되지 않음)
---

<!--- start_remove The following content will be removed on remove_date: '2027-08-18' -->

> [!warning]
> 이 기능은 GitLab 18.0에서 [더 이상 사용되지 않으며](https://gitlab.com/gitlab-org/cli/-/issues/7859) 20.0에서 제거될 예정입니다. 대신 [GitLab CLI](../../../editor_extensions/gitlab_cli/_index.md)를 사용하세요.
>
> 이 변경 사항은 호환성이 깨지는 변경입니다.

## `release-cli`에서 `glab` CLI로 마이그레이션 {#migrate-from-release-cli-to-glab-cli}

`release-cli`에서 `glab` CLI로 마이그레이션하려면 작업의 구성을 기반으로 다음 중 하나를 업데이트합니다:

1. 작업에서 `release` 키워드를 사용하는 경우 `cli:latest` 이미지를 사용하도록 업데이트합니다:

   ```yaml
   release_job:
     stage: release
     image: registry.gitlab.com/gitlab-org/cli:latest
     rules:
       - if: $CI_COMMIT_TAG
     script:
       - echo "Running the release job."
     release:
       tag_name: $CI_COMMIT_TAG
       name: 'Release $CI_COMMIT_TAG'
       description: 'Release created using the CLI.'
   ```

   자세한 내용은 [`release`](../../../ci/yaml/_index.md#release)를 참조하세요.

1. 작업에서 `release-cli` 명령을 `script` 블록에서 사용하는 경우 `glab release create`를 사용하도록 업데이트하고 [릴리스 API](../../../api/releases/_index.md)에 대한 인증을 구성합니다.

### CI/CD 작업 토큰으로 인증 {#authenticate-with-the-cicd-job-token}

[`CI_JOB_TOKEN`](../../../ci/jobs/ci_job_token.md)로 인증하려면 `GLAB_ENABLE_CI_AUTOLOGIN`를 `true`로 설정합니다. `glab` CLI는 `CI_JOB_TOKEN`을 `JOB-TOKEN` 헤더에서 전송하며, 릴리스 API는 이를 수락합니다.

```yaml
release_job:
  stage: release
  image: registry.gitlab.com/gitlab-org/cli:latest
  rules:
    - if: $CI_COMMIT_TAG
  variables:
    GLAB_ENABLE_CI_AUTOLOGIN: "true"
  script:
    - |
      glab release create "$CI_COMMIT_TAG" \
      --name "Release $CI_COMMIT_TAG" \
      --notes "Release created with glab."
```

### 액세스 토큰으로 인증 {#authenticate-with-an-access-token}

[개인](../../profile/personal_access_tokens.md), [프로젝트](../settings/project_access_tokens.md) 또는 [그룹](../../group/settings/group_access_tokens.md) 액세스 토큰으로 인증하려면 `GITLAB_TOKEN`를 액세스 토큰으로 설정합니다. 토큰은 `api` 범위를 가져야 합니다.

```yaml
release_job:
  stage: release
  image: registry.gitlab.com/gitlab-org/cli:latest
  rules:
    - if: $CI_COMMIT_TAG
  variables:
    GITLAB_TOKEN: $RELEASE_ACCESS_TOKEN
  script:
    - |
      glab release create "$CI_COMMIT_TAG" \
      --name "Release $CI_COMMIT_TAG" \
      --notes "Release created with glab."
```

> [!warning]
> `GITLAB_TOKEN`를 `$CI_JOB_TOKEN`로 설정하지 마세요. `glab` CLI는 `GITLAB_TOKEN`를 `PRIVATE-TOKEN` 헤더에서 전송하지만, 릴리스 API는 작업 토큰을 `JOB-TOKEN` 헤더에서만 허용합니다. 이 조합은 `404 Not Found`을 반환합니다. CI/CD 작업 토큰으로 인증하려면 대신 `GLAB_ENABLE_CI_AUTOLOGIN`를 `true`로 설정합니다.

전체 옵션 목록은 [`glab release create`](https://docs.gitlab.com/cli/release/create/) 명령 참고서를 참조하세요.

## `release-cli`로 폴백 {#fall-back-to-release-cli}

{{< history >}}

- GitLab 18.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/524346)되었으며, [기능 플래그](../../../administration/feature_flags/_index.md)명 `ci_glab_for_release`로 도입되었습니다. 기본적으로 활성화됩니다.
- GitLab 18.4에서 [정식 출시(GA)](https://gitlab.com/gitlab-org/gitlab/-/issues/537398). 기능 플래그 `ci_glab_for_release`이 제거되었습니다.

{{< /history >}}

`release` 키워드를 사용하는 CI/CD 작업은 필요한 `glab` 버전을 러너에서 사용할 수 없는 경우 `release-cli`를 사용하여 폴백하는 스크립트를 사용합니다. 폴백 로직은 아직 `glab` CLI로 마이그레이션하지 않은 프로젝트가 계속 작동할 수 있도록 하는 보안 장치입니다.

이 폴백은 GitLab 20.0에서 `release-cli`의 제거와 함께 [제거될 예정](https://gitlab.com/gitlab-org/gitlab/-/issues/537919)입니다.

<!--- end_remove -->
