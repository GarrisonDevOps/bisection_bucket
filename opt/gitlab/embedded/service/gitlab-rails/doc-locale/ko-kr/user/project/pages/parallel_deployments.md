---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab Pages 병렬 배포
description: "GitLab Pages 사이트의 여러 버전을 동시에 게시하며, 각 버전은 자신의 URL을 가집니다."
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 16.7에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/129534)되었으며, [실험](../../../policy/development_stages_support.md)으로 [기능 플래그](../../../administration/feature_flags/list.md) `pages_multiple_versions_setting`로 명명되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.4에서 "다중 배포"에서 "병렬 배포"로 [이름이 변경](https://gitlab.com/gitlab-org/gitlab/-/issues/480195)되었습니다.
- [GitLab.com, GitLab Self-Managed, GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/422145)됨 (GitLab 17.4).
- GitLab 17.7에서 프로젝트 설정을 제거하도록 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/502219)되었습니다.
- GitLab 17.8에서 `path_prefix`에서 마침표를 허용하도록 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/507423)되었습니다.
- GitLab 17.9에서 `publish` 속성에 전달될 때 변수를 허용하도록 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/500000)되었습니다.
- GitLab 17.9에서 [일반 공급 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/487161). 기능 플래그 `pages_multiple_versions_setting`이 제거되었습니다.
- `pages.publish` 경로를 `artifacts:paths`에 자동으로 추가 - GitLab 17.10의 Pages 작업에만 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/428018).

{{< /history >}}

병렬 배포를 사용하면 [GitLab Pages](_index.md) 사이트의 여러 버전을 동시에 게시할 수 있습니다. 각 버전은 사용자가 지정한 경로 접두사를 기반으로 고유한 URL을 가집니다.

병렬 배포를 사용하려면:

- 프로덕션으로 병합하기 전에 개발 브랜치의 변경 사항을 테스트하는 워크플로우를 개선합니다.
- 이해관계자와 함께 작동하는 미리 보기를 공유하여 피드백을 받습니다.
- 여러 소프트웨어 버전에 대한 문서를 동시에 유지합니다.
- 다양한 대상에 맞는 지역화된 콘텐츠를 게시합니다.
- 최종 게시 전에 검토하기 위한 스테이징 환경을 만듭니다.

사이트의 각 버전은 사용자가 지정한 경로 접두사를 기반으로 고유한 URL을 가집니다. 이러한 병렬 배포가 존재하는 기간을 제어합니다. 기본적으로 24시간 후 만료되지만, 검토 타임라인에 맞게 이 기간을 사용자 정의할 수 있습니다.

## 병렬 배포 만들기 {#create-a-parallel-deployment}

사전 요구 사항:

- 루트 수준 네임스페이스는 [병렬 배포 슬롯](../../gitlab_com/_index.md#other-limits)을 사용할 수 있어야 합니다.

병렬 배포를 만들려면:

1. `.gitlab-ci.yml` 파일에서 `path_prefix`와 함께 Pages 작업을 추가합니다:

   ```yaml
   pages:
     stage: deploy
     script:
       - echo "Pages accessible through ${CI_PAGES_URL}"
     pages:  # specifies that this is a Pages job and publishes the default public directory
       path_prefix: "$CI_COMMIT_BRANCH"
   ```

   `path_prefix` 값:

   - 소문자로 변환됩니다.
   - 숫자(`0-9`), 문자(`a-z`), 마침표(`.`)를 포함할 수 있습니다.
   - 다른 문자의 경우 하이픈(`-`)으로 바뀝니다.
   - 하이픈(`-`) 또는 마침표(`.`)로 시작하거나 끝날 수 없으므로 제거됩니다.
   - 63바이트 이하여야 합니다. 더 긴 값은 잘립니다.

1. 선택 사항. 동적 접두사를 원하면 `path_prefix`에서 [CI/CD 변수](../../../ci/variables/where_variables_can_be_used.md#gitlab-ciyml-file)를 사용합니다. 예를 들어:

   ```yaml
   pages:
     path_prefix: "mr-$CI_MERGE_REQUEST_IID" # Results in paths like mr-123
   ```

1. 선택 사항. 배포의 만료 시간을 설정하려면 `expire_in`을 추가합니다:

   ```yaml
   pages:
     pages:
       path_prefix: "$CI_COMMIT_BRANCH"
       expire_in: 1 week
   ```

   기본적으로 병렬 배포는 24시간 후에 [만료](#expiration)됩니다.

1. 변경 사항을 커밋하고 리포지토리로 푸시합니다.

배포는 다음 위치에서 액세스할 수 있습니다:

- [고유 도메인](_index.md#unique-domains)을 사용하는 경우: `https://project-123456.gitlab.io/your-prefix-name`.
- 고유 도메인을 사용하지 않는 경우: `https://namespace.gitlab.io/project/your-prefix-name`.

사이트 도메인과 공개 디렉터리 사이의 URL 경로는 `path_prefix`에 의해 결정됩니다. 예를 들어, 주 배포가 `/index.html`에서 콘텐츠를 가지고 있다면, 접두사 `staging`를 가진 병렬 배포는 `/staging/index.html`에서 동일한 콘텐츠에 액세스할 수 있습니다.

경로 충돌을 방지하려면, 사이트의 기존 폴더 이름과 일치하는 경로 접두사를 사용하지 마세요. 자세한 내용은 [경로 충돌](#path-clash)을 참조하세요.

## 예제 구성 {#example-configuration}

`https://gitlab.example.com/namespace/project`과 같은 프로젝트를 고려합니다. 기본적으로 주 Pages 배포는 다음을 통해 액세스할 수 있습니다:

- [고유 도메인](_index.md#unique-domains)을 사용하는 경우: `https://project-123456.gitlab.io/`.
- 고유 도메인을 사용하지 않는 경우: `https://namespace.gitlab.io/project`.

`pages.path_prefix`이 프로젝트 브랜치 이름으로 구성되어 있고, `path_prefix = $CI_COMMIT_BRANCH`와 같이 `username/testing_feature`이라는 브랜치가 있다면, 이 병렬 Pages 배포는 다음을 통해 액세스할 수 있습니다:

- [고유 도메인](_index.md#unique-domains)을 사용하는 경우: `https://project-123456.gitlab.io/username-testing-feature`.
- 고유 도메인을 사용하지 않는 경우: `https://namespace.gitlab.io/project/username-testing-feature`.

## 제한 {#limits}

병렬 배포의 수는 루트 수준 네임스페이스에 의해 제한됩니다. 다음에 대한 특정 제한:

- GitLab.com의 경우 [기타 제한](../../gitlab_com/_index.md#other-limits)을 참조하세요.
- GitLab Self-Managed의 경우 [병렬 Pages 배포 수](../../../administration/instance_limits.md#number-of-parallel-pages-deployments)를 참조하세요.

네임스페이스의 활성 배포 수를 즉시 줄이려면 일부 배포를 삭제합니다. 자세한 내용은 [배포 삭제](_index.md#delete-a-deployment)를 참조하세요.

만료 시간을 구성하여 이전 배포를 자동으로 삭제하려면 [배포 만료](_index.md#expiring-deployments)를 참조하세요.

## 만료 {#expiration}

기본적으로 병렬 배포는 24시간 후에 [만료](_index.md#expiring-deployments)되며, 그 후 삭제됩니다. 자체 호스팅 인스턴스를 사용하는 경우 인스턴스 관리자는 [다른 기본 기간을 구성](../../../administration/pages/_index.md#configure-the-default-expiry-for-parallel-deployments)할 수 있습니다.

만료 시간을 사용자 정의하려면 [`pages.expire_in`를 구성](_index.md#expiring-deployments)합니다.

배포가 자동으로 만료되지 않도록 하려면 `pages.expire_in`을 `never`로 설정합니다.

## 경로 충돌 {#path-clash}

`pages.path_prefix`은 [CI/CD 변수](../../../ci/variables/_index.md)에서 동적 값을 가져올 수 있으며, 이는 사이트의 기존 경로와 충돌할 수 있는 페이지 배포를 만들 수 있습니다. 예를 들어, 다음 경로를 포함하는 기존 GitLab Pages 사이트가 주어지면:

```plaintext
/index.html
/documents/index.html
```

`pages.path_prefix`이 `documents`이면, 해당 버전은 기존 경로를 재정의합니다. 즉, `https://namespace.gitlab.io/project/documents/index.html`은 사이트의 `documents` 배포의 `/index.html`를 가리키며, 사이트의 `main` 배포의 `documents/index.html`이 아닙니다.

[CI/CD 변수](../../../ci/variables/_index.md)를 다른 문자열과 혼합하면 경로 충돌 가능성을 줄일 수 있습니다. 예를 들어:

```yaml
create-pages:
  stage: deploy
  script:
    - echo "Pages accessible through ${CI_PAGES_URL}"
  variables:
    PAGES_PREFIX: "" # No prefix by default (main)
  pages:  # specifies that this is a Pages job and publishes the default public directory
    path_prefix: "$PAGES_PREFIX"
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH # Run on default branch (with default PAGES_PREFIX)
    - if: $CI_COMMIT_BRANCH == "staging" # Run on main (with default PAGES_PREFIX)
      variables:
        PAGES_PREFIX: '_stg' # Prefix with _stg for the staging branch
    - if: $CI_PIPELINE_SOURCE == "merge_request_event" # Conditionally change the prefix for Merge Requests
      when: manual # Run pages manually on Merge Requests
      variables:
        PAGES_PREFIX: 'mr-$CI_MERGE_REQUEST_IID' # Prefix with the mr-<iid>, like `mr-123`
```

동적 접두사에 대해 [변수](../../../ci/variables/_index.md)를 문자열과 혼합하는 다른 예제들:

- `pages.path_prefix: 'mr-$CI_COMMIT_REF_SLUG'`: `mr-`로 접두사가 붙은 브랜치 또는 태그 이름 (예: `mr-branch-name`).
- `pages.path_prefix: '_${CI_MERGE_REQUEST_IID}_'`: `_`로 접두사와 접미사가 붙은 머지 리퀘스트 번호 (예: `_123_`).

이전 YAML 예제는 [사용자 지정 작업 이름](_index.md#user-defined-job-names)을(를) 사용합니다.

## 병렬 배포를 사용하여 Pages 환경 만들기 {#use-parallel-deployments-to-create-pages-environments}

병렬 GitLab Pages 배포를 사용하여 새로운 [환경](../../../ci/environments/_index.md)을 만들 수 있습니다. 예를 들어:

```yaml
create-pages:
  stage: deploy
  script:
    - echo "Pages accessible through ${CI_PAGES_URL}"
  variables:
    PAGES_PREFIX: "" # no prefix by default (run on the default branch)
  pages:  # specifies that this is a Pages job and publishes the default public directory
    path_prefix: "$PAGES_PREFIX"
  environment:
    name: "Pages ${PAGES_PREFIX}"
    url: $CI_PAGES_URL
  rules:
    - if: $CI_COMMIT_BRANCH == "staging" # ensure to run on the default branch (with default PAGES_PREFIX)
      variables:
        PAGES_PREFIX: '_stg' # prefix with _stg for the staging branch
    - if: $CI_PIPELINE_SOURCE == "merge_request_event" # conditionally change the prefix on Merge Requests
      when: manual # run pages manually on Merge Requests
      variables:
        PAGES_PREFIX: 'mr-$CI_MERGE_REQUEST_IID' # prefix with the mr-<iid>, like `mr-123`
```

이 구성을 사용하면 사용자는 UI를 통해 각 GitLab Pages 배포에 액세스할 수 있습니다. 페이지에 [환경](../../../ci/environments/_index.md)을 사용할 때, 모든 페이지 환경은 프로젝트 환경 목록에 나열됩니다.

[유사한 환경을 그룹화](../../../ci/environments/_index.md#group-similar-environments)할 수도 있습니다.

이전 YAML 예제는 [사용자 지정 작업 이름](_index.md#user-defined-job-names)을(를) 사용합니다.

### 자동 정리 {#auto-clean}

`path_prefix`을 포함한 머지 리퀨스트로 생성된 병렬 Pages 배포는 머지 리퀘스트가 닫히거나 병합될 때 자동으로 삭제됩니다.

## 리다이렉트를 사용한 사용 {#usage-with-redirects}

리다이렉트는 절대 경로를 사용합니다. 병렬 배포를 하위 경로에서 사용할 수 있으므로, 리다이렉트는 병렬 배포에서 작동하기 위해 `_redirects` 파일에 대한 추가 수정이 필요합니다.

기존 파일은 항상 리다이렉트 규칙보다 우선하므로, 접두사가 붙은 경로에 대한 요청을 포착하기 위해 splat 플레이스홀더를 사용할 수 있습니다.

`path_prefix`이 `/mr-${$CI_MERGE_REQUEST_IID}`이면, 이 `_redirect` 파일 예제를 적용하여 기본 배포와 병렬 배포 모두에 대한 요청을 리다이렉트합니다:

```shell
# Redirect the primary deployment
/will-redirect.html /redirected.html 302

# Redirect parallel deployments
/*/will-redirect.html /:splat/redirected.html 302
```
