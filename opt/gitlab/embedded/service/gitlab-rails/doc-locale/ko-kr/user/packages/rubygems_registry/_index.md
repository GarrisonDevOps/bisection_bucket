---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 패키지 레지스트리의 Ruby gem
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  실험적 기능

{{< /details >}}

{{< history >}}

- GitLab 13.9에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/52147)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) `rubygem_packages`로 명명되었습니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../../../policy/development_stages_support.md)입니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요. 이 기능은 테스트 가능하지만 프로덕션 사용은 준비되지 않았습니다.

프로젝트의 패키지 레지스트리에 Ruby 젬을 게시할 수 있습니다. 그런 다음 UI 또는 API를 통해 다운로드할 수 있습니다.

이 기능은 [실험](../../../policy/development_stages_support.md)입니다. 이 기능 개발에 대한 자세한 내용은 [에픽 3200](https://gitlab.com/groups/gitlab-org/-/work_items/3200)을 참조하세요.

## 패키지 레지스트리에 인증 {#authenticate-to-the-package-registry}

패키지 레지스트리와 상호 작용하려면 먼저 인증해야 합니다.

다음 중 하나를 사용할 수 있습니다:

- 범위가 `api`로 설정된 [개인 액세스 토큰](../../profile/personal_access_tokens.md).
- 범위가 `read_package_registry`, `write_package_registry` 또는 둘 다로 설정된 [배포 토큰](../../project/deploy_tokens/_index.md).
- [CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md)

예를 들어:

{{< tabs >}}

{{< tab title="액세스 토큰 사용" >}}

액세스 토큰으로 인증하려면:

- `~/.gem/credentials` 파일을 만들거나 편집하고 다음을 추가합니다:

  ```ini
  ---
  https://gitlab.example.com/api/v4/projects/<project_id>/packages/rubygems: '<token>'
  ```

이 예에서:

- `<token>`는 개인 액세스 토큰 또는 배포 토큰의 토큰 값이어야 합니다.
- `<project_id>`은(는) [프로젝트 개요 페이지](../../project/working_with_projects.md#find-the-project-id)에 표시됩니다.

{{< /tab >}}

{{< tab title="CI/CD 작업 토큰 사용" >}}

CI/CD 작업 토큰으로 인증하려면:

- `.gitlab-ci.yml` 파일을 만들거나 편집하고 다음을 추가합니다:

  ```yaml
  # assuming a my_gem.gemspec file is present in the repository with the version currently set to 0.0.1
  image: ruby

  run:
    before_script:
      - mkdir ~/.gem
      - echo "---" > ~/.gem/credentials
      - |
        echo "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/rubygems: '${CI_JOB_TOKEN}'" >> ~/.gem/credentials
      - chmod 0600 ~/.gem/credentials # rubygems requires 0600 permissions on the credentials file
    script:
      - gem build my_gem
      - gem push my_gem-0.0.1.gem --host ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/rubygems
  ```

  GitLab에 체크 인하는 `~/.gem/credentials` 파일에서 `CI_JOB_TOKEN`을(를) 사용할 수도 있습니다:

  ```ini
  ---
  https://gitlab.example.com/api/v4/projects/${env.CI_PROJECT_ID}/packages/rubygems: '${env.CI_JOB_TOKEN}'
  ```

{{< /tab >}}

{{< /tabs >}}

## Ruby 젬 푸시 {#push-a-ruby-gem}

사전 요구 사항:

- [패키지 레지스트리에 인증](#authenticate-to-the-package-registry)해야 합니다.
- Ruby 젬은 3GB 이하여야 합니다.

다음과 같이 설정합니다.

- 다음과 같은 명령을 실행합니다:

  ```shell
  gem push my_gem-0.0.1.gem --host <host>
  ```

  이 예제에서 `<host>`은(는) 인증을 설정할 때 사용한 URL입니다. 예를 들어:

  ```shell
  gem push my_gem-0.0.1.gem --host https://gitlab.example.com/api/v4/projects/1/packages/rubygems
  ```

젬이 성공적으로 게시되면 다음과 같은 메시지가 표시됩니다:

```plaintext
Pushing gem to https://gitlab.example.com/api/v4/projects/1/packages/rubygems...
{"message":"201 Created"}
```

젬이 패키지 레지스트리에 게시되고 **패키지 및 레지스트리** 페이지에 표시됩니다. GitLab이 젬을 처리하고 표시하기까지 최대 10분이 소요될 수 있습니다.

### 같은 이름 또는 버전으로 젬 푸시 {#pushing-gems-with-the-same-name-or-version}

같은 이름과 버전의 패키지가 이미 존재하는 경우 젬을 푸시할 수 있습니다. 둘 다 UI에서 볼 수 있고 액세스할 수 있습니다.

## Ruby 젬 삭제 {#delete-a-ruby-gem}

사전 요구 사항:

- Maintainer 또는 Owner 역할이 있어야 합니다.

패키지를 삭제하기 전에 [관련 보안 위험](../package_registry/supported_functionality.md#deleting-packages)을 이해해야 합니다.

패키지를 삭제하려면 다음 중 하나를 수행할 수 있습니다:

- [UI 사용](../package_registry/reduce_package_registry_storage.md#delete-a-package)하세요.
- [API 사용](../../../api/packages.md#delete-a-project-package)하세요.

## Ruby 젬 설치 {#install-a-ruby-gem}

사전 요구 사항:

- [패키지 레지스트리에 인증](#authenticate-to-the-package-registry)해야 합니다.

젬을 설치하려면 소스 URL에 HTTP 기본 인증으로 자격 증명을 전달합니다. `__token__`을(를) 사용자 이름으로 사용하고 개인 액세스 토큰, 배포 토큰 또는 CI/CD 작업 토큰을 암호로 사용합니다.

다음 예제에서:

- `<token>`은(는) 개인 액세스 토큰, 배포 토큰 또는 CI/CD 작업 토큰입니다.
- `<project_id>`은(는) [프로젝트 개요 페이지](../../project/working_with_projects.md#find-the-project-id)에 표시됩니다.

{{< tabs >}}

{{< tab title="gem 명령 사용" >}}

다음과 같은 명령을 실행합니다:

```shell
gem install my_gem --source "https://__token__:<token>@gitlab.example.com/api/v4/projects/<project_id>/packages/rubygems"
```

{{< /tab >}}

{{< tab title="Bundler 사용" >}}

`Gemfile` 파일에서 `source` 블록을 추가합니다:

```ruby
source "https://__token__:<token>@gitlab.example.com/api/v4/projects/<project_id>/packages/rubygems" do
  gem "my_gem"
end
```

{{< /tab >}}

{{< /tabs >}}

## 젬 파일 다운로드 {#download-a-gem-file}

설치하지 않고 로컬 사용을 위해 젬 파일을 다운로드하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **패키지 레지스트리**를 선택합니다.
1. 패키지 이름 및 버전을 선택합니다.
1. **자산** 아래에서 다운로드할 Ruby 젬을 선택합니다.

젬 파일을 다운로드하려면 [API를 사용](../../../api/packages/rubygems.md#download-a-gem-file)할 수도 있습니다.

## 관련 항목 {#related-topics}

- [자신의 젬 만들기](https://guides.rubygems.org/make-your-own-gem/)
- [Ruby 젬 API 문서](../../../api/packages/rubygems.md)
