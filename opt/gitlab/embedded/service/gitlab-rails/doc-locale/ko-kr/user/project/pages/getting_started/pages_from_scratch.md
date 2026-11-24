---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: '튜토리얼: GitLab Pages 웹사이트를 처음부터 만들기'
description: 빈 프로젝트에서 Jekyll과 사용자 정의 CI/CD 구성을 사용하여 GitLab Pages 웹사이트를 만듭니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이 자습서에서는 [Jekyll](https://jekyllrb.com/) 정적 사이트 생성기(SSG)를 사용하여 Pages 사이트를 처음부터 만드는 방법을 보여줍니다. 빈 프로젝트에서 시작하여 [러너](https://docs.gitlab.com/runner/)에 지침을 제공하는 CI/CD 구성 파일을 만듭니다. CI/CD [파이프라인](../../../../ci/pipelines/_index.md)이 실행되면 Pages 사이트가 만들어집니다.

이 예제는 Jekyll을 사용하지만 다른 SSG도 유사한 단계를 따릅니다. 이 자습서를 완료하기 위해 Jekyll이나 SSG에 익숙할 필요는 없습니다.

> [!note]
> 순수 HTML로 Pages 사이트를 만들려면 [CI/CD 템플릿에서 GitLab Pages 웹사이트 만들기](pages_ci_cd_template.md) 자습서를 참조하세요. 사용 가능한 템플릿 목록을 보려면 [프로젝트 템플릿](pages_new_project_template.md#project-templates)을 참조하세요.

GitLab Pages 웹사이트를 만들려면:

- [단계 1: 프로젝트 파일 만들기](#create-the-project-files)
- [단계 2: Docker 이미지 선택](#choose-a-docker-image)
- [단계 3: Jekyll 설치](#install-jekyll)
- [단계 4: `public` 디렉터리를 출력으로 지정](#specify-the-public-directory-for-output)
- [단계 5: `public` 디렉터리를 아티팩트로 지정](#specify-the-public-directory-for-artifacts)
- [단계 6: 웹사이트 배포 및 보기](#deploy-and-view-your-website)

## 시작하기 전에 {#before-you-begin}

GitLab에 [빈 프로젝트](../../_index.md#create-a-blank-project)가 있어야 합니다.

## 프로젝트 파일 만들기 {#create-the-project-files}

루트(최상위) 디렉터리에 세 개의 파일을 만듭니다:

- `.gitlab-ci.yml`: 실행하려는 명령이 포함된 YAML 파일입니다. 지금은 파일 내용을 비워 두세요.

- `index.html`: 원하는 HTML 콘텐츠로 채울 수 있는 비어 있지 않은 HTML 파일입니다. 예를 들어:

  ```html
  <html>
  <head>
    <title>Home</title>
  </head>
  <body>
    <h1>Hello World!</h1>
  </body>
  </html>
  ```

- [`Gemfile`](https://bundler.io/gemfile.html): Ruby 프로그램의 종속성을 설명하는 파일입니다.

  이 콘텐츠로 채웁니다:

  ```ruby
  source "https://rubygems.org"

  gem "jekyll"
  ```

## Docker 이미지 선택 {#choose-a-docker-image}

이 예제에서 러너는 [Docker 이미지](../../../../ci/docker/using_docker_images.md)를 사용하여 스크립트를 실행하고 사이트를 배포합니다.

이 특정 Ruby 이미지는 [DockerHub](https://hub.docker.com/_/ruby)에서 유지관리됩니다.

`.gitlab-ci.yml` 파일의 시작 부분에 이 CI/CD 구성을 추가하여 파이프라인에 기본 이미지를 추가합니다:

```yaml
default:
  image: ruby:3.2
```

SSG가 빌드를 위해 [NodeJS](https://nodejs.org/)를 필요로 하는 경우 파일 시스템의 일부로 NodeJS를 포함하는 이미지를 지정해야 합니다. 예를 들어, [Hexo](https://gitlab.com/pages/hexo) 사이트의 경우 `image: node:12.17.0`를 사용할 수 있습니다.

## Jekyll 설치 {#install-jekyll}

[Jekyll](https://jekyllrb.com/)을 로컬에서 실행하려면 설치해야 합니다:

1. 터미널을 엽니다.
1. `gem install bundler`를 실행하여 [Bundler](https://bundler.io/)를 설치합니다.
1. `bundle install`를 실행하여 `Gemfile.lock`을 만듭니다.
1. `bundle exec jekyll build`를 실행하여 Jekyll을 설치합니다.

프로젝트에서 Jekyll을 실행하려면 `.gitlab-ci.yml` 파일을 편집하고 설치 명령을 추가합니다:

```yaml
script:
  - gem install bundler
  - bundle install
  - bundle exec jekyll build
```

또한 `.gitlab-ci.yml` 파일에서 각 `script`는 `job`로 구성됩니다. `job`는 해당 특정 작업에 적용하려는 스크립트와 설정을 포함합니다.

```yaml
job:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build
```

GitLab Pages의 경우 이 `job`에는 `pages`라는 속성이 포함되어야 합니다. 이 설정은 러너에 GitLab Pages를 사용하여 웹사이트를 배포하려는 작업임을 알려줍니다:

```yaml
create-pages:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build
  pages: true  # specifies that this is a Pages job
```

이 페이지의 예제는 [사용자 정의 작업 이름](../_index.md#user-defined-job-names)을 사용합니다.

## `public` 디렉터리를 출력으로 지정 {#specify-the-public-directory-for-output}

Jekyll은 출력을 생성할 위치를 알아야 합니다. GitLab Pages는 `public`라는 디렉터리의 파일만 고려합니다.

Jekyll은 대상 플래그(`-d`)를 사용하여 빌드된 웹사이트의 출력 디렉터리를 지정합니다. 대상을 `.gitlab-ci.yml` 파일에 추가합니다:

```yaml
create-pages:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job
```

## `public` 디렉터리를 아티팩트로 지정 {#specify-the-public-directory-for-artifacts}

{{< history >}}

- `pages.publish` 경로를 `artifacts:paths`에 자동으로 추가 - GitLab 17.10의 Pages 작업에만 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/428018).

{{< /history >}}

이제 Jekyll이 `public` 디렉터리에 파일을 출력했으므로 러너는 파일을 가져올 위치를 알아야 합니다. GitLab 17.10 이상에서는 Pages 작업에만 `public` 디렉터리가 [`artifacts:paths`](../../../../ci/yaml/_index.md#artifactspaths)에 자동으로 추가되며, [`pages.publish`](../../../../ci/yaml/_index.md#pagespublish) 경로가 명시적으로 지정되지 않은 경우입니다:

```yaml
create-pages:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
```

`.gitlab-ci.yml` 파일은 이제 다음과 같아야 합니다:

```yaml
default:
  image: ruby:3.2

create-pages:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
```

## 웹사이트 배포 및 보기 {#deploy-and-view-your-website}

앞의 단계를 완료한 후 웹사이트를 배포합니다:

1. `.gitlab-ci.yml` 파일을 저장하고 커밋합니다.
1. **빌드** > **파이프라인**으로 이동하여 파이프라인을 확인합니다.
1. 파이프라인이 완료되면 **배포** > **Pages**로 이동하여 Pages 웹사이트의 링크를 찾습니다.

이 `pages` 작업이 성공적으로 완료되면 특수 `pages:deploy` 작업이 파이프라인 보기에 나타납니다. GitLab Pages 데몬의 웹사이트 콘텐츠를 준비합니다. GitLab이 백그라운드에서 실행하며 러너를 사용하지 않습니다.

## CI/CD 파일의 다른 옵션 {#other-options-for-your-cicd-file}

`.gitlab-ci.yml` 파일을 [다른 CI/CD YAML 키워드](../../../../ci/yaml/_index.md)로 업데이트할 수 있습니다. `.gitlab-ci.yml` 파일을 GitLab에 포함된 [CI Lint](../../../../ci/yaml/lint.md) 도구로 검증할 수 있습니다.

다음 섹션에서는 CI/CD 파일에 추가할 수 있는 다른 옵션을 보여줍니다.

### 특정 브랜치를 Pages 사이트에 배포 {#deploy-specific-branches-to-a-pages-site}

특정 브랜치에서만 Pages 사이트로 배포하려고 할 수 있습니다.

먼저 `workflow` 섹션을 추가하여 브랜치에 변경 사항이 푸시될 때만 파이프라인을 실행하도록 합니다:

```yaml
default:
  image: ruby:3.2

workflow:
  rules:
    - if: $CI_COMMIT_BRANCH

create-pages:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
```

그런 다음 [기본 브랜치](../../repository/branches/default.md) (여기: `main`)에만 작업을 실행하도록 파이프라인을 구성합니다.

```yaml
default:
  image: ruby:3.2

workflow:
  rules:
    - if: $CI_COMMIT_BRANCH

create-pages:
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

### 배포할 스테이지 지정 {#specify-a-stage-to-deploy}

GitLab CI/CD의 세 가지 기본 스테이지는 빌드, 테스트 및 배포입니다.

스크립트를 테스트하고 프로덕션에 배포하기 전에 빌드된 사이트를 확인하려면 [기본 브랜치](../../repository/branches/default.md) (여기: `main`)에 푸시할 때 정확히 실행되는 대로 테스트를 실행할 수 있습니다.

작업을 실행할 스테이지를 지정하려면 CI 파일에 `stage` 줄을 추가합니다:

```yaml
default:
  image: ruby:3.2

workflow:
  rules:
    - if: $CI_COMMIT_BRANCH

create-pages:
  stage: deploy
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  environment: production
```

이제 CI 파일에 다른 작업을 추가하여 `main` 브랜치를 제외한 모든 브랜치로의 모든 푸시를 테스트하도록 합니다:

```yaml
default:
  image: ruby:3.2

workflow:
  rules:
    - if: $CI_COMMIT_BRANCH

create-pages:
  stage: deploy
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  environment: production

test:
  stage: test
  script:
    - gem install bundler
    - bundle install
    - bundle exec jekyll build -d test
  artifacts:
    paths:
      - test
  rules:
    - if: $CI_COMMIT_BRANCH != "main"
```

`test` 작업이 `test` 스테이지에서 실행될 때 Jekyll은 `test`라는 디렉터리에 사이트를 빌드합니다. 작업은 `main`를 제외한 모든 브랜치에 영향을 미칩니다.

`test` 작업은 GitLab Pages에 게시되지 않으므로 출력은 작업 아티팩트로만 저장됩니다. 빌드된 사이트를 보려면 [아티팩트 아카이브의 콘텐츠를 찾아보세요](../../../../ci/jobs/job_artifacts.md#browse-the-contents-of-the-artifacts-archive). GitLab Pages가 인스턴스에 대해 켜져 있으면 `.html` 파일을 브라우저에서 직접 미리 볼 수 있습니다. 개인 또는 내부 프로젝트의 경우 관리자도 인스턴스에 대해 [GitLab Pages 액세스 제어](../pages_access_control.md)를 켜야 합니다.

브랜치를 자체 URL이 있는 별도의 Pages 사이트로 게시하려면 대신 [병렬 배포](../parallel_deployments.md)를 사용합니다.

다양한 작업에 스테이지를 적용하면 동일한 스테이지의 모든 작업이 병렬로 빌드됩니다. 웹 애플리케이션이 배포하기 전에 하나 이상의 테스트를 필요로 하는 경우 모든 테스트를 동시에 실행할 수 있습니다.

### 중복 명령 제거 {#remove-duplicate-commands}

모든 작업에서 동일한 `before_script` 명령을 반복하지 않으려면 기본 섹션에 추가할 수 있습니다.

예제에서 `gem install bundler`과(와) `bundle install`은(는) `create-pages`과(와) `test` 두 작업 모두에 대해 실행 중이었습니다.

이 명령을 `default` 섹션으로 이동합니다:

```yaml
default:
  image: ruby:3.2
  before_script:
    - gem install bundler
    - bundle install

workflow:
  rules:
    - if: $CI_COMMIT_BRANCH

create-pages:
  stage: deploy
  script:
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  environment: production

test:
  stage: test
  script:
    - bundle exec jekyll build -d test
  artifacts:
    paths:
      - test
  rules:
    - if: $CI_COMMIT_BRANCH != "main"
```

### 캐시된 종속성으로 더 빠르게 빌드 {#build-faster-with-cached-dependencies}

더 빠르게 빌드하려면 `cache` 매개변수를 사용하여 프로젝트 종속성의 설치 파일을 캐시할 수 있습니다.

이 예제는 `bundle install`를 실행할 때 `vendor` 디렉터리에 Jekyll 종속성을 캐시합니다:

```yaml
default:
  image: ruby:3.2
  before_script:
    - gem install bundler
    - bundle install --path vendor
  cache:
    paths:
      - vendor/

workflow:
  rules:
    - if: $CI_COMMIT_BRANCH


create-pages:
  stage: deploy
  script:
    - bundle exec jekyll build -d public
  pages: true  # specifies that this is a Pages job and publishes the default public directory
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
  environment: production

test:
  stage: test
  script:
    - bundle exec jekyll build -d test
  artifacts:
    paths:
      - test
  rules:
    - if: $CI_COMMIT_BRANCH != "main"
```

이 경우 Jekyll이 빌드하는 폴더 목록에서 `/vendor` 디렉터리를 제외해야 합니다. 그렇지 않으면 Jekyll은 사이트와 함께 디렉터리 콘텐츠를 빌드하려고 시도합니다.

루트 디렉터리에 `_config.yml`이(가) 이름인 파일을 만들고 이 콘텐츠를 추가합니다:

```yaml
exclude:
  - vendor
```

이제 GitLab CI/CD는 웹사이트를 빌드할 뿐만 아니라 다음도 수행합니다:

- 기능 브랜치에 지속적인 테스트를 사용하여 푸시합니다.
- Bundler로 설치된 종속성을 캐시합니다.
- `main` 브랜치로의 모든 푸시를 지속적으로 배포합니다.

사이트를 위해 생성된 HTML 및 기타 자산을 보려면 [작업 아티팩트 다운로드](../../../../ci/jobs/job_artifacts.md#download-job-artifacts)합니다.

이 페이지의 예제는 [사용자 정의 작업 이름](../_index.md#user-defined-job-names)을 사용합니다.

## 관련 항목 {#related-topics}

- [웹 앱을 스테이징 및 프로덕션에 배포](https://about.gitlab.com/blog/ci-deployment-and-environments/)
- [작업을 순차적으로 또는 병렬로 실행하거나 사용자 정의 파이프라인 빌드](https://about.gitlab.com/blog/basics-of-gitlab-ci-updated/)
- [다양한 프로젝트에서 특정 디렉터리 가져오기](https://about.gitlab.com/blog/building-a-new-gitlab-docs-site-with-nanoc-gitlab-ci-and-gitlab-pages/)
- [GitLab Pages를 사용하여 코드 적용 범위 보고서 생성](https://about.gitlab.com/blog/publish-code-coverage-report-with-gitlab-pages/)
