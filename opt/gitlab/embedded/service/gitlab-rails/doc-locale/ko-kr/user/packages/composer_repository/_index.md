---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 패키지 레지스트리의 Composer 패키지
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  베타

{{< /details >}}

> [!warning]
> GitLab용 Composer 패키지 레지스트리는 개발 중이며 기능이 제한되어 프로덕션 사용을 위한 준비가 되지 않았습니다. 이 [에픽](https://gitlab.com/groups/gitlab-org/-/work_items/6817)은 프로덕션 준비를 위한 남은 작업 및 일정을 자세히 설명합니다.

프로젝트의 패키지 레지스트리에 [Composer](https://getcomposer.org/) 패키지를 게시합니다. 필요할 때마다 패키지를 종속성으로 사용하기 위해 설치합니다.

Composer 클라이언트가 사용하는 특정 API 엔드포인트의 설명서는 [Composer API 설명서](../../../api/packages/composer.md)를 참조하세요.

Composer v2.0을 권장합니다. Composer v1.0은 지원되지만 매우 많은 수의 패키지가 있는 그룹에서 작업할 때 성능이 낮습니다.

[Composer 패키지 빌드](../workflows/build_packages.md#composer) 방법을 알아봅니다.

## API를 사용하여 Composer 패키지 게시 {#publish-a-composer-package-by-using-the-api}

Composer 패키지를 패키지 레지스트리에 게시하여 프로젝트에 접근할 수 있는 모든 사용자가 패키지를 종속성으로 사용할 수 있도록 합니다.

사전 요구 사항:

- GitLab 리포지토리의 패키지입니다. Composer 패키지는 [Composer 사양](https://getcomposer.org/doc/04-schema.md#version)을 기반으로 버전이 지정되어야 합니다. 버전이 유효하지 않은 경우(예: 점 세 개가 있는 경우 `1.0.0.0`), 게시할 때 오류(`Validation failed: Version is invalid`)가 발생합니다.
- 프로젝트 루트 디렉터리에 유효한 `composer.json` 파일입니다.
- Packages 기능이 GitLab 리포지토리에서 활성화되어 있습니다.
- 프로젝트 ID는 [프로젝트 개요 페이지](../../project/working_with_projects.md#find-the-project-id)에 표시됩니다.
- 다음 토큰 유형 중 하나입니다:
  - [개인 액세스 토큰](../../profile/personal_access_tokens.md)(범위가 `api`(으)로 설정됨)
  - 범위가 `write_package_registry`로 설정된 [배포 토큰](../../project/deploy_tokens/_index.md)입니다.

개인 액세스 토큰으로 패키지를 게시하려면:

- [Packages API](../../../api/packages.md)에 `POST` 요청을 전송합니다.

  예를 들어 `curl`을(를) 사용할 수 있습니다:

  ```shell
  curl --fail-with-body --data tag=<tag> "https://__token__:<personal-access-token>@gitlab.example.com/api/v4/projects/<project_id>/packages/composer"
  ```

  - `<personal-access-token>`은(는) 사용자의 개인 액세스 토큰입니다.
  - `<project_id>`은(는) 프로젝트 ID입니다.
  - `<tag>`은(는) 게시하려는 버전의 Git 태그 이름입니다. 브랜치를 게시하려면 `tag=<tag>` 대신 `branch=<branch>`를 사용합니다.

배포 토큰으로 패키지를 게시하려면:

- [Packages API](../../../api/packages.md)에 `POST` 요청을 전송합니다.

  예를 들어 `curl`을(를) 사용할 수 있습니다:

  ```shell
  curl --fail-with-body --data tag=<tag> --header "Deploy-Token: <deploy-token>" "https://gitlab.example.com/api/v4/projects/<project_id>/packages/composer"
  ```

  - `<deploy-token>`은(는) 배포 토큰입니다.
  - `<project_id>`은(는) 프로젝트 ID입니다.
  - `<tag>`은(는) 게시하려는 버전의 Git 태그 이름입니다. 브랜치를 게시하려면 `tag=<tag>` 대신 `branch=<branch>`를 사용합니다.

**배포** > **패키지 레지스트리**로 이동하여 **Composer** 탭을 선택하면 게시된 패키지를 볼 수 있습니다.

## CI/CD를 사용하여 Composer 패키지 게시 {#publish-a-composer-package-by-using-cicd}

CI/CD 프로세스의 일부로 Composer 패키지를 패키지 레지스트리에 게시할 수 있습니다.

1. `.gitlab-ci.yml` 파일에 `CI_JOB_TOKEN`을(를) 지정합니다:

   ```yaml
   stages:
     - deploy

   deploy:
     stage: deploy
     script:
       - apk add curl
       - 'curl --fail-with-body --header "Job-Token: $CI_JOB_TOKEN" --data tag=<tag> "${CI_API_V4_URL}/projects/$CI_PROJECT_ID/packages/composer"'
     environment: production
   ```

1. 파이프라인을 실행합니다.

게시된 패키지를 보려면 **배포** > **패키지 레지스트리**로 이동하여 **Composer** 탭을 선택합니다.

### CI/CD 템플릿 사용 {#use-a-cicd-template}

더 자세한 Composer CI/CD 파일은 `.gitlab-ci.yml` 템플릿으로도 사용 가능합니다:

1. 왼쪽 사이드바에서 **프로젝트 개요**를 선택합니다.
1. 파일 목록 위에서 **CI/CD 설정**을 선택합니다. 이 버튼을 사용할 수 없으면 **CI/CD 구성**을 선택한 다음 **편집**을 선택합니다.
1. **템플릿 적용** 목록에서 **Composer**를 선택합니다.

> [!warning]
> 기존 CI/CD 파일을 덮어쓰려는 경우가 아니면 저장하지 마세요.

## 동일한 이름 또는 버전의 패키지 게시 {#publishing-packages-with-the-same-name-or-version}

게시할 때:

- 다른 데이터가 있는 동일한 패키지는 기존 패키지를 덮어씁니다.
- 동일한 데이터가 있는 동일한 패키지는 `400 Bad request` 오류가 발생합니다.

## Composer 패키지 설치 {#install-a-composer-package}

패키지를 패키지 레지스트리에서 설치하여 종속성으로 사용할 수 있습니다.

사전 요구 사항:

- 패키지 레지스트리의 패키지입니다.
- 패키지 레지스트리가 패키지를 게시하는 역할을 하는 프로젝트에서 활성화되어 있습니다.
- 그룹의 홈 페이지에 있는 그룹 ID입니다.
- 다음 토큰 유형 중 하나입니다:
  - 범위가 최소한 `api`로 설정된 [개인 액세스 토큰](../../profile/personal_access_tokens.md)입니다.
  - [배포 토큰](../../project/deploy_tokens/_index.md)(범위가 `read_package_registry`, `write_package_registry` 또는 둘 다로 설정됨)
  - [CI/CD Job 토큰](../../../ci/jobs/ci_job_token.md)

패키지를 설치하려면:

1. 패키지 레지스트리 URL을 프로젝트의 `composer.json` 파일에 추가하고 설치하려는 패키지 이름과 버전을 함께 입력합니다:

   - 그룹의 패키지 레지스트리에 연결합니다:

     ```shell
     composer config repositories.<group_id> composer https://gitlab.example.com/api/v4/group/<group_id>/-/packages/composer/packages.json
     ```

   - 필요한 패키지 버전을 설정합니다:

     ```shell
     composer require <package_name>:<version>
     ```

   `composer.json` 파일의 결과:

   ```json
   {
     ...
     "repositories": {
       "<group_id>": {
         "type": "composer",
         "url": "https://gitlab.example.com/api/v4/group/<group_id>/-/packages/composer/packages.json"
       },
       ...
     },
     "require": {
       ...
       "<package_name>": "<version>"
     },
     ...
   }
   ```

   다음 명령으로 이를 설정 해제할 수 있습니다:

   ```shell
   composer config --unset repositories.<group_id>
   ```

   - `<group_id>`은(는) 그룹 ID입니다.
   - `<package_name>`은(는) 패키지의 `composer.json` 파일에 정의된 패키지 이름입니다.
   - `<version>`은(는) 패키지 버전입니다.

1. GitLab 자격증명을 사용하여 `auth.json` 파일을 만듭니다:

   개인 액세스 토큰 사용:

   ```shell
   composer config gitlab-token.<DOMAIN-NAME> <personal_access_token>
   ```

   `auth.json` 파일의 결과:

   ```json
   {
     ...
     "gitlab-token": {
       "<DOMAIN-NAME>": "<personal_access_token>",
       ...
     }
   }
   ```

   배포 토큰 사용:

   ```shell
   composer config gitlab-token.<DOMAIN-NAME> <deploy_token_username> <deploy_token>
   ```

   `auth.json` 파일의 결과:

   ```json
   {
     ...
     "gitlab-token": {
       "<DOMAIN-NAME>": {
         "username": "<deploy_token_username>",
         "token": "<deploy_token>",
       ...
     }
   }
   ```

   CI/CD job 토큰 사용:

   ```shell
   composer config -- gitlab-token.<DOMAIN-NAME> gitlab-ci-token "${CI_JOB_TOKEN}"
   ```

   `auth.json` 파일의 결과:

   ```json
   {
     ...
     "gitlab-token": {
       "<DOMAIN-NAME>": {
         "username": "gitlab-ci-token",
         "token": "<ci-job-token>",
       ...
     }
   }
   ```

   다음 명령으로 이를 설정 해제할 수 있습니다:

   ```shell
   composer config --unset --auth gitlab-token.<DOMAIN-NAME>
   ```

   - `<DOMAIN-NAME>`은(는) GitLab 인스턴스 URL `gitlab.com` 또는 `gitlab.example.com`입니다.
   - `<personal_access_token>` 범위가 `api`로 설정되거나 `<deploy_token>` 범위가 `read_package_registry` 및/또는 `write_package_registry`로 설정됩니다.

1. GitLab Self-Managed를 사용하는 경우 `gitlab-domains`을(를) `composer.json`에 추가합니다.

   ```shell
   composer config gitlab-domains gitlab01.example.com gitlab02.example.com
   ```

   `composer.json` 파일의 결과:

   ```json
   {
     ...
     "repositories": [
       { "type": "composer", "url": "https://gitlab.example.com/api/v4/group/<group_id>/-/packages/composer/packages.json" }
     ],
     "config": {
       ...
       "gitlab-domains": ["gitlab01.example.com", "gitlab02.example.com"]
     },
     "require": {
       ...
       "<package_name>": "<version>"
     },
     ...
   }
   ```

   다음 명령으로 이를 설정 해제할 수 있습니다:

   ```shell
   composer config --unset gitlab-domains
   ```

   > [!note]
   > GitLab.com에서는 Composer가 기본적으로 `auth.json`의 GitLab 토큰을 비공개 토큰으로 사용합니다. `composer.json`에서 `gitlab-domains` 정의 없이 Composer는 GitLab 토큰을 기본 인증으로 사용하며 토큰을 사용자 이름으로, 빈 암호를 사용합니다. 이 경우 401 오류가 발생합니다.

1. `composer.json` 및 `auth.json` 파일이 구성되면 다음을 실행하여 패키지를 설치할 수 있습니다:

   ```shell
   composer update
   ```

   또는 단일 패키지를 설치하려면:

   ```shell
   composer req <package-name>:<package-version>
   ```

> [!warning]
> `auth.json` 파일을 리포지토리에 커밋하지 마세요. CI/CD job에서 패키지를 설치하려면 [`composer config`](https://getcomposer.org/doc/articles/handling-private-packages.md#satis) 도구를 [GitLab CI/CD 변수](../../../ci/variables/_index.md) 또는 [HashiCorp Vault](../../../ci/secrets/_index.md)에 저장된 액세스 토큰과 함께 사용해 봅니다.

### 소스에서 설치 {#install-from-source}

Git 리포지토리를 직접 가져와서 소스에서 설치할 수 있습니다. 이렇게 하려면:

- `--prefer-source` 옵션을 사용합니다.

  ```shell
  composer update --prefer-source
  ```

- `composer.json`에서 [`config` 키 아래의 `preferred-install` 필드](https://getcomposer.org/doc/06-config.md#preferred-install)를 사용합니다:

  ```json
  {
    ...
    "config": {
      "preferred-install": {
        "<package name>": "source"
      }
    }
    ...
   }
  ```

#### SSH 액세스 {#ssh-access}

소스에서 설치할 때 `composer`은(는) 프로젝트의 Git 리포지토리에 대한 액세스를 구성합니다. 프로젝트 가시성에 따라 액세스 유형이 다릅니다:

- 공개 프로젝트에서는 `https` Git URL이 사용됩니다. [HTTPS로 리포지토리 복제](../../../topics/git/clone.md#clone-with-https)할 수 있는지 확인합니다.
- 내부 또는 비공개 프로젝트에서는 `ssh` Git URL이 사용됩니다. [SSH로 리포지토리 복제](../../../topics/git/clone.md#clone-with-ssh)할 수 있는지 확인합니다.

CI/CD job에서 [GitLab CI/CD를 사용하는 SSH 키](../../../ci/jobs/ssh_keys.md)를 사용하여 `ssh` Git URL에 액세스할 수 있습니다.

### 배포 토큰으로 작업 {#working-with-deploy-tokens}

Composer 패키지는 그룹 수준에서 액세스되지만 그룹 또는 프로젝트 배포 토큰을 사용하여 액세스할 수 있습니다:

- 그룹 배포 토큰은 해당 그룹 또는 하위 그룹의 프로젝트에 게시된 모든 패키지에 액세스할 수 있습니다.
- 프로젝트 배포 토큰은 해당 특정 프로젝트에 게시된 패키지에만 액세스할 수 있습니다.

## Composer 패키지 삭제 {#delete-a-composer-package}

사전 요구 사항:

- 유지 관리자 또는 소유자 역할이 있어야 합니다.

패키지를 삭제하기 전에 [관련된 보안 위험](../package_registry/supported_functionality.md#deleting-packages)을(를) 이해해야 합니다.

패키지를 삭제하려면 다음 중 하나를 수행할 수 있습니다:

- [UI 사용](../package_registry/reduce_package_registry_storage.md#delete-a-package)
- [API 사용](../../../api/packages.md#delete-a-project-package)

## 문제 해결 {#troubleshooting}

### 캐싱 {#caching}

성능을 개선하기 위해 Composer는 패키지와 관련된 파일을 캐시합니다. Composer는 자동으로 데이터를 제거하지 않습니다. 새 패키지가 설치되면 캐시가 증가합니다. 문제가 발생하면 이 명령으로 캐시를 지웁니다:

```shell
composer clearcache
```

### `composer install` 사용 시 인증 요구 사항 {#authorization-requirement-when-using-composer-install}

[패키지 아카이브 다운로드](../../../api/packages/composer.md#download-a-package-archive) 엔드포인트에는 인증이 필요합니다. `composer install`을(를) 사용할 때 자격증명 프롬프트가 표시되면 [Composer 패키지 설치](#install-a-composer-package) 섹션의 지침을 따라 `auth.json` 파일을 만듭니다.

### `The file composer.json was not found`로 인해 게시 실패 {#publish-fails-with-the-file-composerjson-was-not-found}

`The file composer.json was not found`이라고 말하는 오류가 표시될 수 있습니다.

이 문제는 [패키지 게시를 위한 구성 요구 사항](#publish-a-composer-package-by-using-the-api)이 충족되지 않을 때 발생합니다.

오류를 해결하려면 `composer.json` 파일을 프로젝트 루트 디렉터리에 커밋합니다.

## 지원되는 CLI 명령 {#supported-cli-commands}

GitLab Composer 리포지토리는 다음 Composer CLI 명령을 지원합니다:

- `composer install`: Composer 종속성을 설치합니다.
- `composer update`: Composer 종속성의 최신 버전을 설치합니다.
