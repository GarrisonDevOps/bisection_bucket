---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Yarn으로 패키지 게시
---

[Yarn 1 (Classic)](https://classic.yarnpkg.com)과 [Yarn 2+](https://yarnpkg.com)로 패키지를 게시하고 설치할 수 있습니다.

배포 컨테이너에서 사용되는 Yarn 버전을 확인하려면 CI/CD 스크립트 작업 블록의 `script` 블록에서 `yarn --version`을 실행하세요. 이 블록은 `yarn publish`을 호출하는 데 책임이 있습니다. Yarn 버전이 파이프라인 출력에 표시됩니다.

## 패키지 레지스트리에 인증 {#authenticating-to-the-package-registry}

패키지 레지스트리와 상호작용하려면 토큰이 필요합니다. 달성하려는 작업에 따라 사용 가능한 토큰이 다릅니다. 자세한 내용은 [토큰 지침](../package_registry/supported_functionality.md#authenticate-with-the-registry)을 검토하세요.

- 조직에서 2단계 인증(2FA)을 사용하는 경우 범위가 `api`로 설정된 [개인 액세스 토큰](../../profile/personal_access_tokens.md)을 사용해야 합니다.
- CI/CD 파이프라인으로 패키지를 게시하는 경우 프라이빗 러너와 함께 [CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md)을 사용할 수 있습니다. 인스턴스 러너에 대해 [변수를 등록](https://docs.gitlab.com/runner/register/#register-with-a-runner-authentication-token)할 수도 있습니다.

### 게시를 위해 Yarn 구성 {#configure-yarn-for-publication}

패키지 레지스트리에 게시하도록 Yarn을 구성하려면 `.yarnrc.yml` 파일을 편집하세요. 이 파일은 프로젝트의 루트 디렉터리, `package.json` 파일과 같은 위치에서 찾을 수 있습니다.

- `.yarnrc.yml`을 편집하고 다음 구성을 추가하세요:

  ```yaml
  npmScopes:
    <my-org>:
      npmPublishRegistry: 'https://<domain>/api/v4/projects/<project_id>/packages/npm/'
      npmAlwaysAuth: true
      npmAuthToken: '<token>'
  ```

  이 구성에서:

  - `<my-org>`을 조직 범위로 바꾸세요. `@` 기호를 포함하지 마세요.
  - `<domain>`을 도메인 이름으로 바꾸세요.
  - `<project_id>`을 프로젝트의 ID로 바꾸세요. 이는 [프로젝트 개요 페이지](../../project/working_with_projects.md#find-the-project-id)에서 찾을 수 있습니다.
  - `<token>`을 배포 토큰, 그룹 액세스 토큰, 프로젝트 액세스 토큰 또는 개인 액세스 토큰으로 바꾸세요.

Yarn Classic에서는 `publishConfig["@scope:registry"]`을 포함한 범위가 지정된 레지스트리가 지원되지 않습니다. 자세한 내용은 [Yarn pull request 7829](https://github.com/yarnpkg/yarn/pull/7829)를 참조하세요. 대신 `package.json` 파일에서 `publishConfig`을 `registry`로 설정하세요.

## 패키지 게시 {#publish-a-package}

명령줄에서 또는 GitLab CI/CD로 패키지를 게시할 수 있습니다.

### 명령줄 사용 {#with-the-command-line}

패키지를 수동으로 게시하려면:

- 다음 명령을 실행하세요:

  ```shell
  # Yarn 1 (Classic)
  yarn publish

  # Yarn 2+
  yarn npm publish
  ```

### CI/CD 사용 {#with-cicd}

인스턴스 러너(기본값) 또는 프라이빗 러너(고급)로 패키지를 자동으로 게시할 수 있습니다. CI/CD로 게시할 때 파이프라인 변수를 사용할 수 있습니다.

{{< tabs >}}

{{< tab title="인스턴스 러너" >}}

1. 프로젝트 또는 그룹에 대한 인증 토큰을 생성하세요:

   1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
   1. 왼쪽 사이드바에서 **설정** > **리포지토리** > **배포 토큰**을 선택하세요.
   1. `read_package_registry` 및 `write_package_registry` 범위를 포함하는 배포 토큰을 생성하고 생성된 토큰을 복사하세요.
   1. 왼쪽 사이드바에서 **설정** > **CI/CD** > **변수**를 선택하세요.
   1. `Add variable`을 선택하고 다음 설정을 사용하세요:

   | 필드              | 값                        |
   |--------------------|------------------------------|
   | 키                | `NPM_AUTH_TOKEN`             |
   | 값              | `<DEPLOY-TOKEN>` |
   | 유형               | 변수                     |
   | 보호된 변수 | `CHECKED`                    |
   | 마스크 변수      | `CHECKED`                    |
   | 변수 확장    | `CHECKED`                    |

1. 선택 사항. 보호된 변수를 사용하려면:

   1. Yarn 패키지 소스 코드가 포함된 리포지토리로 이동하세요.
   1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
      - 태그가 있는 브랜치에서 빌드하는 경우 **보호된 태그**를 선택하고 시멘틱 버전 관리를 위해 `v*`(와일드카드)를 추가하세요.
      - 태그 없이 브랜치에서 빌드하는 경우 **브랜치 규칙**을 선택하세요.

1. 생성한 `NPM_AUTH_TOKEN`을 패키지 프로젝트 루트 디렉터리의 `.yarnrc.yml` 구성에 추가하세요. 여기서 `package.json`을 찾을 수 있습니다:

   ```yaml
   npmScopes:
     <my-org>:
       npmPublishRegistry: '${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/npm/'
       npmAlwaysAuth: true
       npmAuthToken: '${NPM_AUTH_TOKEN}'
   ```

   이 구성에서 `<my-org>`을 조직 범위로 바꾸되 `@` 기호는 제외하세요.

{{< /tab >}}

{{< tab title="프라이빗 러너" >}}

1. `CI_JOB_TOKEN`을 패키지 프로젝트 루트 디렉터리의 `.yarnrc.yml` 구성에 추가하세요. 여기서 `package.json`이 있습니다:

   ```yaml
   npmScopes:
     <my-org>:
       npmPublishRegistry: '${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/npm/'
       npmAlwaysAuth: true
       npmAuthToken: '${CI_JOB_TOKEN}'
   ```

   이 구성에서 `<my-org>`을 조직 범위로 바꾸되 `@` 기호는 제외하세요.

1. `.yarnrc.yml`이 있는 GitLab 프로젝트에서 `.gitlab-ci.yml` 파일을 편집하거나 생성하세요. 예를 들어 태그 푸시에만 트리거하려면:

   Yarn 1에서:

   ```yaml
   image: node:lts

   stages:
     - deploy

   rules:
   - if: $CI_COMMIT_TAG

   deploy:
     stage: deploy
     script:
       - yarn publish
   ```

   Yarn 2 이상에서:

   ```yaml
   image: node:lts

   stages:
     - deploy

   rules:
     - if: $CI_COMMIT_TAG

   deploy:
     stage: deploy
     before_script:
       - corepack enable
       - yarn set version stable
     script:
       - yarn npm publish
   ```

파이프라인이 실행되면 패키지가 패키지 레지스트리에 추가됩니다.

{{< /tab >}}

{{< /tabs >}}

## 패키지 설치 {#install-a-package}

인스턴스 또는 프로젝트에서 설치할 수 있습니다. 여러 패키지의 이름과 버전이 같으면 패키지를 설치할 때 가장 최근에 게시된 패키지만 검색됩니다.

### 범위가 지정된 패키지 이름 {#scoped-package-names}

인스턴스에서 설치하려면 패키지가 [범위](https://docs.npmjs.com/misc/scope/)로 명명되어야 합니다. `.yarnrc.yml` 파일과 `package.json`의 `publishConfig` 옵션에서 패키지의 범위를 설정할 수 있습니다. 프로젝트 또는 그룹에서 설치하는 경우 패키지 명명 규칙을 따를 필요가 없습니다.

패키지 범위는 `@`로 시작하며 `@owner/package-name` 형식을 따릅니다:

- `@owner`은 패키지 소스 코드가 있는 프로젝트의 루트가 아니라 패키지를 호스팅하는 최상위 프로젝트입니다.
- 패키지 이름은 무엇이든 될 수 있습니다.

예를 들어:

| 프로젝트 URL                                                       | 패키지 레지스트리     | 조직 범위 | 전체 패키지 이름           |
|-------------------------------------------------------------------|----------------------|--------------------|-----------------------------|
| `https://gitlab.com/<my-org>/<group-name>/<package-name-example>` | 패키지 이름 예 | `@my-org`          | `@my-org/package-name`      |
| `https://gitlab.com/<example-org>/<group-name>/<project-name>`    | 프로젝트 이름         | `@example-org`     | `@example-org/project-name` |

### 인스턴스에서 설치 {#install-from-the-instance}

같은 조직 범위의 여러 패키지로 작업하는 경우 인스턴스에서 설치하는 것을 고려하세요.

1. 조직 범위를 구성하세요. `.yarnrc.yml` 파일에 다음을 추가하세요:

   ```yaml
   npmScopes:
    <my-org>:
      npmRegistryServer: 'https://<domain_name>/api/v4/packages/npm'
   ```

   - `<my-org>`을 설치 대상 패키지의 루트 레벨 그룹으로 바꾸되 `@` 기호는 제외하세요.
   - `<domain_name>`을 도메인 이름으로 바꾸세요(예: `gitlab.com`).

1. 선택 사항. 패키지가 프라이빗인 경우 패키지 레지스트리에 대한 액세스를 구성해야 합니다:

   ```yaml
   npmRegistries:
     //<domain_name>/api/v4/packages/npm:
       npmAlwaysAuth: true
       npmAuthToken: '<token>'
   ```

   - `<domain_name>`을 도메인 이름으로 바꾸세요(예: `gitlab.com`).
   - `<token>`을 배포 토큰(권장), 그룹 액세스 토큰, 프로젝트 액세스 토큰 또는 개인 액세스 토큰으로 바꾸세요.

1. [Yarn으로 패키지 설치](#install-with-yarn)하세요.

### 그룹 또는 프로젝트에서 설치 {#install-from-a-group-or-project}

일회성 패키지가 있으면 그룹 또는 프로젝트에서 설치할 수 있습니다.

{{< tabs >}}

{{< tab title="그룹에서" >}}

1. 그룹 범위를 구성하세요. `.yarnrc.yml` 파일에 다음을 추가하세요:

   ```yaml
   npmScopes:
     <my-org>:
       npmRegistryServer: 'https://<domain_name>/api/v4/groups/<group_id>/-/packages/npm'
   ```

   - `<my-org>`을 설치 대상 그룹을 포함하는 최상위 그룹으로 바꾸세요. `@` 기호를 제외하세요.
   - `<domain_name>`을 도메인 이름으로 바꾸세요(예: `gitlab.com`).
   - `<group_id>`을 그룹 ID로 바꾸세요. 이는 [그룹 개요 페이지](../../group/_index.md#find-the-group-id)에서 찾을 수 있습니다.

1. 선택 사항. 패키지가 프라이빗인 경우 레지스트리를 설정해야 합니다:

   ```yaml
   npmRegistries:
     //<domain_name>/api/v4/groups/<group_id>/-/packages/npm:
       npmAlwaysAuth: true
       npmAuthToken: "<token>"
   ```

   - `<domain_name>`을 도메인 이름으로 바꾸세요(예: `gitlab.com`).
   - `<token>`을 배포 토큰(권장), 그룹 액세스 토큰, 프로젝트 액세스 토큰 또는 개인 액세스 토큰으로 바꾸세요.
   - `<group_id>`을 그룹 ID로 바꾸세요. 이는 [그룹 개요 페이지](../../group/_index.md#find-the-group-id)에서 찾을 수 있습니다.

1. [Yarn으로 패키지 설치](#install-with-yarn)하세요.

{{< /tab >}}

{{< tab title="프로젝트에서" >}}

1. 프로젝트 범위를 구성하세요. `.yarnrc.yml` 파일에 다음을 추가하세요:

   ```yaml
   npmScopes:
    <my-org>:
      npmRegistryServer: "https://<domain_name>/api/v4/projects/<project_id>/packages/npm"
   ```

   - `<my-org>`을 설치 대상 프로젝트를 포함하는 최상위 그룹으로 바꾸세요. `@` 기호를 제외하세요.
   - `<domain_name>`을 도메인 이름으로 바꾸세요(예: `gitlab.com`).
   - `<project_id>`을 프로젝트 ID로 바꾸세요. 이는 [프로젝트 개요 페이지](../../project/working_with_projects.md#find-the-project-id)에서 찾을 수 있습니다.

1. 선택 사항. 패키지가 프라이빗인 경우 레지스트리를 설정해야 합니다:

   ```yaml
   npmRegistries:
     //<domain_name>/api/v4/projects/<project_id>/packages/npm:
       npmAlwaysAuth: true
       npmAuthToken: "<token>"
   ```

   - `<domain_name>`을 도메인 이름으로 바꾸세요(예: `gitlab.com`).
   - `<token>`을 배포 토큰(권장), 그룹 액세스 토큰, 프로젝트 액세스 토큰 또는 개인 액세스 토큰으로 바꾸세요.
   - `<project_id>`을 프로젝트 ID로 바꾸세요. 이는 [프로젝트 개요 페이지](../../project/working_with_projects.md#find-the-project-id)에서 찾을 수 있습니다.

1. [Yarn으로 패키지 설치](#install-with-yarn)하세요.

{{< /tab >}}

{{< /tabs >}}

### Yarn으로 설치 {#install-with-yarn}

{{< tabs >}}

{{< tab title="Yarn 2 이상" >}}

- 명령줄 또는 CI/CD 파이프라인에서 `yarn add`을 실행하세요:

```shell
yarn add @scope/my-package
```

{{< /tab >}}

{{< tab title="Yarn Classic" >}}

Yarn Classic은 `.npmrc`과 `.yarnrc` 파일이 모두 필요합니다. 자세한 내용은 [Yarn issue 4451](https://github.com/yarnpkg/yarn/issues/4451#issuecomment-753670295)을 참조하세요.

1. 자격 증명을 `.npmrc` 파일에 배치하고 범위가 지정된 레지스트리를 `.yarnrc` 파일에 배치하세요:

   ```shell
   # .npmrc
   ## For the instance
   //<domain_name>/api/v4/packages/npm/:_authToken='<token>'
   ## For the group
   //<domain_name>/api/v4/groups/<group_id>/-/packages/npm/:_authToken='<token>'
   ## For the project
   //<domain_name>/api/v4/projects/<project_id>/packages/npm/:_authToken='<token>'

   # .yarnrc
   ## For the instance
   '@scope:registry' 'https://<domain_name>/api/v4/packages/npm/'
   ## For the group
   '@scope:registry' 'https://<domain_name>/api/v4/groups/<group_id>/-/packages/npm/'
   ## For the project
   '@scope:registry' 'https://<domain_name>/api/v4/projects/<project_id>/packages/npm/'
   ```

1. 명령줄 또는 CI/CD 파이프라인에서 `yarn add`을 실행하세요:

   ```shell
   yarn add @scope/my-package
   ```

{{< /tab >}}

{{< /tabs >}}

## Yarn 패키지 삭제 {#delete-a-yarn-package}

사전 요구 사항:

- Maintainer 또는 Owner 역할이 있어야 합니다.

패키지를 삭제하기 전에 [관련 보안 위험](../package_registry/supported_functionality.md#deleting-packages)을 이해해야 합니다.

패키지를 삭제하려면 다음 중 하나를 수행할 수 있습니다:

- [UI 사용](../package_registry/reduce_package_registry_storage.md#delete-a-package)하세요.
- [API 사용](../../../api/packages.md#delete-a-project-package)하세요.

## 관련 항목 {#related-topics}

- [npm 패키지 레지스트리 설명서](../npm_registry/_index.md#helpful-hints)
- [Yarn 마이그레이션 가이드](https://yarnpkg.com/migration/guide)
- [Yarn 패키지 빌드](../workflows/build_packages.md#yarn)

## 문제 해결 {#troubleshooting}

### npm 레지스트리에 대한 패키지 레지스트리로 Yarn 실행 오류 {#error-running-yarn-with-the-package-registry-for-the-npm-registry}

npm 레지스트리로 [Yarn](https://classic.yarnpkg.com/en/)을 사용하는 경우 다음과 같은 오류 메시지가 나타날 수 있습니다:

```shell
yarn install v1.15.2
warning package.json: No license field
info No lockfile found.
warning XXX: No license field
[1/4] 🔍  Resolving packages...
[2/4] 🚚  Fetching packages...
error An unexpected error occurred: "https://gitlab.example.com/api/v4/projects/XXX/packages/npm/XXX/XXX/-/XXX/XXX-X.X.X.tgz: Request failed \"404 Not Found\"".
info If you think this is a bug, please open a bug report with the information provided in "/Users/XXX/gitlab-migration/module-util/yarn-error.log".
info Visit https://classic.yarnpkg.com/en/docs/cli/install for documentation about this command
```

이 경우 다음 명령은 현재 디렉터리에 `.yarnrc` 파일을 생성합니다. 전역 구성을 위해 사용자 홈 디렉터리에 있거나 프로젝트별 구성을 위해 프로젝트 루트에 있어야 합니다:

```shell
yarn config set '//gitlab.example.com/api/v4/projects/<project_id>/packages/npm/:_authToken' '<token>'
yarn config set '//gitlab.example.com/api/v4/packages/npm/:_authToken' '<token>'
```

### Yarn Classic이 그룹 설치에서 tarball을 가져올 때 `404 Not Found`을 반환함 {#yarn-classic-returns-404-not-found-when-fetching-a-tarball-from-a-group-install}

Yarn Classic을 사용하여 그룹의 레지스트리에서 패키지를 설치할 때 패키지 해석은 성공할 수 있지만 tarball 다운로드는 `404 Not Found` 오류로 실패합니다:

```shell
[1/4] Resolving packages...
[2/4] Fetching packages...
error Error: https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/@scope/my-package/-/@scope/my-package-1.0.0.tgz: Request failed "404 Not Found"
```

이 오류는 그룹 레지스트리에서 반환된 패키지 메타데이터에 프로젝트 엔드포인트를 가리키는 tarball 다운로드 URL이 포함되어 있기 때문에 발생합니다. `.npmrc` 파일에 그룹 엔드포인트에만 인증 토큰이 있으면 프로젝트 엔드포인트에 대한 요청이 인증되지 않아 `404`을(를) 반환합니다.

이 문제를 해결하려면 `.npmrc` 파일에서 그룹 및 프로젝트 엔드포인트 모두에 대한 인증 토큰을 추가하세요:

```ini
# .npmrc
//gitlab.example.com/api/v4/groups/<group_id>/-/packages/npm/:_authToken='<token>'
//gitlab.example.com/api/v4/projects/<project_id>/packages/npm/:_authToken='<token>'
```

### Yarn Classic이 단축된 인증 경로로 `401 Unauthorized`을 반환함 {#yarn-classic-returns-401-unauthorized-with-shortened-authentication-paths}

GitLab 패키지 레지스트리로 Yarn Classic을 사용할 때 인증 토큰이 유효함에도 불구하고 `401 Unauthorized` 오류가 나타날 수 있습니다. 오류 메시지는 다음과 같을 수 있습니다:

```shell
error Couldn't find package "@scope/my-package" on the "npm" registry.
```

`--verbose` 플래그를 사용하면 로그에 `401` 상태 코드가 표시됩니다:

```shell
verbose Performing "GET" request to "https://gitlab.com/api/v4/groups/<group_id>/-/packages/npm/..."
verbose Request "https://gitlab.com/api/v4/groups/<group_id>/-/packages/npm/..." finished with status code 401.
```

이 문제는 `.npmrc`의 `_authToken` 항목이 전체 엔드포인트 경로 대신 단축된 상위 경로를 사용할 때 발생합니다. 예를 들어:

```ini
# Does NOT work with Yarn Classic
//gitlab.com/api/v4/:_authToken='<token>'
```

npm 버전 8 이상은 계층적 인증 매칭을 지원하지만(상위 경로에 설정된 토큰이 모든 하위 경로에 적용됨) Yarn Classic은 `_authToken` 항목과 레지스트리 URL 간에 정확한 경로 일치가 필요합니다.

이 문제를 해결하려면 `.npmrc` 파일에서 인증하는 각 레지스트리에 대해 전체 엔드포인트 경로를 사용하세요. 예를 들어 특정 프로젝트에서 호스팅되는 패키지가 있는 그룹 레지스트리에서 설치하는 경우:

```ini
# .npmrc
//gitlab.com/api/v4/groups/<group_id>/-/packages/npm/:_authToken='<token>'
//gitlab.com/api/v4/projects/<project_id>/packages/npm/:_authToken='<token>'
```

패키지 메타데이터가 그룹 엔드포인트에서 반환되어 프로젝트 엔드포인트를 가리키는 tarball 다운로드 URL을 포함하기 때문에 프로젝트 항목이 필요합니다.

### `yarn install`이 종속성으로 리포지토리를 복제하는 데 실패함 {#yarn-install-fails-to-clone-repository-as-a-dependency}

Dockerfile에서 `yarn install`을 사용하는 경우 Dockerfile을 빌드할 때 다음과 같은 오류가 발생할 수 있습니다:

```plaintext
...
#6 8.621 fatal: unable to access 'https://gitlab.com/path/to/project/': Problem with the SSL CA cert (path? access rights?)
#6 8.621 info Visit https://yarnpkg.com/en/docs/cli/install for documentation about this command.
#6 ...
```

이 문제를 해결하려면 [.dockerignore](https://docs.docker.com/build/building/context/#dockerignore-files) 파일의 모든 Yarn 관련 경로에 [느낌표(`!`)](https://docs.docker.com/build/building/context/#negating-matches)를 추가하세요.

```dockerfile
**

!./package.json
!./yarn.lock
...
```
