---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 패키지 레지스트리의 npm 패키지
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Node Package Manager(npm)는 JavaScript 및 Node.js의 기본 패키지 관리자입니다. 개발자는 npm을 사용하여 코드를 공유 및 재사용하고, 종속성을 관리하고, 프로젝트 워크플로를 간소화합니다. GitLab에서 npm 패키지는 소프트웨어 개발 생애 주기에서 중요한 역할을 합니다.

npm 엔드포인트에 대한 정보는 [API](../../../api/packages/npm.md)를 참조하세요.

GitLab 패키지 레지스트리에 npm 패키지를 게시하는 방법에 대한 [동영상 데모](https://youtu.be/yvLxtkvsFDA)를 확인하세요.

## 패키지 레지스트리에 인증 {#authenticate-to-the-package-registry}

비공개 프로젝트 또는 비공개 그룹에서 패키지를 게시하거나 설치하려면 패키지 레지스트리에 인증해야 합니다. 프로젝트 또는 그룹이 공개인 경우 인증할 필요가 없습니다. 프로젝트가 내부 프로젝트인 경우 GitLab 인스턴스에 등록된 사용자여야 합니다. 익명 사용자는 내부 프로젝트에서 패키지를 가져올 수 없습니다.

인증하려면 다음 중 하나를 사용할 수 있습니다:

- 다음 토큰 중 하나(범위를 `api`로 설정):
  - [개인 액세스 토큰](../../profile/personal_access_tokens.md)
  - [그룹 액세스 토큰](../../group/settings/group_access_tokens.md)
  - [프로젝트 액세스 토큰](../../project/settings/project_access_tokens.md)
- [배포 토큰](../../project/deploy_tokens/_index.md)(범위를 `read_package_registry`, `write_package_registry`, 또는 둘 다로 설정)
- CI/CD 파이프라인으로 패키지를 게시하려면 [CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md)을 사용합니다.

조직에서 2단계 인증(2FA)을 사용하는 경우 범위를 `api`로 설정한 개인 액세스 토큰을 사용해야 합니다. 자세한 내용은 [토큰 가이드](../package_registry/supported_functionality.md#authenticate-with-the-registry)를 참조하세요.

여기에 설명된 방법 이외의 인증 방법을 사용하지 마세요. 문서화되지 않은 인증 방법은 향후 제거될 수 있습니다.

### `.npmrc` 파일 {#with-the-npmrc-file}

`.npmrc` 파일을 `package.json`과 같은 디렉터리에서 생성 또는 편집합니다. `.npmrc` 파일에 다음 줄을 포함합니다:

```shell
  //<domain_name>/api/v4/projects/<project_id>/packages/npm/:_authToken="${NPM_TOKEN}"
```

> [!warning]
> GitLab 토큰(또는 기타 모든 토큰)을 `.npmrc` 파일이나 리포지토리에 커밋할 수 있는 다른 파일에 하드코드하지 마세요.

예를 들어:

{{< tabs >}}

{{< tab title="인스턴스의 경우" >}}

```shell
//<domain_name>/api/v4/packages/npm/:_authToken="${NPM_TOKEN}"
```

`<domain_name>`을(를) 도메인 이름으로 바꿉니다. 예를 들어, `gitlab.com`입니다.

{{< /tab >}}

{{< tab title="그룹의 경우" >}}

```shell
//<domain_name>/api/v4/groups/<group_id>/-/packages/npm/:_authToken="${NPM_TOKEN}"
```

다음을 바꾸어야 합니다:

- `<domain_name>`을(를) 도메인 이름으로 바꿉니다. 예를 들어, `gitlab.com`입니다.
- `<group_id>`을(를) 그룹 홈 페이지의 그룹 ID로 바꿉니다.

{{< /tab >}}

{{< tab title="프로젝트의 경우" >}}

```shell
//<domain_name>/api/v4/projects/<project_id>/packages/npm/:_authToken="${NPM_TOKEN}"
```

다음을 바꾸어야 합니다:

- `<domain_name>`을(를) 도메인 이름으로 바꿉니다. 예를 들어, `gitlab.com`입니다.
- `<project_id>`을(를) [프로젝트 개요 페이지](../../project/working_with_projects.md#find-the-project-id)의 프로젝트 ID로 바꿉니다.

{{< /tab >}}

{{< /tabs >}}

### `npm config set` {#with-npm-config-set}

다음과 같이 설정합니다.

```shell
npm config set -- //<domain_name>/:_authToken=<token>
```

npm 버전에 따라 URL을 변경해야 할 수 있습니다:

- npm 버전 7 이하에서는 엔드포인트에 대한 전체 URL을 사용합니다.
- 버전 8 이상에서는 `_authToken` 매개변수에 대해 전체 URL 대신 URI 조각을 사용할 수 있습니다. 자세한 내용은 [인증 관련 구성](https://docs.npmjs.com/cli/v8/configuring-npm/npmrc/?v=true#auth-related-configuration)을(를) 참조하세요.

> [!note]
> Yarn Classic 1.x를 사용하는 경우 인증 토큰을 설정할 때 전체 엔드포인트 경로를 지정해야 합니다. Yarn Classic은 계층적 인증 매칭을 지원하지 않으므로 `//gitlab.com/api/v4/` 같은 상위 경로에 설정된 토큰은 `//gitlab.com/api/v4/groups/<group_id>/-/packages/npm/` 같은 하위 경로에 적용되지 않습니다. 항상 전체 그룹 또는 프로젝트 경로를 사용합니다. 자세한 내용은 [Yarn Classic이 단축된 인증 경로로 `401 Unauthorized`을(를) 반환합니다](../yarn_repository/_index.md#yarn-classic-returns-401-unauthorized-with-shortened-authentication-paths)를 참조하세요.

예를 들어:

{{< tabs >}}

{{< tab title="인스턴스의 경우" >}}

```shell
npm config set -- //<domain_name>/api/v4/packages/npm/:_authToken=<token>
```

다음을 바꾸어야 합니다:

- `<domain_name>`을(를) 도메인 이름으로 바꿉니다. 예를 들어, `gitlab.com`입니다.
- `<token>`을(를) 배포 토큰, 그룹 액세스 토큰, 프로젝트 액세스 토큰 또는 개인 액세스 토큰으로 바꿉니다.

{{< /tab >}}

{{< tab title="그룹의 경우" >}}

```shell
npm config set -- //<domain_name>/api/v4/groups/<group_id>/-/packages/npm/:_authToken=<token>
```

다음을 바꾸어야 합니다:

- `<domain_name>`을(를) 도메인 이름으로 바꿉니다. 예를 들어, `gitlab.com`입니다.
- `<group_id>`을(를) 그룹 홈 페이지의 그룹 ID로 바꿉니다.
- `<token>`을(를) 배포 토큰, 그룹 액세스 토큰, 프로젝트 액세스 토큰 또는 개인 액세스 토큰으로 바꿉니다.

{{< /tab >}}

{{< tab title="프로젝트의 경우" >}}

```shell
npm config set -- //<domain_name>/api/v4/projects/<project_id>/packages/npm/:_authToken=<token>
```

다음을 바꾸어야 합니다:

- `<domain_name>`을(를) 도메인 이름으로 바꿉니다. 예를 들어, `gitlab.com`입니다.
- `<project_id>`을(를) 프로젝트 ID로 바꿉니다.
- `<token>`을(를) 배포 토큰, 그룹 액세스 토큰, 프로젝트 액세스 토큰 또는 개인 액세스 토큰으로 바꿉니다.

{{< /tab >}}

{{< /tabs >}}

## 레지스트리 URL 설정 {#set-up-the-registry-url}

GitLab 패키지 레지스트리에서 패키지를 게시하거나 설치하려면 올바른 레지스트리 URL을 사용하도록 npm을 구성해야 합니다. 구성 방법과 URL 구조는 패키지를 게시하는지 설치하는지에 따라 다릅니다.

레지스트리 URL을 구성하기 전에 다양한 구성 방법의 범위를 이해하는 것이 중요합니다:

- `.npmrc` 파일: 구성은 파일이 포함된 폴더에 국한됩니다.
- `npm config set` 명령: 이는 글로벌 npm 구성을 수정하고 시스템에서 실행되는 모든 npm 명령에 영향을 미칩니다.
- `publishConfig` in `package.json`: 이 구성은 패키지에만 적용되며 해당 패키지를 게시할 때만 적용됩니다.

> [!warning]
> `npm config set`을(를) 실행하면 글로벌 npm 구성이 변경됩니다. 이 변경은 현재 작업 디렉터리에 관계없이 시스템에서 실행되는 모든 npm 명령에 영향을 미칩니다. 특히 공유 시스템에서는 이 방법을 사용할 때 주의하세요.

### 패키지 게시 {#for-publishing-packages}

패키지를 게시할 때 프로젝트 엔드포인트를 사용합니다:

```shell
https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/
```

`gitlab.example.com`을(를) GitLab 인스턴스의 도메인으로 바꾸고 `<project_id>`을(를) 프로젝트 ID로 바꿉니다. 이 URL을 구성하려면 다음 방법 중 하나를 사용합니다:

{{< tabs >}}

{{< tab title="`.npmrc` 파일" >}}

프로젝트 루트에서 `.npmrc` 파일을 생성 또는 편집합니다:

```plaintext
@scope:registry=https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/
//gitlab.example.com/api/v4/projects/<project_id>/packages/npm/:_authToken="${NPM_TOKEN}"
```

{{< /tab >}}

{{< tab title="`npm config`" >}}

`npm config set` 명령을 사용합니다:

```shell
npm config set @scope:registry=https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/
```

{{< /tab >}}

{{< tab title="`package.json`" >}}

`publishConfig` 섹션을 `package.json`에 추가합니다:

```shell
{
  "publishConfig": {
    "@scope:registry": "https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/"
  }
}
```

{{< /tab >}}

{{< /tabs >}}

`@scope`을(를) 패키지의 범위로 바꿉니다.

### 패키지 설치 {#for-installing-packages}

패키지를 설치할 때 프로젝트, 그룹 또는 인스턴스 엔드포인트를 사용할 수 있습니다. URL 구조는 그에 따라 다릅니다. 이 URL을 구성하려면 다음 방법 중 하나를 사용합니다:

{{< tabs >}}

{{< tab title="`.npmrc` 파일" >}}

프로젝트 루트에서 `.npmrc` 파일을 생성 또는 편집합니다. 필요에 따라 적절한 URL을 사용합니다:

- 프로젝트의 경우:

  ```shell
  @scope:registry=https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/
  ```

- 그룹의 경우:

  ```shell
  @scope:registry=https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/npm/
  ```

- 인스턴스의 경우:

  ```shell
  @scope:registry=https://gitlab.example.com/api/v4/packages/npm/
  ```

{{< /tab >}}

{{< tab title="`npm config`" >}}

`npm config set` 명령을 적절한 URL과 함께 사용합니다:

- 프로젝트의 경우:

  ```shell
  npm config set @scope:registry=https://gitlab.example.com/api/v4/projects/<project_id>/packages/npm/
  ```

- 그룹의 경우:

  ```shell
  npm config set @scope:registry=https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/npm/
  ```

- 인스턴스의 경우:

  ```shell
  npm config set @scope:registry=https://gitlab.example.com/api/v4/packages/npm/
  ```

{{< /tab >}}

{{< /tabs >}}

`gitlab.example.com`, `<project_id>`, `<group_id>`, `@scope`을(를) GitLab 인스턴스 및 패키지의 적절한 값으로 바꿉니다.

레지스트리 URL을 구성한 후 패키지 레지스트리에 인증할 수 있습니다.

## GitLab 패키지 레지스트리에 게시 {#publish-to-gitlab-package-registry}

npm 패키지를 GitLab 패키지 레지스트리에 게시하려면 인증해야 합니다.

### 명명 규칙 {#naming-convention}

패키지 설치 방법에 따라 명명 규칙을 준수해야 할 수 있습니다.

패키지를 설치하기 위해 3가지 API 엔드포인트 중 하나를 사용할 수 있습니다:

- 인스턴스: 여러 GitLab 그룹이나 자체 네임스페이스에 많은 npm 패키지가 있을 때 사용합니다.
- 그룹: 같은 그룹 또는 하위 그룹의 여러 프로젝트에 많은 npm 패키지가 있을 때 사용합니다.
- 프로젝트: 같은 GitLab 그룹에 있지 않은 몇 개의 npm 패키지가 있을 때 사용합니다.

프로젝트 또는 그룹에서 패키지를 설치하려고 계획하는 경우 명명 규칙을 준수할 필요가 없습니다.

인스턴스에서 패키지를 설치하려고 계획하는 경우 범위가 있는 패키지 이름을 지정해야 합니다. 범위가 있는 패키지는 `@`로 시작하며 `@owner/package-name` 형식입니다. `.npmrc` 파일 및 `publishConfig` 옵션을 사용하여 `package.json`에서 패키지의 범위를 설정할 수 있습니다.

- `@scope`에 사용되는 값은 패키지 자체의 소스 코드가 있는 프로젝트의 루트가 아니라 패키지를 호스팅하는 프로젝트의 루트입니다. 범위는 소문자여야 합니다.
- 패키지 이름은 원하는 대로 지정할 수 있습니다.

자세한 내용은 [범위가 있는 패키지](https://docs.npmjs.com/cli/v11/using-npm/scope/)를 참조하세요.

| 프로젝트 URL                                             | 패키지 레지스트리 | 범위     | 전체 패키지 이름      |
| ------------------------------------------------------- | ------------------- | --------- | ---------------------- |
| `https://gitlab.com/my-org/engineering-group/analytics` | 분석           | `@my-org` | `@my-org/package-name` |

`package.json` 파일의 패키지 이름이 이 규칙과 일치하는지 확인합니다:

```shell
"name": "@my-org/package-name"
```

### 명령줄로 패키지 게시 {#publish-a-package-with-the-command-line}

인증을 구성한 후 다음으로 NPM 패키지를 게시합니다:

```shell
npm publish
```

인증을 위해 `.npmrc` 파일을 사용하는 경우 예상 환경 변수를 설정합니다:

```shell
NPM_TOKEN=<token> npm publish
```

업로드된 패키지에 `package.json` 파일이 2개 이상 있는 경우 처음 발견된 파일만 사용되고 나머지는 무시됩니다.

### CI/CD 파이프라인으로 패키지 게시 {#publish-a-package-with-a-cicd-pipeline}

CI/CD 파이프라인을 사용하여 게시할 때 [미리 정의된 변수](../../../ci/variables/predefined_variables.md) `${CI_PROJECT_ID}` 및 `${CI_JOB_TOKEN}`을(를) 사용하여 프로젝트의 패키지 레지스트리로 인증할 수 있습니다. 이러한 변수를 사용하여 CI/CD 작업 실행 중 인증을 위한 `.npmrc` 파일을 생성할 수 있습니다.

> [!note]
> `.npmrc` 파일을 생성할 때 기본 포트인 경우 `${CI_SERVER_HOST}` 뒤에 포트를 지정하지 마세요. `http` URL은 기본값이 `80`이고, `https` URL은 기본값이 `443`입니다.

`package.json`을(를) 포함하는 GitLab 프로젝트에서 `.gitlab-ci.yml` 파일을 편집하거나 생성합니다. 예를 들어:

```yaml
default:
  image: node:latest

stages:
  - deploy

publish-npm:
  stage: deploy
  script:
    - echo "@scope:registry=https://${CI_SERVER_HOST}/api/v4/projects/${CI_PROJECT_ID}/packages/npm/" > .npmrc
    - echo "//${CI_SERVER_HOST}/api/v4/projects/${CI_PROJECT_ID}/packages/npm/:_authToken=${CI_JOB_TOKEN}" >> .npmrc
    - npm publish
```

`@scope`을(를) 게시 중인 패키지의 [범위](https://docs.npmjs.com/cli/v10/using-npm/scope/)로 바꿉니다.

파이프라인에서 `publish-npm` 작업이 실행될 때 패키지가 패키지 레지스트리에 게시됩니다.

## 패키지 설치 {#install-a-package}

여러 패키지의 이름과 버전이 같으면 패키지를 설치할 때 가장 최근에 게시된 패키지가 검색됩니다.

GitLab 프로젝트, 그룹 또는 인스턴스에서 패키지를 설치할 수 있습니다:

- 인스턴스: 여러 GitLab 그룹이나 자체 네임스페이스에 많은 npm 패키지가 있을 때 사용합니다.
- 그룹: 같은 GitLab 그룹의 여러 프로젝트에 많은 npm 패키지가 있을 때 사용합니다.
- 프로젝트: 같은 GitLab 그룹에 있지 않은 몇 개의 npm 패키지가 있을 때 사용합니다.

### 인스턴스에서 설치 {#install-from-an-instance}

사전 요구 사항:

- 범위가 있는 명명 규칙에 따라 패키지가 게시되었습니다.

1. 패키지 레지스트리에 인증합니다.
1. 레지스트리를 설정합니다:

   ```shell
   npm config set @scope:registry https://<domain_name>.com/api/v4/packages/npm/
   ```

   - `@scope`을(를) 패키지를 설치하는 프로젝트의 최상위 그룹으로 바꿉니다.
   - `<domain_name>`을(를) 도메인 이름(예: `gitlab.com`)으로 바꿉니다.

1. 패키지를 설치합니다:

   ```shell
   npm install @scope/my-package
   ```

### 그룹에서 설치 {#install-from-a-group}

1. 패키지 레지스트리에 인증합니다.
1. 레지스트리를 설정합니다:

   ```shell
   npm config set @scope:registry=https://<domain_name>/api/v4/groups/<group_id>/-/packages/npm/
   ```

   - `@scope`을(를) 패키지를 설치하는 그룹의 최상위 그룹으로 바꿉니다.
   - `<domain_name>`을(를) 도메인 이름(예: `gitlab.com`)으로 바꿉니다.
   - `<group_id>`을(를) 그룹 홈 페이지에서 찾을 수 있는 그룹 ID로 바꿉니다.

1. 패키지를 설치합니다:

   ```shell
   npm install @scope/my-package
   ```

### 프로젝트에서 설치 {#install-from-a-project}

1. 패키지 레지스트리에 인증합니다.
1. 레지스트리를 설정합니다:

   ```shell
   npm config set @scope:registry=https://<domain_name>/api/v4/projects/<project_id>/packages/npm/
   ```

   - `@scope`을(를) 패키지를 설치하는 프로젝트의 [최상위 그룹](#naming-convention)으로 바꿉니다.
   - `<domain_name>`을(를) 도메인 이름(예: `gitlab.com`)으로 바꿉니다.
   - `<project_id>`을(를) [프로젝트 개요 페이지](../../project/working_with_projects.md#find-the-project-id)에서 찾을 수 있는 프로젝트 ID로 바꿉니다.

1. 패키지를 설치합니다:

   ```shell
   npm install @scope/my-package
   ```

### CI/CD 파이프라인 내에서 패키지 설치 {#install-a-package-inside-a-cicd-pipeline}

CI/CD 파이프라인 내에서 패키지를 설치할 때 미리 정의된 변수 `${CI_PROJECT_ID}` 및 `${CI_JOB_TOKEN}`를 사용하여 프로젝트의 패키지 레지스트리로 인증할 수 있습니다. 이러한 변수를 사용하여 CI/CD 작업 실행 중 인증을 위한 `.npmrc` 파일을 생성할 수 있습니다.

> [!note]
> `.npmrc` 파일을 생성할 때 기본 포트인 경우 `${CI_SERVER_HOST}` 뒤에 포트를 지정하지 마세요. `http` URL은 기본값이 `80`이고, `https` URL은 기본값이 `443`입니다.

`package.json`을(를) 포함하는 GitLab 프로젝트에서 `.gitlab-ci.yml` 파일을 편집하거나 생성합니다. 예를 들어:

```yaml
default:
  image: node:latest

stages:
  - deploy

publish-npm:
  stage: deploy
  script:
    - echo "@scope:registry=https://${CI_SERVER_HOST}/api/v4/projects/${CI_PROJECT_ID}/packages/npm/" > .npmrc
    - echo "//${CI_SERVER_HOST}/api/v4/projects/${CI_PROJECT_ID}/packages/npm/:_authToken=${CI_JOB_TOKEN}" >> .npmrc
    - npm install @scope/my-package
```

`@scope`을(를) 설치 중인 패키지의 범위 및 패키지 이름으로 바꿉니다.

이전 예제는 프로젝트 수준의 엔드포인트를 사용합니다. 그룹 또는 인스턴스 수준의 엔드포인트를 사용하려면 그룹에서 설치 또는 인스턴스에서 설치에 설명된 대로 레지스트리 및 인증 토큰 URL을 구성합니다.

### npmjs.com으로 패키지 전달 {#package-forwarding-to-npmjscom}

{{< history >}}

- 필요한 역할 [변경됨](https://gitlab.com/gitlab-org/gitlab/-/issues/370471): GitLab 17.0에서 Maintainer에서 Owner로 변경되었습니다.

{{< /history >}}

npm 패키지를 패키지 레지스트리에서 찾을 수 없으면 GitLab이 HTTP 리다이렉트로 응답하여 요청 클라이언트가 `npmjs.com`로 요청을 다시 보낼 수 있습니다.

관리자는 [지속적 통합 설정](../../../administration/settings/continuous_integration.md)에서 이 동작을 비활성화할 수 있습니다.

그룹 소유자는 그룹 **패키지 및 레지스트리** 설정에서 이 동작을 비활성화할 수 있습니다.

개선 사항은 [에픽 3608](https://gitlab.com/groups/gitlab-org/-/epics/3608)에서 추적됩니다.

## 패키지 중단 {#deprecate-a-package}

패키지를 중단하여 패키지를 가져올 때 중단 경고를 표시할 수 있습니다.

사전 요구 사항:

- 패키지를 삭제할 필요한 [권한](../../permissions.md)이 있습니다.
- 패키지 레지스트리에 인증되었습니다.

명령줄에서 실행합니다:

```shell
npm deprecate @scope/package "Deprecation message"
```

CLI는 `@scope/package`에 대한 버전 범위도 허용합니다. 예를 들어:

```shell
npm deprecate @scope/package "All package versions are deprecated"
npm deprecate @scope/package@1.0.1 "Only version 1.0.1 is deprecated"
npm deprecate @scope/package@"< 1.0.5" "All package versions less than 1.0.5 are deprecated"
```

패키지가 중단되면 상태가 `deprecated`로 업데이트됩니다.

### 중단 경고 제거 {#remove-deprecation-warning}

패키지의 중단 경고를 제거하려면 메시지에 대해 `""`(빈 문자열)을 지정합니다. 예를 들어:

```shell
npm deprecate @scope/package ""
```

패키지의 중단 경고를 제거하면 상태가 `default`로 업데이트됩니다.

## 패키지 삭제 {#delete-a-package}

사전 요구 사항:

- Maintainer 또는 Owner 역할이 있어야 합니다.

패키지를 삭제하기 전에 [관련 보안 위험](../package_registry/supported_functionality.md#deleting-packages)을 이해했는지 확인하세요.

패키지를 삭제하려면 다음 중 하나를 수행할 수 있습니다:

- [UI 사용](../package_registry/reduce_package_registry_storage.md#delete-a-package)
- [API 사용](../../../api/packages.md#delete-a-project-package)

## 도움이 되는 힌트 {#helpful-hints}

### 다른 조직에서 npm 패키지 설치 {#install-npm-packages-from-other-organizations}

GitLab 외부의 조직 및 사용자에게 패키지 요청을 라우팅할 수 있습니다.

이를 위해 `.npmrc` 파일에 줄을 추가합니다. `@my-other-org`를 프로젝트 리포지토리를 소유한 네임스페이스 또는 그룹으로 바꾸고 조직의 URL을 사용합니다. 이름은 대소문자를 구분하며 그룹 또는 네임스페이스의 이름과 정확히 일치해야 합니다.

```shell
@scope:registry=https://my_domain_name.com/api/v4/packages/npm/
@my-other-org:registry=https://my_domain_name.example.com/api/v4/packages/npm/
```

### npm 메타데이터 {#npm-metadata}

GitLab 패키지 레지스트리는 npm 클라이언트에 다음 속성을 노출합니다:

- `name`
- `versions`
  - `name`
  - `version`
  - `deprecated`
  - `dependencies`
  - `devDependencies`
  - `bundleDependencies`
  - `peerDependencies`
  - `bin`
  - `directories`
  - `dist`
  - `engines`
  - `_hasShrinkwrap`
  - `hasInstallScript`: `true` (이 버전에 설치 스크립트가 있는 경우)

자세한 내용은 [약식 버전 객체](https://github.com/npm/registry/blob/main/docs/responses/package-metadata.md#abbreviated-version-object)를 참조하세요.

### npm 배포 태그 추가 {#add-npm-distribution-tags}

새로 게시된 패키지에 [배포 태그](https://docs.npmjs.com/cli/dist-tag/)를 추가할 수 있습니다. 태그는 선택 사항이며 한 번에 하나의 패키지에만 할당할 수 있습니다.

태그 없이 패키지를 게시하면 `latest` 태그가 기본적으로 추가됩니다. 태그 또는 버전을 지정하지 않고 패키지를 설치하면 `latest` 태그가 사용됩니다.

지원되는 `dist-tag` 명령의 예:

```shell
npm publish @scope/package --tag               # Publish a package with new tag
npm dist-tag add @scope/package@version my-tag # Add a tag to an existing package
npm dist-tag ls @scope/package                 # List all tags under the package
npm dist-tag rm @scope/package@version my-tag  # Delete a tag from the package
npm install @scope/package@my-tag              # Install a specific tag
```

#### CI/CD에서 {#from-cicd}

GitLab CI/CD 작업에서 `npm dist-tag` 명령을 실행하기 위해 다음 토큰 중 하나를 사용할 수 있습니다:

- [`CI_JOB_TOKEN`](../../../ci/jobs/ci_job_token.md)
- 배포 토큰

사전 요구 사항:

- npm 버전 6.9.1 이상입니다. 이전 버전에서는 npm 6.9.0의 버그로 인해 배포 태그 삭제가 실패합니다.

예를 들어:

```yaml
npm-deploy-job:
  script:
    - echo "//${CI_SERVER_HOST}/api/v4/projects/${CI_PROJECT_ID}/packages/npm/:_authToken=${CI_JOB_TOKEN}">.npmrc
    - npm dist-tag add @scope/package@version my-tag
```

### npm 패키지 감사 {#audit-npm-packages}

GitLab은 `npm audit` 명령을 지원하여 패키지의 알려진 취약점을 확인할 수 있습니다.

#### `npm audit` {#use-npm-audit}

사전 요구 사항:

- 패키지 레지스트리에 대한 인증을 구성합니다.
- 레지스트리 URL을 설정합니다.

보안 감사를 실행하려면 다음 명령을 실행할 수 있습니다:

```shell
npm audit --registry=https://gitlab.example.com/api/v4/packages/npm/
```

또는 레지스트리 구성을 이미 설정한 경우:

```shell
npm audit
```

`npm audit` 명령은 종속성의 알려진 취약점을 확인하고 보고서를 제공합니다.

#### `npm audit` 워크플로 {#npm-audit-workflow}

GitLab 패키지 레지스트리에 대해 `npm audit`을(를) 실행하면 다음 두 가지 시나리오 중 하나가 발생합니다:

1. 패키지 전달이 활성화된 경우(기본값) GitLab은 감사 요청을 `npmjs.com`로 전달하여 공개 및 비공개 패키지 모두에 대한 취약점 정보를 검색합니다.
1. 패키지 전달이 비활성화된 경우 GitLab이 빈 결과 집합을 반환합니다. GitLab은 취약점에 대해 패키지를 독립적으로 검사하지 않습니다.

#### 중요한 보안 고려 사항 {#important-security-considerations}

GitLab을 패키지 레지스트리로 지정하지 않은 경우(`--registry` 플래그 사용 또는 `.npmrc` 파일에서 기본 레지스트리로 설정) 감사 요청이 공개 npm 레지스트리로 대신 이동합니다.

이 경우 요청 본문에는 비공개 GitLab 패키지를 포함한 프로젝트의 모든 패키지에 대한 정보가 포함됩니다.

비공개 패키지 정보가 GitLab 내에 유지되도록 하려면 `npm audit` 명령을 실행할 때 항상 GitLab 레지스트리를 지정해야 합니다.

#### 알려진 이슈 {#known-issues}

- 감사 결과는 패키지 전달이 활성화되어 있는지 여부에 따라 달라집니다. 관리자 또는 그룹 소유자가 전달을 비활성화한 경우 `npm audit`은(는) 취약점 정보를 반환하지 않습니다.
- 감사 요청에는 비공개 패키지를 포함한 프로젝트의 모든 패키지에 대한 정보가 포함됩니다.

### 지원되는 CLI 명령 {#supported-cli-commands}

GitLab npm 리포지토리는 npm CLI(`npm`) 및 yarn CLI(`yarn`)에 대해 다음 명령을 지원합니다:

- `npm install`: npm 패키지를 설치합니다.
- `npm publish`: npm 패키지를 레지스트리에 게시합니다.
- `npm dist-tag add`: npm 패키지에 dist-tag를 추가합니다.
- `npm dist-tag ls`: 패키지의 dist-tag를 나열합니다.
- `npm dist-tag rm`: dist-tag를 삭제합니다.
- `npm ci`: `package-lock.json` 파일에서 직접 npm 패키지를 설치합니다.
- `npm view`: 패키지 메타데이터를 표시합니다.
- `npm pack`: 패키지에서 tarball을 생성합니다.
- `npm deprecate`: 패키지 버전을 중단합니다.
- `npm audit`: 프로젝트 종속성의 취약점을 확인합니다.

## 문제 해결 {#troubleshooting}

### npm 로그가 올바르게 표시되지 않음 {#npm-logs-dont-display-correctly}

다음과 같은 오류가 발생할 수 있습니다:

```shell
npm ERR! A complete log of this run can be found in: .npm/_logs/<date>-debug-0
```

로그가 `.npm/_logs/` 디렉터리에 나타나지 않으면 로그를 루트 디렉터리로 복사하여 볼 수 있습니다:

```yaml
  script:
    - npm install --loglevel verbose
    - cp -r /root/.npm/_logs/ .
  artifacts:
    paths:
      - './_logs'
```

npm 로그가 아티팩트로 `/root/.npm/_logs/`로 복사됩니다.

### `404 Not Found` 오류가 `npm install` 또는 `yarn`에서 발생하고 있습니다 {#404-not-found-errors-are-happening-on-npm-install-or-yarn}

`CI_JOB_TOKEN`을(를) 사용하여 다른 프로젝트의 종속성과 함께 npm 패키지를 설치하면 404 Not Found 오류가 발생합니다. 패키지 및 모든 종속성에 액세스할 수 있는 토큰으로 인증해야 합니다.

Yarn Classic에서 그룹 레지스트리의 패키지를 설치할 때 패키지 해석이 성공할 수 있지만 tarball 다운로드가 `404 Not Found` 오류로 실패할 수 있습니다. 이 오류는 그룹 엔드포인트에서 반환한 패키지 메타데이터에 프로젝트 엔드포인트를 가리키는 tarball URL이 포함되어 있기 때문에 발생합니다. 그룹 및 프로젝트 엔드포인트 모두에 대한 인증 토큰을 구성해야 합니다:

```ini
//gitlab.example.com/api/v4/groups/<group_id>/-/packages/npm/:_authToken=<token>
//gitlab.example.com/api/v4/projects/<project_id>/packages/npm/:_authToken=<token>
```

자세한 내용은 [Yarn Classic이 그룹 설치에서 tarball을 가져올 때 `404 Not Found`을(를) 반환합니다](../yarn_repository/_index.md#yarn-classic-returns-404-not-found-when-fetching-a-tarball-from-a-group-install)를 참조하세요.

패키지 및 종속성이 같은 그룹의 별도 프로젝트에 있는 경우 [그룹 배포 토큰](../../project/deploy_tokens/_index.md#create-a-deploy-token)을(를) 사용할 수 있습니다:

```ini
//gitlab.example.com/api/v4/packages/npm/:_authToken=<group-token>
@group-scope:registry=https://gitlab.example.com/api/v4/packages/npm/
```

패키지 및 종속성이 여러 그룹에 분산된 경우 모든 그룹 또는 개별 프로젝트에 액세스할 수 있는 사용자의 개인 액세스 토큰을 사용할 수 있습니다:

```ini
//gitlab.example.com/api/v4/packages/npm/:_authToken=<personal-access-token>
@group-1:registry=https://gitlab.example.com/api/v4/packages/npm/
@group-2:registry=https://gitlab.example.com/api/v4/packages/npm/
```

> [!warning]
> 개인 액세스 토큰을 조심스럽게 처리해야 합니다. 개인 액세스 토큰 관리(예: 짧은 만료 시간 설정 및 최소 범위 사용)에 대한 지침을 보려면 [토큰 보안 고려 사항](../../../security/tokens/_index.md#security-considerations)을(를) 참조하세요.

### `npm publish`이(가) 기본 npm 레지스트리(`registry.npmjs.org`)를 목표로 함 {#npm-publish-targets-default-npm-registry-registrynpmjsorg}

`package.json` 및 `.npmrc` 파일에서 패키지 범위를 일관되게 설정했는지 확인합니다.

예를 들어 GitLab의 프로젝트 이름이 `@scope/my-package`인 경우 `package.json` 파일은 다음과 같아야 합니다:

```json
{
  "name": "@scope/my-package"
}
```

`.npmrc` 파일은 다음과 같아야 합니다:

```shell
@scope:registry=https://your_domain_name/api/v4/projects/your_project_id/packages/npm/
//your_domain_name/api/v4/projects/your_project_id/packages/npm/:_authToken="${NPM_TOKEN}"
```

### `npm install`이(가) `npm ERR! 403 Forbidden`을(를) 반환함 {#npm-install-returns-npm-err-403-forbidden}

이 오류가 발생하면 다음을 확인하세요:

- 패키지 레지스트리가 프로젝트 설정에서 활성화되었습니다. 패키지 레지스트리는 기본적으로 활성화되어 있지만 [비활성화](../package_registry/_index.md#turn-off-the-package-registry)할 수 있습니다.
- 토큰이 만료되지 않았으며 적절한 권한이 있습니다.
- 같은 이름이나 버전의 패키지가 주어진 범위 내에 이미 존재하지 않습니다.
- 범위가 있는 패키지 URL에 후행 슬래시가 포함됩니다:
  - 올바름: `//gitlab.example.com/api/v4/packages/npm/`
  - 잘못됨: `//gitlab.example.com/api/v4/packages/npm`

### `npm publish`이(가) `npm ERR! 400 Bad Request`을(를) 반환함 {#npm-publish-returns-npm-err-400-bad-request}

이 오류가 발생하면 다음 문제 중 하나가 원인일 수 있습니다.

### 패키지 이름이 명명 규칙을 충족하지 않음 {#package-name-does-not-meet-the-naming-convention}

패키지 이름이 `@scope/package-name` 패키지 명명 규칙을 충족하지 못할 수 있습니다.

대소문자를 포함하여 이름이 규칙을 정확히 충족하는지 확인합니다. 그리고 다시 게시해 보세요.

### 패키지가 이미 존재함 {#package-already-exists}

패키지가 이미 같은 루트 네임스페이스의 다른 프로젝트에 게시되었으므로 같은 이름으로 다시 게시할 수 없습니다.

이는 이전에 게시된 패키지의 이름은 같지만 버전이 다른 경우에도 마찬가지입니다.

### 패키지 JSON 파일이 너무 큼 {#package-json-file-is-too-large}

`package.json` 파일이 `20,000` 문자를 초과하지 않는지 확인합니다.
