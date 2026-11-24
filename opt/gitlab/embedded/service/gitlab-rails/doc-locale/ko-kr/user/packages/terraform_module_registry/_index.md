---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Terraform 모듈 레지스트리
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Terraform 모듈 레지스트리를 사용하면 다음을 수행할 수 있습니다:

- GitLab 프로젝트를 Terraform 모듈의 비공개 레지스트리로 사용할 수 있습니다.
- GitLab CI/CD를 사용하여 모듈을 만들고 게시하면 다른 비공개 프로젝트에서 사용할 수 있습니다.

## Terraform 모듈 레지스트리 인증 {#authenticate-to-the-terraform-module-registry}

Terraform 모듈 레지스트리에 인증하려면 다음 중 하나가 필요합니다:

- [개인 액세스 토큰](../../profile/personal_access_tokens.md)(`read_api` 범위 이상)
- [CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md)
- [배포 토큰](../../project/deploy_tokens/_index.md)(`read_package_registry` 또는 `write_package_registry` 범위 또는 둘 다)

API를 사용할 때:

- 배포 토큰으로 인증하는 경우 모듈을 게시하려면 `write_package_registry` 범위를 적용해야 합니다. 모듈을 다운로드하려면 `read_package_registry` 범위를 적용하세요.
- 개인 액세스 토큰으로 인증하는 경우 최소한 `read_api` 범위로 구성해야 합니다.

여기에 설명된 방법 이외의 인증 방법을 사용하지 마세요. 문서화되지 않은 인증 방법은 향후 제거될 수 있습니다.

## 사전 요구 사항 {#prerequisites}

Terraform 모듈을 게시하려면:

- Developer, Maintainer 또는 Owner 역할이 있어야 합니다.

모듈을 삭제하려면:

- Maintainer 또는 Owner 역할이 있어야 합니다.

## Terraform 모듈 게시 {#publish-a-terraform-module}

Terraform 모듈을 게시하면 존재하지 않는 경우 이를 생성합니다.

Terraform 모듈을 게시한 후 [**Terraform 모듈 레지스트리**](#view-terraform-modules) 페이지에서 확인할 수 있습니다.

### API 사용 {#with-the-api}

[Terraform 모듈 레지스트리 API](../../../api/packages/terraform-modules.md)를 사용하여 Terraform 모듈을 게시합니다.

```plaintext
PUT /projects/:id/packages/terraform/modules/:module-name/:module-system/:module-version/file
```

| 속성          | 형식            | 필수 | 설명                                                                                                                      |
| -------------------| --------------- | ---------| -------------------------------------------------------------------------------------------------------------------------------- |
| `id`               | 정수/문자열  | 예      | 프로젝트의 ID 또는 [URL 인코딩 경로](../../../api/rest/_index.md#namespaced-paths)                                    |
| `module-name`      | 문자열          | 예      | 모듈 이름 지원되는 구문: 1~64자의 ASCII 문자(소문자 a-z 및 숫자 0-9 포함) |
| `module-system`    | 문자열          | 예      | 모듈 시스템 지원되는 구문: 1~64자의 ASCII 문자(소문자 a-z 및 숫자 0-9 포함) 자세한 내용은 [모듈 레지스트리 프로토콜](https://opentofu.org/docs/internals/module-registry-protocol/)을 참조하세요. |
| `module-version`   | 문자열          | 예      | 모듈 버전 [시멘틱 버전 관리 사양](https://semver.org/)을 따라야 합니다. |

요청 본문에 파일 내용을 제공합니다.

요청은 `/file`로 끝나야 합니다. `404 Not Found` 오류가 발생합니다.

{{< tabs >}}

{{< tab title="개인 액세스 토큰" >}}

개인 액세스 토큰을 사용한 예제 요청:

```shell
curl --fail-with-body --header "PRIVATE-TOKEN: <your_access_token>" \
     --upload-file path/to/file.tgz \
     --url "https://gitlab.example.com/api/v4/projects/<your_project_id>/packages/terraform/modules/<your_module>/<your_system>/0.0.1/file"
```

{{< /tab >}}

{{< tab title="배포 토큰" >}}

배포 토큰을 사용한 예제 요청:

```shell
curl --fail-with-body --header "DEPLOY-TOKEN: <deploy_token>" \
     --upload-file path/to/file.tgz \
     --url "https://gitlab.example.com/api/v4/projects/<your_project_id>/packages/terraform/modules/<your_module>/<your_system>/0.0.1/file"
```

{{< /tab >}}

{{< /tabs >}}

응답 예시:

```json
{
  "message":"201 Created"
}
```

### CI/CD 템플릿 사용(권장) {#with-a-cicd-template-recommended}

[`Terraform-Module.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Terraform-Module.gitlab-ci.yml) 또는 고급 [`Terraform/Module-Base.gitlab-ci.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Terraform/Module-Base.gitlab-ci.yml) CI/CD 템플릿을 사용하여 Terraform 모듈을 GitLab Terraform 모듈 레지스트리에 게시할 수 있습니다:

```yaml
include:
  template: Terraform-Module.gitlab-ci.yml
```

파이프라인에는 다음 작업이 포함됩니다:

- `fmt`: Terraform 모듈의 형식 유효성 검사
- `kics-iac-sast`: 보안 문제에 대해 Terraform 모듈 테스트
- `deploy`: Terraform 모듈을 Terraform 모듈 레지스트리에 배포(태그 파이프라인만)

#### 파이프라인 변수 사용 {#use-pipeline-variables}

다음 변수로 파이프라인을 구성합니다:

| 변수                   | 기본값              | 설명                                                                                     |
|----------------------------|----------------------|-------------------------------------------------------------------------------------------------|
| `TERRAFORM_MODULE_DIR`     | `${CI_PROJECT_DIR}`  | Terraform 프로젝트의 루트 디렉터리까지의 상대 경로                               |
| `TERRAFORM_MODULE_NAME`    | `${CI_PROJECT_NAME}` | 모듈 이름 공백이나 밑줄을 포함하지 않아야 합니다.                  |
| `TERRAFORM_MODULE_SYSTEM`  | `local`              | 모듈 대상의 시스템 또는 공급자 예: `local`, `aws` 또는 `google` |
| `TERRAFORM_MODULE_VERSION` | `${CI_COMMIT_TAG}`   | 모듈 버전 [시멘틱 버전 관리 사양](https://semver.org/)을 따라야 합니다.          |

### CI/CD 수동 구성 {#configure-cicd-manually}

[GitLab CI/CD](../../../ci/_index.md)에서 Terraform 모듈로 작업하려면 명령에서 개인 액세스 토큰 대신 `CI_JOB_TOKEN`을 사용하세요.

예를 들어 이 작업은 `local` [시스템 공급자](https://registry.terraform.io/browse/providers)에 대한 새 모듈을 업로드하고 Git 커밋 태그에서 모듈 버전을 사용합니다:

```yaml
stages:
  - deploy

upload:
  stage: deploy
  image: curlimages/curl:latest
  variables:
    TERRAFORM_MODULE_DIR: ${CI_PROJECT_DIR}    # The relative path to the root directory of the Terraform project.
    TERRAFORM_MODULE_NAME: ${CI_PROJECT_NAME}  # The name of your Terraform module, must not have any spaces or underscores (will be translated to hyphens).
    TERRAFORM_MODULE_SYSTEM: local             # The system or provider your Terraform module targets (ex. local, aws, google).
    TERRAFORM_MODULE_VERSION: ${CI_COMMIT_TAG} # The version - it's recommended to follow SemVer for Terraform Module Versioning.
  script:
    - TERRAFORM_MODULE_NAME=$(echo "${TERRAFORM_MODULE_NAME}" | tr " _" -) # module-name must not have spaces or underscores, so translate them to hyphens
    - tar -vczf /tmp/${TERRAFORM_MODULE_NAME}-${TERRAFORM_MODULE_SYSTEM}-${TERRAFORM_MODULE_VERSION}.tgz -C ${TERRAFORM_MODULE_DIR} --exclude=./.git .
    - 'curl --fail-with-body --location --header "JOB-TOKEN: ${CI_JOB_TOKEN}"
         --upload-file /tmp/${TERRAFORM_MODULE_NAME}-${TERRAFORM_MODULE_SYSTEM}-${TERRAFORM_MODULE_VERSION}.tgz
         ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/terraform/modules/${TERRAFORM_MODULE_NAME}/${TERRAFORM_MODULE_SYSTEM}/${TERRAFORM_MODULE_VERSION}/file'
  rules:
    - if: $CI_COMMIT_TAG
```

업로드 작업을 트리거하려면 커밋에 Git 태그를 추가하세요. 태그가 Terraform의 필수 [시멘틱 버전 관리 사양](https://semver.org/)을 따르는지 확인하세요. `rules:if: $CI_COMMIT_TAG`은 저장소에 태그가 지정된 커밋만 모듈 업로드 작업을 트리거하도록 합니다.

CI/CD 파이프라인의 작업을 제어하는 다른 방법은 [CI/CD YAML 구문 참조](../../../ci/yaml/_index.md)를 참조하세요.

### 모듈 해석 워크플로 {#module-resolution-workflow}

새 모듈을 업로드하면 GitLab이 모듈의 경로를 생성합니다. 예를 들어:

- `https://gitlab.example.com/parent-group/my-infra-package`

이 경로는 [Terraform 모듈 레지스트리 프로토콜](https://opentofu.org/docs/internals/module-registry-protocol/)을 따릅니다. 여기서:

- `gitlab.example.com`은 호스트명입니다.
- `parent-group`은 Terraform 모듈 레지스트리의 고유한 최상위 [네임스페이스](../../namespace/_index.md)입니다.
- `my-infra-package`은 모듈의 이름입니다.

[중복이 허용되지 않으면](#allow-duplicate-terraform-modules) 모듈 이름과 버전이 `parent-group` 아래의 모든 그룹, 서브그룹 및 프로젝트에서 고유해야 합니다. 그렇지 않으면 다음 오류를 받습니다:

- `{"message":"A module with the same name already exists in the namespace."}`

[중복이 허용되면](#allow-duplicate-terraform-modules) 모듈 해석은 가장 최근에 게시된 모듈을 기반으로 합니다.

예를 들어:

- 프로젝트는 `gitlab.example.com/parent-group/subgroup/my-project`입니다.
- Terraform 모듈은 `my-infra-package`입니다.

중복이 허용되면 `my-infra-package`이 유효한 모듈입니다. 중복이 허용되지 않으면 모듈 이름이 `parent-group` 아래의 모든 그룹에 있는 모든 프로젝트에서 고유해야 합니다.

모듈의 이름을 지정할 때 다음 명명 규칙을 염두에 두세요:

- 프로젝트 및 그룹 이름에는 점(`.`)이 포함되어야 합니다. 예를 들어 `source = "gitlab.example.com/my.group/project.name"`는 유효하지 않습니다.
- 모듈 버전은 [시멘틱 버전 관리 사양](https://semver.org/)을 따라야 합니다.

### 중복 Terraform 모듈 허용 {#allow-duplicate-terraform-modules}

{{< history >}}

- 필수 역할이 [변경됨](https://gitlab.com/gitlab-org/gitlab/-/issues/370471)(GitLab 17.0에서 유지관리자에서 소유자로)

{{< /history >}}

기본적으로 Terraform 모듈 레지스트리는 동일한 네임스페이스의 모듈 이름에 대한 고유성을 적용합니다.

중복 모듈 이름 게시를 허용하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **Terraform 모듈** 행의 **중복 패키지** 표에서 **중복 허용** 토글을 끕니다.
1. 선택 사항. **예외** 텍스트 상자에 모듈 이름과 일치하는 정규 표현식을 입력합니다.

변경 사항이 자동으로 저장됩니다.

> [!note]
> **중복 허용**이 켜져 있으면 **예외** 텍스트 상자에서 중복이 없어야 하는 모듈 이름을 지정할 수 있습니다.

[GraphQL API](../../../api/graphql/reference/_index.md#packagesettings)에서 `terraform_module_duplicates_allowed`을 활성화하여 중복 이름 게시를 허용할 수도 있습니다.

특정 이름으로 중복을 허용하려면:

1. `terraform_module_duplicates_allowed`이 비활성화되어 있는지 확인하세요.
1. `terraform_module_duplicate_exception_regex`을 사용하여 중복을 허용할 모듈 이름의 정규 표현식 패턴을 정의합니다.

최상위 네임스페이스 설정이 자식 네임스페이스 설정보다 우선합니다. 예를 들어 그룹에 대해 `terraform_module_duplicates_allowed`을 활성화하고 서브그룹에 대해 비활성화하면 그룹 및 해당 서브그룹의 모든 프로젝트에서 중복이 허용됩니다.

모듈 해석에 대한 자세한 내용은 [모듈 해석 워크플로](#module-resolution-workflow)를 참조하세요.

## Terraform 모듈 보기 {#view-terraform-modules}

{{< history >}}

- `README` 파일에 대한 지원이 GitLab 17.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/438060)되었습니다.

{{< /history >}}

프로젝트 또는 그룹에서 Terraform 모듈을 보려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **운영** > **Terraform 모듈**을 선택합니다.

이 페이지에서 모듈을 검색, 정렬 및 필터링할 수 있습니다.

모듈의 `README` 파일을 보려면:

1. **Terraform 모듈 레지스트리** 페이지에서 Terraform 모듈을 선택합니다.
1. **`README`**를 선택합니다.

## Terraform 모듈 참조 {#reference-a-terraform-module}

그룹 또는 프로젝트에서 모듈을 참조합니다.

### 네임스페이스에서 {#from-a-namespace}

환경 변수에서 `terraform`에 대한 인증 토큰(작업 토큰, 개인 액세스 토큰 또는 배포 토큰)을 제공할 수 있습니다.

환경 변수의 도메인 이름에 `TF_TOKEN_` 접두사를 추가해야 하며 마침표는 밑줄로 인코딩해야 합니다. 자세한 내용은 [환경 변수 자격 증명](https://opentofu.org/docs/cli/config/config-file/#environment-variable-credentials)을 참조하세요.

예를 들어 `TF_TOKEN_gitlab_com`이라는 변수의 값은 CLI가 `gitlab.com` 호스트명에 서비스 요청을 할 때 배포 토큰으로 사용됩니다:

```shell
export TF_TOKEN_gitlab_com='glpat-<deploy_token>'
```

이 방법은 엔터프라이즈 구현에 권장됩니다. 로컬 또는 임시 환경의 경우 `~/.terraformrc` 또는 `%APPDATA%/terraform.rc` 파일을 만들 수 있습니다:

```terraform
credentials "<gitlab.com>" {
  token = "<TOKEN>"
}
```

`gitlab.com`은 GitLab Self-Managed 인스턴스의 호스트명으로 바뀔 수 있습니다.

그런 다음 다운스트림 Terraform 프로젝트에서 Terraform 모듈을 참조할 수 있습니다:

```terraform
module "<module>" {
  source = "gitlab.com/<namespace>/<module-name>/<module-system>"
}
```

### 프로젝트에서 {#from-a-project}

프로젝트 소스를 사용하여 Terraform 모듈을 참조하려면 Terraform에서 제공하는 [HTTP를 통한 아카이브 가져오기](https://developer.hashicorp.com/terraform/language/modules/sources#fetching-archives-over-http) 소스 유형을 사용하세요.

`terraform` 파일에서 `~/.netrc`에 대한 인증 토큰(작업 토큰, 개인 액세스 토큰 또는 배포 토큰)을 제공할 수 있습니다:

```plaintext
machine <gitlab.com>
login <USERNAME>
password <TOKEN>
```

`gitlab.com`은 GitLab Self-Managed 인스턴스의 호스트명으로 바뀔 수 있으며 `<USERNAME>`은 토큰 사용자명입니다.

다운스트림 Terraform 프로젝트에서 Terraform 모듈을 참조할 수 있습니다:

```terraform
module "<module>" {
  source = "https://gitlab.com/api/v4/projects/<project-id>/packages/terraform/modules/<module-name>/<module-system>/<module-version>"
}
```

모듈의 최신 버전을 참조해야 하는 경우 소스 URL에서 `<module-version>`을 생략할 수 있습니다. 향후 문제를 방지하려면 가능한 경우 특정 버전을 참조해야 합니다.

동일한 네임스페이스에 [중복 모듈 이름](#allow-duplicate-terraform-modules)이 있으면 네임스페이스 수준에서 모듈을 참조하면 최근에 게시된 모듈이 설치됩니다. 중복 모듈의 특정 버전을 참조하려면 [프로젝트 수준](#from-a-project) 소스 유형을 사용하세요.

## Terraform 모듈 다운로드 {#download-a-terraform-module}

Terraform 모듈을 다운로드하려면:

1. 왼쪽 사이드바에서 **운영** > **Terraform 모듈**을 선택합니다.
1. 다운로드할 모듈의 이름을 선택합니다.
1. **자산** 표에서 다운로드할 모듈을 선택합니다.

## Terraform 모듈 삭제 {#delete-a-terraform-module}

Terraform 모듈 레지스트리에 게시한 후에는 Terraform 모듈을 편집할 수 없습니다. 대신 삭제하고 다시 만들어야 합니다.

[패키지 API](../../../api/packages.md#delete-a-project-package) 또는 UI를 사용하여 모듈을 삭제할 수 있습니다.

UI에서 모듈을 삭제하려면 프로젝트에서:

1. 왼쪽 사이드바에서 **운영** > **Terraform 모듈**을 선택합니다.
1. 삭제하려는 패키지의 이름을 찾습니다.
1. **삭제**를 선택합니다.

패키지가 영구적으로 삭제됩니다.

## Terraform 모듈 레지스트리 비활성화 {#disable-the-terraform-module-registry}

Terraform 모듈 레지스트리는 자동으로 활성화됩니다.

GitLab Self-Managed 인스턴스의 경우 GitLab 관리자가 [비활성화](../../../administration/packages/_index.md#enable-or-disable-the-package-registry)할 수 있으며 **패키지 및 레지스트리**가 사이드바에서 제거됩니다.

특정 프로젝트에 대해 Terraform 모듈 레지스트리를 제거할 수도 있습니다:

1. 프로젝트에서 **설정** > **일반**으로 이동합니다.
1. **표시 여부, 프로젝트 기능, 권한** 섹션을 확장하고 **패키지** 토글을 끕니다.
1. **변경 사항 저장**을 선택합니다.

## 예제 프로젝트 {#example-projects}

Terraform 모듈 레지스트리의 예제는 아래 프로젝트를 확인하세요:

- [_GitLab 로컬 파일_ 프로젝트](https://gitlab.com/mattkasa/gitlab-local-file)는 최소한의 Terraform 모듈을 만들고 GitLab CI/CD를 사용하여 Terraform 모듈 레지스트리에 업로드합니다.
- [_Terraform 모듈 테스트_ 프로젝트](https://gitlab.com/mattkasa/terraform-module-test)는 이전 예제의 모듈을 사용합니다.
