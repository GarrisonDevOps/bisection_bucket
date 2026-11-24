---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab 관리형 Terraform/OpenTofu 상태
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 15.7에서 마침표를 포함하는 상태 이름 지원이 [기능 플래그](../../../administration/feature_flags/_index.md)와 함께 도입되었습니다. 이름은 `allow_dots_on_tf_state_names`입니다. 기본적으로 비활성화되었습니다.
- 마침표를 포함하는 상태 이름 지원이 GitLab 16.0에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/385597)되었습니다. 기능 플래그 `allow_dots_on_tf_state_names`이 제거되었습니다.
- GitLab 관리형 OpenTofu 및 Terraform 상태 지원이 GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/cli/-/issues/7954)되었습니다. GitLab CLI(`glab`) 1.66 이상이 필요합니다.

{{< /history >}}

팀 전체에서 인프라 상태 파일을 관리하려면 보안과 안정성이 모두 필요합니다. GitLab 관리형 OpenTofu 상태는 상태 관리의 일반적인 어려움을 제거합니다. 최소한의 구성으로 OpenTofu 상태가 GitLab 프로젝트의 자연스러운 확장이 됩니다. 이 통합을 통해 인프라 정의, 코드 및 상태를 모두 하나의 안전한 위치에 유지할 수 있습니다.

GitLab 관리형 OpenTofu 상태를 사용하면 다음을 수행할 수 있습니다:

- 자동 암호화를 통해 상태 파일을 안전하게 저장합니다.
- 기본 제공 버전 관리를 통해 변경 사항을 추적하여 누가 언제 무엇을 변경했는지 확인합니다.
- 별도의 인증 시스템을 만드는 대신 GitLab 권한 모델을 사용하여 액세스를 제어합니다.
- 상태 파일 충돌이나 손상 없이 팀 전체에서 협업합니다.
- 기존 GitLab CI/CD 파이프라인과 완벽하게 통합됩니다.
- CI/CD 작업과 로컬 개발 환경 모두에서 상태에 원격으로 액세스합니다.

## 재해 복구 고려 사항 {#disaster-recovery-considerations}

OpenTofu 상태 파일은 디스크와 객체 저장소에 저장되어 있을 때 Lockbox Ruby gem으로 암호화됩니다. 암호화는 `db_key_base` 애플리케이션 설정에서 파생된 키를 사용합니다. 이러한 암호화 방식 때문에 상태 파일을 해독하려면 인스턴스를 사용할 수 있어야 합니다.

인스턴스가 오프라인이 되면 상태 파일에 액세스하거나 해독할 수 없습니다. 상태 파일에 GitLab이 실행되는 데 필요한 인프라의 구성이 포함되어 있으면 문제가 됩니다.

GitLab에서 OpenTofu 모듈 또는 자신을 부트스트랩하는 데 필요한 기타 종속성을 호스팅하는 경우, 인스턴스가 오프라인이 되면 이러한 종속성에 액세스할 수 없습니다.

이 문제를 방지하려면:

- 종속성을 별도로 호스팅하거나 백업합니다.
- 공유 장애 지점이 없는 별도의 GitLab 인스턴스를 사용합니다.
- 중요한 부트스트랩 종속성의 대체 호스팅을 고려합니다.

## 사전 요구 사항 {#prerequisites}

GitLab Self-Managed의 경우 OpenTofu 상태 파일에 GitLab을 사용하기 전에:

- 관리자는 [Terraform/OpenTofu 상태 저장소를 설정](../../../administration/terraform_state.md)해야 합니다.
- 프로젝트에 대해 **인프라** 메뉴를 켜야 합니다:
  1. **설정** > **일반**으로 이동합니다.
  1. **표시 여부, 프로젝트 기능, 권한**을 확장합니다.
  1. **인프라** 아래에서 토글을 켭니다.

## 계획 데이터 보안 {#secure-plan-data}

> [!warning]
> OpenTofu `plan.json` 또는 `plan.cache` 파일은 암호화되지 않으며 비밀번호, 액세스 토큰 또는 인증서와 같은 민감한 데이터를 포함할 수 있습니다. 기본적으로 게스트 역할을 가진 사용자는 계획 파일에 액세스할 수 있습니다.

계획 데이터를 보안하려면:

- `access: 'developer'`을 [아티팩트 구성](../../../ci/yaml/_index.md#artifactsaccess)에 설정합니다. 이 설정은 개발자 역할 이상의 사용자에게만 액세스를 제한합니다.
- [공개 파이프라인을 비활성화](../../../ci/pipelines/settings.md#change-pipeline-visibility-for-non-project-members-in-public-projects)합니다.
- 계획 출력을 암호화합니다.
- 프로젝트 가시성을 비공개로 설정합니다.

## GitLab CI/CD를 사용하여 OpenTofu 상태를 백엔드로 초기화 {#initialize-an-opentofu-state-as-a-backend-by-using-gitlab-cicd}

사전 요구 사항:

- `tofu apply`을 사용하여 상태를 잠금, 잠금 해제 및 쓰려면 유지관리자 역할 또는 소유자 역할이 있어야 합니다.
- `tofu plan -lock=false`을 사용하여 상태를 읽으려면 개발자, 유지관리자 또는 소유자 역할이 있어야 합니다.

GitLab CI/CD를 백엔드로 구성하려면:

1. OpenTofu 프로젝트에서 `.tf` 파일(예: `backend.tf`)에서 [HTTP 백엔드](https://opentofu.org/docs/language/settings/backends/http/)를 정의합니다:

   ```hcl
   terraform {
     backend "http" {
     }
   }
   ```

1. 프로젝트 리포지토리의 루트 디렉터리에서 `.gitlab-ci.yml` 파일을 만듭니다. [OpenTofu CI/CD 구성 요소](https://gitlab.com/components/opentofu)를 사용하여 `.gitlab-ci.yml` 파일을 만듭니다.
1. 프로젝트를 GitLab으로 푸시합니다. 이 작업은 파이프라인을 트리거하여 `gitlab-tofu init`, `gitlab-tofu validate` 및 `gitlab-tofu plan` 명령을 실행합니다.
1. 이전 파이프라인에서 수동 `deploy` 작업을 트리거합니다. 이 작업은 `gitlab-tofu apply` 명령을 실행하여 정의된 인프라를 프로비저닝합니다.

이전 명령의 출력은 작업 로그에서 볼 수 있어야 합니다.

`gitlab-tofu` CLI는 `tofu` CLI의 래퍼입니다.

### OpenTofu 환경 변수 사용자 지정 {#customizing-your-opentofu-environment-variables}

CI/CD 작업을 정의할 때 [OpenTofu HTTP 구성 변수](https://opentofu.org/docs/language/settings/backends/http/#configuration-variables)를 사용할 수 있습니다.

`init`을 사용자 지정하고 OpenTofu 구성을 재정의하려면 `init -backend-config=...` 방식 대신 환경 변수를 사용합니다. `-backend-config`을 사용하면 구성은:

- `plan` 명령의 출력에 캐시됩니다.
- 일반적으로 `apply` 명령으로 전달됩니다.

이 구성은 [CI 작업에서 상태 파일을 잠글 수 없음](troubleshooting.md#cant-lock-terraform-state-files-in-ci-jobs-for-terraform-apply-with-a-previous-jobs-plan)과 같은 문제를 야기할 수 있습니다.

#### 계획 파일 이름 사용자 지정 {#customize-the-plan-filename}

기본적으로 `gitlab-tofu plan`(또는 `gitlab-terraform plan`) 명령은 항상 계획 출력을 `plan.cache` 파일로 씁니다.

파일 이름을 변경하려면 CI/CD 파이프라인 구성에서 `TF_PLAN_CACHE` 환경 변수를 설정합니다. 예를 들어 파일 이름을 `my-plan.tfplan`로 설정하려면:

```yaml
variables:
  TF_PLAN_CACHE: "my-plan.tfplan"
```

> [!note]
> `-out=<filename>` 옵션을 전달하여 출력 파일 이름을 설정하지 마세요. GitLab 명령이 이 옵션을 재정의합니다.

## 로컬 머신에서 상태에 액세스 {#access-the-state-from-your-local-machine}

로컬 머신에서 GitLab 관리형 OpenTofu 상태에 액세스할 수 있습니다.

> [!warning]
> GitLab의 클러스터형 배포에서는 로컬 저장소를 사용하면 안 됩니다. 상태 분할이 노드 전체에서 발생하여 후속 OpenTofu 실행이 일관성이 없어질 수 있습니다. 대신 원격 저장소 리소스를 사용합니다.

1. OpenTofu 상태가 [CI/CD에 대해 초기화](#initialize-an-opentofu-state-as-a-backend-by-using-gitlab-cicd)되었는지 확인합니다.
1. 사전 입력된 OpenTofu `init` 명령을 복사합니다:

   1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
   1. **운영** > **Terraform 상태**를 선택합니다.
   1. 사용하려는 환경 옆에서 **조치**({{< icon name="ellipsis_v" >}}) 및 **Terraform init 명령 복사**를 선택합니다.

1. 터미널을 열고 로컬 머신에서 이 명령을 실행합니다.

## GitLab 관리형 OpenTofu 상태로 마이그레이션 {#migrate-to-a-gitlab-managed-opentofu-state}

OpenTofu는 백엔드가 변경되거나 재구성될 때 상태를 복사하도록 지원합니다. 이러한 작업을 사용하여 다른 백엔드에서 GitLab 관리형 OpenTofu 상태로 마이그레이션합니다.

로컬 터미널을 사용하여 GitLab 관리형 OpenTofu 상태로 마이그레이션하는 데 필요한 명령을 실행해야 합니다.

다음 예제는 상태 이름을 변경하는 방법을 보여줍니다. 다른 상태 저장소 백엔드에서 GitLab 관리형 OpenTofu 상태로 마이그레이션하려면 같은 워크플로우가 필요합니다.

이 명령을 [로컬 머신에서](#access-the-state-from-your-local-machine) 실행해야 합니다.

### 초기 백엔드 설정 {#set-up-the-initial-backend}

{{< tabs >}}

{{< tab title="GitLab CLI(glab) 사용" >}}

`glab`로 백엔드를 초기화하려면 다음 명령을 실행합니다:

```shell
glab opentofu init <old_state_name>
```

{{< /tab >}}

{{< tab title="OpenTofu CLI로 수동 작업" >}}

OpenTofu CLI로 백엔드를 초기화하려면 다음 명령을 실행합니다:

```shell
PROJECT_ID="<gitlab-project-id>"
TF_USERNAME="<gitlab-username>"
TF_PASSWORD="<gitlab-personal-access-token>"
TF_ADDRESS="https://gitlab.com/api/v4/projects/${PROJECT_ID}/terraform/state/old-state-name"

tofu init \
  -backend-config=address=${TF_ADDRESS} \
  -backend-config=lock_address=${TF_ADDRESS}/lock \
  -backend-config=unlock_address=${TF_ADDRESS}/lock \
  -backend-config=username=${TF_USERNAME} \
  -backend-config=password=${TF_PASSWORD} \
  -backend-config=lock_method=POST \
  -backend-config=unlock_method=DELETE \
  -backend-config=retry_wait_min=5
```

{{< /tab >}}

{{< /tabs >}}

백엔드가 성공적으로 초기화되면 다음 응답을 받습니다:

```plaintext
Initializing the backend...

Successfully configured the backend "http"! Terraform will automatically
use this backend unless the backend configuration changes.

Initializing provider plugins...

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
re-run this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```

### 백엔드 변경 {#change-the-backend}

`tofu init`이 이전 상태가 있는 위치를 알고 있는 `.terraform/` 디렉터리를 만들었으므로 새 위치에 대해 알려줄 수 있습니다:

{{< tabs >}}

{{< tab title="GitLab CLI(glab) 사용" >}}

```shell
glab opentofu init <new-state-name> -- -migrate-state
```

{{< /tab >}}

{{< tab title="OpenTofu CLI로 수동 작업" >}}

```shell
TF_ADDRESS="https://gitlab.com/api/v4/projects/${PROJECT_ID}/terraform/state/<new-state-name>"

tofu init \
  -migrate-state \
  -backend-config=address=${TF_ADDRESS} \
  -backend-config=lock_address=${TF_ADDRESS}/lock \
  -backend-config=unlock_address=${TF_ADDRESS}/lock \
  -backend-config=username=${TF_USERNAME} \
  -backend-config=password=${TF_PASSWORD} \
  -backend-config=lock_method=POST \
  -backend-config=unlock_method=DELETE \
  -backend-config=retry_wait_min=5
```

{{< /tab >}}

{{< /tabs >}}

백엔드가 성공적으로 초기화되면 다음 응답을 받습니다. `yes`을 입력하면 상태를 이전 위치에서 새 위치로 복사합니다. 그러면 GitLab CI/CD에서 실행으로 돌아갈 수 있습니다:

```plaintext
Initializing the backend...
Backend configuration changed!

Terraform has detected that the configuration specified for the backend
has changed. Terraform will now check for existing state in the backends.


Acquiring state lock. This may take a few moments...
Do you want to copy existing state to the new backend?
  Pre-existing state was found while migrating the previous "http" backend to the
  newly configured "http" backend. No existing state was found in the newly
  configured "http" backend. Do you want to copy this state to the new "http"
  backend? Enter "yes" to copy and "no" to start with an empty state.

  Enter a value: yes


Successfully configured the backend "http"! Terraform will automatically
use this backend unless the backend configuration changes.

Initializing provider plugins...

Terraform has been successfully initialized!

You may now begin working with Terraform. Try running "terraform plan" to see
any changes that are required for your infrastructure. All Terraform commands
should now work.

If you ever set or change modules or backend configuration for Terraform,
rerun this command to reinitialize your working directory. If you forget, other
commands will detect it and remind you to do so if necessary.
```

## GitLab 백엔드를 원격 데이터 소스로 사용 {#use-your-gitlab-backend-as-a-remote-data-source}

GitLab 관리형 OpenTofu 상태 백엔드를 [OpenTofu 데이터 소스](https://opentofu.org/docs/language/state/remote-state-data/)로 사용할 수 있습니다.

1. `main.tf` 또는 다른 관련 파일에서 이 변수를 선언합니다. 값을 비워 둡니다.

   ```hcl
   variable "example_remote_state_address" {
     type = string
     description = "Gitlab remote state file address"
   }

   variable "example_username" {
     type = string
     description = "Gitlab username to query remote state"
   }

   variable "example_access_token" {
     type = string
     description = "GitLab access token to query remote state"
   }
   ```

1. 이전 단계의 값을 재정의하려면 `example.auto.tfvars` 파일을 만듭니다. 이 파일을 프로젝트 리포지토리에 버전 관리하면 안 됩니다.

   ```plaintext
   example_remote_state_address = "https://gitlab.com/api/v4/projects/<TARGET-PROJECT-ID>/terraform/state/<TARGET-STATE-NAME>"
   example_username = "<GitLab username>"
   example_access_token = "<GitLab personal access token>"
   ```

1. `.tf` 파일에서 [OpenTofu 입력 변수](https://opentofu.org/docs/language/values/variables/)를 사용하여 데이터 소스를 정의합니다:

   ```hcl
   data "terraform_remote_state" "example" {
     backend = "http"

     config = {
       address = var.example_remote_state_address
       username = var.example_username
       password = var.example_access_token
     }
   }
   ```

   - **주소**: 데이터 소스로 사용하려는 원격 상태 백엔드의 URL입니다. 예를 들어, `https://gitlab.com/api/v4/projects/<TARGET-PROJECT-ID>/terraform/state/<TARGET-STATE-NAME>`입니다.
   - **사용자명**: 데이터 소스로 인증할 사용자명입니다. [개인 액세스 토큰](../../profile/personal_access_tokens.md)을 인증에 사용하는 경우 이 값은 GitLab 사용자명입니다. GitLab CI/CD를 사용하는 경우 이 값은 `'gitlab-ci-token'`입니다.
   - **암호**: 데이터 소스로 인증할 암호입니다. 개인 액세스 토큰을 인증에 사용하는 경우 이 값은 토큰 값입니다(토큰은 **API** 범위를 가져야 함). GitLab CI/CD를 사용하는 경우 이 값은 `${CI_JOB_TOKEN}` CI/CD 변수의 내용입니다.

데이터 소스의 출력은 이제 `data.terraform_remote_state.example.outputs.<OUTPUT-NAME>`을 사용하여 Terraform 리소스에서 참조할 수 있습니다.

대상 프로젝트에서 OpenTofu 상태를 읽으려면 개발자, 유지관리자 또는 소유자 역할이 필요합니다.

## OpenTofu 상태 파일 관리 {#manage-opentofu-state-files}

OpenTofu 상태 파일을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **운영** > **Terraform 상태**를 선택합니다.

[에픽이 있습니다](https://gitlab.com/groups/gitlab-org/-/epics/4563). 이 UI 개선을 추적합니다.

### 개별 OpenTofu 상태 버전 관리 {#manage-individual-opentofu-state-versions}

GitLab CLI(`glab`) 또는 API를 사용하여 개별 상태 버전을 관리합니다.

사전 요구 사항:

- 일련 번호를 사용하여 상태 버전을 가져오려면 개발자, 유지관리자 또는 소유자 역할이 있어야 합니다.
- 일련 번호를 사용하여 상태 버전을 제거하려면 유지관리자 또는 소유자 역할이 있어야 합니다.

일련 번호를 사용하여 상태 버전을 가져오려면: {{< tabs >}}

{{< tab title="GitLab CLI(glab) 사용" >}}

```shell
glab opentofu state download <your_state_name> <version_serial_number>
```

{{< /tab >}}

{{< tab title="curl을 사용하여 수동 작업" >}}

```shell
curl --header "PRIVATE-TOKEN: <your_access_token>" \
     --url "https://gitlab.example.com/api/v4/projects/<your_project_id>/terraform/state/<your_state_name>/versions/<version_serial_number>"
```

{{< /tab >}}

{{< /tabs >}}

일련 번호를 사용하여 상태 버전을 제거하려면:

{{< tabs >}}

{{< tab title="GitLab CLI(glab) 사용" >}}

```shell
glab opentofu state delete <your_state_name> <version_serial_number>
```

{{< /tab >}}

{{< tab title="curl을 사용하여 수동 작업" >}}

```shell
curl --request DELETE --header "PRIVATE-TOKEN: <your_access_token>" \
     --url "https://gitlab.example.com/api/v4/projects/<your_project_id>/terraform/state/<your_state_name>/versions/<version_serial_number>"
```

{{< /tab >}}

{{< /tabs >}}

### 상태 파일 제거 {#remove-a-state-file}

사전 요구 사항:

- 상태 파일을 제거하려면 유지관리자 또는 소유자 역할이 있어야 합니다.

{{< tabs >}}

{{< tab title="GitLab CLI(glab) 사용" >}}

```shell
glab opentofu state delete <your_state_name>
```

{{< /tab >}}

{{< tab title="curl을 사용하여 수동 작업" >}}

```shell
curl --request DELETE --header "PRIVATE-TOKEN: <your_access_token>" \
     --url "https://gitlab.example.com/api/v4/projects/<your_project_id>/terraform/state/<your_state_name>"
```

[CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md)과 기본 인증을 사용할 수도 있습니다:

```shell
curl --request DELETE --user "gitlab-ci-token:$CI_JOB_TOKEN" \
     --url "https://gitlab.example.com/api/v4/projects/<your_project_id>/terraform/state/<your_state_name>"
```

[GraphQL API](../../../api/graphql/reference/_index.md#mutationterraformstatedelete)를 사용할 수도 있습니다.

{{< /tab >}}

{{< tab title="UI 사용" >}}

UI를 사용하여 상태 파일을 제거하려면:

1. 왼쪽 사이드바에서 **운영** > **Terraform 상태**를 선택합니다.
1. **조치** 열에서 **조치**({{< icon name="ellipsis_v" >}}) > **상태 파일 및 버전 제거**를 선택합니다.

{{< /tab >}}

{{< /tabs >}}

### 상태 잠금 및 잠금 해제 {#lock-and-unlock-a-state}

사전 요구 사항:

- 상태 파일을 잠금 상태로 유지하려면 유지관리자 또는 소유자 역할이 있어야 합니다.

{{< tabs >}}

{{< tab title="GitLab CLI(glab) 사용" >}}

```shell
# Lock a state file
glab opentofu state lock <your_state_name>

# Unlock a state file
glab opentofu state unlock <your_state_name>
```

{{< /tab >}}

{{< tab title="curl을 사용하여 수동 작업" >}}

```shell
# Lock a state file
curl --request POST --header "PRIVATE-TOKEN: <your_access_token>" \
     --url "https://gitlab.example.com/api/v4/projects/<your_project_id>/terraform/state/<your_state_name>/lock"

# Unlock a state file
curl --request DELETE --header "PRIVATE-TOKEN: <your_access_token>" \
     --url "https://gitlab.example.com/api/v4/projects/<your_project_id>/terraform/state/<your_state_name>/lock"
```

{{< /tab >}}

{{< tab title="UI 사용" >}}

UI를 사용하여 상태 파일을 잠금 또는 잠금 해제하려면:

1. 왼쪽 사이드바에서 **운영** > **Terraform 상태**를 선택합니다.
1. **조치** 열에서 **조치**({{< icon name="ellipsis_v" >}}) > **잠금**을 선택하여 잠금을 하거나 **조치**({{< icon name="ellipsis_v" >}}) > **잠금 해제**를 선택합니다.

{{< /tab >}}

{{< /tabs >}}

### 상태 파일 다운로드 {#download-a-state-file}

사전 요구 사항:

- 상태 파일을 다운로드하려면 개발자, 유지관리자 또는 소유자 역할이 있어야 합니다.

{{< tabs >}}

{{< tab title="GitLab CLI(glab) 사용" >}}

```shell
# Download the latest state
glab opentofu state download <your_state_name>

# Download a specific version (serial) of a state
glab opentofu state download <your_state_name> <your_serial>
```

{{< /tab >}}

{{< tab title="curl을 사용하여 수동 작업" >}}

```shell
# Download the latest state
curl --header "PRIVATE-TOKEN: <your_access_token>" \
     --url "https://gitlab.example.com/api/v4/projects/<your_project_id>/terraform/state/<your_state_name>"

# Download a specific version (serial) of a state
curl --header "PRIVATE-TOKEN: <your_access_token>" \
     --url "https://gitlab.example.com/api/v4/projects/<your_project_id>/terraform/state/<your_state_name>/versions/<version_serial_number>"
```

{{< /tab >}}

{{< tab title="UI 사용" >}}

UI를 사용하여 최신 상태 파일을 다운로드하려면:

1. 왼쪽 사이드바에서 **운영** > **Terraform 상태**를 선택합니다.
1. **조치** 열에서 **조치**({{< icon name="ellipsis_v" >}}) > **JSON 다운로드**를 선택합니다.

UI를 사용하여 특정 버전의 상태를 다운로드할 수 있는 방법이 없습니다.

{{< /tab >}}

{{< /tabs >}}

#### Terraform 상태 파일의 민감한 데이터 보호 {#protect-sensitive-data-in-terraform-state-files}

Terraform 상태 파일에는 비밀번호, 개인 키, API 토큰 및 데이터베이스 연결 문자열과 같은 민감한 정보가 포함될 수 있습니다. GitLab에서 개발자 역할 이상을 가진 모든 사용자는 멤버인 프로젝트의 Terraform 상태 파일을 다운로드하고 볼 수 있습니다.

민감한 데이터 노출을 줄이려면:

- GitLab Ultimate 고객: 개발자 역할을 복제하지만 `admin_terraform_state` 권한을 제외하는 사용자 지정 역할을 만듭니다. 이 작업을 통해 팀 멤버가 민감한 데이터가 포함된 Terraform 상태 파일에 액세스하지 않고 인프라 기반 코드(IaC) 프로젝트에 기여할 수 있습니다.

  > [!note]
  > 사용자 지정 역할은 GitLab Ultimate에서만 사용할 수 있습니다. Premium 또는 낮은 티어의 고객은 이 완화 옵션에 액세스할 수 없으며 이전에 설명한 다른 전략에 중점을 두어야 합니다.

- OpenTofu 사용자: 상태 및 계획 암호화를 켜서 민감한 데이터를 보호합니다. GitLab은 [OpenTofu CI/CD 구성 요소](https://gitlab.com/components/opentofu)를 통해 이를 기본적으로 지원하며, 암호화 구성을 제공합니다. 권한이 없는 사용자가 상태 파일에 액세스하더라도 암호화된 내용은 보호됩니다.
- 모든 사용자:
  - 인프라 상태에 액세스해야 하는 사용자에게만 프로젝트 멤버십을 제한합니다.
  - 상태를 저장할 별도의 프로젝트를 사용하여 필요한 사용자만 멤버로 추가합니다.
  - HashiCorp Vault 또는 AWS Secrets Manager와 같은 외부 비밀 관리 솔루션을 사용하여 Terraform 구성에 저장하는 대신 비밀을 동적으로 참조합니다.
  - Terraform [`sensitive`](https://developer.hashicorp.com/terraform/language/values/variables#suppressing-values-in-cli-output) 매개변수를 사용하여 변수 정의에 민감한 값을 표시합니다. 이 작업은 값이 CLI 출력과 계획 파일에 나타나는 것을 방지하지만 상태 파일에는 남아 있습니다.
  - 개발자 역할을 가진 프로젝트 멤버를 정기적으로 감사하고 실수로 노출된 비밀이 있는지 상태 파일 내용을 검토합니다.

## 관련 항목 {#related-topics}

- [GitLab 관리형 Terraform 상태 문제 해결](troubleshooting.md)
- [샘플 프로젝트: 사용자 지정 VPC의 AWS EC2 인스턴스 Terraform 배포](https://gitlab.com/gitlab-org/ci-cd/deploy-stage/environments-group/examples/gitlab-terraform-aws)
