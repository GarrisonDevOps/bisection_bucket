---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Terraform과 GitLab 통합 문제 해결
---

Terraform과 GitLab의 통합을 사용할 때 문제를 해결해야 할 수 있습니다.

## `gitlab_group_share_group` 리소스가 서브그룹 상태를 새로 고칠 때 감지되지 않음 {#gitlab_group_share_group-resources-not-detected-when-subgroup-state-is-refreshed}

GitLab Terraform 공급자는 `gitlab_group_share_group` 리소스를 감지하지 못할 수 있습니다. 이는 ["사용자가 API에서 `share_with_groups`를 검색할 수 없음"](https://gitlab.com/gitlab-org/gitlab/-/issues/328428) 문제 때문입니다. 이로 인해 `terraform apply`를 실행할 때 오류가 발생합니다. Terraform이 기존 리소스를 다시 생성하려고 시도하기 때문입니다.

예를 들어 다음과 같은 그룹/서브그룹 구성을 생각해 봅시다:

```plaintext
parent-group
├── subgroup-A
└── subgroup-B
```

위치:

- 사용자 `user-1`은 `parent-group`, `subgroup-A`, `subgroup-B`를 생성합니다.
- `subgroup-A`은 `subgroup-B`와 공유됩니다.
- 사용자 `terraform-user`은 `parent-group`의 멤버이며 두 서브그룹에 대해 상속된 `owner` 액세스 권한을 가집니다.

Terraform 상태를 새로 고칠 때 공급자가 발행한 API 쿼리 `GET /groups/:subgroup-A_id`은 `shared_with_groups` 배열에서 `subgroup-B`의 세부 정보를 반환하지 않습니다. 이로 인해 오류가 발생합니다.

이 문제를 해결하려면 다음 조건 중 하나를 적용해야 합니다:

1. `terraform-user`은 모든 서브그룹 리소스를 생성합니다.
1. `terraform-user` 사용자에게 `subgroup-B`에 대한 유지 관리자 또는 소유자 역할을 부여합니다.
1. `terraform-user`이 `subgroup-B`에 대해 상속된 액세스 권한을 가지고 있으며 `subgroup-B`에 최소한 하나의 프로젝트가 있습니다.

## Terraform 상태 문제 해결 {#troubleshooting-terraform-state}

### CI 작업에서 `terraform apply`에 대한 Terraform 상태 파일을 잠글 수 없음(이전 작업의 계획 포함) {#cant-lock-terraform-state-files-in-ci-jobs-for-terraform-apply-with-a-previous-jobs-plan}

`-backend-config=`을 `terraform init`에 전달할 때 Terraform은 이러한 값을 계획 캐시 파일 내에 유지합니다. 여기에는 `password` 값이 포함됩니다.

따라서 계획을 만들고 나중에 다른 CI 작업에서 동일한 계획을 사용하려고 할 때 `-backend-config=password=$CI_JOB_TOKEN`를 사용할 때 `Error: Error acquiring the state lock` 오류가 발생할 수 있습니다. 이는 `$CI_JOB_TOKEN`의 값이 현재 작업의 기간 동안만 유효하기 때문에 발생합니다.

해결 방법으로 CI 작업에서 [HTTP 백엔드 구성 변수](https://www.terraform.io/language/settings/backends/http#configuration-variables)를 사용합니다. 이는 [GitLab CI 시작하기](terraform_state.md#initialize-an-opentofu-state-as-a-backend-by-using-gitlab-cicd) 지침을 따를 때 백그라운드에서 발생하는 작업입니다.

### 오류: `"address": required field is not set` {#error-address-required-field-is-not-set}

기본적으로 GitLab은 `TF_ADDRESS`을 `${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/terraform/state/${TF_STATE_NAME}`로 설정합니다. 작업에서 `TF_STATE_NAME` 또는 `TF_ADDRESS`를 설정하지 않으면 작업이 `Error: "address": required field is not set` 오류 메시지와 함께 실패합니다.

이를 해결하려면 오류를 반환한 작업에서 `TF_ADDRESS` 또는 `TF_STATE_NAME`가 액세스 가능한지 확인합니다:

1. 작업에 대해 [CI/CD 환경 범위](../../../ci/variables/_index.md#for-a-project)를 구성합니다.
1. 작업의 [환경](../../../ci/yaml/_index.md#environment)을 설정하고 이전 단계의 환경 범위와 일치시킵니다.

### 상태 새로 고침 오류: HTTP 원격 상태 끝점에 인증 필요 {#error-refreshing-state-http-remote-state-endpoint-requires-auth}

이를 해결하려면 다음을 확인합니다:

- 사용하는 액세스 토큰에 `api` 범위가 있습니다.
- `TF_HTTP_PASSWORD` CI/CD 변수를 설정한 경우 다음 중 하나를 확인합니다:
  - `TF_PASSWORD`과 동일한 값으로 설정합니다.
  - CI/CD 작업에서 명시적으로 사용하지 않으면 `TF_HTTP_PASSWORD` 변수를 제거합니다.

### 개발자 역할 액세스를 파괴적 명령으로 활성화 {#enable-developer-role-access-to-destructive-commands}

개발자 역할을 가진 사용자가 파괴적 명령을 실행할 수 있도록 허용하려면 다음 해결 방법이 필요합니다:

1. [프로젝트 액세스 토큰을 생성](../../project/settings/project_access_tokens.md#create-a-project-access-token)하고 `api` 범위를 사용합니다.
1. CI/CD 변수에 `TF_USERNAME`과 `TF_PASSWORD`를 추가합니다:
   1. `TF_USERNAME`의 값을 프로젝트 액세스 토큰의 사용자 이름으로 설정합니다.
   1. `TF_PASSWORD`의 값을 프로젝트 액세스 토큰의 암호로 설정합니다.
   1. 선택 사항. 변수를 보호하여 보호된 브랜치 또는 보호된 태그에서 실행되는 파이프라인에서만 사용 가능하도록 합니다.

### 상태 이름에 마침표가 포함된 경우 상태를 찾을 수 없음 {#state-not-found-if-the-state-name-contains-a-period}

GitLab 15.6 이전 버전에서는 상태 이름에 마침표가 포함되어 있고 Terraform이 상태 잠금을 시도한 경우 404 오류를 반환했습니다.

Terraform 명령에 `-lock=false`을 추가하여 이 제한을 해결할 수 있습니다. GitLab 백엔드는 요청을 수락했지만 내부적으로 마침표와 상태 이름에서 뒤따르는 모든 문자를 제거했습니다. 예를 들어 `foo.bar` 이름의 상태는 `foo`로 저장됩니다. 그러나 이 해결 방법은 권장되지 않았으며 상태 이름 충돌을 유발할 수도 있습니다.

GitLab 15.7 이후 버전에서는 [마침표가 있는 상태 이름이 지원됩니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/106861). `-lock=false` 해결 방법을 사용하고 GitLab 15.7 이후 버전으로 업그레이드하면 작업이 실패할 수 있습니다. 이 실패는 GitLab 백엔드가 전체 상태 이름으로 새 상태를 저장하는 것으로 인해 발생하며, 이는 기존 상태 이름과 다릅니다.

실패한 작업을 해결하려면 상태 이름을 마침표 및 뒤따르는 모든 문자를 제외하도록 이름을 변경합니다.

`TF_HTTP_ADDRESS`, `TF_HTTP_LOCK_ADDRESS`, `TF_HTTP_UNLOCK_ADDRESS`이 설정되어 있으면 해당 위치의 상태 이름을 업데이트해야 합니다.

또는 [OpenTofu 상태를 마이그레이션](terraform_state.md#migrate-to-a-gitlab-managed-opentofu-state)할 수 있습니다.

### 상태 저장 오류: HTTP 오류: 404 {#error-saving-state-http-error-404}

이 오류는 상태 이름에 슬래시(`/`) 문자가 포함된 경우 발생할 수 있습니다. 이를 해결하려면 상태 이름에 슬래시(`/`) 문자가 포함되지 않도록 합니다.
