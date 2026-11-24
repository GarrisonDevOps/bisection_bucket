---
stage: Tutorials
group: Tutorials
info: For assistance with this tutorial, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
title: '자습서: 러너 생성 및 등록 자동화'
---

이 튜토리얼에서는 러너 생성 및 등록을 자동화하는 방법을 설명합니다.

러너 생성 및 등록을 자동화하려면:

1. [개인 액세스 토큰 생성](#create-a-personal-access-token).
1. [러너 구성 생성](#create-a-runner-configuration).
1. [GitLab Runner 설치 및 등록 자동화](#automate-runner-installation-and-registration).
1. [동일한 구성의 러너 보기](#view-runners-with-the-same-configuration).

> [!note]
> 이 튜토리얼의 지침에서는 더 이상 사용되지 않는 등록 토큰을 사용하는 등록 방법을 대체한 러너 인증 토큰을 사용한 러너 생성 및 등록을 설명합니다. 자세한 내용은 [새로운 러너 등록 워크플로](../../ci/runners/new_creation_workflow.md#the-new-runner-registration-workflow)를 참조하세요.

## 시작하기 전에 {#before-you-begin}

- GitLab Runner는 GitLab 인스턴스에 설치되어야 합니다.
- 인스턴스 러너를 생성하려면 관리자여야 합니다.
- 그룹 러너를 생성하려면 관리자이거나 그룹에 대한 소유자 역할이 있어야 합니다.
- 프로젝트 러너를 생성하려면 관리자이거나 프로젝트에 대한 유지관리자 역할이 있어야 합니다.

## 액세스 토큰 생성 {#create-an-access-token}

REST API를 사용하여 러너를 생성할 수 있도록 액세스 토큰을 생성합니다.

다음을 생성할 수 있습니다:

- 공유, 그룹 및 프로젝트 러너에 사용할 개인 액세스 토큰입니다.
- 그룹 및 프로젝트 러너에 사용할 그룹 또는 프로젝트 액세스 토큰입니다.

액세스 토큰은 GitLab UI에서 한 번만 표시됩니다. 페이지를 나간 후에는 토큰에 더 이상 액세스할 수 없습니다. HashiCorp Vault 또는 Keeper Secrets Manager Terraform 플러그인과 같은 시크릿 관리 솔루션을 사용하여 토큰을 저장해야 합니다.

### 개인 액세스 토큰 생성 {#create-a-personal-access-token}

{{< history >}}

- GitLab 17.6에서 `buffered_token_expiration_limit`라는 [기능 플래그](../../administration/feature_flags/_index.md)로 최대 허용 수명 제한을 400일로 증가된 값으로 [변경했습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/461901). 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 확장된 최대 허용 수명 제한의 사용 가능성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **개인 액세스 토큰**을 선택합니다.
1. **새 토큰 추가**를 선택합니다.
1. 토큰의 이름과 만료 날짜를 입력합니다.
   - 토큰은 해당 날짜의 자정 UTC에 만료됩니다. 만료 날짜가 2024-01-01인 토큰은 2024-01-01 00:00:00 UTC에 만료됩니다.
   - 만료 날짜를 입력하지 않으면 만료 날짜가 현재 날짜보다 365일 뒤로 자동으로 설정됩니다.
   - 기본적으로 이 날짜는 현재 날짜보다 최대 365일 뒤일 수 있습니다. GitLab 17.6 이상에서는 [이 제한을 400일로 연장](https://gitlab.com/gitlab-org/gitlab/-/issues/461901)할 수 있습니다.
1. **범위 선택** 섹션에서 **create_runner** 확인란을 선택합니다.
1. **개인 액세스 토큰 생성**을 선택합니다.

### 프로젝트 또는 그룹 액세스 토큰 생성 {#create-a-project-or-group-access-token}

{{< history >}}

- GitLab 17.6에서 `buffered_token_expiration_limit`라는 [기능 플래그](../../administration/feature_flags/_index.md)로 최대 허용 수명 제한을 400일로 증가된 값으로 [변경했습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/461901). 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 확장된 최대 허용 수명 제한의 사용 가능성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.

프로젝트 액세스 토큰은 하나의 프로젝트에만 액세스할 수 있는 반면 그룹 액세스 토큰은 그룹의 모든 프로젝트에 액세스합니다.

> [!warning]
> 프로젝트 액세스 토큰은 [내부 사용자](../../administration/internal_users.md)로 처리됩니다. 내부 사용자가 프로젝트 액세스 토큰을 생성하면 해당 토큰은 표시 수준이 [내부](../../user/public_access.md)로 설정된 모든 프로젝트에 액세스할 수 있습니다.

프로젝트 액세스 토큰을 생성하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **액세스 토큰**을 선택합니다.
1. **새 토큰 추가**를 선택합니다
1. 이름을 입력합니다. 토큰 이름은 그룹 또는 프로젝트를 볼 수 있는 권한이 있는 모든 사용자에게 표시됩니다.
1. 토큰의 만료 날짜를 입력합니다.
   - 토큰은 해당 날짜의 자정 UTC에 만료됩니다. 만료 날짜가 2024-01-01인 토큰은 2024-01-01 00:00:00 UTC에 만료됩니다.
   - 만료 날짜를 입력하지 않으면 만료 날짜가 현재 날짜보다 365일 뒤로 자동으로 설정됩니다.
   - 기본적으로 이 날짜는 현재 날짜보다 최대 365일 뒤일 수 있습니다. GitLab 17.6 이상에서는 [이 제한을 400일로 연장](https://gitlab.com/gitlab-org/gitlab/-/issues/461901)할 수 있습니다.
   - 인스턴스 전체 [최대 수명](../../administration/settings/account_and_limit_settings.md#limit-the-lifetime-of-access-tokens) 설정은 GitLab Self-Managed 인스턴스에서 최대 허용 수명을 제한할 수 있습니다.
1. **역할 선택** 드롭다운 목록에서:
   - 프로젝트 액세스 토큰의 경우 **유지관리자**를 선택합니다.
   - 그룹 액세스 토큰의 경우 **소유자**를 선택합니다.
1. **범위 선택** 섹션에서 **create_runner** 확인란을 선택합니다.
1. **프로젝트 액세스 토큰 생성**을 선택합니다.

## 러너 구성 생성 {#create-a-runner-configuration}

러너 구성은 러너를 요구 사항에 맞게 구성하는 위치입니다.

러너 구성을 생성한 후 러너를 등록하기 위한 러너 인증을 받습니다. 하나 이상의 러너는 같은 러너 인증 토큰으로 등록된 경우 동일한 구성에 연결될 수 있습니다. 러너 구성은 `config.toml` 파일에 저장됩니다.

러너 구성을 생성하려면 다음을 사용할 수 있습니다:

- GitLab REST API.
- `gitlab_user_runner` Terraform 리소스.

### GitLab REST API 사용 {#with-the-gitlab-rest-api}

시작하기 전에 다음이 필요합니다:

- GitLab 인스턴스의 URL입니다. 예를 들어 프로젝트가 `gitlab.example.com/yourname/yourproject`에서 호스팅되는 경우 GitLab 인스턴스 URL은 `https://gitlab.example.com`입니다.
- 그룹 또는 프로젝트 러너의 경우 그룹 또는 프로젝트의 ID 번호입니다. ID 번호는 프로젝트 또는 그룹 개요 페이지에서 프로젝트 또는 그룹 이름 아래에 표시됩니다.

[`POST /user/runners`](../../api/users.md#create-a-runner-linked-to-a-user) REST 엔드포인트에서 액세스 토큰을 사용하여 러너를 생성합니다:

1. `curl`을 사용하여 엔드포인트를 호출하여 러너를 생성합니다:

   {{< tabs >}}

   {{< tab title="프로젝트" >}}

   ```shell
   curl --silent --request POST --url "https://gitlab.example.com/api/v4/user/runners"
     --data "runner_type=project_type"
     --data "project_id=<project_id>"
     --data "description=<your_runner_description>"
     --data "tag_list=<your_comma_separated_job_tags>"
     --header "PRIVATE-TOKEN: <project_access_token>"
   ```

   {{< /tab >}}

   {{< tab title="그룹" >}}

   ```shell
   curl --silent --request POST --url "https://gitlab.example.com/api/v4/user/runners"
     --data "runner_type=group_type"
     --data "group_id=<group_id>"
     --data "description=<your_runner_description>"
     --data "tag_list=<your_comma_separated_job_tags>"
     --header "PRIVATE-TOKEN: <group_access_token>"
   ```

   {{< /tab >}}

   {{< tab title="공유" >}}

   ```shell
   curl --silent --request POST --url "https://gitlab.example.com/api/v4/user/runners"
     --data "runner_type=instance_type"
     --data "description=<your_runner_description>"
     --data "tag_list=<your_comma_separated_job_tags>"
     --header "PRIVATE-TOKEN: <personal_access_token>"
   ```

   {{< /tab >}}

   {{< /tabs >}}
1. 반환된 `token` 값을 안전한 위치나 시크릿 관리 솔루션에 저장합니다. `token` 값은 API 응답에서 한 번만 반환됩니다.

### `gitlab_user_runner` Terraform 리소스 사용 {#with-the-gitlab_user_runner-terraform-resource}

Terraform을 사용하여 러너 구성을 생성하려면 [`gitlab_user_runner` Terraform 리소스](https://gitlab.com/gitlab-org/terraform-provider-gitlab/-/blob/main/docs/resources/user_runner.md?ref_type=heads)를 [GitLab Terraform 공급자](https://gitlab.com/gitlab-org/terraform-provider-gitlab)에서 사용합니다.

다음은 구성 블록의 예입니다:

```terraform
resource "gitlab_user_runner" "example_runner" {
  runner_type = "instance_type"
  description = "my-runner"
  tag_list = ["shell", "docker"]
}
```

## 러너 설치 및 등록 자동화 {#automate-runner-installation-and-registration}

공용 클라우드의 가상 머신 인스턴스에서 러너를 호스팅하는 경우 러너 설치 및 등록을 자동화할 수 있습니다.

러너 및 구성을 생성한 후 동일한 러너 인증 토큰을 사용하여 여러 러너를 동일한 구성으로 등록할 수 있습니다. 예를 들어 동일한 실행기 유형 및 작업 태그를 가진 여러 인스턴스 러너를 대상 컴퓨팅 호스트에 배포할 수 있습니다. 동일한 러너 인증 토큰으로 등록된 각 러너는 GitLab Runner가 임의로 생성하고 로컬 파일 시스템에 저장하는 고유한 `system_id`을 갖습니다.

다음은 Google Compute Engine에 러너를 등록하고 배포하는 데 사용할 수 있는 자동화 워크플로의 예입니다:

1. [Terraform 코드 기반 인프라](../../user/infrastructure/iac/_index.md)를 사용하여 Google Cloud Platform(GCP)에서 호스팅되는 가상 머신에 러너 애플리케이션을 설치합니다.
1. [GCP Terraform 공급자](https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/compute_instance)에서 `metadata` 키를 사용하여 GCP 가상 머신의 러너 구성 파일에 러너 인증 토큰을 추가합니다.
1. 대상 GitLab 인스턴스에 러너를 등록하려면 GCP Terraform 공급자에서 채워진 `cloud-init` 스크립트를 사용합니다. 다음은 예입니다:

   ```shell
   #!/bin/bash
   apt update
   curl --location "https://packages.gitlab.com/install/repositories/runner/
   gitlab-runner/script.deb.sh" | bash
   GL_NAME=$(curl 169.254.169.254/computeMetadata/v1/instance/name
   --header "Metadata-Flavor:Google")
   GL_EXECUTOR=$(curl 169.254.169.254/computeMetadata/v1/instance/attributes/
   gl_executor --header "Metadata-Flavor:Google")
   apt update
   apt install -y gitlab-runner
   gitlab-runner register --non-interactive --name="$GL_NAME" --url="https://gitlab.com"
     --token="$RUNNER_TOKEN" --request-concurrency="12" --executor="$GL_EXECUTOR"
     --docker-image="alpine:latest"
   systemctl restart gitlab-runner
   ```

## 동일한 구성의 러너 보기 {#view-runners-with-the-same-configuration}

러너 생성 및 등록을 자동화했으므로 이제 GitLab UI에서 동일한 구성을 사용하는 러너를 볼 수 있습니다.

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **CI/CD** > **러너**를 선택합니다.
1. 검색 상자에 러너 설명을 입력하거나 러너 목록을 검색합니다.
1. 동일한 구성을 사용하는 러너를 보려면 **상세정보** 탭의 **러너** 옆에서 **세부 정보 보기**를 선택합니다.
