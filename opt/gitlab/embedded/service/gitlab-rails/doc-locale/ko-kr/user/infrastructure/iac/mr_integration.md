---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 병합 요청에서의 OpenTofu 통합
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

코드 기반 인프라(IaC) 변경 사항 주변에서 협업하려면 코드 변경 사항과 예상되는 인프라 변경 사항이 모두 확인되고 승인되어야 합니다. GitLab은 병합 요청 페이지를 사용하여 OpenTofu 코드 변경 사항 및 예상되는 영향에 대한 협업을 돕기 위한 솔루션을 제공합니다. 이렇게 하면 사용자가 사용자 정의 도구를 구축하거나 타사 솔루션에 의존하여 IaC 워크플로우를 간소화할 필요가 없습니다.

## 병합 요청에 OpenTofu 플랜 정보 출력 {#output-opentofu-plan-information-into-a-merge-request}

[GitLab Terraform/OpenTofu Report 아티팩트](../../../ci/yaml/artifacts_reports.md#artifactsreportsterraform)를 사용하여 `tofu plan` 실행에서 병합 요청 위젯으로 직접 세부 정보를 노출할 수 있으며, OpenTofu가 생성, 수정 또는 삭제하는 리소스에 대한 통계를 볼 수 있습니다.

> [!warning]
> 다른 작업 아티팩트처럼 OpenTofu 플랜 데이터는 리포지토리의 게스트 역할을 가진 모든 사람이 볼 수 있습니다. OpenTofu와 GitLab 모두 기본적으로 플랜 파일을 암호화하지 않습니다. OpenTofu `plan.json` 또는 `plan.cache` 파일에 비밀번호, 액세스 토큰 또는 인증서와 같은 민감한 데이터가 포함되어 있으면 플랜 출력을 암호화하거나 프로젝트 가시성 설정을 수정해야 합니다. [공개 파이프라인](../../../ci/pipelines/settings.md#change-pipeline-visibility-for-non-project-members-in-public-projects)을 비활성화하고 [아티팩트의 공개 플래그를 거짓으로 설정](../../../ci/yaml/_index.md#artifactspublic)(`public: false`)해야 합니다. 이 설정은 아티팩트가 GitLab 관리자 및 Reporter, Developer, Maintainer 또는 Owner 역할을 가진 프로젝트 구성원에게만 액세스할 수 있도록 합니다.

## OpenTofu 보고서 아티팩트 구성 {#configure-opentofu-report-artifacts}

GitLab [OpenTofu와 통합](_index.md#quickstart-an-opentofu-project-in-pipelines)되어 있으며 OpenTofu CI/CD 구성 요소를 통해 통합됩니다. 이 구성 요소는 GitLab에서 관리하는 OpenTofu 상태를 사용하여 병합 요청에 OpenTofu 변경 사항을 표시합니다.

### OpenTofu 보고서 아티팩트 자동 구성 {#automatically-configure-opentofu-report-artifacts}

[OpenTofu CI/CD 구성 요소](https://gitlab.com/components/opentofu)를 사용해야 하며, 이는 `plan` 작업에서 OpenTofu 보고서 아티팩트를 자동으로 구성합니다.

### OpenTofu 보고서 아티팩트 수동 구성 {#manually-configure-opentofu-report-artifacts}

빠른 설정을 위해 미리 빌드된 이미지를 사용자 정의하고 `gitlab-tofu` 헬퍼에 의존해야 합니다.

GitLab OpenTofu Report 아티팩트를 수동으로 구성하려면:

1. 이 파일들을 여러 번 참조하도록 재사용 가능한 변수를 정의합니다:

   ```yaml
   variables:
     PLAN: plan.cache
     PLAN_JSON: plan.json
   ```

1. `jq`을(를) 설치하고, 이는 [가볍고 유연한 명령줄 JSON 프로세서](https://stedolan.github.io/jq/)입니다.
1. `tofu plan` 출력에서 추출하려는 정보를 구문 분석하는 특정 `jq` 명령에 대한 별칭을 만듭니다:

   ```yaml
   before_script:
     - apk --no-cache add jq
     - alias convert_report="jq -r '([.resource_changes[]?.change.actions?]|flatten)|{\"create\":(map(select(.==\"create\"))|length),\"update\":(map(select(.==\"update\"))|length),\"delete\":(map(select(.==\"delete\"))|length)}'"
   ```

   > [!note]
   > Bash(예: Ubuntu)를 사용하는 배포판에서는 `alias` 문이 대화형 모드가 아닌 모드에서 확장되지 않습니다. 파이프라인이 오류 `convert_report: command not found`로 인해 실패하면 스크립트에 `shopt` 명령을 추가하여 별칭 확장을 명시적으로 활성화할 수 있습니다:

   ```yaml
   before_script:
     - shopt -s expand_aliases
     - alias convert_report="jq -r '([.resource_changes[]?.change.actions?]|flatten)|{\"create\":(map(select(.==\"create\"))|length),\"update\":(map(select(.==\"update\"))|length),\"delete\":(map(select(.==\"delete\"))|length)}'"
   ```

1. `tofu plan` 및 `tofu show`을(를) 실행하는 `script`을(를) 정의합니다. 이 명령은 출력을 파이프하고 관련 비트를 저장 변수 `PLAN_JSON`로 변환합니다. 이 JSON은 [GitLab OpenTofu Report 아티팩트](../../../ci/yaml/artifacts_reports.md#artifactsreportsterraform)를 만드는 데 사용됩니다. OpenTofu 보고서는 OpenTofu `tfplan.json` 파일을 획득합니다. 수집된 OpenTofu 플랜 보고서가 아티팩트로 GitLab에 업로드되고 병합 요청에 표시됩니다.

   ```yaml
   plan:
     stage: build
     script:
       - terraform plan -out=$PLAN
       - terraform show -json $PLAN | convert_report > $PLAN_JSON
     artifacts:
       reports:
         terraform: $PLAN_JSON
   ```

1. 파이프라인을 실행하여 병합 요청에 위젯을 표시합니다. 다음과 같습니다:

   ![병합 요청 Terraform 위젯](img/terraform_plan_widget_v13_2.png)

   > [!note]
   > 위젯에서 보고하는 최대 변경 수는 각 작업에 대해 999,999입니다. 이 제한은 표시 목적으로만 제공되며, 더 많은 수의 리소스를 변경하는 플랜은 의도한 대로 적용할 수 있습니다.

1. 위젯에서 **전체 로그 보기**를 선택하여 파이프라인 로그에 있는 플랜 출력으로 이동합니다:

   ![Terraform 플랜 로그](img/terraform_plan_log_v13_0.png)
