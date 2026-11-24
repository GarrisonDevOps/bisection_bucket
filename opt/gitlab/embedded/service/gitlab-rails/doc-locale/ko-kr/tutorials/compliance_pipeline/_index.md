---
stage: Software Supply Chain Security
group: Compliance
info: For assistance with this tutorial, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
title: '자습서: 규정 준수 파이프라인 만들기(더 이상 사용되지 않음)'
---

<!--- start_remove The following content will be removed on remove_date: '2027-05-25' -->

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> 이 기능은 GitLab 17.3에서 [더 이상 사용되지 않으며](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/159841) 20.0에서 제거될 예정입니다. 대신 [파이프라인 실행 정책 유형](../../user/application_security/policies/pipeline_execution_policies.md)을 사용하세요. 이는 호환성이 깨지는 변경입니다. 자세한 내용은 [마이그레이션 가이드](../../user/compliance/compliance_pipelines.md#pipeline-execution-policies-migration)를 참조하세요.

<!-- vale gitlab_base.FutureTense = NO -->

[규정 준수 파이프라인](../../user/compliance/compliance_pipelines.md)을 사용하여 그룹의 모든 프로젝트 파이프라인에서 특정 규정 준수 관련 작업이 실행되도록 할 수 있습니다. 규정 준수 파이프라인은 [규정 준수 프레임워크](../../user/compliance/compliance_frameworks/_index.md)를 통해 프로젝트에 적용됩니다.

이 튜토리얼에서 수행하는 작업은 다음과 같습니다:

1. [새 그룹](#create-a-new-group)을 만듭니다.
1. [규정 준수 파이프라인 구성을 위한 새 프로젝트](#create-a-new-compliance-pipeline-project)를 만듭니다.
1. [규정 준수 프레임워크](#configure-compliance-framework)를 구성하여 다른 프로젝트에 적용합니다.
1. [새 프로젝트를 만들고 규정 준수 프레임워크](#create-a-new-project-and-apply-the-compliance-framework)를 적용합니다.
1. [규정 준수 파이프라인 구성과 일반 파이프라인 구성](#combine-pipeline-configurations)을 결합합니다.

## 시작하기 전에 {#before-you-begin}

- 최상위 그룹을 만들 수 있는 권한이 필요합니다.

## 새 그룹 만들기 {#create-a-new-group}

규정 준수 프레임워크는 최상위 그룹에서 구성됩니다. 이 튜토리얼에서는 다음과 같은 최상위 그룹을 만듭니다:

- 두 개의 프로젝트 포함:
  - 규정 준수 파이프라인 구성을 저장하는 규정 준수 파이프라인 프로젝트.
  - 규정 준수 파이프라인 구성에서 정의한 파이프라인에서 작업을 실행해야 하는 다른 프로젝트.
- 프로젝트에 적용할 규정 준수 프레임워크 보유.

새 그룹을 만들려면:

1. 오른쪽 위 모서리에서 **새로 만들기** ({{< icon name="plus" >}}) 및 **새 그룹**을 선택합니다.
1. **그룹 생성**를 선택합니다.
1. **그룹 이름** 필드에 `Tutorial group`를 입력합니다.
1. **그룹 생성**를 선택합니다.

## 새 규정 준수 파이프라인 프로젝트 만들기 {#create-a-new-compliance-pipeline-project}

이제 규정 준수 파이프라인 프로젝트를 만들 준비가 되었습니다. 이 프로젝트에는 규정 준수 프레임워크가 적용된 모든 프로젝트에 적용할 [규정 준수 파이프라인 구성](../../user/compliance/compliance_pipelines.md#example-configuration)이 포함되어 있습니다.

규정 준수 파이프라인 프로젝트를 만들려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 `Tutorial group` 그룹을 찾습니다.
1. **새 프로젝트**를 선택합니다.
1. **빈 프로젝트 생성**을 선택합니다.
1. **프로젝트 이름** 필드에 `Tutorial compliance project`를 입력합니다.
1. **프로젝트 생성**을 선택합니다.

`Tutorial compliance project`에 규정 준수 파이프라인 구성을 추가하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `Tutorial compliance project` 프로젝트를 찾습니다.
1. **빌드** > **파이프라인 편집기**를 선택합니다.
1. **파이프라인 구성**을 선택합니다.
1. 파이프라인 편집기에서 기본 구성을 다음으로 바꿉니다:

   ```yaml
   ---
   compliance-job:
     script:
       - echo "Running compliance job required for every project in this group..."
   ```

1. **변경 사항 커밋**을 선택합니다.

## 규정 준수 프레임워크 구성 {#configure-compliance-framework}

규정 준수 프레임워크는 [새 그룹](#create-a-new-group)에서 구성됩니다.

규정 준수 프레임워크를 구성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 `Tutorial group` 그룹을 찾습니다.
1. **안전함** > **규정준수 센터**를 선택합니다.
1. 페이지에서 **프레임워크** 탭을 선택합니다.
1. **새 프레임워크**를 선택합니다.
1. **이름** 필드에 `Tutorial compliance framework`를 입력합니다.
1. **설명** 필드에 `Compliance framework for tutorial`를 입력합니다.
1. **규정 준수 파이프라인 구성 (옵션)** 필드에 `.gitlab-ci.yml@tutorial-group/tutorial-compliance-project`를 입력합니다.
1. **배경 색** 필드에서 원하는 색을 선택합니다.
1. **프레임워크 추가**를 선택합니다.

편의상 새 규정 준수 프레임워크를 그룹의 모든 새 프로젝트에 대한 기본값으로 설정합니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 `Tutorial group` 그룹을 찾습니다.
1. **안전함** > **규정준수 센터**를 선택합니다.
1. 페이지에서 **프레임워크** 탭을 선택합니다.
1. `Tutorial compliance framework`을 선택한 다음 **프레임워크 편집**을 선택합니다.
1. **기본값으로 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 새 프로젝트 만들기 및 규정 준수 프레임워크 적용 {#create-a-new-project-and-apply-the-compliance-framework}

규정 준수 프레임워크가 준비되었으므로 이제 그룹에서 프로젝트를 만들 수 있으며 해당 파이프라인에서 규정 준수 파이프라인 구성이 자동으로 실행됩니다.

규정 준수 파이프라인 구성을 실행하기 위한 새 프로젝트를 만들려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 `Tutorial group` 그룹을 찾습니다.
1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **빈 프로젝트 생성**을 선택합니다.
1. **프로젝트 이름** 필드에 `Tutorial project`를 입력합니다.
1. **프로젝트 생성**을 선택합니다.

프로젝트 페이지에서 그룹에 대한 기본 규정 준수 프레임워크로 설정되었기 때문에 `Tutorial compliance framework` 레이블이 표시됩니다.

다른 파이프라인 구성 없이 `Tutorial project`은 `Tutorial compliance project`의 규정 준수 파이프라인 구성에서 정의한 작업을 실행할 수 있습니다.

`Tutorial project`에서 규정 준수 파이프라인 구성을 실행하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `Tutorial project` 프로젝트를 찾습니다.
1. **빌드** > **파이프라인**을 선택합니다.
1. **새 파이프라인**을 선택합니다.
1. **새 파이프라인** 페이지에서 **파이프라인 실행**을 선택합니다.

파이프라인이 **테스트** 스테이지에서 `compliance-job` 작업을 실행합니다. 잘했습니다. 첫 번째 규정 준수 작업을 실행했습니다!

## 파이프라인 구성 결합 {#combine-pipeline-configurations}

프로젝트가 자체 작업과 규정 준수 파이프라인 작업을 모두 실행하도록 하려면 규정 준수 파이프라인 구성과 프로젝트의 일반 파이프라인 구성을 결합해야 합니다.

파이프라인 구성을 결합하려면 일반 파이프라인 구성을 정의한 후 규정 준수 파이프라인 구성을 업데이트하여 이를 참조하도록 해야 합니다.

일반 파이프라인 구성을 만들려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `Tutorial project` 프로젝트를 찾습니다.
1. **빌드** > **파이프라인 편집기**를 선택합니다.
1. **파이프라인 구성**을 선택합니다.
1. 파이프라인 편집기에서 기본 구성을 다음으로 바꿉니다:

   ```yaml
   ---
   project-job:
     script:
       - echo "Running project job..."
   ```

1. **변경 사항 커밋**을 선택합니다.

새 프로젝트 파이프라인 구성을 규정 준수 파이프라인 구성과 결합하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `Tutorial compliance project` 프로젝트를 찾습니다.
1. **빌드** > **파이프라인 편집기**를 선택합니다.
1. 기존 구성에서 다음을 추가합니다:

   ```yaml
   include:
     - project: 'tutorial-group/tutorial-project'
       file: '.gitlab-ci.yml'
    ```

1. **변경 사항 커밋**을 선택합니다.

일반 파이프라인 구성이 규정 준수 파이프라인 구성과 결합되었는지 확인하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `Tutorial project` 프로젝트를 찾습니다.
1. **빌드** > **파이프라인**을 선택합니다.
1. **새 파이프라인**을 선택합니다.
1. **새 파이프라인** 페이지에서 **파이프라인 실행**을 선택합니다.

파이프라인이 **테스트** 스테이지에서 두 개의 작업을 실행합니다:

- `compliance-job`.
- `project-job`.

축하합니다. 규정 준수 파이프라인을 만들고 구성했습니다!

[규정 준수 파이프라인 구성 예제](../../user/compliance/compliance_pipelines.md#example-configuration)를 자세히 확인하세요.

<!--- end_remove -->
