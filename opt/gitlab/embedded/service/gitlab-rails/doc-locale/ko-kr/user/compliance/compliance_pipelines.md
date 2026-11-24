---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 규정준수 파이프라인(더 이상 사용되지 않음)
description: "규정준수 파이프라인(GitLab 17.3에서 더 이상 사용되지 않음, 20.0에서 제거 예정)은 레이블이 지정된 프로젝트를 위한 중앙집중식 CI/CD 제어를 지원합니다. 파이프라인 실행 정책으로 대체되었습니다."
---

<!--- start_remove The following content will be removed on remove_date: '2027-05-25' -->

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> 이 기능은 GitLab 17.3에서 [더 이상 사용되지 않으며](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/159841), 20.0에서 제거될 예정입니다. 대신 [파이프라인 실행 정책 유형](../application_security/policies/pipeline_execution_policies.md)을 사용합니다. 이것은 주요 변경 사항입니다. 자세한 내용은 [마이그레이션 가이드](#pipeline-execution-policies-migration)를 참조하세요.

그룹 소유자는 다른 프로젝트와 별도로 프로젝트에서 규정준수 파이프라인을 구성할 수 있습니다. 기본적으로 규정준수 파이프라인 구성(예: `.compliance-gitlab-ci.yml`)은 레이블이 지정된 프로젝트의 파이프라인 구성(예: `.gitlab-ci.yml`) 대신 실행됩니다.

그러나 규정준수 파이프라인 구성은 레이블이 지정된 프로젝트의 `.gitlab-ci.yml` 파일을 참조할 수 있습니다:

- 규정준수 파이프라인은 레이블이 지정된 프로젝트 파이프라인의 작업도 실행할 수 있습니다. 이를 통해 파이프라인 구성의 중앙집중식 제어가 가능합니다.
- 규정준수 파이프라인에서 정의된 작업 및 변수는 레이블이 지정된 프로젝트의 `.gitlab-ci.yml` 파일의 변수로 변경될 수 없습니다.

> [!note]
> [알려진 문제](https://gitlab.com/gitlab-org/gitlab/-/issues/414004) 때문에 프로젝트 파이프라인을 규정준수 파이프라인 구성의 맨 위에 먼저 포함하여 프로젝트가 다운스트림 설정을 재정의하는 것을 방지해야 합니다.

자세한 정보는 다음을 참조하세요.

- 레이블이 지정된 프로젝트 파이프라인 구성에서 작업을 실행하는 규정준수 파이프라인을 구성하는 데 도움이 되는 [구성 예제](#example-configuration)입니다.
- [규정준수 파이프라인 만들기](../../tutorials/compliance_pipeline/_index.md) 자습서입니다.

## 파이프라인 실행 정책 마이그레이션 {#pipeline-execution-policies-migration}

파이프라인 실행 정책은 스캔 및 파이프라인 적용을 통합하고 단순화하는 것을 목표로 합니다. 규정준수 파이프라인은 GitLab 17.3에서 더 이상 사용되지 않으며 GitLab 19.0에서 제거될 예정입니다.

파이프라인 실행 정책은 프로젝트의 `.gitlab-ci.yml` 파일을 파이프라인 실행 정책에 연결된 별도의 YAML 파일(예: `pipeline-execution.yml`)에서 제공하는 구성으로 확장합니다.

기본적으로 새로운 규정준수 프레임워크를 만들 때 규정준수 파이프라인 대신 파이프라인 실행 정책 유형을 사용하도록 안내됩니다.

기존 규정준수 파이프라인을 마이그레이션해야 합니다. 고객은 가능한 한 빨리 규정준수 파이프라인에서 새로운 [파이프라인 실행 정책 유형](../application_security/policies/pipeline_execution_policies.md)으로 마이그레이션해야 합니다.

### 기존 규정준수 프레임워크 마이그레이션 {#migrate-an-existing-compliance-framework}

기존 규정준수 프레임워크를 파이프라인 실행 정책 유형을 사용하도록 마이그레이션하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **안전함** > **규정준수 센터**를 선택합니다.
1. 기존 규정준수 프레임워크를 [편집](compliance_frameworks/_index.md#create-edit-or-delete-a-compliance-framework)합니다.
1. 표시되는 배너에서 **파이프라인을 정책으로 마이그레이션**을 선택하여 보안 정책에서 새 정책을 만듭니다.
1. 규정준수 프레임워크를 다시 편집하여 규정준수 파이프라인을 제거합니다.

자세한 내용은 [보안 정책 프로젝트](../application_security/policies/enforcement/security_policy_projects.md)를 참조하세요.

마이그레이션 중에 `Pipeline execution policy error: Job names must be unique` 오류가 발생하면 [관련 문제 해결 정보](#error-job-names-must-be-unique)를 참조하세요.

## 레이블이 지정된 프로젝트에 미치는 영향 {#effect-on-labeled-projects}

사용자는 규정준수 파이프라인이 구성되었는지 알 수 있는 방법이 없으며 자신의 파이프라인이 실행되지 않는 이유나 자신이 정의하지 않은 작업이 포함되는 이유에 대해 혼란스러워할 수 있습니다.

레이블이 지정된 프로젝트에서 파이프라인을 작성할 때 규정준수 파이프라인이 구성되었는지 나타내는 표시가 없습니다. 프로젝트 수준의 유일한 표시는 규정준수 프레임워크 레이블 자체이지만 레이블은 프레임워크에 규정준수 파이프라인이 구성되어 있는지 여부를 표시하지 않습니다.

따라서 규정준수 파이프라인 구성에 대해 프로젝트 사용자와 소통하여 불확실성과 혼란을 줄입니다.

### 여러 규정준수 프레임워크 {#multiple-compliance-frameworks}

규정준수 파이프라인이 구성된 여러 규정준수 프레임워크를 단일 프로젝트에 [적용](compliance_frameworks/_index.md#apply-a-compliance-framework-to-a-project)할 수 있습니다. 이 경우 프로젝트에 적용된 첫 번째 규정준수 프레임워크만 규정준수 파이프라인이 프로젝트 파이프라인에 포함됩니다.

올바른 규정준수 파이프라인이 프로젝트에 포함되어 있는지 확인하려면:

1. 프로젝트에서 모든 규정준수 프레임워크를 제거합니다.
1. 올바른 규정준수 파이프라인이 있는 규정준수 프레임워크를 프로젝트에 적용합니다.
1. 추가 규정준수 프레임워크를 프로젝트에 적용합니다.

## 규정준수 파이프라인 구성 {#configure-a-compliance-pipeline}

규정준수 파이프라인을 구성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **안전함** > **규정준수 센터**를 선택합니다.
1. **프레임워크** 섹션을 선택합니다.
1. **새 프레임워크** 섹션을 선택하고 규정준수 프레임워크 정보를 추가합니다. 규정준수 프레임워크 구성의 경로를 포함합니다. `path/file.y[a]ml@group-name/project-name` 형식을 사용합니다. 예를 들어:

   - `.compliance-ci.yml@gitlab-org/gitlab`입니다.
   - `.compliance-ci.yaml@gitlab-org/gitlab`입니다.

이 구성은 규정준수 프레임워크 레이블이 [적용](../project/working_with_projects.md#add-a-compliance-framework-to-a-project)되는 프로젝트에 상속됩니다. 규정준수 프레임워크 레이블이 적용된 프로젝트에서 규정준수 파이프라인 구성은 레이블이 지정된 프로젝트의 자체 파이프라인 구성 대신 실행됩니다.

레이블이 지정된 프로젝트에서 파이프라인을 실행하는 사용자는 규정준수 프로젝트에서 최소한 리포터 역할을 가져야 합니다.

스캔 실행을 적용할 때 이 기능은 [스캔 실행 정책](../application_security/policies/scan_execution_policies.md)과 일부 겹칩니다. 이 두 기능의 사용자 경험은 [통합되지 않았습니다](https://gitlab.com/groups/gitlab-org/-/epics/7312).

## 중요한 고려 사항 {#important-considerations}

> [!warning]
> 같은 프로젝트에서 기존 규정준수 파이프라인을 마이그레이션할 때까지 [파이프라인 실행 정책](../application_security/policies/pipeline_execution_policies.md)을 활성화하지 마세요. 둘 다 구성되면 규정준수 파이프라인은 표준 프로젝트 파이프라인을 대체하지만 파이프라인 실행 정책은 원본 프로젝트 파이프라인에 따라 적용됩니다. 이는 파이프라인 실행 정책 전략 및 CI/CD 구성에 따라 달라지는 예측 불가능한 동작을 만들고, 중복된 작업, 파이프라인 실패 또는 누락된 중요한 보안 및 규정 준수 검사로 인해 발생할 수 있습니다. 규정 준수 파이프라인은 [더 이상 사용되지 않습니다](../../update/deprecations.md#compliance-pipelines). 기존 규정 준수 파이프라인을 최대한 빨리 마이그레이션하고, 모든 새로운 구현에 파이프라인 실행 정책을 사용해야 합니다.

### 구성 예제 {#example-configuration}

다음 예제 `.compliance-gitlab-ci.yml`에는 레이블이 지정된 프로젝트 파이프라인 구성이 실행되도록 하기 위해 `include` 키워드가 포함되어 있습니다.

```yaml
include:  # Execute individual project's configuration (if project contains .gitlab-ci.yml)
  - project: '$CI_PROJECT_PATH'
    file: '$CI_CONFIG_PATH'
    ref: '$CI_COMMIT_SHA' # Must be defined or MR pipelines always use the use default branch
    rules:
      - if: $CI_PROJECT_PATH != "my-group/project-1" # Must run on projects other than the one hosting this configuration.

# Allows compliance team to control the ordering and interweaving of stages/jobs.
# Stages without jobs defined will remain hidden.
stages:
  - pre-compliance
  - build
  - test
  - pre-deploy-compliance
  - deploy
  - post-compliance

variables:  # Can be overridden by setting a job-specific variable in project's local .gitlab-ci.yml
  FOO: sast

sast:  # None of these attributes can be overridden by a project's local .gitlab-ci.yml
  variables:
    FOO: sast
  image: ruby:2.6
  stage: pre-compliance
  rules:
    - if: $CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS && $CI_PIPELINE_SOURCE == "push"
      when: never
    - when: always  # or when: on_success
  allow_failure: false
  before_script:
    - "# No before scripts."
  script:
    - echo "running $FOO"
  after_script:
    - "# No after scripts."

sanity check:
  image: ruby:2.6
  stage: pre-deploy-compliance
  rules:
    - if: $CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS && $CI_PIPELINE_SOURCE == "push"
      when: never
    - when: always  # or when: on_success
  allow_failure: false
  before_script:
    - "# No before scripts."
  script:
    - echo "running $FOO"
  after_script:
    - "# No after scripts."

audit trail:
  image: ruby:2.7
  stage: post-compliance
  rules:
    - if: $CI_COMMIT_BRANCH && $CI_OPEN_MERGE_REQUESTS && $CI_PIPELINE_SOURCE == "push"
      when: never
    - when: always  # or when: on_success
  allow_failure: false
  before_script:
    - "# No before scripts."
  script:
    - echo "running $FOO"
  after_script:
    - "# No after scripts."
```

`rules` 구성은 `include` 정의에서 규정준수 파이프라인이 호스트 프로젝트에서 실행될 수 있는 경우 순환 포함을 방지합니다. 규정준수 파이프라인이 레이블이 지정된 프로젝트에서만 실행되는 경우 이를 생략할 수 있습니다.

#### 외부에서 호스팅되는 규정준수 파이프라인 및 사용자 지정 파이프라인 구성 {#compliance-pipelines-and-custom-pipeline-configuration-hosted-externally}

이전 예제에서는 모든 프로젝트가 같은 프로젝트에서 파이프라인 구성을 호스트한다고 가정합니다. 프로젝트에서 [외부에서 호스팅되는 구성](../../ci/pipelines/settings.md#specify-a-custom-cicd-configuration-file)을 사용하면 예제 구성이 작동하지 않습니다. 자세한 내용은 [문제 393960](https://gitlab.com/gitlab-org/gitlab/-/issues/393960)을 참조하세요.

외부에서 호스팅되는 구성을 사용하는 프로젝트의 경우 다음 해결 방법을 시도할 수 있습니다:

- 예제 규정준수 파이프라인 구성의 `include` 섹션을 조정해야 합니다. 예를 들어 [`include:rules`](../../ci/yaml/includes.md#use-rules-with-include)를 사용:

  ```yaml
  include:
    # If the custom path variables are defined, include the project's external config file.
    - project: '$PROTECTED_PIPELINE_CI_PROJECT_PATH'
      file: '$PROTECTED_PIPELINE_CI_CONFIG_PATH'
      ref: '$PROTECTED_PIPELINE_CI_REF'
      rules:
        - if: $PROTECTED_PIPELINE_CI_PROJECT_PATH && $PROTECTED_PIPELINE_CI_CONFIG_PATH && $PROTECTED_PIPELINE_CI_REF
    # If any custom path variable is not defined, include the project's internal config file as normal.
    - project: '$CI_PROJECT_PATH'
      file: '$CI_CONFIG_PATH'
      ref: '$CI_COMMIT_SHA'
      rules:
        - if: $PROTECTED_PIPELINE_CI_PROJECT_PATH == null || $PROTECTED_PIPELINE_CI_CONFIG_PATH == null || $PROTECTED_PIPELINE_CI_REF == null
  ```

- [CI/CD 변수](../../ci/variables/_index.md)를 외부 파이프라인 구성이 있는 프로젝트에 추가해야 합니다. 이 예에서:

  - `PROTECTED_PIPELINE_CI_PROJECT_PATH`: 구성 파일을 호스팅하는 프로젝트의 경로(예: `group/subgroup/project`).
  - `PROTECTED_PIPELINE_CI_CONFIG_PATH`: 프로젝트의 구성 파일 경로(예: `path/to/.gitlab-ci.yml`).
  - `PROTECTED_PIPELINE_CI_REF`: 구성 파일을 검색할 때 사용할 ref(예: `main`).

#### 프로젝트 포크에서 발생하는 머지 리퀘스트의 규정준수 파이프라인 {#compliance-pipelines-in-merge-requests-originating-in-project-forks}

머지 리퀘스트가 포크에서 발생하면 병합할 브랜치는 일반적으로 포크에만 있습니다. 규정준수 파이프라인이 있는 프로젝트에 대해 이러한 머지 리퀘스트를 만들 때 이전 코드 조각은 `Project <project-name> reference <branch-name> does not exist!` 오류 메시지로 실패합니다. 이 오류는 대상 프로젝트의 컨텍스트에서 `$CI_COMMIT_REF_NAME`이 존재하지 않는 브랜치 이름으로 평가되기 때문에 발생합니다.

올바른 컨텍스트를 얻으려면 `$CI_PROJECT_PATH` 대신 `$CI_MERGE_REQUEST_SOURCE_PROJECT_PATH`을 사용합니다. 이 변수는 [머지 리퀘스트 파이프라인](../../ci/pipelines/merge_request_pipelines.md)에서만 사용 가능합니다.

예를 들어 프로젝트 포크에서 발생하는 머지 리퀘스트 파이프라인과 브랜치 파이프라인을 모두 지원하는 구성의 경우 [`include` 지시문을 `rules:if`과 결합](../../ci/yaml/includes.md#use-rules-with-include)해야 합니다:

```yaml
include:  # Execute individual project's configuration (if project contains .gitlab-ci.yml)
  - project: '$CI_MERGE_REQUEST_SOURCE_PROJECT_PATH'
    file: '$CI_CONFIG_PATH'
    ref: '$CI_COMMIT_REF_NAME'
    rules:
      - if: $CI_PIPELINE_SOURCE == 'merge_request_event'
  - project: '$CI_PROJECT_PATH'
    file: '$CI_CONFIG_PATH'
    ref: '$CI_COMMIT_REF_NAME'
    rules:
      - if: $CI_PIPELINE_SOURCE != 'merge_request_event'
```

#### 구성 파일이 없는 프로젝트의 규정준수 파이프라인 {#compliance-pipelines-in-projects-with-no-configuration-file}

[구성 예제](#example-configuration)에서는 모든 프로젝트가 파이프라인 구성 파일(`.gitlab-ci.yml` 기본값)을 포함한다고 가정합니다. 그러나 구성 파일이 없는 프로젝트(따라서 기본적으로 파이프라인이 없음)에서는 `include:project`에 지정된 파일이 필요하기 때문에 규정준수 파이프라인이 실패합니다.

대상 프로젝트에 존재하는 경우에만 구성 파일을 포함하려면 [`rules:exists:project`](../../ci/yaml/_index.md#rulesexistsproject)를 사용합니다:

```yaml
include:  # Execute individual project's configuration
  - project: '$CI_PROJECT_PATH'
    file: '$CI_CONFIG_PATH'
    ref: '$CI_COMMIT_SHA'
    rules:
      - exists:
          paths:
            - '$CI_CONFIG_PATH'
          project: '$CI_PROJECT_PATH'
          ref: '$CI_COMMIT_SHA'
```

이 예제에서는 주어진 `ref`에 대해 `exists:project: '$CI_PROJECT_PATH'`의 프로젝트에 존재하는 경우에만 구성 파일이 포함됩니다.

`exists:project`이 규정준수 파이프라인 구성에 지정되지 않으면 `include`이 정의된 프로젝트에서 파일을 검색합니다. 규정준수 파이프라인에서 이전 예제의 `include`은 규정준수 파이프라인 구성 파일을 호스팅하는 프로젝트에 정의되어 있으며, 파이프라인을 실행하는 프로젝트가 아닙니다.

## 규정준수 작업이 항상 실행되도록 보장 {#ensure-compliance-jobs-are-always-run}

규정준수 파이프라인은 [GitLab CI/CD를 사용](../../ci/_index.md)하여 정의하고 싶은 모든 종류의 규정준수 작업을 위한 엄청난 유연성을 제공합니다. 목표에 따라 이러한 작업을 다음과 같이 구성할 수 있습니다:

- 사용자가 수정합니다.
- 수정 불가능합니다.

일반적으로 규정준수 작업의 값이:

- 설정된 경우 프로젝트 수준의 구성으로 변경하거나 재정의할 수 없습니다.
- 설정되지 않은 경우 프로젝트 수준의 구성이 설정될 수 있습니다.

사용 사례에 따라 원하거나 원하지 않을 수 있습니다.

다음은 이러한 작업이 정의한 대로 정확히 실행되고 다운스트림 프로젝트 수준의 파이프라인 구성이 변경할 수 없도록 보장하기 위한 몇 가지 모범 사례입니다:

- 각 규정준수 작업에 [`rules:when:always` 블록](../../ci/yaml/_index.md#when)을 추가합니다. 이렇게 하면 수정 불가능하고 항상 실행됩니다.
- 작업이 참조하는 모든 [변수](../../ci/yaml/_index.md#variables)를 명시적으로 설정합니다. 이것:
  - 프로젝트 수준의 파이프라인 구성이 이를 설정하고 동작을 변경하지 않도록 보장합니다. 예를 들어 [구성 예제](#example-configuration)에서 `before_script`과 `after_script` 구성을 참조하세요.
  - 작업의 논리를 드라이브하는 모든 작업을 포함합니다.
- 작업을 실행할 [컨테이너 이미지](../../ci/yaml/_index.md#image)를 명시적으로 설정합니다. 이렇게 하면 스크립트 단계가 올바른 환경에서 실행됩니다.
- 관련 GitLab 사전 정의된 [작업 키워드](../../ci/yaml/_index.md#job-keywords)를 명시적으로 설정합니다. 이렇게 하면 작업이 의도한 설정을 사용하고 프로젝트 수준의 파이프라인으로 재정의되지 않도록 보장합니다.

## 문제 해결 {#troubleshooting}

### 규정준수 작업이 대상 리포지토리로 덮어써짐 {#compliance-jobs-are-overwritten-by-target-repository}

규정준수 파이프라인 구성에서 `extends` 문을 사용하면 규정준수 작업이 대상 리포지토리 작업으로 덮어써집니다. 예를 들어 다음과 같은 `.compliance-gitlab-ci.yml` 구성을 가질 수 있습니다:

```yaml
"compliance job":
  extends:
    - .compliance_template
  stage: build

.compliance_template:
  script:
    - echo "take compliance action"
```

다음과 같은 `.gitlab-ci.yml` 구성을 가질 수도 있습니다:

```yaml
"compliance job":
  stage: test
  script:
    - echo "overwriting compliance action"
```

이 구성으로 인해 대상 리포지토리 파이프라인이 규정준수 파이프라인을 덮어쓰고 다음 메시지가 표시됩니다: `overwriting compliance action`.

규정준수 작업 덮어쓰기를 방지하려면 규정준수 파이프라인 구성에서 `extends` 키워드를 사용하지 마세요. 예를 들어 다음과 같은 `.compliance-gitlab-ci.yml` 구성을 가질 수 있습니다:

```yaml
"compliance job":
  stage: build
  script:
    - echo "take compliance action"
```

다음과 같은 `.gitlab-ci.yml` 구성을 가질 수도 있습니다:

```yaml
"compliance job":
  stage: test
  script:
    - echo "overwriting compliance action"
```

이 구성은 규정준수 파이프라인을 덮어쓰지 않으며 다음 메시지가 표시됩니다: `take compliance action`.

### 사전 입력된 변수가 표시되지 않음 {#prefilled-variables-are-not-shown}

[알려진 문제](https://gitlab.com/gitlab-org/gitlab/-/issues/382857) 때문에 규정준수 파이프라인은 파이프라인을 수동으로 시작할 때 [사전 입력된 변수](../../ci/pipelines/_index.md#prefill-variables-in-manual-pipelines)가 나타나지 않도록 할 수 있습니다.

이 문제를 해결하려면 개별 프로젝트의 구성을 실행하는 `include:` 문에서 `ref: '$CI_COMMIT_REF_NAME'` 대신 `ref: '$CI_COMMIT_SHA'`을 사용합니다.

[구성 예제](#example-configuration)가 이 변경 사항으로 업데이트되었습니다:

```yaml
include:
  - project: '$CI_PROJECT_PATH'
    file: '$CI_CONFIG_PATH'
    ref: '$CI_COMMIT_SHA'
```

### 오류: `Job names must be unique` {#error-job-names-must-be-unique}

규정준수 파이프라인을 구성하려면 [구성 예제](#example-configuration)에서 `include.project`를 사용한 개별 프로젝트 구성 포함을 권장합니다.

이 구성은 프로젝트 파이프라인을 실행할 때 오류가 발생할 수 있습니다: `Pipeline execution policy error: Job names must be unique`. 이 오류는 파이프라인 실행 정책이 프로젝트의 `.gitlab-ci.yml`를 포함하고 작업이 파이프라인에서 이미 선언된 경우 작업을 삽입하려고 할 때 발생합니다.

이 오류를 해결하려면 파이프라인 실행 정책에 연결된 별도의 YAML 파일에서 `include.project`을 제거합니다.

<!--- end_remove -->
