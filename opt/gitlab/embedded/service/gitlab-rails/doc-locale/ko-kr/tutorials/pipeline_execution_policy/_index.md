---
stage: Security Risk Management
group: Security Policies
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: "자습서: 파이프라인 실행 정책 설정"
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이 튜토리얼에서는 [파이프라인 실행 정책](../../user/application_security/policies/pipeline_execution_policies.md)을 `inject_policy` 전략으로 만들고 구성하는 방법을 보여줍니다. 이 정책들을 사용하여 정책이 연결된 프로젝트에서 필수 파이프라인이 항상 실행되도록 할 수 있습니다.

이 튜토리얼에서는 파이프라인 실행 정책을 만들고 테스트 프로젝트에 연결한 다음 파이프라인이 실행되는지 확인할 수 있습니다.

파이프라인 실행 정책을 설정하려면 다음을 수행합니다:

1. [테스트 프로젝트 만들기](#create-a-test-project)
1. [CI/CD 구성 파일 만들기](#create-a-cicd-configuration-file)
1. [파이프라인 실행 정책 추가](#add-a-pipeline-execution-policy)
1. [파이프라인 실행 정책 테스트](#test-the-pipeline-execution-policy)

## 시작하기 전에 {#before-you-begin}

이 튜토리얼을 완료하려면 다음이 필요합니다:

- 기존 그룹에서 프로젝트를 만들 수 있는 권한입니다.
- 보안 정책을 만들고 링크할 수 있는 권한입니다.

## 테스트 프로젝트 만들기 {#create-a-test-project}

먼저 파이프라인 실행 정책을 적용할 테스트 프로젝트를 만듭니다:

1. 상단 바에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **새 프로젝트**를 선택합니다.
1. **빈 프로젝트 생성**을 선택하세요.
1. 필드를 완성합니다.
   - **프로젝트 이름**: `my-pipeline-execution-policy`
   - **정적 애플리케이션 보안 테스트(SAST) 활성화** 확인란을 선택합니다.
1. **프로젝트 생성**을 선택합니다.

## CI/CD 구성 파일 만들기 {#create-a-cicd-configuration-file}

다음으로, 파이프라인 실행 정책이 적용할 CI/CD 구성 파일을 만듭니다:

1. 왼쪽 사이드바에서 **코드** > **리포지토리**를 선택합니다.
1. **추가** (+) 드롭다운 목록에서 **새 파일**을 선택합니다.
1. **파일명** 필드에 `pipeline-config.yml`을(를) 입력합니다.
1. 파일 콘텐츠에 다음을 복사합니다:

   ```yaml
   ---
   # This file defines the CI/CD jobs that will be
   # enforced by the pipeline execution policy
   enforced-security-scan:
     stage: .pipeline-policy-pre
     script:
       - echo "Running enforced security scan from pipeline execution policy"
       - echo "This job cannot be skipped by developers"
       - echo "Checking for security vulnerabilities..."
       - echo "Security scan completed successfully"
     rules:
       - when: always

   enforced-test-job:
     stage: test
     script:
       - echo "Running enforced test job in test stage"
       - echo "Creating test stage if it doesn't exist"
       - echo "Performing mandatory testing requirements..."
       - echo "Enforced tests completed successfully"
     rules:
       - when: always

   enforced-compliance-check:
     stage: .pipeline-policy-post
     script:
       - echo "Running enforced compliance check"
       - echo "Verifying pipeline compliance requirements"
       - echo "Compliance check passed"
     rules:
       - when: always
   ```

1. **커밋 메시지** 필드에 `Add pipeline execution policy configuration`을(를) 입력합니다.
1. **변경 사항 커밋**을 선택합니다.

## 파이프라인 실행 정책 추가 {#add-a-pipeline-execution-policy}

다음으로, 테스트 프로젝트에 파이프라인 실행 정책을 추가합니다:

1. **안전함** > **정책**을 선택합니다.
1. **새 정책**을 선택합니다.
1. **파이프라인 실행 정책**에서 **정책 선택**을 선택합니다.
1. 필드를 완성합니다.
   - **이름**: `Enforce Security and Compliance Jobs`
   - **설명**: `Enforces required security and compliance jobs across all pipelines`
   - **정책 상태**: **Enabled (활성화됨)**

1. **조치**을 다음으로 설정합니다:

   ![파이프라인 실행 정책 동작](img/pipeline_execution_policy_actions_v18_7.png)
1. **머지 리퀘스트로 설정**을 선택합니다.
1. 머지 리퀘스트의 **변경사항** 탭에서 생성된 정책 YAML을 검토합니다. 정책은 다음과 유사해야 합니다:

   ```yaml
   ---
   pipeline_execution_policy:
   - name: Enforce Security and Compliance Jobs
     description: Enforces required security and compliance jobs across all pipelines
     enabled: true
     pipeline_config_strategy: inject_policy
     content:
       include:
       - project: [group]/my-pipeline-execution-policy
         file: pipeline-config.yml
     skip_ci:
       - allowed: false
   ```

1. **개요** 탭으로 이동하여 **머지**를 선택합니다. 이 단계에서는 `My Pipeline Execution Policy - Security Policy Project`이라는 새 프로젝트를 만듭니다. 보안 정책 프로젝트는 보안 정책을 저장하여 동일한 정책을 여러 프로젝트에 적용할 수 있도록 하는 데 사용됩니다.
1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `my-pipeline-execution-policy` 프로젝트를 찾습니다.
1. **안전함** > **정책**을 선택합니다.

   이전 단계에서 추가된 정책 목록을 볼 수 있습니다.

## 파이프라인 실행 정책 테스트 {#test-the-pipeline-execution-policy}

이제 머지 리퀘스트를 만들어서 파이프라인 실행 정책을 테스트합니다:

1. 왼쪽 사이드바에서 **코드** > **리포지토리**를 선택합니다.
1. **추가** (+) 드롭다운 목록에서 **새 파일**을 선택합니다.
1. **파일명** 필드에 `test-file.txt`을(를) 입력합니다.
1. 파일 콘텐츠에 다음을 추가합니다:

   ```plaintext
   This is a test file to trigger the pipeline execution policy.
   ```

1. **커밋 메시지** 필드에 `Add test file to trigger pipeline`을(를) 입력합니다.
1. **대상 브랜치** 필드에 `test-policy-branch`을(를) 입력합니다.
1. **변경 사항 커밋**을 선택합니다.
1. 머지 리퀘스트 페이지가 열리면 **머지 리퀘스트 생성**를 선택합니다.

   파이프라인이 완료될 때까지 기다립니다. 몇 분 정도 걸릴 수 있습니다.
1. 머지 리퀘스트에서 **파이프라인** 탭을 선택하고 생성된 파이프라인을 선택합니다.

   실행되는 강제된 작업을 확인해야 합니다:
   - `.pipeline-policy-pre` 스테이지의 `enforced-security-scan` (먼저 실행됨)
   - `test` 스테이지의 `enforced-test-job` (정책에 의해 주입됨)
   - `.pipeline-policy-post` 스테이지의 `enforced-compliance-check` (마지막으로 실행됨)

1. `enforced-security-scan` 작업을 선택하여 로그를 보고 정책에 정의된 대로 보안 스캔이 실행되었는지 확인합니다.

파이프라인 실행 정책이 필수 작업을 성공적으로 적용하여 개발자가 프로젝트의 `.gitlab-ci.yml` 파일에 포함하는 내용에 관계없이 실행되도록 보장합니다.

이제 조직의 프로젝트 전체에서 필수 CI/CD 작업의 사용을 적용하기 위해 파이프라인 실행 정책을 설정하고 사용하는 방법을 알았습니다!

## 다음 단계 {#next-steps}

- [파이프라인 실행 정책 구성 전략](../../user/application_security/policies/pipeline_execution_policies.md#pipeline-configuration-strategies)에 대해 자세히 알아보세요.
- [고급 파이프라인 실행 정책 예제](../../user/application_security/policies/pipeline_execution_policies.md#examples)를 살펴보세요.
