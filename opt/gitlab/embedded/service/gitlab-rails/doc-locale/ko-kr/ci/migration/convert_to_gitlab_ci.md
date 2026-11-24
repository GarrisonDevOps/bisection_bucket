---
stage: Agent Foundations
group: Agent Developer
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Convert to GitLab CI/CD 플로우
---

{{< details >}}

- 티어: [Free](../../subscriptions/gitlab_credits.md#for-the-free-tier), Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 18.3에서 [베타](../../policy/development_stages_support.md)로 도입되었으며 [기능 플래그](../../administration/feature_flags/_index.md) `duo_workflow_in_ci`로 명명되었습니다. 기본적으로 비활성화되어 있으나, 인스턴스 또는 사용자 단위로 활성화됨.
- 기능 플래그 `duo_workflow_in_ci`은 GitLab 18.4에서 기본적으로 활성화됩니다. 기능 플래그 `duo_workflow`도 활성화해야 하지만, 기본적으로 활성화됨.
- GitLab 18.8에서 [정식 출시(GA)](https://gitlab.com/gitlab-org/gitlab/-/work_items/585273)되었습니다.
- 기능 플래그 `duo_workflow_in_ci` 및 `duo_workflow`은 GitLab 18.9에서 제거되었습니다.
- GitLab 18.10부터 GitLab.com의 Free 티어에서 GitLab Credits를 사용하여 이용 가능합니다.

{{< /history >}}

Convert to GitLab CI/CD 플로우는 Jenkins 파이프라인을 GitLab CI/CD로 마이그레이션할 수 있도록 도와줍니다. 이 플로우:

- 기존 Jenkins 파이프라인 구성을 분석합니다.
- Jenkins 파이프라인 구문을 GitLab CI/CD YAML로 변환합니다.
- GitLab CI/CD 구현에 대한 모범 사례를 제안합니다.
- 변환된 파이프라인 구성으로 머지 리퀘스트를 생성합니다.
- Jenkins 플러그인을 GitLab 기능으로 마이그레이션하는 방법에 대한 지침을 제공합니다.

이 플로우는 GitLab UI에서만 사용할 수 있습니다.

## 전제 조건 {#prerequisites}

- [GitLab Duo Agent Platform 사전 요구 사항](../../user/duo_agent_platform/_index.md#prerequisites)을 충족합니다.
- {{< ui text="파운데이셔널 플로우 허용" >}} 및 {{< ui text="GitLab CI/CD로 전환" >}} [최상위 그룹](../../user/duo_agent_platform/flows/foundational_flows/_index.md#turn-foundational-flows-on-or-off)에 대해 설정합니다.
- 대상 GitLab 프로젝트에 대한 개발자, 유지 관리자 또는 소유자 역할이 있어야 합니다.
- Jenkins 파이프라인 구성에 액세스할 수 있어야 합니다.
- [서비스 계정을 허용하도록 푸시 규칙을 구성해야 합니다](../../user/duo_agent_platform/troubleshooting.md#configure-push-rules-to-allow-a-service-account).
- 프로젝트를 위해 [자체 러너를 구성](../../user/duo_agent_platform/flows/execution/_index.md#configure-runners-to-execute-flows)하거나 [GitLab 호스팅 러너](../../ci/runners/hosted_runners/_index.md)를 활성화해야 합니다.
- 권장하는 방식입니다. [에이전트 구성 파일](../../user/duo_agent_platform/flows/execution/_index.md#create-the-agent-configuration-file)을 생성하여 플로우가 프로젝트의 도구 체인 및 종속성에 액세스할 수 있도록 합니다.

## 플로우 사용 {#use-the-flow}

Jenkinsfile을 GitLab CI/CD로 변환하려면:

1. 상단 바에서 {{< ui text="검색 또는 이동" >}}을 선택하고 프로젝트를 찾습니다.
1. Jenkinsfile을 엽니다.
1. 파일 위의 {{< ui text="GitLab CI/CD로 변환" >}}을 선택합니다.
1. {{< ui text="AI" >}} > {{< ui text="세션" >}}을 선택하여 진행 상황을 모니터링합니다.
1. 파이프라인이 성공적으로 실행되면 왼쪽 사이드바에서 {{< ui text="코드" >}} > {{< ui text="머지 리퀘스트" >}}를 선택합니다. `Duo Workflow: Convert to GitLab CI` 제목의 머지 리퀘스트가 표시됩니다.
1. 머지 리퀘스트를 검토하고 필요에 따라 변경합니다.

### 변환 프로세스 {#conversion-process}

프로세스가 변환하는 항목:

- 파이프라인 스테이지 및 단계.
- 환경 변수.
- 빌드 트리거 및 매개 변수.
- 아티팩트 및 종속성.
- 병렬 실행.
- 조건부 로직.
- 빌드 후 작업.

## 예 {#example}

Jenkinsfile 입력:

```groovy
pipeline {
    agent any
    stages {
        stage('Build') {
            steps {
                sh 'npm install'
                sh 'npm build'
            }
        }
        stage('Test') {
            steps {
                sh 'npm test'
            }
        }
        stage('Deploy') {
            when { branch 'main' }
            steps {
                sh './deploy.sh'
            }
        }
    }
}
```

GitLab 출력:

```yaml
stages:
  - build
  - test
  - deploy

build:
  stage: build
  script:
    - npm install
    - npm build
  artifacts:
    paths:
      - node_modules/
      - dist/

test:
  stage: test
  script:
    - npm test

deploy:
  stage: deploy
  script:
    - ./deploy.sh
  only:
    - main
```
