---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: '자습서: 자신의 프로젝트 러너 생성, 등록 및 실행'
---

<!-- vale gitlab_base.FutureTense = NO -->

이 튜토리얼은 GitLab에서 첫 번째 러너를 구성하고 실행하는 방법을 보여줍니다.

러너는 GitLab CI/CD 파이프라인에서 작업을 실행하는 GitLab Runner 애플리케이션의 에이전트입니다. 작업은 `.gitlab-ci.yml` 파일에서 정의되며 사용 가능한 러너에 할당됩니다.

GitLab에는 세 가지 유형의 러너가 있습니다:

- 공유: GitLab 인스턴스의 모든 그룹 및 프로젝트에서 사용 가능합니다.
- 그룹: 그룹의 모든 프로젝트 및 하위 그룹에서 사용 가능합니다.
- 프로젝트: 특정 프로젝트와 연결되어 있습니다. 일반적으로 프로젝트 러너는 한 번에 하나의 프로젝트에서 사용됩니다.

이 튜토리얼에서는 기본 파이프라인 구성에서 정의된 작업을 실행하는 프로젝트 러너를 만듭니다:

1. [빈 프로젝트 생성](#create-a-blank-project)
1. [프로젝트 파이프라인 생성](#create-a-project-pipeline)
1. [프로젝트 러너 생성 및 등록](#create-and-register-a-project-runner)
1. [러너를 실행할 파이프라인 트리거](#trigger-a-pipeline-to-run-your-runner)

## 시작하기 전에 {#before-you-begin}

러너를 생성, 등록 및 실행하려면 먼저 로컬 컴퓨터에 [GitLab Runner를 설치](https://docs.gitlab.com/runner/install/)해야 합니다.

## 빈 프로젝트 생성 {#create-a-blank-project}

먼저 CI/CD 파이프라인과 러너를 만들 수 있는 빈 프로젝트를 만듭니다.

빈 프로젝트를 생성하려면:

1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **빈 프로젝트 생성**을 선택합니다.
1. 프로젝트 세부 정보를 입력합니다:
   - **프로젝트 이름** 필드에 프로젝트 이름을 입력합니다. 이름은 소문자 또는 대문자(`a-zA-Z`), 숫자(`0-9`), 이모지 또는 밑줄(`_`)로 시작해야 합니다. 또한 점(`.`), 더하기(`+`), 대시(`-`) 또는 공백을 포함할 수 있습니다.
   - **프로젝트 슬러그** 필드에 프로젝트 경로를 입력합니다. GitLab 인스턴스는 슬러그를 프로젝트의 URL 경로로 사용합니다. 슬러그를 변경하려면 먼저 프로젝트 이름을 입력한 다음 슬러그를 변경합니다.
1. **프로젝트 생성**을 선택합니다.

## 프로젝트 파이프라인 생성 {#create-a-project-pipeline}

다음으로 프로젝트에 대한 `.gitlab-ci.yml` 파일을 만듭니다. 이는 GitLab CI/CD에 대한 지시사항을 지정하는 YAML 파일입니다.

이 파일에서는 다음을 정의합니다:

- 러너가 실행해야 하는 작업의 구조 및 순서입니다.
- 특정 조건이 발생했을 때 러너가 해야 할 결정입니다.

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. **프로젝트 개요**를 선택합니다.
1. 더하기 아이콘({{< icon name="plus" >}})을 선택한 다음 **새 파일**을 선택합니다.
1. **파일명** 필드에 `.gitlab-ci.yml`을 입력합니다.
1. 큰 텍스트 상자에 이 샘플 구성을 붙여넣습니다:

   ```yaml
   stages:
     - build
     - test

   job_build:
     stage: build
     script:
       - echo "Building the project"

   job_test:
     stage: test
     script:
       - echo "Running tests"
   ```

   이 구성에는 러너가 실행하는 두 개의 작업이 있습니다. 빌드 작업과 테스트 작업입니다.
1. **변경 사항 커밋**을 선택합니다.

## 프로젝트 러너 생성 및 등록 {#create-and-register-a-project-runner}

다음으로 프로젝트 러너를 만들고 등록합니다. 러너를 등록하여 GitLab에 연결해야 프로젝트 파이프라인에서 작업을 선택할 수 있습니다.

프로젝트 러너를 만들려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **러너** 섹션을 확장합니다.
1. **프로젝트 러너 생성**을 선택합니다.
1. **태그** 섹션에서 **태그 없이 실행** 확인란을 선택합니다. [태그](../../ci/runners/configure_runners.md#control-jobs-that-a-runner-can-run)는 러너가 실행할 수 있는 작업을 지정하며 선택 사항입니다.
1. **러너 만들기**를 선택합니다.
1. 운영 체제를 선택합니다.
1. 명령줄에서 러너를 등록하기 위한 화면상의 지시사항을 따릅니다. 메시지가 표시되면:
   - `executor`의 경우 러너가 호스트 컴퓨터에서 직접 실행되므로 `shell`을 입력합니다. [실행기](https://docs.gitlab.com/runner/executors/)는 러너가 작업을 실행하는 환경입니다.
   - `GitLab instance URL`의 경우 GitLab 인스턴스의 URL을 사용합니다. 예를 들어 프로젝트가 `gitlab.example.com/yourname/yourproject`에 호스팅되어 있으면 GitLab 인스턴스 URL은 `https://gitlab.example.com`입니다. 프로젝트가 GitLab.com에 호스팅되어 있으면 URL은 `https://gitlab.com`입니다.
1. 러너를 시작합니다:

   ```shell
   gitlab-runner run
   ```

### 러너 구성 파일 확인 {#check-the-runner-configuration-file}

러너를 등록한 후 구성 및 러너 인증 토큰이 `config.toml`에 저장됩니다. 러너는 토큰을 사용하여 작업 큐에서 작업을 선택할 때 GitLab으로 인증합니다.

`config.toml`을 사용하여 [고급 러너 구성](https://docs.gitlab.com/runner/configuration/advanced-configuration/)을 더 정의할 수 있습니다.

러너를 등록하고 시작한 후 `config.toml`는 다음과 같아야 합니다:

```toml
[[runners]]
  name = "my-project-runner1"
  url = "http://127.0.0.1:3000"
  id = 38
  token = "glrt-TOKEN"
  token_obtained_at = 2023-07-05T08:56:33Z
  token_expires_at = 0001-01-01T00:00:00Z
  executor = "shell"
```

## 러너를 실행할 파이프라인 트리거 {#trigger-a-pipeline-to-run-your-runner}

다음으로 프로젝트에서 파이프라인을 트리거하여 러너가 작업을 실행하는 것을 볼 수 있습니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다.
1. **새 파이프라인**을 선택합니다.
1. 작업을 선택하여 작업 로그를 봅니다. 출력은 이 예제와 유사하게 보이며, 이는 러너가 작업을 성공적으로 실행하는 것을 보여줍니다:

   ```shell
      Running with gitlab-runner 18.0.0 (d7f2cea7)
      on my-project-runner TOKEN, system ID: SYSTEM ID
      Preparing the "shell" executor
      00:00
      Using Shell (bash) executor...
      Preparing environment
      00:00
      /Users/username/.bash_profile: line 9: setopt: command not found
      Running on MACHINE-NAME...
      Getting source from Git repository
      00:01
      /Users/username/.bash_profile: line 9: setopt: command not found
      Fetching changes with git depth set to 20...
      Reinitialized existing Git repository in /Users/username/project-repository
      Checking out 7226fc70 as detached HEAD (ref is main)...
      Skipping object checkout, Git LFS is not installed for this repository.
      Consider installing it with 'git lfs install'.
      Skipping Git submodules setup
      Executing "step_script" stage of the job script
      00:00
      /Users/username/.bash_profile: line 9: setopt: command not found
      $ echo "Building the project"
      Building the project
      Job succeeded

   ```

이제 첫 번째 러너를 성공적으로 만들었고, 등록했으며, 실행했습니다!
