---
stage: Application Security Testing
group: Dynamic Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: '자습서: GitLab에서 퍼즈 테스팅 수행(더 이상 사용되지 않음)'
---

<!--- start_remove The following content will be removed on remove_date: '2026-12-31' -->

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> 커버리지 기반 퍼즈 테스팅은 GitLab 18.0에서 [더 이상 사용되지 않으며](https://gitlab.com/gitlab-org/gitlab/-/issues/517841) 19.0에서 제거될 예정입니다. 이것은 주요 변경 사항입니다.

<!-- vale gitlab_base.FutureTense = NO -->

[커버리지 기반 퍼즈 테스팅](../../user/application_security/coverage_fuzzing/_index.md#coverage-guided-fuzz-testing-process)은 애플리케이션에 예기치 않은, 잘못된 형식이거나 무작위 데이터를 전송한 다음 애플리케이션의 불안정한 동작과 충돌을 모니터링합니다.

이를 통해 다른 QA 프로세스에서 놓칠 수 있는 버그와 잠재적 보안 문제를 발견할 수 있습니다.

다른 보안 스캐너 및 자체 테스트 프로세스와 함께 퍼즈 테스팅을 사용해야 합니다. GitLab CI/CD를 사용 중인 경우 CI/CD 워크플로의 일부로 퍼즈 테스트를 실행할 수 있습니다.

이 튜토리얼에서 JavaScript를 사용하여 커버리지 기반 퍼즈 테스팅을 설정, 구성 및 수행하려면 다음을 수행하세요:

1. [프로젝트 템플릿 포크](#fork-the-project-template)하여 퍼즈 테스트를 실행할 프로젝트를 만듭니다.
1. [퍼즈 타겟 생성](#create-the-fuzz-targets)합니다.
1. 포크된 프로젝트에서 [커버리지 기반 퍼즈 테스팅 활성화](#enable-coverage-guided-fuzz-testing)합니다.
1. [퍼즈 테스트 실행](#run-the-fuzz-test)하여 보안 취약성을 식별합니다.
1. [모든 취약성 수정](#fix-the-vulnerabilities)(퍼즈 테스트에서 식별된)합니다.

## 프로젝트 템플릿 포크 {#fork-the-project-template}

먼저 퍼즈 테스팅을 시도할 프로젝트를 만들려면 `fuzz-testing` 프로젝트 템플릿을 포크해야 합니다:

1. [`fuzz-testing` 프로젝트 템플릿](https://gitlab.com/gitlab-org/tutorial-project-templates/fuzz-testing)을 엽니다.
1. [프로젝트 템플릿 포크](../../user/project/repository/forking_workflow.md)합니다.
1. 프로젝트 템플릿을 포크할 때:
   - 포크된 프로젝트의 이름을 `fuzz-testing-demo`로 지정합니다.
   - 적절한 [네임스페이스](../../user/namespace/_index.md)를 선택합니다.
   - [프로젝트 가시성](../../user/public_access.md)을 **비공개**로 설정합니다.

`fuzz-testing` 프로젝트 템플릿을 성공적으로 포크했습니다. 퍼즈 테스팅을 시작하기 전에 프로젝트 템플릿과 포크 간의 관계를 제거해야 합니다:

1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **고급**을 확장합니다.
1. **포크 관계 제거** 섹션에서 **포크 관계 제거**를 선택합니다. 메시지가 나타나면 프로젝트의 이름을 입력합니다.

프로젝트가 준비되었으며 이제 퍼즈 테스트를 만들 수 있습니다. 다음으로 퍼즈 타겟을 만들겠습니다.

## 퍼즈 타겟 생성 {#create-the-fuzz-targets}

이제 퍼즈 테스팅을 위한 프로젝트가 있으므로 퍼즈 타겟을 만들 수 있습니다. 퍼즈 타겟은 입력이 주어졌을 때 테스트 중인 애플리케이션을 호출하는 함수 또는 프로그램입니다.

이 튜토리얼에서 퍼즈 타겟은 `my-tools.js` 파일의 함수를 무작위 버퍼를 매개변수로 사용하여 호출합니다.

두 개의 퍼즈 타겟 파일을 만들려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 `fuzz-testing-demo` 프로젝트를 찾습니다.
1. 프로젝트의 루트 디렉토리에 파일을 만듭니다.
1. 파일의 이름을 `fuzz-sayhello.js`로 지정하고 다음 코드를 추가합니다:

   ```javascript
   let tools = require('./my-tools')

   function fuzz(buf) {
     const text = buf.toString()
     tools.sayHello(text)
   }

   module.exports = {
     fuzz
   }
   ```

   `fuzz-testing-demo/fuzzers/fuzz-sayhello.js` 프로젝트 파일에서 이 코드를 복사할 수도 있습니다.
1. **대상 브랜치**의 이름을 `add-fuzz-test`로 지정하고 설명적인 커밋 메시지를 작성합니다.
   - **이 변경사항으로 새 머지 리퀘스트 시작** 체크박스를 아직 선택하지 마세요.
1. **변경 사항 커밋**을 선택합니다.
1. 프로젝트의 루트 디렉토리로 돌아갑니다.
1. `add-fuzz-test` 브랜치에 있는지 확인합니다.
1. `fuzz-readme.js`이라는 두 번째 파일을 만들고 다음 코드를 추가합니다:

   ```javascript
   let tools = require('./my-tools')
   function fuzz(buf) {
       const text = buf.toString()
       tools.readmeContent(text)
   }
   module.exports = {
       fuzz
   }
   ```

   `fuzz-testing-demo/fuzzers/fuzz-readme.js` 프로젝트 파일에서 이 코드를 복사할 수도 있습니다.
1. 설명적인 커밋 메시지를 작성합니다.
1. **대상 브랜치**가 `add-fuzz-test`인지 확인합니다.
1. **변경 사항 커밋**을 선택합니다.

이제 두 개의 퍼즈 타겟이 있으며, 이를 통해 테스트 중인 애플리케이션을 호출할 수 있습니다. 다음으로 퍼즈 테스팅을 활성화합니다.

## 커버리지 기반 퍼즈 테스팅 활성화 {#enable-coverage-guided-fuzz-testing}

커버리지 기반 퍼즈 테스팅을 활성화하려면 `gitlab-cov-fuzz` CLI를 실행하는 CI/CD 파이프라인을 만들어 두 개의 퍼즈 타겟에서 퍼즈 테스트를 실행합니다.

파이프라인 파일을 만들려면:

1. `add-fuzz-test` 브랜치에 있는지 확인합니다.
1. `fuzz-testing-demo` 프로젝트의 루트 디렉토리에서 새 파일을 만듭니다.
1. 파일의 이름을 `.gitlab-ci.yml`로 지정하고 다음 코드를 추가합니다:

   ```yaml
   default:
     image: node:18

   stages:
     - fuzz

   include:
     - template: Coverage-Fuzzing.gitlab-ci.yml

   readme_fuzz_target:
     extends: .fuzz_base
     tags: [saas-linux-large-amd64] # Optional
     variables:
       COVFUZZ_ADDITIONAL_ARGS: '--fuzzTime=60'
     script:
       - npm config set @gitlab-org:registry https://gitlab.com/api/v4/packages/npm/ && npm i -g @gitlab-org/jsfuzz
       - ./gitlab-cov-fuzz run --engine jsfuzz -- fuzz-readme.js

   hello_fuzzing_target:
     extends: .fuzz_base
     tags: [saas-linux-large-amd64] # Optional
     variables:
       COVFUZZ_ADDITIONAL_ARGS: '--fuzzTime=60'
     script:
       - npm config set @gitlab-org:registry https://gitlab.com/api/v4/packages/npm/ && npm i -g @gitlab-org/jsfuzz
       - ./gitlab-cov-fuzz run --engine jsfuzz -- fuzz-sayhello.js
   ```

   이 단계는 파이프라인에 다음을 추가합니다:
   - 템플릿을 사용하는 `fuzz` 스테이지입니다.
   - 두 개의 작업(`readme_fuzz_target`과(와) `hello_fuzzing_target`)입니다. 각 작업은 `jsfuzz` 엔진을 사용하여 실행되며, 이는 처리되지 않은 예외를 충돌로 보고합니다.

   `fuzz-testing-demo/fuzzers/fuzzers.yml` 프로젝트 파일에서 이 코드를 복사할 수도 있습니다.

1. 설명적인 커밋 메시지를 작성합니다.
1. **대상 브랜치**가 `add-fuzz-test`인지 확인합니다.
1. **변경 사항 커밋**을 선택합니다.

커버리지 기반 퍼즈 테스팅을 성공적으로 활성화했습니다. 다음으로 방금 만든 파이프라인을 사용하여 퍼즈 테스트를 실행합니다.

## 퍼즈 테스트 실행 {#run-the-fuzz-test}

퍼즈 테스트를 실행하려면:

1. 왼쪽 사이드바에서 **코드** > **머지 리퀘스트**를 선택합니다.
1. **새 머지 리퀘스트**를 선택합니다.
1. **소스 브랜치** 섹션에서 `add-fuzz-test` 브랜치를 선택합니다.
1. **타겟 브랜치** 섹션에서 네임스페이스와 `main` 브랜치가 선택되어 있는지 확인합니다.
1. **브랜치를 비교하고 계속**을 선택합니다.
1. [머지 리퀘스트를 만듭니다](../../user/project/merge_requests/creating_merge_requests.md).

머지 리퀘스트를 만들면 새 파이프라인이 트리거되어 퍼즈 테스트를 실행합니다. 파이프라인 실행이 완료되면 머지 리퀘스트 페이지에 보안 취약성 경고가 표시되어야 합니다.

각 취약성에 대한 자세한 정보를 보려면 개별 **Uncaught-exception** 링크를 선택합니다.

퍼즈 테스트를 성공적으로 실행하고 수정할 취약성을 식별했습니다.

## 취약성 수정 {#fix-the-vulnerabilities}

퍼즈 테스트에서 두 개의 보안 취약성을 식별했습니다. 이러한 취약성을 수정하려면 `my-tools.js` 라이브러리를 사용합니다.

`my-tools.js` 파일을 만들려면:

1. 프로젝트의 `add-fuzz-test` 브랜치에 있는지 확인합니다.
1. 프로젝트의 루트 디렉토리로 이동하여 `my-tools.js` 파일을 엽니다.
1. 이 파일의 내용을 다음 코드로 바꿉니다:

   ```javascript
   const fs = require('fs')

   function sayHello(name) {
     if(name.includes("z")) {
       //throw new Error("😡 error name: " + name)
       console.log("😡 error name: " + name)
     } else {
       return "😀 hello " + name
     }
   }

   function readmeContent(name) {

     let fileName = name => {
       if(name.includes("w")) {
         return "./README.txt"
       } else {
         return "./README.md"
       }
     }

     //const data = fs.readFileSync(fileName(name), 'utf8')
     try {
       const data = fs.readFileSync(fileName(name), 'utf8')
       return data
     } catch (err) {
       console.error(err.message)
       return ""
     }

   }

   module.exports = {
     sayHello, readmeContent
   }
   ```

   `fuzz-testing-demo/javascript/my-tools.js` 프로젝트 파일에서 코드를 복사할 수도 있습니다.
1. **변경 사항 커밋**을 선택합니다. 이렇게 하면 다른 파이프라인이 트리거되어 다른 퍼즈 테스트를 실행합니다.
1. 파이프라인 실행이 완료되면 머지 리퀘스트 **개요** 페이지를 확인합니다. 보안 스캔에서 새로운 잠재적 취약성을 감지하지 못했다는 것을 확인해야 합니다.
1. 변경 사항을 병합합니다.

축하합니다. 퍼즈 테스트를 성공적으로 실행하고 식별된 보안 취약성을 수정했습니다!

자세한 내용은 [커버리지 기반 퍼즈 테스팅](../../user/application_security/coverage_fuzzing/_index.md)을 참조합니다.

<!--- end_remove -->
