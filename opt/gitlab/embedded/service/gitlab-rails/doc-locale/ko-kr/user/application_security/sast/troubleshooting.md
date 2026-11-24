---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: SAST 문제 해결
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

다음의 문제 해결 시나리오는 고객 지원 사례에서 수집되었습니다. 여기에 다루지 않은 문제가 발생하거나 제공된 정보로 문제가 해결되지 않으면 [GitLab 지원](https://support.gitlab.com/) 페이지에서 도움을 받는 방법을 확인하세요.

## 디버그 수준 로깅 {#debug-level-logging}

디버그 수준 로깅은 문제 해결에 도움이 될 수 있습니다. 자세한 내용은 [디버그 수준 로깅](../troubleshooting_application_security.md#turn-on-debug-level-logging)을 참조하세요.

## CI/CD 템플릿의 변경 사항 {#changes-in-the-cicd-template}

GitLab에서 관리하는 SAST CI/CD 템플릿은 어느 [분석기](analyzers.md) 작업이 실행되는지, 그리고 어떻게 구성되는지를 제어합니다. 템플릿을 사용하는 동안 작업 실패 또는 기타 파이프라인 오류가 발생할 수 있습니다. 예를 들어 다음과 같은 경우가 있을 수 있습니다:

- `'<your job>' needs 'spotbugs-sast' job, but 'spotbugs-sast' is not in any previous stage`과 같은 오류 메시지가 표시되면 영향을 받는 파이프라인을 볼 때 확인할 수 있습니다.
- CI/CD 파이프라인 구성과 관련된 다른 유형의 예기치 않은 문제가 발생합니다.

작업 실패가 발생하거나 SAST 관련 `yaml invalid` 파이프라인 상태가 표시되면 템플릿의 이전 버전으로 일시적으로 되돌려서 문제를 조사하는 동안 파이프라인을 계속 작동하도록 유지할 수 있습니다. 템플릿의 이전 버전을 사용하려면 CI/CD YAML 파일의 기존 `include` 문을 `v19.2.0-ee`과 같은 특정 템플릿 버전을 참조하도록 변경하세요:

```yaml
include:
  remote: 'https://gitlab.com/gitlab-org/gitlab/-/raw/v19.2.0-ee/lib/gitlab/ci/templates/Jobs/SAST.gitlab-ci.yml'
```

GitLab 인스턴스의 네트워크 연결이 제한되어 있는 경우 파일을 다운로드하여 다른 곳에서 호스팅할 수도 있습니다.

이 솔루션은 임시로만 사용해야 합니다. 가능한 빨리 표준 템플릿으로 돌아가세요.

## 특정 분석기 작업의 오류 {#errors-in-a-specific-analyzer-job}

GitLab SAST [분석기](analyzers.md)는 컨테이너 이미지로 릴리스됩니다. GitLab에서 관리하는 SAST CI/CD 템플릿 또는 자신의 프로젝트 변경과 관련이 없어 보이는 새로운 오류가 표시되면 [영향을 받는 분석기를 특정 이전 버전으로 고정](_index.md#pin-analyzer-image-version)하기를 시도할 수 있습니다. 이 솔루션은 임시로만 사용해야 합니다. 가능한 빨리 표준 템플릿으로 돌아가세요.

각 [분석기 프로젝트](analyzers.md)에는 사용 가능한 각 버전에서 수행된 변경 사항을 나열하는 `CHANGELOG.md` 파일이 있습니다.

## 작업 로그 메시지 {#job-log-messages}

SAST 작업의 로그에는 근본 원인을 파악하는 데 도움이 되는 오류 메시지가 포함될 수 있습니다. 아래는 오류 메시지 및 권장 조치의 일부입니다.

### 실행 파일 형식 {#executable-format}

```plaintext
exec /bin/sh: exec format error` message in job log
```

GitLab SAST 분석기는 `amd64` CPU 아키텍처에서만 실행을 [지원](_index.md#getting-started)합니다. 이 메시지는 작업이 `arm`과 같은 다른 아키텍처에서 실행 중임을 나타냅니다.

### Docker 오류 {#docker-error}

```plaintext
Error response from daemon: error processing tar file: docker-tar: relocation error
```

이 오류는 SAST 작업을 실행하는 Docker 버전이 `19.03.0`일 때 발생합니다. Docker `19.03.1` 이상으로 업데이트하는 것을 고려하세요. 이전 버전은 영향을 받지 않습니다. 자세한 내용은 [이슈 13830](https://gitlab.com/gitlab-org/gitlab/-/issues/13830#note_211354992) \- "현재 SAST 컨테이너 실패"를 참조하세요.

### 일치하는 파일 없음 {#no-matching-files}

```plaintext
gl-sast-report.json: no matching files
```

이에 대한 정보는 [일반 애플리케이션 보안 문제 해결 섹션](../../../ci/jobs/job_artifacts_troubleshooting.md#error-message-no-files-to-upload)을 참조하세요.

### 구성만 해당 {#configuration-only}

```plaintext
sast is used for configuration only, and its script should not be executed
```

이에 대한 정보는 [GitLab 보안 문제 해결 섹션](../troubleshooting_application_security.md#error-job-is-used-for-configuration-only-and-its-script-should-not-be-executed)을 참조하세요.

## 오류: `An error occurred while creating the merge request` {#error-an-error-occurred-while-creating-the-merge-request}

UI를 사용하여 프로젝트에서 SAST를 사용하도록 설정하려고 할 때 작업이 경고와 함께 실패할 수 있습니다:

```plaintext
An error occurred while creating the merge request.
```

이 문제는 병합 요청을 위한 브랜치 생성을 방해하는 것 때문에 발생할 수 있습니다. UI를 사용하여 SAST를 구성할 때 숫자 접미사가 있는 브랜치가 생성됩니다(예: `set-sast-config-1`). [브랜치 이름의 유효성을 검사하는 푸시 규칙](../../project/repository/push_rules.md#validate-branch-names)과 같은 기능은 이름 지정 형식 때문에 브랜치 생성을 차단할 수 있습니다.

이 문제를 해결하려면 SAST에 필요한 브랜치 이름 지정 형식을 허용하도록 푸시 규칙을 편집하세요.

## SAST 작업이 예기치 않게 실행됨 {#sast-jobs-run-unexpectedly}

[SAST CI 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/SAST.gitlab-ci.yml)은 `rules:exists` 매개변수를 사용합니다. 성능상의 이유로 주어진 glob 패턴에 대해 최대 10000개의 일치가 수행됩니다. 일치 수가 최대값을 초과하면 `rules:exists` 매개변수가 `true`를 반환합니다. 리포지토리의 파일 수에 따라 스캐너가 프로젝트를 지원하지 않더라도 SAST 작업이 트리거될 수 있습니다. 이 제한 사항에 대한 자세한 내용은 [`rules:exists` 설명서](../../../ci/yaml/_index.md#rulesexists)를 참조하세요.

## SpotBugs 오류 {#spotbugs-errors}

다음은 발생하는 가장 일반적인 SpotBugs 오류와 권장 조치에 대한 세부 정보입니다.

### UTF-8 매핑 불가능한 문자 오류 {#utf-8-unmappable-character-errors}

이러한 오류는 SpotBugs 빌드에서 UTF-8 인코딩이 활성화되지 않았고 소스 코드에 UTF-8 문자가 있을 때 발생합니다. 이 오류를 수정하려면 프로젝트의 빌드 도구에 대해 UTF-8을 활성화하세요.

Gradle 빌드의 경우 `build.gradle` 파일에 다음을 추가하세요:

```groovy
compileJava.options.encoding = 'UTF-8'
tasks.withType(JavaCompile) {
    options.encoding = 'UTF-8'
}
```

Maven 빌드의 경우 `pom.xml` 파일에 다음을 추가하세요:

```xml
<properties>
  <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
</properties>
```

### 프로젝트를 빌드할 수 없음 {#project-couldnt-be-built}

`spotbugs-sast` 작업이 "프로젝트를 빌드할 수 없음" 메시지와 함께 빌드 단계에서 실패하는 경우 가능성이 높은 이유는 다음과 같습니다:

- 프로젝트에서 SpotBugs가 기본 도구에 포함되지 않은 도구로 빌드하도록 요청하고 있습니다. SpotBugs 기본 도구 목록은 [SpotBugs의 asdf 종속성](https://gitlab.com/gitlab-org/security-products/analyzers/spotbugs/-/blob/master/config/.gl-tool-versions)을 참조하세요.
- 빌드에 분석기의 자동 빌드 프로세스가 수용할 수 없는 사용자 지정 구성 또는 추가 종속성이 필요합니다.

SpotBugs 기반 분석기는 Groovy 코드 스캔에만 사용되지만 [모든 SAST 작업이 예기치 않게 실행](#sast-jobs-run-unexpectedly)되는 경우와 같은 다른 경우에도 트리거될 수 있습니다.

솔루션은 Groovy 코드를 스캔해야 하는지 여부에 따라 달라집니다:

- Groovy 코드가 없거나 스캔할 필요가 없으면 [SpotBugs 분석기를 비활성화](analyzers.md#disable-specific-default-analyzers)해야 합니다.
- Groovy 코드를 스캔해야 하면 [사전 컴파일](_index.md#using-pre-compilation-with-spotbugs-analyzer)을 사용해야 합니다. 사전 컴파일은 파이프라인에서 이미 빌드한 아티팩트를 스캔하여 `spotbugs-sast` 작업에서 컴파일하려고 시도하는 대신 이러한 오류를 방지합니다.

### Java 메모리 부족 오류 {#java-out-of-memory-error}

`spotbugs-sast` 작업이 실행 중일 때 `java.lang.OutOfMemoryError`를 나타내는 오류가 발생할 수 있습니다. 이 문제는 스캔 중에 Java의 메모리가 부족할 때 발생합니다.

이 문제를 해결하기 위해 다음을 수행할 수 있습니다:

- 낮은 [노력 수준](_index.md#security-scanner-configuration)을 선택하세요.
- CI/CD 변수 `JAVA_OPTS`을 기본값 `-XX:MaxRAMPercentage=80`(예: `-XX:MaxRAMPercentage=90`)로 바꾸도록 설정하세요.
- `spotbugs-sast` 작업에서 [더 큰 러너를 태깅](../../../ci/runners/hosted_runners/linux.md#machine-types-available-for-linux-x86-64)하세요.

#### 관련 항목 {#related-topics}

- [OpenJDK 컨테이너의 메모리 튜닝 개선](https://developers.redhat.com/articles/2023/03/07/overhauling-memory-tuning-openjdk-containers-updates)
- [OpenJDK 구성 및 튜닝](https://wiki.openjdk.org/display/zgc/Main#Main-Configuration&Tuning)
- [Garbage First Garbage Collector 튜닝](https://www.oracle.com/technical-resources/articles/java/g1gc.html)

### 예외 분석 {#exception-analyzing}

작업 로그에 "Exception analyzing ... using detector ..." 형식의 메시지 다음에 Java 스택 추적이 포함되어 있으면 이는 SAST 파이프라인 실패가 아닙니다. SpotBugs는 예외가 [복구 가능](https://github.com/spotbugs/spotbugs/blob/5ebd4439f6f8f2c11246b79f58c44324718d39d8/spotbugs/src/main/java/edu/umd/cs/findbugs/FindBugs2.java#L1200)하다고 판단했으며 이를 기록하고 분석을 재개했습니다.

메시지의 첫 번째 "..." 부분은 분석 중인 클래스이므로, 프로젝트의 일부가 아니면 메시지와 그 뒤의 스택 추적을 무시할 수 있습니다.

반면에 분석 중인 클래스가 프로젝트의 일부인 경우 [GitHub](https://github.com/spotbugs/spotbugs/issues)의 SpotBugs 프로젝트를 사용하여 이슈를 생성하는 것을 고려하세요.

## Flawfinder 인코딩 오류 {#flawfinder-encoding-error}

Flawfinder가 잘못된 UTF-8 문자를 만날 때 발생합니다. 이를 수정하려면 [문서화된 조언](https://github.com/david-a-wheeler/flawfinder#character-encoding-errors)을 전체 리포지토리에 적용하거나 [`before_script`](../../../ci/yaml/_index.md#before_script) 기능을 사용하여 작업별로만 적용하세요.

각 `.gitlab-ci.yml` 파일에서 `before_script` 섹션을 구성하거나 [파이프라인 실행 정책](../policies/pipeline_execution_policies.md)을 사용하여 인코더를 설치하고 변환기 명령을 실행할 수 있습니다. 예를 들어 보안 스캐너 템플릿에서 생성된 `flawfinder-sast` 작업에 `before_script` 섹션을 추가하여 `.cpp` 확장을 가진 모든 파일을 변환할 수 있습니다.

### 파이프라인 실행 정책 YAML 예제 {#example-pipeline-execution-policy-yaml}

```yaml
---
pipeline_execution_policy:
- name: SAST
  description: 'Run SAST on C++ application'
  enabled: true
  pipeline_config_strategy: inject_ci
  content:
    include:
    - project: my-group/compliance-project
      file: flawfinder.yml
      ref: main
```

`flawfinder.yml`:

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

flawfinder-sast:
  before_script:
    - pip install cvt2utf
    - cvt2utf convert "$PWD" -i cpp
```

## Semgrep 느림, 예기치 않은 결과 또는 기타 오류 {#semgrep-slowness-unexpected-results-or-other-errors}

Semgrep이 느리거나 거짓 양성 또는 거짓 음성을 너무 많이 보고하거나 작동이 중단되거나 실패하거나 다른 문제가 있으면 [GitLab SAST 문제 해결](https://semgrep.dev/docs/troubleshooting/semgrep-app#troubleshooting-gitlab-sast)에 대한 Semgrep 문서를 참조하세요.
