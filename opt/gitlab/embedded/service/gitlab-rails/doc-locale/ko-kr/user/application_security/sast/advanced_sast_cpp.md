---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 고급 SAST C/C++ 구성
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [소개됨](https://gitlab.com/groups/gitlab-org/-/work_items/18368) \- GitLab 18.6에서 [베타](../../../policy/development_stages_support.md#beta)로 출시됨.
- GitLab 18.8에서 [정식 출시(GA)](https://gitlab.com/groups/gitlab-org/-/work_items/18369)되었습니다.

{{< /history >}}

## GitLab Advanced SAST C/C++ 분석 활성화 {#turn-on-gitlab-advanced-sast-cc-analysis}

사전 요구 사항:

- [GitLab Advanced SAST 활성화](gitlab_advanced_sast.md#turn-on-gitlab-advanced-sast)하세요.
- [컴파일 데이터베이스](#compilation-database)

프로젝트에서 GitLab Advanced SAST C/C++ 분석을 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **빌드** > **파이프라인** 편집기로 이동합니다.
1. SAST 작업 구성에 C/C++ 분석을 추가합니다. 여기의 지침은 컴파일 데이터베이스의 이름이 `compile_commands.json`인 것으로 가정합니다.

   - CI/CD 템플릿을 사용 중인 경우 `include:` 문 다음에 다음 CI/CD 변수를 구성에 추가합니다:

     ```yaml
     include:
       - template: Jobs/SAST.gitlab-ci.yml

     variables:
       GITLAB_ADVANCED_SAST_CPP_ENABLED: "true"
       SAST_COMPILATION_DATABASE: "compile_commands.json"
     ```

   - CI/CD 구성 요소를 사용 중인 경우 다음 입력 매개변수와 CI/CD 변수를 구성에 추가합니다:

     ```yaml
     include:
     - component: gitlab.com/components/sast/sast@main
         inputs:
           run_advanced_sast_cpp: "true"

     variables:
       SAST_COMPILATION_DATABASE: "compile_commands.json"
     ```

1. **검증** 탭을 선택한 후 **파이프라인 검증**을 선택합니다.

   **시뮬레이션이 성공적으로 완료되었습니다** 메시지는 파일이 유효함을 확인합니다.
1. **편집** 탭을 선택합니다.
1. 필드를 완성합니다:
   - 커밋 메시지.
   - 브랜치. 예를 들어, `add-sast`입니다.
1. **이 변경 사항으로 새로운 머지 리퀘스트 시작** 확인란을 선택한 후 **변경 사항 커밋**을 선택합니다.

   머지 리퀘스트 페이지가 열립니다.
1. 표준 워크플로에 따라 필드를 완성한 후 **머지 리퀘스트 생성**을 선택합니다.
1. 표준 워크플로에 따라 머지 리퀘스트를 검토하고 편집한 후 **머지**를 선택합니다.

## 컴파일 데이터베이스 {#compilation-database}

GitLab Advanced SAST CPP 분석기는 소스 파일을 올바르게 구문 분석하고 분석하기 위해 컴파일 데이터베이스(CDB)가 필요합니다.

CDB는 각 번역 단위에 대해 하나의 항목을 포함하는 JSON 파일(`compile_commands.json`)입니다. 각 항목은 일반적으로 다음을 지정합니다:

- 파일을 빌드하는 데 사용된 컴파일러 명령
- 컴파일러 플래그 및 포함 경로
- 컴파일이 수행되는 작업 디렉터리

CDB를 사용하면 분석기가 정확한 빌드 환경을 재현하여 정확한 구문 분석과 의미 분석을 보장합니다.

GitLab Advanced SAST CPP를 사용하려면 CDB를 만들어 분석기에 제공해야 합니다.

### CDB 만들기 {#create-a-cdb}

CDB를 생성하는 방법은 빌드 시스템에 따라 다릅니다. 아래는 일반적인 예입니다.

#### 예: CMake {#example-cmake}

[CMake](https://cmake.org/)는 `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` 매개변수가 추가된 `cmake` 호출로 CDB를 직접 생성할 수 있습니다:

```shell
cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
```

이 옵션은 프로젝트를 구성하고 `build` 폴더에 `compile_commands.json` 파일을 생성하며, 각 소스 파일의 컴파일러 명령을 기록합니다.

GitLab Advanced SAST CPP 분석기는 이 파일을 사용하여 빌드 환경을 정확하게 재현합니다.

생성된 `compile_commands.json` 파일을 다음 빌드 작업 예제에서 [작업 아티팩트](../../../ci/jobs/job_artifacts.md)로 내보냅니다:

```yaml
<YOUR-BUILD-JOB-NAME>:
  image: ubuntu:24.04
  before_script:
    - apt update -qq && apt install -y -qq cmake build-essential
  script:
    - mkdir -p build
    - cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    - make -j$(nproc)
  artifacts:
    paths:
      - build/compile_commands.json # Pass the CDB file to the gitlab-advanced-sast-cpp job
```

#### 다양한 빌드 시스템의 예 {#examples-for-various-build-systems}

CDB를 만들고 다양한 빌드 시스템을 사용하여 GitLab Advanced SAST CPP를 실행하는 완전한 예를 찾을 수도 있습니다:

- [CMake 예](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/1)
- [Meson 예](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/2)
- [compiledb 예](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/5)
- [compiledb-go 예](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/7)
- [Make + Bear 예](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/4)
- [Ninja + Bear 예](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/3)
- [Bazel 예](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/highway/-/merge_requests/8)

### 분석기에 CDB 제공 {#provide-the-cdb-to-the-analyzer}

GitLab Advanced SAST CPP 분석기에 `SAST_COMPILATION_DATABASE` 변수를 사용하여 CDB의 위치를 알립니다:

```yaml
variables:
  SAST_COMPILATION_DATABASE: YOUR_COMPILATION_DATABASE.json
```

`SAST_COMPILATION_DATABASE`을(를) 지정하지 않으면 GitLab Advanced SAST CPP 분석기는 기본적으로 프로젝트 루트 디렉터리에 있는 `compile_commands.json` 파일을 사용합니다.

`compile_commands.json` 파일을 생성하는 빌드 작업은 이를 [작업 아티팩트](../../../ci/jobs/job_artifacts.md)로 내보내야 `gitlab-advanced-sast-cpp` 작업이 사용할 수 있습니다:

```yaml
variables:
  SAST_COMPILATION_DATABASE: build/compile_commands.json

<YOUR-BUILD-JOB-NAME>:
  image: ubuntu:24.04
  before_script:
    - apt update -qq && apt install -y -qq cmake build-essential
  script:
    - mkdir -p build
    - cmake -S . -B build -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
    - make -j$(nproc)
  artifacts:
    paths:
      - build/compile_commands.json # Pass the CDB file to the gitlab-advanced-sast-cpp job
```

또는 [CDB 캐싱](#caching-a-cdb)을 검토합니다.

### 분석 런타임 최적화 {#optimize-analysis-runtime}

C/C++ 코드의 분석 런타임을 최적화하려면 CDB를 여러 조각으로 분할하여 분석을 병렬로 실행할 수 있습니다.

[`GitLab Advanced SAST CPP` 리포지토리](https://gitlab.com/gitlab-org/security-products/demos/sast/gitlab-advanced-sast-cpp-templates/-/blob/main/templates/scripts.yml)는 CDB를 분할하고 병렬 분석을 실행하기 위한 도우미 스크립트를 제공합니다.

C/C++ 코드 분석을 병렬로 실행하려면:

1. 스크립트를 포함합니다:

   ```yaml
   include:
     - project: "gitlab-org/security-products/demos/sast/gitlab-advanced-sast-cpp-templates"
       file: "templates/scripts.yml"
   ```

1. 도우미 스크립트를 참조하고 빌드 작업에서 CDB를 분할합니다:

   ```yaml
   <YOUR-BUILD-JOB-NAME>:
     script:
       - <your-script to generate the CDB>
       - !reference [.gitlab-advanced-sast-cpp-scripts]
       - split_cdb "${BUILD_DIR}" 1 4 # Split into 4 fragments
     artifacts:
       paths:
         - ${BUILD_DIR} # Pass the split CDB files to the parallelized gitlab-advanced-sast-cpp jobs
   ```

   > [!note]
   > `split_cdb`은 `${BUILD_DIR}/compile_commands.json`을(를) 읽도록 하드코딩되어 있습니다. 빌드는 `split_cdb`을(를) 호출하기 전에 정확한 위치에서 CDB를 생성해야 합니다.

1. 병렬 분석기 작업 실행:

   ```yaml
   gitlab-advanced-sast-cpp:
     parallel: 4
     variables:
       SAST_COMPILATION_DATABASE: "${BUILD_DIR}/compile_commands${CI_NODE_INDEX}.json"
     needs:
       - job: <YOUR-BUILD-JOB-NAME>
         artifacts: true
   ```

   - `parallel: 4`은 4개 작업에 걸쳐 실행을 분할합니다.
   - `${CI_NODE_INDEX}` (1, 2, 3, 4)은(는) 올바른 CDB 조각을 선택합니다.
   - `needs`은(는) 분석기 작업이 빌드 작업에서 생성된 아티팩트를 수신하도록 합니다.

이 설정으로 빌드 작업은 단일 `compile_commands.json`을(를) 생성합니다. `split_cdb` 스크립트는 여러 분할을 만들고, 분석기 작업은 병렬로 실행되며, 각 작업은 하나의 분할을 처리합니다.

## 규칙 집합 구성 {#ruleset-configuration}

GitLab Advanced SAST CPP는 "rule"이 GitLab Advanced SAST CPP 검사기인 [사용자 지정 규칙 집합](customize_rulesets.md)을 지원합니다.

사용자 지정 규칙 집합은 [패스스루](customize_rulesets.md#build-a-custom-configuration-using-a-passthrough-chain-for-semgrep)로 구성되며, 이는 [`CodeChecker` 구성 파일](https://github.com/Ericsson/codechecker/blob/master/docs/config_file.md)로 구성됩니다.

패스스루 구성은 다음과 같이 처리됩니다:

- `targetDir`과(와) `target`은(는) 무시됩니다. 패스스루 처리 후 결과 플래그는 `CodeChecker`으로 직접 전달됩니다.
- `overwrite` 모드는 전체 구성을 바꾸고 `append` 모드는 플래그를 추가합니다.
- 특정 `CodeChecker` 플래그는 사용자 지정할 수 없으며, 여기에는 분석기 플래그 `-o`, `--output` 및 구문 분석 플래그 `-o, --output, -e, --export`이(가) 포함됩니다.
- `server` 및 `store` 구성 항목은 무시됩니다.

다음 예에서는 다양한 소스의 패스스루가 어떻게 결합되는지 보여줍니다:

파일 `.gitlab/sast-ruleset.toml`:

```toml
[gitlab-advanced-sast-cpp]
    description = "My ruleset"

    [[gitlab-advanced-sast-cpp.passthrough]]
        # replace the GitLab default configuration with my own
        mode  = "overwrite"
        type  = "url"
        value = "https://example.com/gitlab-advanced-sast-cpp.yaml"

    [[gitlab-advanced-sast-cpp.passthrough]]
        # append flags from a file in the current repository
        mode  = "append"
        type  = "file"
        value = "gitlab-advanced-sast-cpp.yml"
```

`https://example.com/gitlab-advanced-sast-cpp.yaml`의 원격 구성:

```yaml
analyzer:
  - --disable-all
  - --enable=core.DivideZero
```

`gitlab-advanced-sast-cpp.yml`의 로컬 구성:

```yaml
analyzer:
  - --enable=core.CallAndMessage
```

결과 통합 구성은 다음과 같습니다:

```yaml
analyzer:
  - --disable-all
  - --enable=core.DivideZero
  - --enable=core.CallAndMessage
```

## 오프라인 환경 {#offline-environment}

오프라인 환경에서 GitLab Advanced SAST C/C++을(를) 실행하려면 스캔을 실행하기 전에 `clangsa` 분석기 이미지를 로컬 레지스트리로 미러링합니다. 표준 `gitlab-advanced-sast` 이미지에는 다른 언어에 사용되는 `clangsa` 이미지가 포함되지 않습니다. 이 이미지를 별도로 미러링해야 합니다.

`clangsa` 이미지를 미러링하려면 [`Secure-Binaries.gitlab-ci.yml` 템플릿](https://gitlab.com/gitlab-org/gitlab/-/blob/master/lib/gitlab/ci/templates/Security/Secure-Binaries.gitlab-ci.yml)을(를) 사용합니다. 이 템플릿은 `gitlab-advanced-sast-cpp` 작업을 포함하며, 이는 `clangsa` 이미지를 레지스트리로 가져오고 밀어냅니다.

오프라인 환경 설정에 대한 자세한 내용은 [오프라인 환경](../offline_deployments/_index.md)을 참조하세요.

## 문제 해결 {#troubleshooting}

### `cdb-rebase`으로(로) 경로 리베이싱 {#rebasing-paths-with-cdb-rebase}

CDB의 경로가 CI/CD 작업의 컨테이너 경로와 일치하지 않으면 [cdb-rebase](https://gitlab.com/gitlab-org/security-products/analyzers/clangsa/-/tree/main/cmd/cdb-rebase)를 사용하여 조정합니다.

설치:

```shell
go install gitlab.com/gitlab-org/secure/tools/cdb-rebase@latest
```

이진 파일은 `$GOPATH/bin` 또는 `$HOME/go/bin`에 설치됩니다. 이 디렉터리가 `PATH`에 있는지 확인하세요.

사용 예:

```shell
cdb-rebase compile_commands.json /host/path /container/path > rebased_compile_commands.json
```

### CDB 수정 {#fixing-the-cdb}

빌드 환경이 스캔 환경과 다르면 생성된 CDB에 조정이 필요할 수 있습니다. [jq](https://jqlang.org)로 수정하거나 `cdb_append`을(를) 사용할 수 있습니다. 이는 [미리 정의된 도우미 스크립트](https://gitlab.com/gitlab-org/security-products/demos/sast/gitlab-advanced-sast-cpp-templates/-/blob/main/templates/scripts.yml)의 셸 함수입니다.

`cdb_append`은(는) 기존 CDB에 컴파일러 옵션을 추가합니다. 다음을 허용합니다:

- 첫 번째 인수: `compile_commands.json`을(를) 포함하는 폴더
- 이후 인수: 추가할 추가 컴파일러 옵션

CI/CD의 예:

```yaml
include:
  - project: "gitlab-org/security-products/demos/sast/gitlab-advanced-sast-cpp-templates"
    file: "templates/scripts.yml"

<YOUR-BUILD-JOB-NAME>:
  script:
    - !reference [.gitlab-advanced-sast-cpp-scripts]
    - <your-script to generate the CDB>
    - cdb_append "${BUILD_DIR}" "-I'$PWD/include-cache'" "-Wno-error=register"
```

### CDB 캐싱 {#caching-a-cdb}

컴파일 및 분석 프로세스를 가속화하려면 CDB를 [캐시](../../../ci/caching/_index.md)할 수 있습니다.

```yaml
.cdb_cache:
  cache: &cdb_cache
    key:
      files:
        - Makefile
        - src/
    paths:
      - compile_commands.json

<YOUR-BUILD-JOB-NAME>:
  script:
    - <your-script to generate the CDB>
  cache:
    <<: *cdb_cache
    policy: pull-push

gitlab-advanced-sast-cpp:
  cache:
    <<: *cdb_cache
    policy: pull
```

완전한 예는 데모 프로젝트 [`cached-cdb`](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/cached-db)를 참조하세요.

### CDB의 절대 경로 처리 {#handling-absolute-paths-in-a-cdb}

[데모 프로젝트](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/cached-db/-/blob/1a36792b744d7a6ad396a8ac8114ca8947e45b62/.gitlab-ci.yml#L27)에서 `bear`은(는) Docker 작업의 [빌드 디렉터리](https://docs.gitlab.com/runner/configuration/advanced-configuration/#default-build-directory)에서 실행됩니다. CDB 경로는 절대 경로이며 [/builds/$CI_PROJECT_PATH](../../../ci/variables/predefined_variables.md)를 기반으로 합니다. 분석기 작업 `gitlab-advanced-sast-cpp`은(는) 같은 위치에서 실행되므로 경로가 올바릅니다.

CDB가 분석 중에 사용할 수 없는 경로에서 생성된 경우 리베이싱해야 합니다. 분석기 이미지에 포함된 `cdb-rebase` 도구는 `directory`, `file` 및 `output` 경로를 다시 씁니다.

예:

```yaml
gitlab-advanced-sast-cpp:
  before-script:
    # Rebase the original CDB to be relative to the current directory.
    #
    # ORIGINAL_CDB_PATH     - Path to the CDB artifact from a previous job (e.g., artifacts/compile_commands.json)
    # ORIGINAL_CDB_BASEPATH - The absolute path to the project root when the ORIGINAL_CDB_PATH was generated.
    #                         (e.g., /mnt/custom_build_area/my-project or /home/user/my-project)
    - /cdb-rebase   --input "$ORIGINAL_CDB_PATH" \
                    --output compile_commands.json \
                    --src "$ORIGINAL_CDB_BASEPATH" \
                    --dst .
```

전체 데모는 [cdb-rebase-demo](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/cdb-rebase-demo)를 참조하세요.

단순 경로 리베이싱 외에도 `cdb-rebase`은(는) 빌드 및 스캔 환경 간에 포함 파일도 관리할 수 있습니다:

- 외부 헤더 캐시: `--include-cache`을(를) 사용하면 소스 트리 외부의 헤더가 이식 가능한 캐시로 복사됩니다.
- 포함 경로 추가: `--include`을(를) 사용하여 캐시할 추가 포함 디렉터리를 지정합니다.
- 파일 제외: `--exclude`을(를) 사용하여 전달하지 않으려는 헤더를 건너뜁니다.

예:

```shell
/cdb-rebase --src /my-project \
            --dst /scan-env \
            --input build/compile_commands.json \
            --output rebased_cdb.json \
            --include-cache include-cache \
            --include third_party/include \
            --exclude dummy.h
```

`cdb-rebase` 도구는 Go가 설치된 환경에서도 사용할 수 있으므로 생성될 때 CDB를 리베이싱하는 것이 가능합니다(예:).

```shell
go install gitlab.com/gitlab-org/security-products/analyzers/clangsa/cmd/cdb-rebase@latest
bear -o compile_commands_abs.json -- make
cdb-rebase -i compile_commands_abs.json -o compile_commands.json -s "$PWD" -d .
```

> [!note]
> `go install` 명령 위의 `cdb-rebase`을(를) `GOBIN` 경로에 설치하며, 이는 `go env GOBIN`으로 찾을 수 있습니다.

### 누락된 헤더 파일로 인한 부분 스캔 범위 {#partial-scan-coverage-due-to-missing-header-files}

필수 시스템 또는 타사 헤더 파일을 스캔 작업에서 사용할 수 없을 때 부분 스캔 범위가 발생할 수 있습니다. 빌드 작업 중에 설치된 헤더를 스캔 작업으로 명시적으로 전달해야 하며 컴파일 데이터베이스에 기록된 포함 경로를 통해 확인 가능하게 만들어야 합니다.

일반적인 방법은 필수 헤더를 캐시하고 컴파일 데이터베이스를 업데이트하여 이를 참조하도록 하는 것입니다:

```shell
# Create and populate an include cache
mkdir -p include-cache
dpkg -L <build-dependency-packages> | sed -n 's:^/usr/include/::p' > headers.txt
rsync -a --files-from=headers.txt /usr/include/ include-cache/

# Add cached headers to compile flags
cdb_append . "-I'$PWD/include-cache'"
```

전체 데모는 [예](https://gitlab.com/gitlab-org/security-products/demos/experiments/advanced-sast-cpp/OpenSceneGraph/-/merge_requests/4)를 참조하세요.
