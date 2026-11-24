---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "GitLab에서 기본 규칙을 비활성화, 재정의 또는 대체하여 SAST 분석기 규칙을 사용자 정의할 수 있습니다."
title: 규칙 집합 사용자 정의
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Semgrep 기반 SAST 분석기 및 GitLab Advanced SAST 분석기에는 각각 [기본 규칙 집합](rules.md)이 있습니다. 조직의 보안 요구 사항에 맞게 규칙을 사용자 정의할 수 있습니다. 예를 들어 특정 규칙의 심각도 수준을 높일 수 있습니다.

Semgrep 기반 SAST 분석기용 사용자 정의 규칙을 작성하기 전에 [Semgrep Playground](https://semgrep.dev/playground/new)에서 대화형으로 프로토타입을 작성하고 테스트할 수 있습니다. Playground를 사용할 때 **테스트 코드** 패널에서 별 아이콘({{< icon name="star" >}})으로 표시되고 **Semgrep Pro Engine으로 발견된 검사 결과** 도구 설명이 있는 검사 결과는 무시하세요. 이러한 검사 결과는 GitLab이 사용하는 오픈 소스 Semgrep 엔진과 호환되지 않습니다. Semgrep 규칙 형식에 대한 자세한 내용은 [Semgrep 구문 배우기](https://semgrep.dev/learn)를 참조하세요.

## 규칙 집합 용어집 {#ruleset-glossary}

규칙 : 특정 취약성을 검사하는 개별 보안 검사 또는 탐지 패턴입니다.

규칙 집합 : 분석기에 의해 적용될 개별 규칙을 지정하는 YAML 형식 파일입니다.

규칙 집합 구성 파일 : 적용할 규칙 집합을 지정하고 로컬로 저장되는지 원격으로 저장되는지를 나타내는 TOML 형식 파일입니다. 파일 이름 `sast-ruleset.toml`입니다.

통과(Passthrough) : 통과는 파일, Git 리포지토리, URL 또는 인라인 구성에서 규칙 집합 사용자 정의를 가져오는 구성 원본입니다. 여러 통과를 체인으로 결합할 수 있으며, 각 통과는 이전 구성을 덮어쓰거나 추가할 수 있습니다.

## 규칙 사용자 정의 옵션 {#rule-customization-options}

기본 규칙 집합을 사용자 정의하여 규칙을 비활성화하고, 메타데이터를 재정의하거나, 규칙을 대체하거나 추가할 수 있습니다.

아래 표는 각 분석기 유형에 사용 가능한 사용자 정의 옵션을 보여줍니다.

| 사용자 정의                          | GitLab Advanced SAST                                                                                                                                             | GitLab Semgrep             | [기타 분석기](analyzers.md#official-analyzers) 및 [IaC 검사](../iac_scanning/_index.md) |
|----------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------|----------------------------------------------------|
| 기본 규칙 비활성화               | {{< yes >}}                                                                                                                                                      | {{< yes >}}                | {{< yes >}}                                        |
| 기본 규칙의 메타데이터 재정의  | {{< yes >}}                                                                                                                                                      | {{< yes >}}                | {{< yes >}}                                        |
| 기본 규칙 대체 또는 추가 | 기본 비-오염, 구조적 규칙의 동작 수정 및 파일과 원본 통과의 적용을 지원합니다. 기타 통과 유형은 무시됩니다. | 전체 통과를 지원합니다. | {{< no >}}                                         |

> [!note]
> GitLab 지원 범위는 Semgrep 분석기 통합 및 기본 규칙 집합으로 제한됩니다. 기본 규칙을 대체하거나 추가하는 경우 발생할 수 있는 호환성 문제를 관리해야 합니다. 자세한 내용은 [Semgrep 분석기 호환성 설명서](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep/-/blob/main/COMPATIBILITY.md)를 참조하세요.

### 기본 규칙 비활성화 {#disable-default-rules}

모든 SAST 분석기에 대해 기본 규칙을 비활성화할 수 있습니다. 예를 들어 조직 정책에 따라 특정 규칙을 제외할 수 있습니다.

다음 예제를 참조하세요:

- [GitLab Advanced SAST의 특정 기본 규칙 비활성화](#disable-specific-default-gitlab-advanced-sast-rules)
- [기타 SAST 분석기의 특정 기본 규칙 비활성화](#disable-specific-default-rules-of-other-sast-analyzers)

### 기본 규칙의 메타데이터 재정의 {#override-metadata-of-default-rules}

모든 SAST 분석기에 대해 기본 규칙의 특정 속성을 재정의할 수 있습니다. 예를 들어 조직 정책에 따라 취약성의 심각도를 재정의하거나 취약성 보고서에 표시할 다른 메시지를 선택할 수 있습니다.

[기본 규칙 메타데이터 재정의](#override-default-rule-metadata) 예제를 참조하세요.

### 기본 규칙 대체 또는 추가 {#replace-or-add-to-the-default-rules}

Semgrep 기반 SAST 분석기 및 GitLab Advanced SAST 분석기의 기본 규칙을 대체하거나 추가할 수 있습니다. 기본적으로 사용자 정의 규칙 집합을 정의하면 기본 규칙 집합이 대체됩니다. 기본 규칙 집합에 추가하려면 [규칙 집합 구성 파일](#configuration-methods)에서 `keepdefaultrules`를 `true`로 설정해야 합니다.

다음 예제를 참조하세요:

- [GitLab Advanced SAST의 모든 기본 규칙 대체](#replace-all-default-gitlab-advanced-sast-rules)
- [`semgrep`의 기본 규칙 대체 또는 추가](#replace-or-add-to-the-default-rules-of-semgrep)

### 규칙 집합 사용자 정의의 영향 {#effects-of-ruleset-customization}

다음 표는 SAST 규칙 집합을 사용자 정의할 때 발생하는 현상을 설명합니다:

| 작업                     | 검사 동작                                                                                                                                                               | 파이프라인 보안 탭                                                                                                      | 취약점 보고서                                                                                                                                   |
|----------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------|----------------------------------------------------------------------------------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| 규칙 비활성화             | 분석기는 여전히 취약성을 검사하지만 검사가 완료된 후 규칙의 결과가 제거됩니다. GitLab Advanced SAST는 초기 검사에서 비활성화된 규칙을 제외합니다. | 규칙이 비활성화되기 전에 규칙으로 탐지된 검사 결과는 다음 파이프라인 실행 후 더 이상 표시되지 않습니다.                        | 규칙이 비활성화되기 전에 규칙으로 탐지된 취약성은 [**더 이상 탐지되지 않음**](../vulnerability_report/_index.md#activity-filter)으로 표시됩니다. |
| 메타데이터 재정의          | 검사 동작에 변화가 없습니다.                                                                                                                                                 | 규칙이 재정의되기 전에 규칙으로 탐지된 검사 결과의 메타데이터는 다음 파이프라인 실행 후 업데이트됩니다.               | 규칙이 재정의되기 전에 규칙으로 탐지된 취약성의 메타데이터가 업데이트됩니다.                                                                 |
| 기본 규칙 집합 대체 | 기본 규칙 집합은 사용자 정의 규칙 집합을 지원하는 분석기에서 사용되지 않습니다.                                                                                               | 기본 규칙 집합의 규칙으로 탐지된 검사 결과는 대체된 후 다음 파이프라인 실행 후 더 이상 표시되지 않습니다. | 기본 규칙 집합의 규칙으로 탐지된 취약성은 [**더 이상 탐지되지 않음**](../vulnerability_report/_index.md#activity-filter)으로 표시됩니다. |

## 구성 방법 {#configuration-methods}

다음 방법으로 규칙 집합 사용자 정의를 제공할 수 있습니다:

로컬 규칙 집합 파일 : `sast-ruleset.toml` 파일에서 사용자 정의를 정의하여 리포지토리에 커밋하세요. 이 방법은 소스 코드와 함께 규칙 집합 구성을 버전 관리 하에 유지합니다.

원격 규칙 집합 파일 : 규칙 집합 파일이 호스팅되는 원격 위치(Git 리포지토리, URL 또는 기타 원본)를 지정하세요. 이 방법을 사용하면 규칙 집합을 중앙에서 관리하고 여러 프로젝트에서 재사용할 수 있습니다.

> [!note]
> 로컬 `.gitlab/sast-ruleset.toml` 파일은 원격 규칙 집합 파일보다 우선합니다.

규칙 집합으로 결합할 수 있는 구성 원본인 통과를 사용하여 사용자 정의를 제공합니다.

모든 규칙 집합 사용자 정의는 [SAST 규칙 집합 스키마](#schema)를 따라야 합니다.

### 로컬 규칙 집합 파일 사용 {#use-a-local-ruleset-file}

소스 코드와 함께 사용자 정의를 저장하려는 경우 로컬 규칙 집합 파일을 사용하세요. 로컬 사용자 정의는 개별 프로젝트에만 적용됩니다.

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.

로컬 규칙 집합 파일을 생성하려면:

1. 프로젝트의 루트에 `.gitlab` 디렉터리를 생성합니다. 이미 있는 경우는 제외입니다.
1. `.gitlab` 디렉터리에 `sast-ruleset.toml` 파일을 생성합니다.
1. `sast-ruleset.toml` 파일에 사용자 정의 규칙 집합을 추가합니다.
1. 로컬 규칙 집합 파일을 리포지토리에 커밋합니다.

로컬 규칙 집합 파일의 [예제](#examples)를 참조하세요.

### 원격 규칙 집합 파일 사용 {#use-a-remote-ruleset-file}

같은 사용자 정의를 여러 프로젝트에 적용하려는 경우 원격 규칙 집합 파일을 사용하세요. 원격 규칙 집합 파일은 규칙 집합을 사용하는 프로젝트의 리포지토리 외부에 저장됩니다.

원격 규칙 집합 파일을 사용하려면 다음을 수행하세요:

- 원격 규칙 집합을 생성합니다.
- 각 프로젝트에서 원격 규칙 집합을 참조합니다.

로컬 `.gitlab/sast-ruleset.toml` 파일은 원격 규칙 집합 파일보다 우선합니다.

> [!warning]
> `SAST_RULESET_GIT_REFERENCE` 설정이 프로젝트의 신뢰 경계를 참조된 리포지토리로 확장합니다. 해당 리포지토리의 유지 관리자는 SAST 작업에서 환경 변수를 평가하기 위해 [`interpolate`](#interpolate)를 활성화하는 것을 포함하여 언제든지 규칙 집합 구성을 변경할 수 있습니다. 제어하거나 신뢰하는 팀이 관리하는 리포지토리에서만 규칙 집합을 참조하세요. `SAST_RULESET_GIT_REFERENCE`를 공개 또는 제어되지 않는 리포지토리에 지정하지 마세요. 자동 변경을 방지하려면 참조를 특정 Git SHA에 고정하면 프로젝트의 명시적 업데이트 없이 규칙 집합을 변경할 수 없습니다.

#### 원격 규칙 집합 파일 생성 {#create-a-remote-ruleset-file}

여러 프로젝트의 중앙 규칙 집합으로 원격 규칙 집합 파일을 생성합니다.

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.

원격 규칙 집합을 생성하려면:

- 프로젝트의 리포지토리에 규칙 집합을 생성합니다.

  예를 들어 규칙 집합 파일은 [예제](#examples)를 참조하세요.

#### 원격 규칙 집합 파일 참조 {#reference-the-remote-ruleset-file}

원격 규칙 집합 파일을 참조하여 규칙을 프로젝트에 적용합니다.

사전 요구 사항:

- 프로젝트에 대한 Maintainer 또는 Owner 역할.
- [프로젝트의 원격 규칙 집합](#create-a-remote-ruleset-file)입니다.
- 원격 규칙 집합이 저장된 프로젝트에 대한 읽기 액세스 권한입니다. 예를 들어 작업 토큰 또는 그룹 액세스 토큰을 사용합니다.

각 프로젝트에서 원격 규칙 집합 파일을 참조하려면 다음을 수행하세요:

- CI/CD 변수 `SAST_RULESET_GIT_REFERENCE` 변수를 설정하여 원격 규칙 집합 파일의 위치를 지정합니다.

  원격 규칙 집합 파일 참조는 [Git URL](https://git-scm.com/docs/git-clone#_git_urls)과 유사한 형식을 사용하여 프로젝트 URI, 선택적 인증 및 선택적 Git SHA를 지정합니다. 변수는 다음 형식을 사용합니다:

  ```plaintext
  [<AUTH_USER>[:<AUTH_PASSWORD>]@]<PROJECT_PATH>[@<GIT_SHA>]
  ```

다음 예제는 SAST를 활성화하고 원격 규칙 집합 파일을 사용합니다. 이 예제에서 파일은 `example-ruleset-project`의 기본 브랜치에 커밋되며 경로는 `.gitlab/sast-ruleset.toml`입니다.

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  SAST_RULESET_GIT_REFERENCE: "gitlab.com/example-group/example-ruleset-project"
```

고급 예제는 [개인 원격 구성 예제 지정](#specify-a-private-remote-configuration)을 참조하세요.

#### 원격 구성 파일 문제 해결 {#troubleshooting-remote-configuration-files}

원격 구성 파일이 사용자 정의를 제대로 적용하지 않는 것 같으면 원인은 다음과 같을 수 있습니다:

1. 리포지토리에 로컬 `.gitlab/sast-ruleset.toml` 파일이 있습니다.
   - 기본적으로 로컬 파일이 있으면 원격 구성이 변수로 설정되었더라도 로컬 파일이 사용됩니다.
   - [SECURE_ENABLE_LOCAL_CONFIGURATION CI/CD 변수](../../../ci/variables/_index.md)를 `false`로 설정하여 로컬 구성 파일을 무시할 수 있습니다.
1. 인증에 문제가 있습니다.
   - 이것이 문제의 원인인지 확인하려면 인증이 필요하지 않은 리포지토리 위치에서 구성 파일을 참조해 보세요.

## 스키마 {#schema}

규칙 집합 구성 파일은 TOML 구문을 사용합니다. 다음 섹션에서 각 구성 요소의 구조 및 유효한 설정을 설명합니다.

### 최상위 섹션 {#top-level-section}

최상위 섹션은 [TOML 테이블](https://toml.io/en/v1.0.0#table)로 정의된 하나 이상의 구성 섹션을 포함합니다.

| 설정       | 설명                                                                                                                                            |
|---------------|--------------------------------------------------------------------------------------------------------------------------------------------------------|
| `[$analyzer]` | 분석기에 대한 구성 섹션을 선언합니다. 이름은 [SAST 분석기](analyzers.md#official-analyzers) 목록에서 정의된 이름을 따릅니다. |

구성 예제:

```toml
[semgrep]
...
```

기존 규칙을 수정하고 사용자 정의 규칙 집합을 빌드하는 구성 섹션을 만드는 것을 피하세요. 후자는 기본 규칙을 완전히 대체하기 때문입니다.

### `[$analyzer]` 구성 섹션 {#analyzer-configuration-section}

`[$analyzer]` 섹션을 사용하면 분석기의 동작을 사용자 정의할 수 있습니다. 유효한 속성은 생성하는 구성의 종류에 따라 다릅니다.

| 설정                 | 적용 대상    | 설명                                                                                                                                                                                                                                                                                                   |
|-------------------------|---------------|---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `[[$analyzer.ruleset]]` | 기본 규칙 | 기존 규칙에 대한 수정을 정의합니다.                                                                                                                                                                                                                                                                    |
| `interpolate`           | 모두           | `true`로 설정된 경우 구성에서 `$VAR`을 사용하여 환경 변수를 평가할 수 있습니다. 비밀번호나 토큰 유출을 방지하도록 이 기능을 주의해서 사용하세요. (기본값: `false`)                                                                                                                           |
| `description`           | 통과  | 사용자 정의 규칙 집합의 설명입니다.                                                                                                                                                                                                                                                                            |
| `targetdir`             | 통과  | 최종 구성을 유지해야 하는 디렉터리입니다. 비어 있으면 임의의 이름을 가진 디렉터리가 생성됩니다. 디렉터리는 최대 100MB의 파일을 포함할 수 있습니다. SAST 작업이 root가 아닌 사용자 권한으로 실행되는 경우 사용자가 이 디렉터리에 대한 읽기 및 쓰기 권한을 가지고 있는지 확인하세요. |
| `validate`              | 통과  | `true`로 설정된 경우 각 통과의 내용이 검증됩니다. 검증은 `yaml`, `xml`, `json`, 및 `toml` 콘텐츠에 대해 작동합니다. 올바른 검증자는 `[[$analyzer.passthrough]]` 섹션의 `target` 매개 변수에 사용된 확장자를 기반으로 식별됩니다. (기본값: `false`)                    |
| `timeout`               | 통과  | 통과 체인을 평가하는 데 소요되는 최대 시간입니다. 시간 초과 전에 모두입니다. 시간 초과는 300초를 초과할 수 없습니다. (기본값: 60)                                                                                                                                                                          |
| `keepdefaultrules`      | 통과  | `true`로 설정된 경우 분석기의 기본 규칙이 정의된 통과와 함께 활성화됩니다. (기본값: `false`)                                                                                                                                                                                 |

#### `interpolate` {#interpolate}

> [!warning]
> 비밀번호 유출 위험을 줄이려면 이 기능을 주의해서 사용하세요. `interpolate = true`일 때 구성의 `$VAR` 참조는 CI/CD 작업 환경에 대해 확장되며, CI/CD 변수 및 작업에 노출된 보호된 변수를 포함합니다. 확장된 값은 검사 출력, 아티팩트 또는 규칙 집합이 쓰는 다른 채널에 나타날 수 있습니다. [`SAST_RULESET_GIT_REFERENCE`](#reference-the-remote-ruleset-file)로 설정된 원격 위치에서 구성 파일을 로드한 경우 원격 작성자는 `interpolate`가 활성화되는지 제어합니다. 신뢰하는 리포지토리에서만 규칙 집합을 참조하세요.

아래 예제는 `$GITURL` 환경 변수를 사용하여 개인 리포지토리에 액세스하는 구성을 보여줍니다. 변수에는 사용자 이름 및 토큰(예: `https://user:token@url`)이 포함되므로 구성 파일에 명시적으로 저장되지 않습니다.

```toml
[semgrep]
  description = "My private Semgrep ruleset"
  interpolate = true

  [[semgrep.passthrough]]
    type  = "git"
    value = "$GITURL"
    ref = "main"
```

### `[[$analyzer.ruleset]]` 섹션 {#analyzerruleset-section}

`[[$analyzer.ruleset]]` 섹션은 단일 기본 규칙을 대상으로 하고 수정합니다. 분석기당 이러한 섹션을 하나 이상 정의할 수 있습니다.

| 설정                          | 설명                                             |
|----------------------------------|---------------------------------------------------------|
| `disable`                        | 규칙을 비활성화할지 여부입니다. (기본값: `false`) |
| `[$analyzer.ruleset.identifier]` | 수정할 기본 규칙을 선택합니다.                |
| `[$analyzer.ruleset.override]`   | 규칙의 재정의를 정의합니다.                     |

구성 예제:

```toml
[semgrep]
  [[semgrep.ruleset]]
    disable = true
    ...
```

### `[$analyzer.ruleset.identifier]` 섹션 {#analyzerrulesetidentifier-section}

`[$analyzer.ruleset.identifier]` 섹션은 수정하려는 기본 규칙의 식별자를 정의합니다.

| 설정 | 설명                                           |
|---------|-------------------------------------------------------|
| `type`  | 기본 규칙에서 사용하는 식별자의 유형입니다.      |
| `value` | 기본 규칙에서 사용하는 식별자의 값입니다. |

`type` 및 `value`의 올바른 값은 분석기에서 생성한 [`gl-sast-report.json`](_index.md#download-a-sast-report)을 보면 찾을 수 있습니다. 이 파일은 분석기의 CI 작업에서 작업 아티팩트로 다운로드할 수 있습니다.

예를 들어 아래 스니펫은 3개의 식별자를 가진 `semgrep` 규칙의 검사 결과를 보여줍니다. JSON 개체의 `type` 및 `value` 키는 이 섹션에 제공해야 하는 값에 해당합니다.

```json
...
  "vulnerabilities": [
    {
      "id": "7331a4b7093875f6eb9f6eb1755b30cc792e9fb3a08c9ce673fb0d2207d7c9c9",
      "category": "sast",
      "message": "Key Exchange without Entity Authentication",
      "description": "Audit the use of ssh.InsecureIgnoreHostKey\n",
      ...
      "identifiers": [
        {
          "type": "semgrep_id",
          "name": "gosec.G106-1",
          "value": "gosec.G106-1"
        },
        {
          "type": "cwe",
          "name": "CWE-322",
          "value": "322",
          "url": "https://cwe.mitre.org/data/definitions/322.html"
        },
        {
          "type": "gosec_rule_id",
          "name": "Gosec Rule ID G106",
          "value": "G106"
        }
      ]
    }
    ...
  ]
...
```

구성 예제:

```toml
[semgrep]
  [[semgrep.ruleset]]
    [semgrep.ruleset.identifier]
      type = "semgrep_id"
      value = "gosec.G106-1
    ...
```

### `[$analyzer.ruleset.override]` 섹션 {#analyzerrulesetoverride-section}

`[$analyzer.ruleset.override]` 섹션을 사용하면 기본 규칙의 속성을 재정의할 수 있습니다.

| 설정       | 설명                                                                                         |
|---------------|-----------------------------------------------------------------------------------------------------|
| `description` | 문제에 대한 상세 설명입니다.                                                                |
| `message`     | (더 이상 사용되지 않음) 문제에 대한 설명입니다.                                                            |
| `name`        | 규칙의 이름입니다.                                                                               |
| `severity`    | 규칙의 심각도입니다. 유효한 옵션은: `Critical`, `High`, `Medium`, `Low`, `Unknown`, `Info` |

> [!note]
> `message`는 분석기에 의해 입력되지만 `name` 및 `description`에 선호하여 [더 이상 사용되지 않음](https://gitlab.com/gitlab-org/security-products/analyzers/report/-/blob/1d86d5f2e61dc38c775fb0490ee27a45eee4b8b3/vulnerability.go#L22)입니다.

구성 예제:

```toml
[semgrep]
  [[semgrep.ruleset]]
    [semgrep.ruleset.override]
      severity = "Critical"
      name = "Command injection"
    ...
```

### `[[$analyzer.passthrough]]` 섹션 {#analyzerpassthrough-section}

> [!note]
> 통과 구성은 [Semgrep 기반 분석기](https://gitlab.com/gitlab-org/security-products/analyzers/semgrep)에서만 사용 가능합니다.

`[[$analyzer.passthrough]]` 섹션을 사용하면 분석기를 위한 사용자 정의 구성을 빌드할 수 있습니다. 분석기당 최대 20개의 이러한 섹션을 정의할 수 있습니다. 통과는 _통과 체인_으로 구성되며, 분석기의 기본 규칙을 대체하는 완전한 구성으로 평가됩니다.

통과는 순서대로 평가됩니다. 체인에서 나중에 나열된 통과는 더 높은 우선 순위를 가지며 `mode`에 따라 이전 통과에서 생성된 데이터를 덮어쓰거나 추가할 수 있습니다. 이는 기존 구성을 사용하거나 수정해야 하는 경우에 유용합니다.

단일 통과로 생성된 구성의 크기는 10MB로 제한됩니다.

| 설정     | 적용 대상     | 설명                                                                                                                                                                   |
|-------------|----------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `type`      | 모두            | `file`, `raw`, `git` 또는 `url` 중 하나입니다.                                                                                                                                        |
| `target`    | 모두            | 통과 평가로 작성된 데이터를 포함할 대상 파일입니다. 비어 있으면 임의의 파일 이름이 사용됩니다.                                                               |
| `mode`      | 모두            | `overwrite`인 경우 `target` 파일을 덮어씁니다. `append`인 경우 새 콘텐츠가 `target` 파일에 추가됩니다. `git` 유형은 `overwrite`만 지원합니다. (기본값: `overwrite`) |
| `ref`       | `type = "git"` | 끌어올 분기, 태그 또는 SHA의 이름을 포함합니다                                                                                                                      |
| `subdir`    | `type = "git"` | Git 리포지토리의 하위 디렉터리를 구성 원본으로 선택하는 데 사용됩니다.                                                                                              |
| `value`     | 모두            | `file`, `url` 및 `git` 유형의 경우 파일의 위치 또는 Git 리포지토리를 정의합니다. `raw` 유형의 경우 인라인 구성을 포함합니다.                            |
| `validator` | 모두            | 통과 평가 후 대상 파일에 대해 검증자(`xml`, `yaml`, `json`, `toml`)를 명시적으로 호출하는 데 사용됩니다.                                                |

#### 통과 유형 {#passthrough-types}

| 형식   | 설명                                          |
|--------|------------------------------------------------------|
| `file` | Git 리포지토리에 있는 파일을 사용합니다.    |
| `raw`  | 인라인으로 구성을 제공합니다.                    |
| `git`  | 원격 Git 리포지토리에서 구성을 끌어옵니다. |
| `url`  | HTTP를 사용하여 구성을 가져옵니다.                  |

> [!warning]
> `raw` 통과를 YAML 스니펫과 함께 사용할 때 `sast-ruleset.toml` 파일의 모든 들여쓰기를 공백으로 형식화하는 것이 좋습니다. YAML 사양은 탭보다 공백을 규정하며, 들여쓰기가 그에 따라 표현되지 않으면 분석기가 사용자 정의 규칙 집합을 구문 분석하지 못합니다.

## 예제 {#examples}

다음 예제는 일반적인 시나리오에 대해 규칙 집합을 사용자 정의하는 방법을 보여줍니다. 각 예제에 사용된 구성 옵션을 이해하려면 스키마 섹션을 사용하세요.

### GitLab Advanced SAST의 모든 기본 규칙 대체 {#replace-all-default-gitlab-advanced-sast-rules}

다음 사용자 정의 규칙 집합 구성을 사용하면 GitLab Advanced SAST 분석기의 기본 규칙 집합이 검사 중인 리포지토리의 `my-gitlab-advanced-sast-rules.yml` 파일에 포함된 사용자 정의 규칙 집합으로 대체됩니다.

```yaml
# my-gitlab-advanced-sast-rules.yml
---
rules:
- id: my-custom-rule
  pattern: print("Hello World")
  message: |
    Unauthorized use of Hello World.
  severity: ERROR
  languages:
  - python
```

```toml
[gitlab-advanced-sast]
  description = "My custom ruleset for Semgrep"

  [[gitlab-advanced-sast.passthrough]]
    type  = "file"
    value = "my-gitlab-advanced-sast-rules.yml"
```

### GitLab Advanced SAST의 특정 기본 규칙 비활성화 {#disable-specific-default-gitlab-advanced-sast-rules}

이 예제에서 특정 기본 규칙은 다음 기준에 따라 비활성화됩니다:

- 전체 취약성 클래스를 식별하는 CWE 식별자입니다.
- GitLab Advanced SAST에서 사용되는 특정 탐지 전략을 식별하는 GitLab Advanced SAST 규칙 ID입니다.
- 호환성을 위해 GitLab Advanced SAST 검사 결과에 포함된 관련 Semgrep 규칙 ID입니다. 이 추가 메타데이터를 사용하면 두 분석기가 같은 위치에서 유사한 검사 결과를 만들 때 검사 결과가 자동으로 전환됩니다.

이러한 식별자는 각 취약성의 [취약성 세부 정보](../vulnerabilities/_index.md)에 표시됩니다. 또한 [다운로드 가능한 SAST 보고서 아티팩트](_index.md#download-a-sast-report)에서 각 식별자 및 관련 `type`를 볼 수 있습니다.

```toml
[gitlab-advanced-sast]
  [[gitlab-advanced-sast.ruleset]]
    disable = true
    [gitlab-advanced-sast.ruleset.identifier]
      type = "cwe"
      value = "89"

  [[gitlab-advanced-sast.ruleset]]
    disable = true
    [gitlab-advanced-sast.ruleset.identifier]
      type = "gitlab-advanced-sast_id"
      value = "java-spring-csrf-unrestricted-requestmapping-atomic"

  [[gitlab-advanced-sast.ruleset]]
    disable = true
    [gitlab-advanced-sast.ruleset.identifier]
      type = "semgrep_id"
      value = "java_cookie_rule-CookieHTTPOnly"
```

### 기타 SAST 분석기의 특정 기본 규칙 비활성화 {#disable-specific-default-rules-of-other-sast-analyzers}

다음 사용자 정의 규칙 집합 구성을 사용하면 다음 기본 규칙이 보고서에서 생략됩니다:

- `semgrep` 규칙이 `gosec.G106-1`의 `semgrep_id` 또는 `322`의 `cwe`를 가집니다.
- `sobelow` 규칙이 `sql_injection`의 `sobelow_rule_id`를 가집니다.
- `flawfinder` 규칙이 `memcpy`의 `flawfinder_func_name`를 가집니다.

```toml
[semgrep]
  [[semgrep.ruleset]]
    disable = true
    [semgrep.ruleset.identifier]
      type = "semgrep_id"
      value = "gosec.G106-1"

  [[semgrep.ruleset]]
    disable = true
    [semgrep.ruleset.identifier]
      type = "cwe"
      value = "322"

[sobelow]
  [[sobelow.ruleset]]
    disable = true
    [sobelow.ruleset.identifier]
      type = "sobelow_rule_id"
      value = "sql_injection"

[flawfinder]
  [[flawfinder.ruleset]]
    disable = true
    [flawfinder.ruleset.identifier]
      type = "flawfinder_func_name"
      value = "memcpy"
```

### 기본 규칙 메타데이터 재정의 {#override-default-rule-metadata}

다음 사용자 정의 규칙 집합 구성을 사용하면 `semgrep` 유형 `CWE` 및 값 `322`으로 발견된 취약성의 심각도가 `Critical`로 재정의됩니다.

```toml
[semgrep]
  [[semgrep.ruleset]]
    [semgrep.ruleset.identifier]
      type = "cwe"
      value = "322"
    [semgrep.ruleset.override]
      severity = "Critical"
```

### `semgrep`의 기본 규칙 대체 또는 추가 {#replace-or-add-to-the-default-rules-of-semgrep}

다음 사용자 정의 규칙 집합 구성을 사용하면 `semgrep` 분석기의 기본 규칙 집합이 검사 중인 리포지토리의 `my-semgrep-rules.yml` 파일에 포함된 사용자 정의 규칙 집합으로 대체됩니다.

```yaml
# my-semgrep-rules.yml
---
rules:
- id: my-custom-rule
  pattern: print("Hello World")
  message: |
    Unauthorized use of Hello World.
  severity: ERROR
  languages:
  - python
```

```toml
[semgrep]
  description = "My custom ruleset for Semgrep"

  [[semgrep.passthrough]]
    type  = "file"
    value = "my-semgrep-rules.yml"
```

### `semgrep`에 대해 통과 체인을 사용하여 사용자 정의 구성 빌드 {#build-a-custom-configuration-using-a-passthrough-chain-for-semgrep}

다음 사용자 정의 규칙 집합 구성을 사용하면 `semgrep` 분석기의 기본 규칙 집합이 4개의 통과 체인을 평가하여 생성된 사용자 정의 규칙 집합으로 대체됩니다. 각 통과는 `/sgrules` 디렉터리 내 컨테이너에 작성되는 파일을 생성합니다. Git 리모트가 응답하지 않는 경우를 대비하여 `timeout`의 60초가 설정됩니다.

이 예제에서는 다양한 통과 유형이 시연됩니다:

- 2개의 `git` 통과는 `myrules` Git 리포지토리에서 `develop` 브랜치를 가져오고, `sast-rules` 리포지토리에서 리비전 `97f7686`를 가져오며, `go` 하위 디렉터리의 파일만 고려합니다.
  - `sast-rules` 항목은 구성에서 나중에 나타나므로 더 높은 우선 순위를 갖습니다.
  - 2개의 체크아웃 간에 파일 이름 충돌이 있으면 `sast-rules` 리포지토리의 파일이 `myrules` 리포지토리의 파일을 덮어씁니다.
- `raw` 통과로 해당 `value`을 `/sgrules/insecure.yml`에 작성합니다.
- `url` 통과로 URL에서 호스팅되는 구성을 가져와 `/sgrules/gosec.yml`에 작성합니다.

그 후 Semgrep은 `/sgrules` 아래에 있는 최종 구성으로 호출됩니다.

```toml
[semgrep]
  description = "My custom ruleset for Semgrep"
  targetdir = "/sgrules"
  timeout = 60

  [[semgrep.passthrough]]
    type  = "git"
    value = "https://gitlab.com/user/myrules.git"
    ref = "develop"

  [[semgrep.passthrough]]
    type  = "git"
    value = "https://gitlab.com/gitlab-org/secure/gsoc-sast-vulnerability-rules/playground/sast-rules.git"
    ref = "97f7686db058e2141c0806a477c1e04835c4f395"
    subdir = "go"

  [[semgrep.passthrough]]
    type  = "raw"
    target = "insecure.yml"
    value = """
rules:
- id: "insecure"
  patterns:
    - pattern: "func insecure() {...}"
  message: |
    Insecure function insecure detected
  metadata:
    cwe: "CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"
  severity: "ERROR"
  languages:
    - "go"
"""

  [[semgrep.passthrough]]
    type  = "url"
    value = "https://semgrep.dev/c/p/gosec"
    target = "gosec.yml"
```

### 체인에서 통과의 모드 구성 {#configure-the-mode-for-passthroughs-in-a-chain}

체인의 통과 간에 발생하는 파일 이름 충돌을 처리하는 방법을 선택할 수 있습니다. 기본 동작은 같은 이름의 기존 파일을 덮어쓰는 것이지만 `mode = append`을 선택하여 나중 파일의 콘텐츠를 이전 파일에 추가할 수 있습니다.

`file`, `url` 및 `raw` 통과 유형에만 `append` 모드를 사용할 수 있습니다.

다음 사용자 정의 규칙 집합 구성을 사용하면 2개의 `raw` 통과를 사용하여 `/sgrules/my-rules.yml` 파일을 반복적으로 조합합니다. 그러면 Semgrep에 규칙 집합으로 제공됩니다. 각 통과는 규칙 집합에 단일 규칙을 추가합니다. 첫 번째 통과는 [Semgrep 규칙 구문](https://semgrep.dev/docs/writing-rules/rule-syntax)에 따라 최상위 `rules` 개체를 초기화하는 역할을 합니다.

```toml
[semgrep]
  description = "My custom ruleset for Semgrep"
  targetdir = "/sgrules"
  validate = true

  [[semgrep.passthrough]]
    type  = "raw"
    target = "my-rules.yml"
    value = """
rules:
- id: "insecure"
  patterns:
    - pattern: "func insecure() {...}"
  message: |
    Insecure function 'insecure' detected
  metadata:
    cwe: "..."
  severity: "ERROR"
  languages:
    - "go"
"""

  [[semgrep.passthrough]]
    type  = "raw"
    mode  = "append"
    target = "my-rules.yml"
    value = """
- id: "secret"
  patterns:
    - pattern-either:
        - pattern: '$MASK = "..."'
    - metavariable-regex:
        metavariable: "$MASK"
        regex: "(password|pass|passwd|pwd|secret|token)"
  message: |
    Use of hard-coded password
  metadata:
    cwe: "..."
  severity: "ERROR"
  languages:
    - "go"
"""
```

```yaml
# /sgrules/my-rules.yml
rules:
- id: "insecure"
  patterns:
    - pattern: "func insecure() {...}"
  message: |
    Insecure function 'insecure' detected
  metadata:
    cwe: "..."
  severity: "ERROR"
  languages:
    - "go"
- id: "secret"
  patterns:
    - pattern-either:
        - pattern: '$MASK = "..."'
    - metavariable-regex:
        metavariable: "$MASK"
        regex: "(password|pass|passwd|pwd|secret|token)"
  message: |
    Use of hard-coded password
  metadata:
    cwe: "..."
  severity: "ERROR"
  languages:
    - "go"
```

### 개인 원격 구성 지정 {#specify-a-private-remote-configuration}

다음 예제는 SAST를 활성화하고 공유 규칙 집합 사용자 정의 파일을 사용합니다:

- 파일은 인증이 필요한 개인 프로젝트에서 다운로드됩니다. 이 예제는 CI/CD 변수에 안전하게 저장된 [그룹 액세스 토큰](../../group/settings/group_access_tokens.md)을 사용합니다.
- 파일은 기본 브랜치 대신 특정 Git 커밋 SHA에서 체크아웃됩니다.

```yaml
include:
  - template: Jobs/SAST.gitlab-ci.yml

variables:
  SAST_RULESET_GIT_REFERENCE: "oauth2:$GROUP_ACCESS_TOKEN@gitlab.com/example-group/example-ruleset-project@c8ea7e3ff126987fb4819cc35f2310755511c2ab"
```

### 시연 프로젝트 {#demonstration-projects}

[시연 프로젝트](https://gitlab.com/gitlab-org/security-products/demos/analyzer-configurations)를 검색합니다. 이는 이러한 구성 옵션의 일부를 보여줍니다.

이러한 많은 프로젝트는 원격 규칙 집합을 사용하여 규칙을 재정의하거나 비활성화하는 것을 시연하며 어느 분석기용인지로 그룹화됩니다.

또한 원격 규칙 집합 설정에 대한 비디오 시연도 볼 수 있습니다:

- [원격 규칙 집합을 포함한 IaC 분석기](https://youtu.be/VzJFyaKpA-8)
