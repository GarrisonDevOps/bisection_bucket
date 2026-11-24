---
stage: Security Risk Management
group: Pipeline Security
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 의존성 방화벽
description: "패키지 관리자가 패키지를 설치하기 전에 허용되지 않는 라이선스, 높은 취약성 위험 또는 악성 코드가 있는 패키지를 차단합니다."
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed
- 상태:  베타

{{< /details >}}

{{< history >}}

- [GitLab 19.0에서 도입되었으며](https://gitlab.com/groups/gitlab-org/-/epics/22189) [실험](../../../policy/development_stages_support.md)으로 제공됩니다.
- GitLab 19.5에서 [베타](../../../policy/development_stages_support.md)로 변경되었습니다. GitLab.com 및 GitLab Self-Managed에서 Premium 및 Ultimate에서 사용 가능합니다. GitLab Dedicated 지원은 일반 가용성을 위해 계획되어 있습니다.

{{< /history >}}

> [!warning]
> 의존성 방화벽은 [베타](../../../policy/development_stages_support.md) 상태입니다. 동작, 정책 스키마 및 지원되는 에코시스템은 릴리스 간에 변경될 수 있습니다. 정책을 적용하기 전에 `warn` 모드에서 테스트하세요.

의존성 방화벽을 사용하여 개발자와 CI/CD 작업이 설치하는 패키지를 제어합니다. 의존성 방화벽 정책은 라이선스, 취약성 위험 및 악성 코드에 대해 정의한 규칙에 대해 각 패키지를 평가합니다. 패키지가 거부 규칙과 일치하면 방화벽이 다운로드를 거부하고 결정을 기록합니다.

## 의존성 방화벽은 어떻게 작동하나요 {#how-does-dependency-firewall-work}

[GitLab CLI](../../../editor_extensions/gitlab_cli/_index.md)를 통해 패키지 관리자를 `glab dependency-firewall`(으)로 실행하거나 더 짧은 별칭 `glab df`(으)로 실행합니다. 각 패키지는 패키지 관리자가 해결할 때 머신에 도달하기 전에 평가됩니다:

1. 패키지 관리자가 npmjs.com, PyPI, Maven Central 또는 RubyGems.org와 같이 이미 구성된 레지스트리에서 패키지를 요청합니다.
1. CLI가 로컬 검사 프록시를 통해 요청을 가로채고 GitLab에 프로젝트에 적용되는 정책에 대해 패키지 이름과 버전을 평가하도록 요청합니다.
1. GitLab은 세 가지 결과 중 하나를 반환합니다. 허용된 패키지는 평소대로 가져옵니다. 경고 패키지는 가져오고 보고됩니다. 차단된 패키지는 거부되며 패키지 관리자는 `403 Forbidden` 응답을 수신합니다.

GitLab은 평가하는 패키지를 호스팅하거나 미러링하지 않으므로 종속성을 GitLab 패키지 레지스트리로 이동하거나 프로젝트에서 이미 사용 중인 레지스트리 구성을 변경할 필요가 없습니다.

## 지원되는 에코시스템 {#supported-ecosystems}

| 에코시스템 | 패키지 관리자 |
|-----------|------------------|
| Java      | Maven, Gradle |
| Node.js   | npm, pnpm, Yarn |
| Python    | pip, `uv`, Poetry, pipenv, twine |
| Ruby      | `gem`, Bundler |

다른 에코시스템의 패키지는 평가 없이 가져옵니다.

## 제한 사항 {#restrictions}

- `glab df`이 프록시하는 트래픽만 평가됩니다. `npm install` 없이 자체적으로 실행되는 패키지 관리자는 방화벽에 도달하지 않습니다. 방화벽을 유일한 레지스트리 경로로 만들려면 [방화벽 우회 방지](#prevent-bypassing-the-firewall)를 참조하세요.
- 정책은 패키지 이름, 버전 및 에코시스템에 대해 평가됩니다. 방화벽은 패키지 메타데이터 데이터베이스 및 [GitLab 권고 데이터베이스](../gitlab_advisory_database/_index.md)에서 라이선스, 취약성 및 악성 패키지 데이터를 확인합니다.
- 패키지 메타데이터 데이터베이스에 없는 패키지는 허용됩니다. 허용된 결과는 GitLab이 패키지에 대한 라이선스 또는 취약성 데이터를 보유하고 있다는 주장이 아닙니다.
- 최대 5개의 의존성 방화벽 정책이 보안 정책 프로젝트당 허용됩니다. 이 제한은 `dependency_firewall_policies_per_configuration_limit` 애플리케이션 설정으로 제어됩니다.
- 로컬 프록시가 레지스트리에 직접 연결합니다. 아웃바운드 기업 프록시를 사용하지 않으므로 `glab df`은 프록시가 필요한 네트워크의 레지스트리에 도달할 수 없습니다.
- 레지스트리는 HTTPS를 사용해야 합니다. 프록시는 HTTPS 트래픽만 허용하고 순수 `http://` 요청을 거부합니다.
- 패키지 관리자 캐시에 이미 있는 패키지는 다시 평가되지 않습니다. Maven은 `~/.m2/repository/`에서, npm은 `node_modules/`에서, Bundler는 `vendor/bundle/`에서 읽습니다. 방화벽은 패키지 관리자가 네트워크를 통해 패키지를 가져올 때만 평가됩니다.

## 전제 조건 {#prerequisites}

의존성 방화벽을 사용하려면:

- 네임스페이스가 Premium 또는 Ultimate 티어에 액세스할 수 있어야 합니다.
- [보안 정책 프로젝트](../policies/enforcement/security_policy_projects.md)가 프로젝트 또는 상위 그룹 중 하나에 연결되어 있어야 합니다.
- 의존성 방화벽이 켜져 있어야 합니다. [의존성 방화벽 켜기](#turn-on-the-dependency-firewall)를 참조하세요.
- 개발자는 GitLab CLI를 설치하고 GitLab 인스턴스에 대해 인증해야 합니다.
- 개발자와 CI/CD 작업을 실행하는 사용자는 프로젝트에서 최소한 Reporter 역할을 가져야 합니다.

## 의존성 방화벽 켜기 {#turn-on-the-dependency-firewall}

GitLab.com에서 방화벽은 각 최상위 그룹에 대해 켜집니다. GitLab Self-Managed에서는 전체 인스턴스에 대해 한 번만 켜집니다.

### GitLab.com {#on-gitlabcom}

전제 조건:

- 최상위 그룹에 대한 Owner 역할이 있어야 합니다.

의존성 방화벽을 켜려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. **설정** > **안전함**을 선택합니다.
1. **종속성 방화벽 활성화** 토글을 켭니다.

이 설정은 최상위 그룹에서만 사용 가능합니다. 하위 그룹과 프로젝트는 최상위 그룹에서 설정을 상속합니다.

### GitLab Self-Managed {#on-gitlab-self-managed}

전제 조건:

- 관리자여야 합니다.

의존성 방화벽을 켜려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. **설정** > **보안 및 규정 준수**를 선택합니다.
1. **의존성 방화벽**을 확장합니다.
1. **종속성 방화벽 활성화** 체크박스를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

이 설정은 인스턴스의 모든 프로젝트에 적용됩니다. 그룹별 토글이 없습니다.

방화벽을 끄려면 제공 서비스에 대한 단계를 반복하고 설정을 끕니다. 기존 정책은 보존되지만 방화벽이 패키지 평가를 중지합니다.

## 방화벽 우회 방지 {#prevent-bypassing-the-firewall}

방화벽은 `glab df`이 볼 수 있는 트래픽만 평가합니다. 자체적으로 실행되는 패키지 관리자는 해결하는 모든 것을 설치하고, AI 코딩 에이전트도 마찬가지입니다. 둘 다 방화벽에 도달하지 않으므로 블록을 볼 수 없습니다. 또한 위에서 언급했듯이 패키지가 캐시될 수 있습니다.

그 간격을 좁히려면 모든 호출자가 접두사를 기억하도록 의존하는 대신 네트워크 송신 지점에서 방화벽을 적용합니다.

CLI는 메타데이터 및 인덱스 요청, 허용되고 경고된 패키지에 대한 요청을 포함하여 레지스트리로 전달하는 모든 요청에 다음 헤더를 추가합니다:

```plaintext
X-Gitlab-Dependency-Firewall: allowed
```

해당 헤더가 있을 때만 HTTPS 트래픽을 패키지 레지스트리로 허용하도록 송신 프록시 또는 게이트웨이를 구성합니다. `glab df` 외부에서 실행되는 패키지 관리자는 그러한 헤더를 전송하지 않으므로 요청이 조용히 성공하지 않고 네트워크 경계에서 거부됩니다.

이 제어에는 다음이 필요합니다:

- HTTPS 트래픽을 검사하는 송신 제어 지점입니다. 헤더는 CLI가 레지스트리에 여는 TLS 세션 내부를 이동하므로 대상 호스트만 보는 게이트웨이는 이를 읽을 수 없습니다.
- 팀이 사용하는 각 레지스트리 호스트 이름에 대한 규칙(예: `registry.npmjs.org`, `pypi.org`, `files.pythonhosted.org`, `repo.maven.apache.org` 및 `rubygems.org`)입니다.

헤더는 CLI에 의해 설정되므로 이것은 경계가 아닌 가드레일입니다. 헤더에 대해 알지 못하는 패키지 관리자 또는 에이전트를 중지합니다. 헤더를 스스로 설정하는 호출자는 여전히 레지스트리에 도달합니다.

헤더는 또한 정책이 요청을 평가했음을 증명하지 않습니다. CLI는 방화벽이 프로젝트를 평가하지 않을 때(예: 방화벽이 꺼져 있거나 프로젝트를 찾을 수 없을 때)에도 이를 추가합니다. 헤더는 요청이 `glab df`을 통과했음을 보여줍니다. CLI는 차단된 패키지를 전달하지 않습니다.

일부 구성도 CLI 주변의 트래픽을 전송합니다. 예를 들어 `gemrc` 파일의 `http_proxy:` 설정은 CLI가 `gem` 및 `bundle`에 적용하는 프록시 설정보다 우선하므로 해당 트래픽은 검사되지 않습니다. RubyGems는 시스템 `gemrc` 파일, `~/.gemrc` 및 `GEMRC` 변수로 명명된 파일을 읽습니다. 리포지토리에서 이러한 파일을 읽지 않으므로 커밋된 프로젝트 파일은 이를 야기할 수 없지만 CI 이미지 또는 개발자 머신은 가능합니다.

## 베타 기간 중 가격 책정 {#pricing-during-beta}

의존성 방화벽은 베타 기간 동안 무료입니다. 일반 가용성 시 [GitLab Credits](../../../subscriptions/gitlab_credits.md)를 통해 청구되는 유료 기능이 됩니다. 청구되기 전에 옵트인해야 하며 GitLab은 그 전에 알림을 제공합니다.

## 의존성 방화벽 정책 생성 {#create-a-dependency-firewall-policy}

의존성 방화벽 정책은 [보안 정책 프로젝트](../policies/enforcement/security_policy_projects.md)의 `.gitlab/security-policies/policy.yml` 파일에 저장됩니다. 정책 편집기에서 정책을 빌드하거나 해당 파일에 직접 커밋합니다.

그룹 수준에서 정책을 생성하면 정책이 그룹의 모든 프로젝트 및 해당 하위 그룹에 적용됩니다. 프로젝트 수준에서 정책을 생성하면 정책이 해당 프로젝트에만 적용됩니다.

전제 조건:

- 기본적으로 그룹, 서브그룹 또는 프로젝트 소유자만 보안 정책 프로젝트를 만들거나 할당하는 데 필요한 [권한](../../permissions.md#project-application-security)을 가집니다. 또는 [보안 정책 링크 관리](../../custom_roles/abilities.md#security-policy-management) 권한이 있는 사용자 지정 역할을 만들 수 있습니다.

의존성 방화벽 정책을 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 그룹 또는 프로젝트를 찾습니다.
1. **안전함** > **정책**을 선택합니다.
1. **새 정책**을 선택합니다.
1. **의존성 방화벽 정책**에서 **정책 선택**을 선택합니다.
1. 필드를 완성합니다. 각각의 의미는 [정책 스키마](#policy-schema)를 참조하세요.
1. **머지 리퀘스트로 설정**을 선택합니다.
1. 병합 요청을 검토하고 병합합니다.

머지 리퀘스트가 병합되면 정책이 다음 평가에 적용됩니다.

### 편집기 모드 {#editor-modes}

정책 편집기가 규칙 모드로 열립니다. 이는 정책을 빌드하는 양식입니다. 규칙 모드는 이름, 설명, 범위, 적용 모드 및 규칙을 포함합니다. 우회 설정은 **고급** 아래에 있습니다.

대신 정책을 YAML로 작성하려면 **YAML 모드**를 선택합니다. YAML 모드를 사용하여 프로젝트 간에 정책을 복사하거나 규칙 모드에서 표시하지 않는 필드를 사용합니다.

언제든지 두 모드 사이를 전환할 수 있습니다. YAML에 오류가 포함되어 있으면 규칙 모드는 수정할 때까지 꺼집니다. 자세한 내용은 [정책 편집기](../policies/_index.md#policy-editor)를 참조하세요.

### 정책 스키마 {#policy-schema}

의존성 방화벽 정책에는 다음 최상위 필드가 있습니다.

| 필드              | 형식    | 필수 | 설명 |
|--------------------|---------|----------|-------------|
| `name`             | 문자열  | 예      | 정책의 이름입니다. 최대 255자입니다. |
| `description`      | 문자열  | 아니요       | 정책의 더 긴 설명입니다. |
| `enabled`          | 부울 | 예      | 정책이 평가되는지 여부입니다. `false`(으)로 설정하여 제거하지 않고 정책을 끕니다. |
| `enforcement_type` | 문자열  | 예      | `enforced` 또는 `warn` 중 하나입니다. [적용 모드](#enforcement-modes)를 참조하세요. |
| `rules`            | 배열   | 예      | 하나 이상의 규칙입니다. [규칙 유형](#rule-types)을 참조하세요. |
| `bypass_settings`  | 개체  | 아니요       | 정책을 우회하는 사용자 및 액세스 토큰입니다. [우회 설정](#bypass-settings)을 참조하세요. |
| `policy_scope`     | 개체  | 아니요       | 정책이 적용되는 그룹 및 프로젝트입니다. [정책 범위](#policy-scope)를 참조하세요. |

### 적용 모드 {#enforcement-modes}

`enforcement_type` 필드는 규칙이 일치할 때 어떻게 되는지를 제어합니다:

- `enforced`: 방화벽이 패키지를 거부합니다. 패키지 관리자는 `403 Forbidden` 응답을 수신하고 패키지가 설치되지 않습니다.
- `warn`: 방화벽이 패키지를 가져오고 실행 요약에서 보고합니다. 이 모드를 사용하여 정책을 적용하기 전에 테스트합니다.

어떤 활성 정책의 규칙도 패키지와 일치하지 않으면 방화벽이 이를 허용합니다.

### 규칙 유형 {#rule-types}

정책에는 최소한 하나의 규칙이 포함되어야 합니다. 각 규칙에는 `type` 필드가 있으며 `license`, `risk_severity` 또는 `malicious` 중 하나입니다. 규칙 모드에서 **규칙 유형 선택**에서 유형을 선택합니다.

> [!note]
> 규칙 모드는 **취약점** 규칙 유형도 제공합니다. 이것은 더 이상 사용되지 않으며 제거되고 있습니다. 대신 **위험 심각도**를 사용하면 단일 심각도 하한과 일치하는 대신 심각도별로 취약성을 계산합니다.

#### 라이선스 규칙 {#license-rules}

라이선스 규칙은 SPDX 라이선스 이름으로 패키지를 일치시킵니다. `denied`(을)를 사용하여 나열된 라이선스를 선언하는 패키지를 차단합니다. `allowed`(을)를 사용하여 목록에 없는 라이선스를 선언하는 패키지를 차단합니다. 두 키는 상호 배타적입니다.

```yaml
rules:
  - type: license
    denied:
      - name: GNU General Public License v3.0 only
      - name: GNU Affero General Public License v3.0 only
```

```yaml
rules:
  - type: license
    allowed:
      - name: MIT License
      - name: Apache License 2.0
```

#### 위험 심각도 규칙 {#risk-severity-rules}

위험 심각도 규칙은 각 심각도에서 가지고 있는 알려진 취약성의 수로 패키지를 일치시킵니다. 각 항목은 `severity`(을)를 `threshold`(와)과 쌍을 이루며, 이는 해당 심각도에서 허용하는 최대 취약성 수입니다. 패키지는 그 이상을 가지고 있으면 거부됩니다.

`threshold`(이)가 `0`이면 없음을 허용하므로 해당 심각도에서 취약성이 하나라도 있으면 패키지를 거부합니다. `threshold`(이)가 `2`이면 두 개를 허용하고 세 번째를 거부합니다.

심각도는 `critical`, `high`, `medium` 및 `low`입니다. 각 심각도를 최대 한 번 나열합니다. `denied`만 지원됩니다.

다음 규칙은 중요한 취약성이 있는 패키지, 높은 취약성이 2개 이상인 패키지 또는 중간 취약성이 10개 이상인 패키지를 차단합니다:

```yaml
rules:
  - type: risk_severity
    denied:
      - severity: critical
        threshold: 0
      - severity: high
        threshold: 2
      - severity: medium
        threshold: 10
```

알려지지 않은 심각도의 취약성은 절대 계산되지 않습니다.

#### 악성 패키지 규칙 {#malicious-package-rules}

악성 패키지 규칙은 GitLab 악성 패키지 데이터 피드가 플래그한 패키지를 차단합니다. `denied`만 지원되며 단일 항목은 `is_malicious: true`(이)어야 합니다.

```yaml
rules:
  - type: malicious
    denied:
      - is_malicious: true
```

### 규칙 예외 {#rule-exceptions}

각 규칙은 선택적 `exceptions` 배열을 지원합니다. 예외 항목은 패키지 URL(PURL) 또는 CVE와 같은 취약성 식별자입니다. 일치하는 예외는 해당 규칙의 평가에서 패키지 또는 취약성을 제거합니다.

PURL 예외를 사용하여 라이선스 또는 악성 규칙에서 내부 패키지를 제외합니다. PURL은 버전을 포함하거나 생략할 수 있습니다. 버전을 생략하면 예외가 패키지의 모든 버전에 적용됩니다.

```yaml
rules:
  - type: license
    denied:
      - name: GNU General Public License v3.0 only
    exceptions:
      - purl: pkg:npm/my-internal-lib
      - purl: pkg:npm/another-lib@1.2.3
```

ID 예외를 사용하여 위험 심각도 규칙에서 특정 CVE를 제외합니다. 제외된 취약성은 어떤 임계값으로도 계산되지 않습니다.

```yaml
rules:
  - type: risk_severity
    denied:
      - severity: high
        threshold: 0
    exceptions:
      - id: CVE-2024-12345
```

### 우회 설정 {#bypass-settings}

우회 설정을 통해 특정 사용자 또는 액세스 토큰이 정책을 건너뜁니다. 나열된 사용자가 만든 요청 또는 나열된 액세스 토큰으로 만든 요청은 허용되며 우회 이유가 기록됩니다.

```yaml
bypass_settings:
  users:
    - id: 1234
  access_tokens:
    - id: 5678
```

사용자 ID를 찾으려면 사용자의 프로필을 보고 URL에 `.json`(을)를 추가합니다. 액세스 토큰 ID를 찾으려면 프로젝트 또는 그룹 액세스 토큰 목록을 봅니다.

내부 패키지를 설치해야 하는 서비스 계정 또는 인시던트 중 긴급 액세스에 대해 우회 설정을 사용합니다.

### 정책 범위 {#policy-scope}

기본적으로 의존성 방화벽 정책은 정책이 적용되는 모든 프로젝트에 적용됩니다. `policy_scope`(을)를 사용하여 특정 그룹 또는 프로젝트 세트로 범위를 좁히거나 광범위한 롤아웃에서 프로젝트를 제외합니다.

`policy_scope`(은)는 `groups` 및 `projects` 두 개의 키를 허용합니다. 각 키는 `including` 목록, `excluding` 목록 또는 둘 다를 허용합니다.

모든 경우에 각 항목은 `id`(이)를 가진 객체입니다.

| 필드                | 형식  | 설명 |
|----------------------|-------|-------------|
| `groups.including`   | 배열 | 정책이 적용되는 그룹입니다. |
| `groups.excluding`   | 배열 | 정책이 적용되지 않는 그룹입니다. |
| `projects.including` | 배열 | 정책이 적용되는 프로젝트입니다. |
| `projects.excluding` | 배열 | 정책이 적용되지 않는 프로젝트입니다. `type`(이)가 `personal` 또는 `archived`인 경우 모든 개인 또는 보관 프로젝트를 제외합니다. |

예를 들어 다음 범위는 두 그룹에 정책을 적용하지만 해당 그룹의 하나의 프로젝트와 모든 보관 프로젝트를 제외합니다:

```yaml
policy_scope:
  groups:
    including:
      - id: 100
      - id: 101
  projects:
    excluding:
      - id: 555
      - type: archived
```

`policy_scope`이 생략되면 정책이 보안 정책 프로젝트의 적용 대상에 있는 모든 프로젝트에 적용됩니다.

> [!note]
> 의존성 방화벽 `policy_scope`(은)는 `groups` 및 `projects`만 지원합니다. 규정 준수 프레임워크 및 보안 특성은 지원되지 않습니다.

### 정책 예제 {#example-policy}

다음 정책:

- 카피레프트 라이선스를 차단합니다
- 중요한 취약성을 가지고 있는 패키지를 차단합니다
- 높은 취약성이 2개 초과인 패키지
- 악성 패키지를 차단합니다
- 그리고 내부 라이브러리와 알려진 거짓 양성 CVE를 제외합니다.

```yaml
---
dependency_firewall_policy:
  - name: Restrict copyleft licenses and high-risk packages
    description: Blocks copyleft-licensed packages, high-risk packages, and malicious packages.
    enabled: true
    enforcement_type: enforced
    rules:
      - type: license
        denied:
          - name: GNU General Public License v3.0 only
          - name: GNU Affero General Public License v3.0 only
        exceptions:
          - purl: pkg:npm/my-internal-lib
      - type: risk_severity
        denied:
          - severity: critical
            threshold: 0
          - severity: high
            threshold: 2
        exceptions:
          - id: CVE-2024-12345
      - type: malicious
        denied:
          - is_malicious: true
    bypass_settings:
      users:
        - id: 1234
    policy_scope:
      projects:
        excluding:
          - type: archived
```

## 의존성 방화벽 정책 편집 {#edit-a-dependency-firewall-policy}

의존성 방화벽 정책을 편집하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 그룹 또는 프로젝트를 찾습니다.
1. **안전함** > **정책**을 선택합니다.
1. 정책 행에서 **편집**을 선택합니다.
1. 정책을 편집합니다.
1. **머지 리퀘스트로 설정**을 선택합니다.
1. 병합 요청을 검토하고 병합합니다.

업데이트된 정책은 머지 리퀘스트가 병합된 후 다음 평가에서 적용됩니다.

## 의존성 방화벽 활동 보기 {#view-dependency-firewall-activity}

의존성 방화벽 대시보드는 방화벽이 차단하고 경고한 내용과 활성 정책 규칙을 보여줍니다.

전제 조건:

- 의존성 방화벽이 켜져 있어야 합니다.
- 그룹 또는 프로젝트에 대한 보안 정책을 읽을 권한이 있어야 합니다.

대시보드를 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 그룹 또는 프로젝트를 찾습니다.
1. **안전함** > **의존성 방화벽**을 선택합니다.

대시보드에는 두 개의 요약 카드와 표가 있습니다:

- **모든 활동**은 선택한 기간에 차단된 패키지, 경고된 패키지 및 총 트리거 수를 계산합니다.
- **활성 정책 규칙**은 활성화된 규칙을 계산하고 차단 수와 경고 수로 분할합니다.
- **정책**은 각 활성 규칙과 해당 정책 이름, 규칙 유형, 모드, 상태, 트리거 수 및 마지막 수정 시간 및 수정자를 나열합니다.

**최근 7일** 또는 **최근 30일**을 선택하여 기간을 변경합니다. 기본값은 지난 7일입니다.

### 감사 이벤트 {#audit-events}

모든 평가도 프로젝트 범위 감사 이벤트를 생성합니다. 감사 이벤트를 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. **안전함** > **감사 이벤트**를 선택합니다.

다음 감사 이벤트 유형이 기록됩니다:

| 이벤트 유형                    | 기록된 시기 |
|-------------------------------|---------------|
| `dependency_firewall_allowed` | 방화벽이 우회 또는 예외를 통해 패키지를 허용합니다. |
| `dependency_firewall_warned`  | `warn` 정책이 패키지와 일치합니다. |
| `dependency_firewall_blocked` | `enforced` 정책이 패키지와 일치합니다. |

각 이벤트는 패키지, 작업, 정책 이름 및 일치하는 규칙을 기록합니다. 자세한 내용은 [감사 이벤트 유형](../../compliance/audit_event_types.md#dependency-firewall)을 참조하세요.
