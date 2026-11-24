---
stage: Application Security Testing
group: Threat Research
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 악의적인 소스 스캔
description: 소스 코드에서 알려진 악의적인 도메인에 대한 참조를 감지합니다.
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com
- 상태:  실험

{{< /details >}}

{{< history >}}

- [GitLab.com에서 도입됨](https://gitlab.com/groups/gitlab-org/-/work_items/22809) \- GitLab 19.3에서 [실험](../../../policy/development_stages_support.md#experiment)으로 제공됩니다.

{{< /history >}}

악의적인 소스 스캔은 리포지토리에서 polyfill.io 공급망 공격과 관련된 CDN과 같은 알려진 악의적인 외부 도메인에 대한 참조를 찾습니다. 각 참조는 SAST 취약성으로 보고됩니다.

이 실험의 향후 발전을 결정하는 데 도움을 주려면 [이슈 634760](https://gitlab.com/gitlab-org/gitlab/-/work_items/634760)에 피드백을 공유하세요.

## 악의적인 소스 스캔 켜기 {#turn-on-malicious-sources-scanning}

악의적인 소스 스캔을 켜려면 [악의적인 소스 CI/CD 구성 요소](https://gitlab.com/explore/catalog/security-products/experiments/malicious-sources)를 `.gitlab-ci.yml` 파일에 추가하세요:

```yaml
include:
  - component: gitlab.com/security-products/experiments/malicious-sources/malicious-sources@0.2.0
```

이 구성 요소는 `malicious-sources-scan` 작업을 `test` 스테이지에 추가합니다. 검출 결과는 [취약성 보고서](../vulnerability_report/_index.md)와 머지 리퀘스트에 나타납니다.

## 감지된 도메인 {#detected-domains}

악의적인 소스 스캔은 `Critical` 심각도로 이러한 도메인에 대한 참조를 감지합니다:

- `bootcdn.net`
- `bootcss.com` 및 `cdn.bootcss.com`
- `polyfill.com`
- `polyfill.io` 및 `cdn.polyfill.io`
- `staticfile.net` 및 `cdn.staticfile.net`
- `staticfile.org` 및 `cdn.staticfile.org`
- `unionadjs.com`

분석기는 `https://`, `http://`, 프로토콜 상대 (`//`) 참조를 대소문자를 구분하지 않고 일치시킵니다.

## 경로 제외 {#exclude-paths}

파일 및 디렉터리를 건너뛰려면 `SAST_EXCLUDED_PATHS`을(를) gitignore 스타일 패턴의 쉼표로 구분된 목록으로 설정하세요. `.git` 디렉터리는 항상 제외됩니다.

```yaml
variables:
  SAST_EXCLUDED_PATHS: "node_modules, vendor, **/*.min.js"
```

## 사용자 지정 규칙 추가 {#add-custom-rules}

다른 도메인을 감지하려면 `MALICIOUS_SOURCES_CUSTOM_RULES`을(를) YAML 규칙 목록으로 설정하세요. 사용자 지정 규칙은 기본 제공 규칙에 추가됩니다.

```yaml
variables:
  MALICIOUS_SOURCES_CUSTOM_RULES: |
    - rule_id: malicious.example.test
      substring: //malicious.example.test
      severity: High
      title: "Malicious CDN: malicious.example.test"
      description: "Known malicious CDN observed in supply chain attacks."
```

| 필드              | 필수 | 설명 |
|--------------------|----------|-------------|
| `rule_id`          | 예      | 고유 ID입니다. 기본 제공 규칙을 재정의하려면 규칙의 도메인을 ID로 사용하세요. |
| `substring`        | 예      | 각 줄과 일치하는 리터럴 텍스트입니다. 정규식은 지원되지 않습니다. |
| `severity`         | 예      | `Info`, `Low`, `Medium`, `High` 또는 `Critical` 중 하나입니다. |
| `title`            | 예      | 검출 결과에 표시되는 이름입니다. |
| `description`      | 예      | 취약성 보고서에 표시되는 설명입니다. |
| `case_insensitive` | 아니요       | `true`일 때 일치는 대소문자를 무시합니다. 기본값은 `false`입니다. |
| `disabled`         | 아니요       | `true`일 때 규칙이 제거됩니다. 기본값은 `false`입니다. |

기본 제공 규칙을 비활성화하려면 해당 도메인에서 `disabled: true`을(를) 설정하세요:

```yaml
variables:
  MALICIOUS_SOURCES_CUSTOM_RULES: |
    - rule_id: cdn.polyfill.io
      disabled: true
```

YAML이 유효하지 않으면 스캔이 오류로 실패합니다.
