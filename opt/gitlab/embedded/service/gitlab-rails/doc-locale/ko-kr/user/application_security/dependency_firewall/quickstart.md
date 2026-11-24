---
stage: Security Risk Management
group: Pipeline Security
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 의존성 방화벽 시작하기
description: 의존성 방화벽을 켜고 정책을 경고 모드에 추가한 다음 결과를 확인합니다.
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed
- 상태: 베타

{{< /details >}}

의존성 방화벽을 설정하고 첫 번째 결과를 확인합니다. 방화벽을 켜고 일치하는 항목을 보고하지만 차단하지 않는 정책을 추가하고 패키지를 설치한 다음 방화벽이 본 내용을 읽습니다.

이 가이드의 정책은 `warn` 모드를 사용하므로 시도할 때 아무것도 차단되지 않습니다. 마지막 단계는 강제 적용으로 전환하는 방법을 설명합니다.

약 15분이 소요될 것으로 예상합니다.

전제 조건:

- 네임스페이스는 Premium 또는 Ultimate 티어에 액세스할 수 있어야 합니다.
- GitLab.com에서는 최상위 그룹의 소유자 역할이 있어야 합니다. GitLab Self-Managed에서는 관리자여야 합니다.
- 이 기능이 지원하는 패키지 관리자가 있는 프로젝트가 필요합니다. 이 가이드는 npm을 사용합니다.

## 1단계:  방화벽 켜기 {#step-1-turn-on-the-firewall}

GitLab.com에서:

1. 상단 바에서 **검색 또는 이동**을 선택하고 최상위 그룹을 찾습니다.
1. **설정** > **안전함**을 선택합니다.
1. **종속성 방화벽 활성화** 토글을 켭니다.

GitLab Self-Managed에서:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. **설정** > **보안 및 규정 준수**를 선택합니다.
1. **의존성 방화벽**을 확장합니다.
1. **종속성 방화벽 활성화** 체크박스를 선택한 다음 **변경사항 저장**을 선택합니다.

아직 평가되지 않았습니다. 방화벽에는 정책이 필요하며, 이를 다음에 추가합니다.

## 2단계:  경고 모드에서 정책 추가 {#step-2-add-a-policy-in-warn-mode}

정책은 [보안 정책 프로젝트](../policies/enforcement/security_policy_projects.md)에 있습니다. 그룹에 보안 정책 프로젝트가 없으면 첫 번째 정책을 저장할 때 GitLab이 이를 생성합니다.

1. 상단 바에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. **안전함** > **정책**을 선택합니다.
1. **새 정책**을 선택합니다.
1. **의존성 방화벽 정책**에서 **정책 선택**을 선택합니다.
   <!-- markdownlint-disable-next-line MD044 -->
1. 편집기는 규칙 모드(양식)로 열립니다. 대신 정책을 붙여 넣으려면 **.yaml 모드**를 선택합니다.
1. 편집기의 내용을 다음 정책으로 바꿉니다:

   ```yaml
   dependency_firewall_policy:
     - name: Audit high-risk packages
       description: Reports packages with critical vulnerabilities or malicious code.
       enabled: true
       enforcement_type: warn
       rules:
         - type: risk_severity
           denied:
             # threshold is the number of vulnerabilities you permit.
             # 0 permits none, so a single critical vulnerability matches.
             - severity: critical
               threshold: 0
         - type: malicious
           denied:
             - is_malicious: true
   ```

1. **머지 리퀘스트로 설정**을 선택합니다.
1. 머지 리퀘스트를 검토하고 병합합니다.

이 정책은 중요한 취약성이 있거나 악성으로 플래그된 모든 패키지를 보고합니다. `enforcement_type`이(가) `warn`이므로 아무것도 차단되지 않습니다.

## 3단계:  방화벽을 통해 패키지 설치 {#step-3-install-a-package-through-the-firewall}

정책은 [GitLab CLI](../../../editor_extensions/gitlab_cli/_index.md)에 의해 평가되므로 먼저 설치하고 인증합니다:

```shell
glab auth login
```

정책이 적용되는 프로젝트를 복제한 다음 일반적인 명령 앞에 `glab df`로 종속 항목을 설치합니다:

```shell
git clone https://gitlab.example.com/my-group/my-project.git
cd my-project
glab df npm install
```

`npm`은(는) 항상 그대로 실행됩니다. CLI는 정책에 대해 확인된 각 패키지를 확인합니다.

## 4단계:  결과 읽기 {#step-4-read-the-result}

`npm`이(가) 완료되면 CLI는 방화벽이 본 내용을 출력합니다:

```plaintext
╭──────────────────────────────────────────────────────────────────────────────────╮
│ ▲  GitLab Dependency Firewall                                                    │
│ 1 package warning                                                                │
├──────────────────────────────────────────────────────────────────────────────────┤
│    PACKAGE  VERSION  REASON                                                      │
│ ▲  lodash   4.17.15  Package 'lodash' violates 'Audit high-risk packages' policy │
╰──────────────────────────────────────────────────────────────────────────────────╯
```

`▲`은(는) 경고된 패키지를 표시합니다. 정책이 `enforced` 모드였다면 이 패키지는 대신 `✖`을(를) 표시했을 것이고 `npm`이(가) 실패했을 것입니다.

요약이 출력되지 않으면 패키지가 정책과 일치하지 않습니다. 일치 항목을 보려면 `glab df npm install lodash@4.17.15`(알려진 취약점이 있음)을 시도합니다.

> [!tip]
> 패키지를 설치하지 않고 확인하려면 `glab df package pkg:npm/lodash@4.17.15`을(를) 실행합니다. 자세한 내용은 [`glab dependency-firewall package`](https://docs.gitlab.com/cli/dependency-firewall/package/)를 참조하세요.

GitLab에서 동일한 결과를 보려면 그룹 또는 프로젝트에서 **안전함** > **의존성 방화벽**을 선택합니다. 대시보드는 차단되고 경고된 항목을 계산하고 각 활성 규칙을 나열합니다.

## 5단계:  강제 적용으로 전환 {#step-5-switch-to-enforcement}

경고가 차단할 것으로 예상하는 항목과 일치하면 정책을 변경하여 강제 적용합니다:

1. **안전함** > **정책**을 선택합니다.
1. 정책 행에서 **편집**을 선택합니다.
   <!-- markdownlint-disable-next-line MD044 -->
1. **강제적용 모드**에 대해 **강제적용**을 선택합니다. **.yaml 모드**에서 `enforcement_type`를 `enforced`로 설정합니다.
1. **머지 리퀘스트로 설정**을 선택한 다음 검토하고 병합합니다.

일치하는 패키지는 이제 거부됩니다. 패키지 관리자는 `403 Forbidden` 응답을 받으며 설치가 실패하여 패키지가 시스템 또는 파이프라인에 도달하지 못하게 됩니다.

강제 적용을 단계적으로 적용합니다. [`policy_scope`](_index.md#policy-scope)를 사용하여 정책을 몇 가지 프로젝트에 먼저 적용하고 [바이패스 설정](_index.md#bypass-settings)을 사용하여 계속 게시해야 하는 서비스 계정을 제외합니다.

## 다음 단계 {#next-steps}

- [라이선스](_index.md#license-rules)에 대한 규칙을 추가하거나 [위험 심각도 임계값](_index.md#risk-severity-rules)을 조정합니다.
- CI/CD에서 [작업 스크립트에서 `glab df`](_index.md#use-the-dependency-firewall-in-cicd)를 사용하여 방화벽을 실행합니다.
