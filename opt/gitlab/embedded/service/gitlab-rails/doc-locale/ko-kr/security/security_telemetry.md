---
stage: Security
group: Security Operations
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "GitLab이 생성하는 보안 원격 측정을 이해하고, GitLab.com, GitLab Self-Managed, GitLab Dedicated에서 수집하는 방법을 알아봅니다."
title: 보안 원격 측정
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

보안 원격 측정은 보안 사건을 감지하고 조사하기 위해 GitLab에서 수집하는 데이터입니다.

GitLab 보안 운영 팀이 GitLab Self-Managed 및 GitLab Dedicated 인스턴스의 관리자와 GitLab.com의 네임스페이스 소유자를 위해 이러한 권장 사항을 작성했습니다. GitLab이 생성하는 보안 원격 측정의 종류, 각각이 말해주는 것, 그리고 제공 서비스 및 구독 티어에서 수집할 수 있는 내용을 이해하는 데 사용합니다. 로깅 및 모니터링 프로세스는 조직에서 정의한 것을 보완하지만 대체하지는 않습니다.

감지가 실행되면 [보안 사건에 대응](responding_to_security_incidents.md)을(를) 따라 사건을 포함하고 완화합니다.

> [!warning]
> 이러한 제안 및 권장 사항을 자신의 책임 하에 사용합니다. 사용 가능한 원격 측정은 제공 서비스, 구독 티어, 구성에 따라 달라집니다.

## 보안 원격 측정의 종류 {#kinds-of-security-telemetry}

GitLab은 두 가지 주요 보안 원격 측정을 생성합니다. 서로 다른 질문에 답하고 다양한 방식으로 수집되므로 가능한 한 둘 다 사용합니다.

[감사 이벤트](../user/compliance/audit_events.md) : GitLab이 보안 관련 작업이 발생할 때 내보내는 구조화된 이벤트입니다: 사용자 로그인, 권한 변경, 토큰 생성, 설정 변경. 각 이벤트는 누가 했는지, 무엇이 영향을 받았는지, 어느 IP 주소에서, 언제를 기록합니다. 감사 이벤트는 "사용자가 GitLab에서 무엇을 했습니까?"라는 질문에 답합니다. GitLab은 수백 개의 [감사 이벤트 유형](../user/compliance/audit_event_types.md)을(를) 정의합니다.

[애플리케이션 로그](../administration/logs/_index.md) : GitLab Rails 애플리케이션 및 주변 구성 요소에서 작성한 로그 파일입니다: Workhorse, Gitaly, GitLab Shell, Sidekiq. 모든 HTTP 요청, Git 작업, 백그라운드 작업을 기록합니다. 이 활동의 대부분은 감사 이벤트가 되지 않습니다: 실패하거나 차단된 요청, 감사되지 않은 엔드포인트로의 요청, 요청의 정확한 매개변수, GitLab이 처리하기 위해 취한 내부 단계. 애플리케이션 로그는 "GitLab 내부에서 무엇이 발생했습니까?"라는 질문에 답하며, GitLab 자체에 대한 악용 시도를 감지하기 위한 유일한 소스입니다.

이 둘 외에도 CI/CD 작업 로그 및 자격 증명 인벤토리와 같은 보안 관련 데이터를 자체적으로 기록하는 여러 GitLab 기능이 있습니다. 자세한 내용은 [보안 데이터의 다른 소스](#other-sources-of-security-data)를 참조하세요.

## 제공 서비스 및 티어에서 수집할 수 있는 것 {#what-you-can-collect-on-your-offering-and-tier}

다음 표는 각 제공 서비스에서 보안 원격 측정을 수집하는 각 방법에 필요한 최소 티어를 나타냅니다. GitLab Dedicated는 Ultimate에서만 사용 가능하므로 이 표의 모든 기능이 GitLab Dedicated에서 사용 가능합니다.

| 수집 방법 | GitLab.com | GitLab Self-Managed | GitLab Dedicated |
|-------------------|------------|---------------------|------------------|
| GitLab에서 감사 이벤트 보기 또는 API로 검색 | Premium | Premium | 예 |
| 감사 이벤트를 보안 정보 및 이벤트 관리(SIEM) 시스템 또는 다른 대상으로 스트리밍 | Ultimate | Ultimate | 예 |
| 애플리케이션 로그 수집 | 사용 불가능합니다. GitLab은 이러한 로그를 운영하고 유지합니다. | 모든 티어 | 예 |

실제로 이는 다음을 의미합니다:

- Free에서는 자신의 로그인 이벤트를 보고 CI/CD 작업 로그를 검토할 수 있지만 그룹, 프로젝트 또는 인스턴스 감사 이벤트는 볼 수 없습니다. GitLab Self-Managed에서는 여전히 `audit_json.log`에 기록된 작은 수의 감사 이벤트를 포함하는 애플리케이션 로그를 수집할 수 있습니다.
- Premium에서는 GitLab에서 감사 이벤트를 보고 검색할 수 있으며 API로 검색할 수 있지만 스트리밍할 수는 없습니다. GitLab에서 발생하는 일에 대해 맹목적이지는 않지만 감지 및 장기 보존은 사용자에게 달려 있습니다.
- Ultimate에서는 감사 이벤트를 거의 실시간으로 SIEM에 스트리밍할 수 있으며 GitLab에 표시되지 않는 스트리밍 전용 이벤트를 받을 수 있습니다.

## 감사 이벤트 보기 {#view-audit-events}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

Premium 및 Ultimate에서는 설정 없이 감사 이벤트를 볼 수 있습니다:

- GitLab UI에서 [그룹, 프로젝트, 인스턴스 수준](../administration/compliance/audit_event_reports.md)에서. 인스턴스 수준 감사 이벤트는 GitLab Self-Managed 및 GitLab Dedicated에서 사용 가능합니다.
- [감사 이벤트 API](../api/audit_events.md)를 사용하여 UI와 동일한 이벤트를 반환합니다.

Free에서는 볼 수 있는 유일한 감사 이벤트는 사용자 프로필의 **인증 로그**에 있는 자신의 [로그인 이벤트](../user/compliance/audit_events.md#sign-in-audit-events)입니다.

감사 이벤트 보기는 특정 사용자 또는 프로젝트의 임시 확인 및 사후 조사에는 충분합니다. 감지에는 충분하지 않으며 몇 가지 이유가 있습니다:

- 각 쿼리는 30일 기간으로 제한되며 UI는 이벤트 세부 정보를 검색하지 않습니다.
- 일부 이벤트 유형은 [스트리밍 전용](#streaming-only-events)이며 GitLab에 표시되지 않습니다.
- 이벤트를 경고하거나 다른 데이터와 관련시키거나 보존 기간을 제어할 수 없습니다.

감사 이벤트를 스트리밍할 수 없는 경우 일정에 따라 API에서 검색하여 로그 플랫폼에 로드할 수 있습니다. 이렇게 하면 검색 가능한 복사본과 감지 기반을 제공하지만 지연이 있고 스트리밍 전용 이벤트는 없습니다.

## 감사 이벤트 스트리밍 {#stream-audit-events}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

감사 이벤트 스트리밍은 발생하는 즉시 제어하는 대상으로 모든 감사 이벤트를 전송하므로 SIEM에 완전한 거의 실시간 기록이 있습니다. 스트리밍은 모든 제공 서비스에서 감사 이벤트를 수집하는 권장 방법이며 스트리밍 전용 이벤트를 받는 유일한 방법입니다.

### 스트리밍 전용 이벤트 {#streaming-only-events}

일부 감사 이벤트 유형은 스트리밍 전용입니다: GitLab에 저장되지 않으며 스트리밍 대상이 있는 경우에만 받습니다. 많은 경우 민감한 데이터에 대한 읽기 액세스를 기록하므로 감지에 특히 유용합니다. 다음은 예시입니다.

| 스트리밍 전용 이벤트 | 말하는 것 |
|----------------------|-------------------|
| `repository_git_operation` | 리포지토리를 누가 복제, 페치 또는 푸시했는지 |
| `repository_file_accessed_api` 및 `repository_file_accessed_web` | API 또는 웹 UI를 통해 파일을 누가 읽었는지 |
| `job_artifact_downloaded` | CI/CD 작업 아티팩트를 누가 다운로드했는지 |
| `variable_viewed_api` 및 `variable_viewed_graphql` | CI/CD 변수를 누가 읽었는지 |
| `personal_access_token_used_from_unseen_ip` | 이전에 보지 못한 IP 주소에서 토큰이 사용되었습니다 |
| `user_authenticated_using_job_token` | CI/CD 작업 토큰을 사용하여 인증했습니다 |

전체 목록이 아닙니다. 모든 스트리밍 전용 이벤트에 대해 [사용 가능한 감사 이벤트 유형](../user/compliance/audit_event_types.md#available-audit-event-types) 목록에서 **데이터베이스에 저장됨** 열을 참조하세요.

### 스트리밍 설정 {#set-up-streaming}

스트리밍을 구성하는 위치는 제공 서비스에 따라 다릅니다:

| 제공 서비스 | 누가 구성하는지 | 범위 | 추가 정보 |
|----------|-------------------|-------|------------------|
| GitLab.com | 최상위 그룹의 소유자 | 최상위 그룹, 그 하위 그룹 및 그 프로젝트 | [최상위 그룹을 위한 감사 이벤트 스트리밍](../user/compliance/audit_event_streaming.md) |
| GitLab Self-Managed 및 GitLab Dedicated | 관리자 | 전체 인스턴스입니다. 조직 전체에서 다양한 대상을 위해 최상위 그룹별로 구성할 수도 있습니다. | [인스턴스의 감사 이벤트 스트리밍](../administration/compliance/audit_event_streaming.md) |

스트리밍은 HTTP 엔드포인트, Google Cloud Logging, Amazon S3의 세 가지 대상 유형을 지원합니다. 여러 대상을 추가하고 [이벤트 유형별로 각각을 필터링](../user/compliance/audit_event_streaming.md#update-event-filters)할 수 있습니다.

수신 측을 설계할 때:

- 가끔 중복 배달이 발생할 수 있으므로 이벤트 `id`에서 중복을 제거합니다.
- GitLab.com에서 대상에서 [GitLab.com IP 범위](../user/gitlab_com/_index.md#ip-range)의 트래픽을 허용합니다.
- 대상을 민감한 것으로 취급합니다. 스트리밍된 이벤트에는 전체 이벤트 세부 정보가 포함됩니다.
- 많은 대상을 계획하는 경우 [대상 제한](../administration/instance_limits.md#audit-events-streaming-destination-limits)을(를) 확인하세요.

## 애플리케이션 로그 수집 {#collect-application-logs}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

감사 이벤트는 작업이 발생했음을 알려줍니다. 애플리케이션 로그는 어떻게 발생했는지를 알려줍니다. 감사 이벤트 요약 수준의 요청 세부 정보를 제공하고 감사 이벤트가 없는 많은 보안 관련 활동(예: 실패한 요청, 속도 제한된 요청, 감사되지 않은 엔드포인트로의 요청, 각 요청의 전체 매개변수)을 기록합니다. 애플리케이션 로그를 수집할 수 있으면 수집합니다.

### 보안 관련 로그 {#security-relevant-logs}

다음 로그는 보안 모니터링에 가장 적합합니다. 경로는 Linux 패키지 설치에서 `/var/log/gitlab/`에 상대적입니다. [로그 시스템](../administration/logs/_index.md#accessing-logs-on-helm-chart-installations) 설명서는 Helm 차트 설치에서 동일한 로그를 찾는 위치를 설명합니다.

| 로그 | 기록하는 것 | 감지하는 데 사용 |
|-----|-----------------|------------------|
| [`gitlab-rails/production_json.log`](../administration/logs/_index.md#production_jsonlog) | 웹 애플리케이션에서 처리하는 모든 요청: 사용자, IP, 경로, 상태, 매개변수. | 의심스러운 로그인 흐름, 설정 변경, 웹 엔드포인트에 대한 악용 시도. |
| [`gitlab-rails/api_json.log`](../administration/logs/_index.md#api_jsonlog) | 모든 REST API 요청: 사용자, IP, 경로, 상태, 매개변수. | 토큰 남용, API를 통한 대량 데이터 액세스, 손상된 계정의 자동화. |
| [`gitlab-rails/graphql_json.log`](../administration/logs/_index.md#graphql_jsonlog) | GraphQL 쿼리 및 해당 복잡성. | GraphQL을 통한 열거 및 대량 데이터 액세스. |
| [`gitlab-rails/auth_json.log`](../administration/logs/_index.md#auth_jsonlog) | 속도 제한 및 보호된 경로 규칙에 의해 차단된 요청. | 무차별 대입 공격 및 자격 증명 채우기. |
| [`gitlab-rails/audit_json.log`](../administration/logs/_index.md#audit_jsonlog) | 파일에 작성된 감사 이벤트. | 스트리밍할 수 없는 티어를 포함한 감사 이벤트의 로컬 복사본. |
| [`gitlab-rails/application_json.log`](../administration/logs/_index.md#application_jsonlog) | 사용자 생성 및 프로젝트 삭제와 같은 인스턴스 이벤트. | 계정 및 프로젝트 생명 주기 변경. |
| [`gitlab-shell/gitlab-shell.log`](../administration/logs/_index.md#gitlab-shelllog) | SSH를 통한 Git 작업: 사용자, 프로젝트, 명령. | 배포 키를 포함한 SSH를 통한 리포지토리 복제 및 푸시. |
| [`gitlab-workhorse/current`](../administration/logs/_index.md#workhorse-logs) | Git over HTTPS 및 파일 다운로드를 포함한 모든 트래픽에 대한 HTTP 액세스 로그. | HTTPS를 통한 리포지토리 복제, 아티팩트 및 내보내기 다운로드, 웹 스캔. |
| [`gitaly/current`](../administration/logs/_index.md#gitaly-logs) | 리포지토리 작업 및 Git 훅. | 비정상적인 리포지토리 액세스 패턴, 훅 실패. |
| [`sidekiq/current`](../administration/logs/_index.md#sidekiq-logs) | 백그라운드 작업: 가져오기, 내보내기, 미러 업데이트, 알림. | 유출을 위해 사용되는 프로젝트 내보내기 및 미러 구성. |

### 로그 전체에서 요청 추적 {#follow-a-request-across-logs}

GitLab이 처리하는 모든 요청은 상관 ID를 가져오며, 동일한 ID가 요청이 닿는 모든 로그(Workhorse에서 Rails, Gitaly, Sidekiq까지)에 나타납니다. 한 로그에서 의심스러운 항목을 찾으면 모든 로그에서 해당 상관 ID를 검색하여 전체 요청을 재구성합니다. 자세한 내용은 [상관 ID로 관련 로그 항목 찾기](../administration/logs/tracing_correlation_id.md)를 참조하세요.

### 애플리케이션 로그를 플랫폼으로 전송 {#ship-application-logs-to-your-platform}

GitLab Self-Managed에서 : 선택한 로그 shipper를 사용하여 각 노드의 로그를 로그 플랫폼으로 전송합니다. GitLab은 로그를 로컬에서 순환시키고 결국 오래된 파일을 삭제하므로 순환이 제거하기 전에 전송합니다. 회전을 조정하려면 [로깅 구성](https://docs.gitlab.com/omnibus/settings/logs/)을(를) 참조하세요. 다중 노드 배포에서 플랫폼이 모든 노드의 로그를 집계하므로 상관 ID 검색이 전체 요청을 다룹니다.

GitLab Dedicated에서 : GitLab은 애플리케이션 및 인프라 로그를 AWS 계정의 Amazon S3 버킷에 전달하고 1년 동안 보존합니다. Switchboard에서 로그 수집기에 버킷에 대한 읽기 액세스 권한을 부여하고, 1년 이상 로그가 필요한 경우 자신의 스토리지로 복사합니다. 설정 단계는 [GitLab Dedicated에 대한 애플리케이션 로그](../administration/dedicated/monitor.md)를 참조하세요.

## 보안 데이터의 다른 소스 {#other-sources-of-security-data}

감사 이벤트 및 애플리케이션 로그 외에도 보안 관련 데이터를 직접 검토하거나 감지에 당겨 올 수 있는 여러 GitLab 기능이 있습니다. 대부분은 수집 설정 없이 GitLab UI에서 사용 가능하며 몇 개는 모든 티어에서 사용 가능합니다.

| 데이터 소스 | 가용성 | 보여주는 것 |
|-------------|--------------|---------------|
| [로그인 감사 이벤트](../user/compliance/audit_events.md#sign-in-audit-events) | 모든 티어 | 사용자 프로필의 **인증 로그**에서 사용자의 성공한 로그인. Free에서 사용 가능한 유일한 감사 이벤트. |
| [CI/CD 작업 로그](../ci/jobs/job_logs.md) | 모든 티어 | 실행된 명령, 노출된 시크릿, 예기치 않은 사용자가 시작한 파이프라인. 저장소 및 보존을 위해 [작업 로그 관리](../administration/cicd/job_logs.md)를 참조하세요. |
| [작업 토큰 인증 로그](../ci/jobs/ci_job_token.md#job-token-authentication-log) | 모든 티어 | CI/CD 작업 토큰으로 프로젝트에 인증한 프로젝트. |
| [자격 증명 인벤토리](../administration/credentials_inventory.md) | Ultimate | 인스턴스 또는 최상위 그룹에 존재하는 개인, 그룹 및 프로젝트 액세스 토큰, SSH 키 및 GPG 키(범위 및 만료 포함). |
| [시크릿 푸시 보호](../user/application_security/secret_detection/secret_push_protection/_index.md) 및 [파이프라인 시크릿 검색](../user/application_security/secret_detection/_index.md) | 시크릿 푸시 보호: Ultimate. 파이프라인 시크릿 검색: 모든 계층. | 사용자가 푸시하려고 시도하거나 리포지토리에 커밋된 시크릿. |

<!-- Keep this table in sync with the detection data sources table on detecting_security_incidents.md. -->

## 다음 단계 {#next-steps}

원격 측정이 SIEM 또는 로그 플랫폼에 도달한 후:

- 모니터링할 신호를 결정하고 TLDR 감지 규칙을 배포하려면 [감지 기능 구축](detecting_security_incidents.md#build-a-detection-capability)을(를) 참조하세요.
- 감지가 의존하는 이벤트 유형이 플랫폼에 도달하는지 확인합니다(특히 스트리밍 전용 이벤트). API 대신 스트리밍으로 감사 이벤트를 수집하는 경우 받지 못한 이벤트에 의존하는 감지를 확인합니다.
- 조사 및 규정 준수 요구 사항을 충족하는 보존 기간을 정의합니다. GitLab은 저장된 감사 이벤트를 무기한 보존하지만 스트리밍 대상 및 로그 플랫폼이 실제로 검색할 수 있는 것을 정의합니다.

## 관련 항목 {#related-topics}

- [보안 사건](security_incidents.md)
- [GitLab 보안](_index.md)
