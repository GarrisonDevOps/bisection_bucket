---
stage: none
group: unassigned
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: GitLab.com 설정
description: GitLab.com 인스턴스의 구성입니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

이 설정은 GitLab.com에서 사용되며 [GitLab.com](https://about.gitlab.com/pricing/) 고객이 이용할 수 있습니다.

[GitLab.com용 인스턴스 구성 페이지](https://gitlab.com/help/instance_configuration)에서 이 설정들 중 일부를 확인할 수 있습니다.

## 계정 및 제한 설정 {#account-and-limit-settings}

GitLab.com에서는 이러한 계정 제한을 사용합니다. 설정이 나열되지 않은 경우 기본값은 [GitLab Self-Managed 인스턴스와 동일합니다](../../administration/settings/account_and_limit_settings.md):

| 설정                                                                                                                                                                                                            | GitLab.com 기본값 |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|--------------------|
| [LFS를 포함한 리포지토리 크기](../../administration/settings/account_and_limit_settings.md#repository-size-limit)                                                                                                 | 10GB              |
| [최대 가져오기 크기](../project/settings/import_export.md#import-a-project-and-its-data)                                                                                                                          | 5GiB              |
| [최대 내보내기 크기](../project/settings/import_export.md#export-a-project-and-its-data)                                                                                                                          | 40GiB             |
| [외부 객체 스토리지에서 가져오기 위한 최대 원격 파일 크기](../../administration/settings/import_and_export_settings.md#maximum-remote-file-size-for-imports)                                             | 10GiB             |
| [직접 전송으로 원본 GitLab 인스턴스에서 가져올 때의 최대 다운로드 파일 크기](../../administration/settings/import_and_export_settings.md#maximum-download-file-size-for-imports-by-direct-or-offline-transfer) | 5GiB              |
| 최대 첨부 파일 크기                                                                                                                                                                                            | 100MiB            |
| [가져온 아카이브의 최대 압축 해제 파일 크기](../../administration/settings/import_and_export_settings.md#maximum-decompressed-file-size-for-imported-archives)                                           | 25GiB             |
| [최대 푸시 크기](../../administration/settings/account_and_limit_settings.md#max-push-size)                                                                                                                     | 5GiB              |

리포지토리 크기 제한에 도달하거나 초과한 경우 다음을 수행할 수 있습니다:

- [Git를 사용하여 리포지토리 크기 줄이기](../project/repository/repository_size.md#methods-to-reduce-repository-size).
- [추가 저장소 구입](https://about.gitlab.com/pricing/licensing-faq/#can-i-buy-more-storage).

> [!note]
> `git push`와 GitLab 프로젝트 가져오기는 Cloudflare를 통한 각 요청마다 5GiB로 제한됩니다. 파일 업로드 이외의 가져오기는 이 제한의 영향을 받지 않습니다. 리포지토리 제한은 공개 및 비공개 프로젝트 모두에 적용됩니다.

## 백업 {#backups}

GitLab.com의 전체 프로젝트를 백업하려면 내보낼 수 있습니다:

- [UI를 통해](../project/settings/import_export.md).
- [API를 통해](../../api/project_import_export.md#export-a-project). API를 사용하여 프로그래밍 방식으로 Amazon S3와 같은 저장소 플랫폼에 내보내기를 업로드할 수도 있습니다.

내보내기 시 [포함되고 포함되지 않는 항목](../project/settings/import_export.md#project-items-that-are-exported)을 인식하세요.

프로젝트 또는 위키의 Git 리포지토리를 백업하려면 다른 컴퓨터로 복제합니다. [2020년 8월 22일 이후 위키에 업로드된](../project/wiki/_index.md#create-a-new-wiki-page) 모든 파일은 리포지토리를 복제할 때 포함됩니다.

## CI/CD {#cicd}

GitLab.com은 이러한 [GitLab CI/CD](../../ci/_index.md) 설정을 사용합니다. 여기에 나열되지 않은 설정 또는 기능 제한은 관련 설명서에 나열된 기본값을 사용합니다:

| 설정                                                                          | GitLab.com                                                                                                 | 기본값(GitLab Self-Managed) |
|----------------------------------------------------------------------------------|------------------------------------------------------------------------------------------------------------|-------------------------------|
| 아티팩트 최대 크기(압축)                                              | 1GB                                                                                                       | [최대 아티팩트 크기](../../administration/cicd/limits.md#maximum-artifacts-size)를 참조하세요. |
| 아티팩트 [만료 시간](../../ci/yaml/_index.md#artifactsexpire_in)              | 별도로 지정하지 않는 한 30일                                                                         | [기본 아티팩트 만료](../../administration/settings/continuous_integration.md#set-default-artifacts-expiration)를 참조하세요. 2020년 6월 22일 이전에 생성된 아티팩트는 만료되지 않습니다. |
| 보안 검사 [발견](../application_security/detect/security_scanning_results.md) 보존   | 30일                                                                                                    | [보안 검사 보존 기간](../../administration/settings/security_and_compliance.md#security-scan-retention-period)을 참조하세요. |
| 예약된 파이프라인 Cron                                                          | `*/5 * * * *`                                                                                              | [파이프라인 일정 고급 구성](../../administration/cicd/limits.md#maximum-scheduled-pipeline-frequency)을 참조하세요. |
| 단일 파이프라인의 최대 작업 수                                                | Free 티어의 경우 `500`, 모든 평가판 티어의 경우 `1000`, Premium의 경우 `1500`, Ultimate의 경우 `2000`.              | [파이프라인의 최대 작업 수](../../administration/cicd/limits.md#maximum-number-of-jobs-in-a-pipeline)를 참조하세요. |
| 활성 파이프라인의 최대 작업 수                                                 | Free 티어의 경우 `500`, 모든 평가판 티어의 경우 `1000`, Premium의 경우 `20000`, Ultimate의 경우 `60000`.            | [활성 파이프라인의 작업 수](../../administration/cicd/limits.md#number-of-jobs-in-active-pipelines)를 참조하세요. |
| 프로젝트에 대한 최대 CI/CD 구독 수                                         | `2`                                                                                                        | [프로젝트에 대한 CI/CD 구독 수](../../administration/cicd/limits.md#number-of-cicd-subscriptions-to-a-project)를 참조하세요. |
| 프로젝트의 최대 파이프라인 트리거 수                                 | `25000`                                                                                                    | [파이프라인 트리거 수 제한](../../administration/cicd/limits.md#limit-the-number-of-pipeline-triggers)을 참조하세요. |
| 프로젝트의 최대 파이프라인 일정 수                                           | Free 티어의 경우 `10`, 모든 유료 티어의 경우 `50`                                                                | [파이프라인 일정 수](../../administration/cicd/limits.md#number-of-pipeline-schedules)를 참조하세요. |
| 각 일정의 최대 파이프라인 수                                              | Free 티어의 경우 `24`, 모든 유료 티어의 경우 `288`                                                               | [파이프라인 일정에서 매일 생성하는 파이프라인 수 제한](../../administration/cicd/limits.md#limit-the-number-of-pipelines-created-by-a-pipeline-schedule-each-day)을 참조하세요. |
| 각 보안 정책 프로젝트에 대해 정의된 최대 일정 규칙 수        | 모든 유료 티어에 대해 무제한                                                                               | [각 보안 정책 프로젝트에 대해 정의된 일정 규칙 수](../../administration/cicd/limits.md#limit-the-number-of-schedule-rules-defined-for-security-policy-project)를 참조하세요. |
| [파이프라인 아카이빙](../../administration/settings/continuous_integration.md#archive-pipelines) | 1년                                                                                       | 안 함. 2020년 6월 22일 이전에 생성된 작업은 2020년 9월 22일 이후에 아카이빙되었습니다. |
| 각 [단위 테스트 보고서](../../ci/testing/unit_test_reports.md)의 최대 테스트 케이스 수 | `500000`                                                                                              | 무제한.                    |
| 최대 등록 러너 수                                                       | Free 티어: 각 그룹에 `50` 개, 각 프로젝트에 `50`개<br/>모든 유료 티어: 각 그룹에 `1000` 개, 각 프로젝트에 `1000` 개 | [각 범위의 등록 러너 수](../../administration/cicd/limits.md#number-of-registered-runners-for-groups-and-projects)를 참조하세요. |
| dotenv 변수의 제한                                                        | Free 티어: `50`<br>Premium 티어: `100`<br>Ultimate 티어: `150`                                             | [dotenv 변수 제한](../../administration/cicd/limits.md#limit-dotenv-variables)을 참조하세요. |
| 최대 다운스트림 파이프라인 트리거 속도(특정 프로젝트, 사용자 및 커밋의 경우) | 분당 `350`                                                                                          | [최대 다운스트림 파이프라인 트리거 속도](../../administration/cicd/limits.md#limit-downstream-pipeline-trigger-rate)를 참조하세요. |
| 파이프라인당 최대 파이프라인 취소 속도(지정된 사용자의 경우) | 분당 `5`   | [파이프라인 취소 속도 제한](../../administration/cicd/limits.md#pipeline-cancellation-rate-limits)을 참조하세요. |
| 프로젝트당 최대 파이프라인 취소 속도(지정된 사용자의 경우)  | 분당 `120` | [파이프라인 취소 속도 제한](../../administration/cicd/limits.md#pipeline-cancellation-rate-limits)을 참조하세요. |
| 파이프라인당 최대 파이프라인 재시도 속도(지정된 사용자의 경우) | 분당 `5`   | [파이프라인 재시도 속도 제한](../../administration/cicd/limits.md#pipeline-retry-rate-limits)을 참조하세요. |
| 프로젝트당 최대 파이프라인 재시도 속도(지정된 사용자의 경우)  | 분당 `200` | [파이프라인 재시도 속도 제한](../../administration/cicd/limits.md#pipeline-retry-rate-limits)을 참조하세요. |
| 작업당 최대 작업 재시도 속도(지정된 사용자의 경우)                                | 분당 `3`                                                                                            | [작업 재시도 및 수동 작업 실행 속도 제한](../../administration/cicd/limits.md#job-retry-and-manual-job-run-rate-limits)을 참조하세요. |
| 프로젝트당 최대 작업 재시도 속도(지정된 사용자의 경우)                            | 분당 `320`                                                                                          | [작업 재시도 및 수동 작업 실행 속도 제한](../../administration/cicd/limits.md#job-retry-and-manual-job-run-rate-limits)을 참조하세요. |
| 작업당 최대 수동 작업 실행 속도(지정된 사용자의 경우)                           | 분당 `3`                                                                                            | [작업 재시도 및 수동 작업 실행 속도 제한](../../administration/cicd/limits.md#job-retry-and-manual-job-run-rate-limits)을 참조하세요. |
| 프로젝트당 최대 수동 작업 실행 속도(지정된 사용자의 경우)                       | 분당 `200`                                                                                          | [작업 재시도 및 수동 작업 실행 속도 제한](../../administration/cicd/limits.md#job-retry-and-manual-job-run-rate-limits)을 참조하세요. |
| 파이프라인당 최대 파이프라인 삭제 속도(지정된 사용자의 경우) | 분당 `5`   | [파이프라인 삭제 속도 제한](../../administration/cicd/limits.md#pipeline-deletion-rate-limits)을 참조하세요. |
| 프로젝트당 최대 파이프라인 삭제 속도(지정된 사용자의 경우)  | 분당 `400` | [파이프라인 삭제 속도 제한](../../administration/cicd/limits.md#pipeline-deletion-rate-limits)을 참조하세요. |
| 파이프라인의 계층 트리에서 최대 다운스트림 파이프라인 수            | `1000`                                                                                                     | [파이프라인 계층 크기 제한](../../administration/cicd/limits.md#limit-pipeline-hierarchy-size)을 참조하세요. |
| 프로젝트, 커밋 및 사용자당 최대 파이프라인 생성 요청 수(분당) | `25`                                                                                                | [파이프라인 생성 속도 제한](../../administration/cicd/limits.md#pipeline-creation-rate-limits)을 참조하세요. |

## 컨테이너 레지스트리 {#container-registry}

| 설정                                | GitLab.com                       | GitLab Self-Managed |
|:---------------------------------------|:---------------------------------|------------------------|
| 도메인 이름                            | `registry.gitlab.com`            |                        |
| IP 주소                             | `35.227.35.254`                  |                        |
| CDN 도메인 이름                        | `cdn.registry.gitlab-static.net` |                        |
| CDN IP 주소                         | `34.149.22.116`                  |                        |
| 인증 토큰 지속 시간(분) | `15`                             | [컨테이너 레지스트리 토큰 지속 시간 증가](../../administration/packages/container_registry.md#increase-token-duration)를 참조하세요. |

GitLab 컨테이너 레지스트리를 사용하려면 Docker 클라이언트가 다음에 액세스할 수 있어야 합니다:

- 인증을 위한 레지스트리 엔드포인트 및 GitLab.com.
- Google Cloud Storage([Google이 인터넷 사용자에게 제공하는 IP 범위](https://knowledge.workspace.google.com/admin/security/obtain-google-ip-address-ranges) 참조) 또는 Google Cloud Content Delivery Network에서 이미지를 다운로드합니다.

GitLab.com은 Cloudflare로 보호됩니다. GitLab.com으로 들어오는 연결의 경우 Cloudflare의 CIDR 블록([IPv4](https://www.cloudflare.com/ips-v4/) 및 [IPv6](https://www.cloudflare.com/ips-v6/))을 허용해야 합니다.

## Diff 표시 제한 {#diff-display-limits}

GitLab.com에서는 diff 파일 표시 설정을 변경할 수 없습니다. 이 제한은 GitLab UI 및 API 엔드포인트에 모두 적용됩니다.

| 설정                 | 정의                                     | GitLab.com |
|-------------------------|------------------------------------------------|------------|
| 최대 Diff 패치 크기 | 전체 Diff의 총 크기.             | 200KB |
| 최대 Diff 파일      | Diff에서 변경된 파일의 총 개수.   | 3,000 |
| 최대 Diff 라인      | Diff에서 변경된 줄의 총 개수.   | 100,000 |

[Diff 제한을 변경할 수 있습니다](../../administration/diff_limits.md#configure-diff-limits). GitLab Self-Managed에서.

## 이메일 {#email}

이메일 구성 설정, IP 주소 및 별칭.

### 확인 설정 {#confirmation-settings}

GitLab.com은 이러한 이메일 확인 설정을 사용합니다:

- [`email_confirmation_setting`](../../administration/settings/sign_up_restrictions.md#confirm-user-email)는 **Hard**로 설정됩니다.
- [`unconfirmed_users_delete_after_days`](../../administration/moderate_users.md#automatically-delete-unconfirmed-users)는 3일로 설정됩니다.

### IP 주소 {#ip-addresses}

GitLab.com은 [Mailgun](https://www.mailgun.com/)을 사용하여 `mg.gitlab.com` 도메인에서 이메일을 보내고 자체 전용 IP 주소를 보유합니다:

- `23.253.183.236`
- `69.72.35.190`
- `69.72.44.107`
- `159.135.226.146`
- `161.38.202.219`
- `192.237.158.143`
- `192.237.159.239`
- `198.61.254.136`
- `198.61.254.160`
- `209.61.151.122`

`mg.gitlab.com`의 IP 주소는 언제든지 변경될 수 있습니다.

### Service Desk 별칭 {#service-desk-alias}

GitLab.com은 Service Desk용으로 구성된 사서함을 이메일 주소 `contact-project+%{key}@incoming.gitlab.com`로 보유합니다. 이 사서함을 사용하려면 프로젝트 설정에서 [사용자 지정 접미사](../project/service_desk/configure.md#configure-a-suffix-for-service-desk-alias-email)를 구성합니다.

## GitLab.com의 Gitaly RPC 동시성 제한 {#gitaly-rpc-concurrency-limits-on-gitlabcom}

리포지토리별 Gitaly RPC 동시성 및 큐 제한은 `git clone`와 같은 다양한 유형의 Git 작업에 대해 구성됩니다. 이 제한을 초과하면 `fatal: remote error: GitLab is currently unable to handle this request due to load` 메시지가 클라이언트로 반환됩니다.

가져오기 또는 복제 작업은 이전 작업이 완료되기 전에 작업이 시작될 때 동시입니다.

| 작업               | GitLab.com 제한         |
|:------------------------|:-------------------------|
| HTTP 가져오기 및 복제 | 60개의 동시 작업 |
| SSH 가져오기 및 복제  | 30개의 동시 작업 |

관리자 설명서는 [RPC 동시성 제한](../../administration/gitaly/concurrency_limiting.md#limit-rpc-concurrency)을 참조하세요.

## GitLab Pages {#gitlab-pages}

[GitLab Pages](../project/pages/_index.md)의 일부 설정은 [GitLab Self-Managed의 기본값](../../administration/pages/_index.md)과 다릅니다:

| 설정                                                | GitLab.com |
|--------------------------------------------------------|------------|
| 도메인 이름                                            | `gitlab.io` |
| IP 주소                                             | `35.185.44.232` |
| 사용자 지정 도메인 지원                             | {{< yes >}} |
| TLS 인증서 지원                           | {{< yes >}} |
| 최대 사이트 크기                                      | 1GB       |
| 각 GitLab Pages 웹사이트의 사용자 지정 도메인 수 | 150        |

Pages 사이트의 최대 크기는 최대 아티팩트 크기에 따라 다르며, 이는 [GitLab CI/CD 설정](#cicd)의 일부입니다.

[속도 제한](rate_limits.md#current-rate-limits)도 GitLab Pages에 존재합니다.

## 규모별 GitLab.com {#gitlabcom-at-scale}

GitLab Enterprise Edition Linux 패키지 설치 외에도 GitLab.com은 다음 애플리케이션 및 설정을 사용하여 규모를 달성합니다. 모든 설정은 [Kubernetes 구성](https://gitlab.com/gitlab-com/gl-infra/k8s-workloads/gitlab-com) 또는 [Chef 쿡북](https://gitlab.com/gitlab-cookbooks)으로 공개적으로 사용 가능합니다.

### Consul {#consul}

서비스 디스커버리:

- [`gitlab-cookbooks` / `gitlab_consul` · GitLab](https://gitlab.com/gitlab-cookbooks/gitlab_consul)

### Fluentd {#fluentd}

Fluentd를 사용하여 GitLab 로그를 통합합니다:

- [`gitlab-cookbooks` / `gitlab_fluentd` · GitLab](https://gitlab.com/gitlab-cookbooks/gitlab_fluentd)

### Grafana {#grafana}

모니터링 데이터 시각화:

- [`gitlab-cookbooks` / `gitlab-grafana` · GitLab](https://gitlab.com/gitlab-cookbooks/gitlab-grafana)

### HAProxy {#haproxy}

고성능 TCP/HTTP 로드 밸런서:

- [`gitlab-cookbooks` / `gitlab-haproxy` · GitLab](https://gitlab.com/gitlab-cookbooks/gitlab-haproxy)

### Prometheus {#prometheus}

Prometheus는 모니터링 스택을 완성합니다:

- [`gitlab-cookbooks` / `gitlab-prometheus` · GitLab](https://gitlab.com/gitlab-cookbooks/gitlab-prometheus)

### Sentry {#sentry}

오픈 소스 오류 추적:

- [`gitlab-cookbooks` / `gitlab-sentry` · GitLab](https://gitlab.com/gitlab-cookbooks/gitlab-sentry)

## GitLab 호스팅 러너 {#gitlab-hosted-runners}

GitLab 호스팅 러너를 사용하여 GitLab.com 및 GitLab Dedicated에서 CI/CD 작업을 실행하고 다양한 환경에서 애플리케이션을 원활하게 빌드, 테스트 및 배포합니다.

자세한 내용은 [GitLab 호스팅 러너](../../ci/runners/_index.md)를 참조하세요.

## 호스트명 목록 {#hostname-list}

로컬 HTTP(S) 프록시의 허용 목록 또는 최종 사용자 컴퓨터를 제어하는 기타 웹 차단 소프트웨어를 구성할 때 이 호스트명을 추가합니다. GitLab.com의 페이지는 이 호스트명에서 콘텐츠를 로드합니다:

- `gitlab.com`
- `*.gitlab.com`
- `*.gitlab-static.net`
- `*.gitlab.io`
- `*.gitlab.net`

`docs.gitlab.com` 및 `about.gitlab.com`를 통해 제공되는 설명서 및 GitLab 회사 페이지는 공용 CDN 호스트명에서 특정 페이지 콘텐츠를 직접 로드합니다.

### 컨테이너 레지스트리 호스트명 목록 {#container-registry-hostname-list}

`registry.gitlab.com`에서 이미지를 가져오는 경우 다음 호스트명을 허용 목록에 추가합니다:

- `*.storage.googleapis.com`
- `*.cdn.registry.gitlab-static.net`

## 가져오기 {#imports}

GitLab.com은 GitLab으로의 데이터 가져오기를 제한하는 설정을 사용합니다.

### 기본 가져오기 원본 {#default-import-sources}

기본적으로 사용 가능한 [가져오기 원본](../import/_index.md)(마이그레이션 도구)은 사용 중인 GitLab에 따라 다릅니다:

- GitLab.com: 기본적으로 사용 가능한 모든 가져오기 원본이 활성화됩니다.
- GitLab Self-Managed: 기본적으로 활성화된 가져오기 원본이 없으며 [활성화](../../administration/settings/import_and_export_settings.md#configure-allowed-import-sources)해야 합니다.

### 가져오기 자리 표시자 사용자 제한 {#import-placeholder-user-limits}

GitLab.com으로의 가져오기는 각 최상위 네임스페이스에 대한 [자리 표시자 사용자](../import/mapping/post_migration_mapping.md#placeholder-users) 수를 제한합니다. 제한은 계획 및 사용자 수에 따라 다릅니다. 자세한 내용은 [GitLab.com의 자리 표시자 사용자 제한 표](../import/mapping/post_migration_mapping.md#placeholder-user-limits)를 참조하세요.

## IP 범위 {#ip-range}

GitLab.com은 IP 범위 `34.74.90.64/28` 및 `34.74.226.0/24`를 Web/API 플릿의 트래픽에 사용합니다. 이 전체 범위는 GitLab에만 할당됩니다. 웹후크 또는 리포지토리 미러링의 연결은 이러한 IP 주소에서 나옵니다. 이 연결을 허용해야 합니다.

- 들어오는 연결 - GitLab.com은 Cloudflare로 보호됩니다. GitLab.com으로 들어오는 연결의 경우 Cloudflare의 CIDR 블록([IPv4](https://www.cloudflare.com/ips-v4/) 및 [IPv6](https://www.cloudflare.com/ips-v6/))을 허용합니다.

- CI/CD 러너에서 나가는 연결 - CI/CD 러너에서 나가는 연결을 위한 정적 IP 주소를 제공하지 않습니다. 그러나 이 지침이 도움이 될 수 있습니다:
  - Linux GPU 지원 및 Linux Arm64 러너는 Google Cloud(`us-central1`)에 배포됩니다.
  - 다른 GitLab.com 인스턴스 러너는 Google Cloud(`us-east1`)에 배포됩니다.
  - macOS 러너는 AWS의 `us-east-1` 리전에서 호스팅되며, 러너 관리자는 Google Cloud에서 호스팅됩니다.

IP 기반 방화벽을 구성하려면 [AWS IP 주소 범위](https://docs.aws.amazon.com/vpc/latest/userguide/aws-ip-ranges.html) 및 [Google Cloud IP 주소 범위](https://cloud.google.com/compute/docs/faq#find_ip_range)를 모두 허용해야 합니다.

[GCP의 IP 주소 범위 또는 CIDR 블록을 조회하는 방법](https://cloud.google.com/compute/docs/faq#find_ip_range)을 참조하세요.

## 검토자 및 담당자의 최대 수 {#maximum-number-of-reviewers-and-assignees}

머지 리퀘스트는 이러한 최대값을 적용합니다:

- 최대 담당자: 200
- 최대 검토자: 200

## 머지 리퀘스트 제한 {#merge-request-limits}

{{< history >}}

- GitLab 17.10에서 `merge_requests_diffs_limit`라는 [기능 플래그](../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/521970)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.10에서 [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/521970)되었습니다.
- GitLab 19.0에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/537447)합니다. `merge_requests_diffs_limit` 기능 플래그가 제거되었습니다.

{{< /history >}}

GitLab은 각 머지 리퀘스트를 1000 [diff 버전](../project/merge_requests/versions.md)으로 제한합니다. 이 제한에 도달한 머지 리퀘스트는 더 이상 업데이트할 수 없습니다. 대신, 영향을 받는 머지 리퀘스트를 닫고 새 머지 리퀘스트를 만드세요.

### Diff 커밋 제한 {#diff-commits-limit}

{{< history >}}

- [GitLab 17.11에서 도입](https://gitlab.com/gitlab-org/gitlab/-/issues/527036) [기능 플래그](../../administration/feature_flags/_index.md) 명명된 `merge_requests_diff_commits_limit`. 기본적으로 비활성화되었습니다.
- GitLab 19.0에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/537446)합니다. `merge_requests_diff_commits_limit` 기능 플래그가 제거되었습니다.

{{< /history >}}

GitLab은 각 머지 리퀘스트를 1,000,000(백만)개의 Diff 커밋으로 제한합니다. 이 제한에 도달한 머지 리퀘스트는 더 이상 업데이트할 수 없습니다. 대신, 영향을 받는 머지 리퀘스트를 닫고 새 머지 리퀘스트를 만드세요.

## 암호 요구 사항 {#password-requirements}

GitLab.com은 새 계정 및 암호 변경에 대해 다음 암호 요구 사항을 설정합니다:

- 최소 문자 길이 8자.
- 최대 문자 길이 128자.
- 모든 문자가 허용됩니다. 예를 들어 `~`, `!`, `@`, `#`, `$`, `%`, `^`, `&`, `*`, `()`, `[]`, `_`, `+`, `=` 및 `-`.

## 그룹 생성 {#group-creation}

{{< history >}}

- [GitLab 18.0에서 도입](https://gitlab.com/gitlab-org/gitlab/-/issues/506673)
- [GitLab 18.5에서 GitLab SAAS 관리자 예외 도입](https://gitlab.com/gitlab-org/gitlab/-/issues/560840)

{{< /history >}}

GitLab.com에서는 [최상위 그룹 생성](../../api/groups.md#create-a-group)은 UI를 통해서만 허용됩니다. 관리자만 API를 사용하여 최상위 그룹을 생성할 수 있습니다.

## 프로젝트 및 그룹 삭제 {#project-and-group-deletion}

프로젝트 및 그룹 삭제와 관련된 설정.

### 지연된 그룹 삭제 {#delayed-group-deletion}

{{< history >}}

- [GitLab Premium에서 GitLab Free로 이동](https://gitlab.com/groups/gitlab-org/-/work_items/17208) 18.0.
- [삭제 기간 증가](https://gitlab.com/groups/gitlab-org/-/work_items/17375) 7일에서 30일로 18.0.2.

{{< /history >}}

그룹은 30일 지연 후 영구적으로 삭제됩니다.

[삭제 표시된 그룹을 보고 복원하는 방법](../group/_index.md#restore-a-group)을 참조하세요.

### 지연된 프로젝트 삭제 {#delayed-project-deletion}

{{< history >}}

- [GitLab Premium에서 GitLab Free로 이동](https://gitlab.com/groups/gitlab-org/-/work_items/17208) 18.0.
- [삭제 기간 증가](https://gitlab.com/groups/gitlab-org/-/work_items/17375) 7일에서 30일로 18.0.2.

{{< /history >}}

프로젝트는 30일 지연 후 영구적으로 삭제됩니다.

[삭제 표시된 프로젝트를 보고 복원하는 방법](../project/working_with_projects.md#restore-a-project)을 참조하세요.

### 휴면 프로젝트 삭제 {#dormant-project-deletion}

[휴면 프로젝트 삭제](../../administration/dormant_project_deletion.md)는 GitLab.com에서 비활성화됩니다.

## 패키지 레지스트리 제한 {#package-registry-limits}

[최대 파일 크기](../../administration/instance_limits.md#file-size-limits) 및 [GitLab 패키지 레지스트리](../packages/package_registry/_index.md)에 업로드된 패키지의 형식에 따라 다릅니다:

| 패키지 유형           | GitLab.com                         |
|------------------------|------------------------------------|
| Conan                  | 5GB                               |
| Generic                | 5GB                               |
| Helm                   | 5MB                               |
| 머신 러닝 모델 | 10GB (업로드는 5GB로 제한) |
| Maven                  | 5GB                               |
| npm                    | 5GB                               |
| NuGet                  | 5GB                               |
| PyPI                   | 5GB                               |
| Terraform              | 1GB                               |

## Puma {#puma}

GitLab.com은 [Puma 요청 타임아웃](../../administration/operations/puma.md#change-the-worker-timeout)의 기본값인 60초를 사용합니다.

## GitLab.com의 속도 제한 {#rate-limits-on-gitlabcom}

GitLab.com의 속도 제한은 구독 계획에 따라 다르며 사용자당 및 최상위 그룹당 모두 적용됩니다. 각 계획에는 사용을 관리하는 시간당 제한과 분당 버스트 제한이 있으며, 시간당 제한이 우선합니다. 인증된 요청은 계획의 전체 허용량을 받습니다.

각 계획의 제한, 적용 시기 및 `429 Too Many Requests` 응답 처리 방법에 대해서는 [GitLab.com 속도 제한](rate_limits.md)을 참조하세요.

## Sidekiq {#sidekiq}

GitLab.com은 [Sidekiq](https://sidekiq.org)을 Ruby 작업 스케줄링을 위한 [외부 프로세스](../../administration/sidekiq/_index.md)로 실행합니다.

현재 설정은 [GitLab.com Kubernetes 포드 구성](https://gitlab.com/gitlab-com/gl-infra/k8s-workloads/gitlab-com/-/blob/master/releases/gitlab/values/gprd.yaml.gotmpl)에 있습니다.

## SSH 키 및 인증 {#ssh-keys-and-authentication}

SSH를 사용한 인증과 관련된 설정. 최대 연결 수에 대한 정보는 [SSH 최대 연결 수](rate_limits.md#ssh-maximum-number-of-connections)를 참조하세요.

### 대체 SSH 포트 {#alternative-ssh-port}

GitLab.com은 [다른 SSH 포트](https://about.gitlab.com/blog/gitlab-dot-com-now-supports-an-alternate-git-plus-ssh-port/)를 사용하여 `git+ssh`에 도달할 수 있습니다.

| 설정    | 값               |
|------------|---------------------|
| `Hostname` | `altssh.gitlab.com` |
| `Port`     | `443`               |

예: `~/.ssh/config`는 다음과 같습니다:

```plaintext
Host gitlab.com
  Hostname altssh.gitlab.com
  User git
  Port 443
  PreferredAuthentications publickey
  IdentityFile ~/.ssh/gitlab
```

### SSH 호스트 키 핑거프린트 {#ssh-host-keys-fingerprints}

현재 인스턴스 구성으로 이동하여 GitLab.com에서 SSH 호스트 키 핑거프린트를 확인합니다.

1. GitLab에 로그인합니다.
1. 왼쪽 사이드바에서 **도움말** ({{< icon name="question-o" >}}) > **도움말**을 선택합니다.
1. 도움말 페이지에서 **현재 인스턴스 구성 확인**을 선택합니다.

인스턴스 구성에서 **SSh 호스트 키 핑거프린트**를 확인합니다:

| 알고리즘        | MD5 (사용 중단) | SHA256  |
|------------------|------------------|---------|
| ECDSA            | `f1:d0:fb:46:73:7a:70:92:5a:ab:5d:ef:43:e2:1c:35` | `SHA256:HbW3g8zUjNSksFbqTiUWPWg2Bq1x8xdGUrliXFzSnUw` |
| ED25519          | `2e:65:6a:c8:cf:bf:b2:8b:9a:bd:6d:9f:11:5c:12:16` | `SHA256:eUXGGm1YGsMAS7vkcx6JOJdOGHPem5gQp4taiCfCLB8` |
| RSA              | `b6:03:0e:39:97:9e:d0:e7:24:ce:a3:77:3e:01:42:09` | `SHA256:ROQFvPThGrW4RuWLoL9tq9I9zJ42fK4XywyRtbOz/EQ` |

GitLab.com 리포지토리에 처음 연결할 때 이 키 중 하나가 출력에 표시됩니다.

### SSH 키 제한 {#ssh-key-restrictions}

GitLab.com은 기본 [SSH 키 제한](../../security/ssh_keys_restrictions.md)을 사용합니다.

### SSH `known_hosts` 항목 {#ssh-known_hosts-entries}

SSH에서 수동 핑거프린트 확인을 건너뛰려면 `.ssh/known_hosts`에 다음을 추가합니다:

```plaintext
gitlab.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAfuCHKVTjquxvt6CM6tdG4SLp1Btn/nOeHHE5UOzRdf
gitlab.com ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsj2bNKTBSpIYDEGk9KxsGh3mySTRgMtXL583qmBpzeQ+jqCMRgBqB98u3z++J1sKlXHWfM9dyhSevkMwSbhoR8XIq/U0tCNyokEi/ueaBMCvbcTHhO7FcwzY92WK4Yt0aGROY5qX2UKSeOvuP4D6TPqKF1onrSzH9bx9XUf2lEdWT/ia1NEKjunUqu1xOB/StKDHMoX4/OKyIzuS0q/T1zOATthvasJFoPrAjkohTyaDUz2LN5JoH839hViyEG82yB+MjcFV5MU3N1l1QL3cVUCh93xSaua1N85qivl+siMkPGbO5xR/En4iEY6K2XPASUEMaieWVNTRCtJ4S8H+9
gitlab.com ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBFSMqzJeV9rUzU4kWitGjeR4PWSa29SPqJ1fVkhtj3Hw9xjLVXVYrU9QlYWrOLXBpQ6KWjbjTDTdDkoohFzgbEY=
```

## 표시 설정 {#visibility-settings}

프로젝트, 그룹 및 스니펫에는 [내부 표시 여부](../public_access.md#internal-projects-and-groups) 설정 [GitLab.com에서 비활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/12388)이 있습니다.

## 웹후크 {#webhooks}

다음 제한은 [웹후크](../project/integrations/webhooks.md)에 적용됩니다.

### 속도 제한 {#rate-limits}

최상위 네임스페이스의 웹후크가 분당 호출될 수 있는 횟수. 네임스페이스 내의 모든 프로젝트 및 그룹 웹후크는 이 제한을 공유합니다. 제한은 계획 및 구독의 사용자 수에 따라 다릅니다.

| 계획                                                   | GitLab.com의 기본값 |
|--------------------------------------------------------|------------------------|
| GitLab Free                                            | `500`                  |
| GitLab Premium, `99` 사용자 이상                    | `1,600`                |
| GitLab Premium, `100-399` 사용자                        | `2,800`                |
| GitLab Premium, `400` 사용자 이상                    | `4,000`                |
| GitLab Ultimate 및 오픈 소스, `999` 사용자 이상  | `6,000`                |
| GitLab Ultimate 및 오픈 소스, `1,000-4,999` 사용자   | `9,000`                |
| GitLab Ultimate 및 오픈 소스, `5,000` 사용자 이상 | `13,000`               |

속도 제한에 도달하면 네임스페이스의 모든 웹후크가 일시적으로 비활성화되고 다음 분에 자동으로 다시 활성화됩니다.

속도 제한 시 웹후크 목록의 웹후크 옆에 배지가 나타납니다. 웹후크 편집 페이지에 네임스페이스 제한이 분당 초과된 횟수와 웹후크가 다시 활성화되는 시기를 나타내는 메시지가 표시됩니다.

### 보안 정책 제한 {#security-policy-limits}

보안 정책 프로젝트에 추가할 수 있는 정책의 최대 수. 이 제한은 각 정책 유형에 개별적으로 적용됩니다. 예를 들어 같은 보안 정책 프로젝트에 5개의 머지 리퀘스트 승인 정책과 5개의 검사 실행 정책을 가질 수 있습니다.

| 정책 유형                                            | 기본 제한                             |
|--------------------------------------------------------|-------------------------------------------|
| 머지 리퀘스트 승인 정책                        | 보안 정책 프로젝트당 5개 정책 |
| 검사 실행 정책                                | 보안 정책 프로젝트당 5개 정책 |
| 파이프라인 실행 정책                            | 보안 정책 프로젝트당 5개 정책 |
| 취약성 관리 정책                      | 보안 정책 프로젝트당 5개 정책 |

### 기타 제한 {#other-limits}

| 설정                                                             | GitLab.com의 기본값 |
|:--------------------------------------------------------------------|:-----------------------|
| 웹후크 수                                                  | 각 프로젝트에 100개, 각 그룹에 50개(하위 그룹 웹후크는 상위 그룹 제한에 포함되지 않음) |
| 최대 페이로드 크기                                                | 25MB                  |
| 타임아웃                                                             | 10초             |
| [병렬 Pages 배포](../project/pages/parallel_deployments.md#limits) | 100개의 추가 배포(Premium 티어), 500개의 추가 배포(Ultimate 티어) |

GitLab Self-Managed 인스턴스 제한은 다음을 참조하세요:

- [웹후크 속도 제한](../../administration/instance_limits.md#webhook-rate-limit).
- [웹후크 수](../../administration/instance_limits.md#number-of-webhooks).
- [웹후크 타임아웃](../../administration/instance_limits.md#webhook-timeout).
- [병렬 Pages 배포](../../administration/instance_limits.md#number-of-parallel-pages-deployments).
