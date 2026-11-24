---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: GitLab 18 업그레이드 참고사항
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

이 페이지에는 GitLab 18의 마이너 및 패치 버전에 대한 업그레이드 정보가 포함되어 있습니다. 다음 항목에 대한 지침을 검토하세요:

- 설치 유형
- 현재 버전과 대상 버전 사이의 모든 버전

Helm 차트 설치에 대한 추가 정보는 [Helm 차트 9.0 업그레이드 참고사항](https://docs.gitlab.com/charts/releases/9_0/)을 참조하세요.

## 필수 업그레이드 중지 {#required-upgrade-stops}

인스턴스 관리자에게 예측 가능한 업그레이드 일정을 제공하기 위해 필수 업그레이드 중지는 다음 버전에서 발생합니다:

- `18.2`
- `18.5`
- `18.8`
- `18.11`

## 업그레이드 참고사항 참고 {#upgrade-notes-reference}

다음은 각 마이너 GitLab 버전에 대한 업그레이드 참고사항의 참고 목록입니다. 각 목록 항목은 추가 정보를 포함하는 특정 섹션을 가리킵니다.

`(Geo)` 또는 `(Linux package)`와 같은 설치 방법으로 표시된 항목은 해당 방법에만 적용됩니다. 다른 모든 항목은 모든 설치 방법에 적용됩니다.

### 18.11로 업그레이드 {#upgrade-to-1811}

GitLab 18.11로 업그레이드하기 전에 다음을 검토하세요:

- [18.11.0 - 18.11.2] - [Geo Blob 동기화 실패 `log_error` 파일 저장소의 NoMethodError](#geo-blob-sync-failures-with-log_error-nomethoderror-on-file-storage) (Geo)
- [18.11.0 - 18.11.4] - [Geo 컨테이너 리포지토리 동기화가 OCI 이미지 인덱스 태그를 자동으로 건너뜀](#geo-container-repository-sync-silently-skips-oci-image-index-tags) (Geo)
- [18.11.0 - 18.11.1] - [내부 및 공개 프로젝트에서 컨테이너 이미지를 가져오는 CI 작업 토큰 회귀](#ci-job-token-regression-pulling-container-images-from-internal-and-public-projects)
- [18.11.0] - [GitLab 18.11로 업그레이드하면 PostgreSQL 17.7 버전 업그레이드가 트리거됨](#postgresql-version-177-upgrade-on-gitlab-1811) (Linux 패키지, Docker, Geo)
- [18.11.0] - [Mattermost 및 Spamcheck이 SLES 12.5 패키지에서 제거됨](#mattermost-and-spamcheck-removed-from-sles-125-packages) (Linux 패키지)
- [18.11.0] - [Gitaly cgroup 메트릭이 변경되었으며 일부가 제거됨](#gitaly-cgroup-metrics-changed-and-some-were-removed)
- [18.11.0] - [컴파일된 작업별 구성은 1 MiB 크기 제한이 적용됨](#compiled-per-job-config-is-subject-to-a-1-mib-size-limit)

### 18.10으로 업그레이드 {#upgrade-to-1810}

GitLab 18.10으로 업그레이드하기 전에 다음을 검토하세요:

- [18.10.0 - 18.10.3] - [SLES 12.5 RPM 패키지 설치 실패](#sles-125-rpm-package-installation-failure) (Linux 패키지)
- [18.10.0 - 18.10.5] - [Geo Blob 동기화 실패 `log_error` 파일 저장소의 NoMethodError](#geo-blob-sync-failures-with-log_error-nomethoderror-on-file-storage) (Geo)
- [18.10.0 - 18.10.7] - [Geo 컨테이너 리포지토리 동기화가 OCI 이미지 인덱스 태그를 자동으로 건너뜀](#geo-container-repository-sync-silently-skips-oci-image-index-tags) (Geo)
- [18.10.0 - 18.10.3] - [아웃바운드 필터링을 사용할 때 Geo 사이트 URL이 차단됨](#geo-site-url-blocked-when-using-outbound-filtering) (Geo)
- [18.10.0 - 18.10.4] - [Geo Blob 다운로드 실패](#geo-blob-download-failures) (Geo)
- [18.10.0 - 18.10.3] - [Geo 보조 사이트의 제한된 작업이 배출되지 않음](#geo-secondary-throttled-jobs-not-draining) (Geo)
- [18.10.0 - 18.10.3] - [Sidekiq 동시성 제한자가 Helm 차트 및 Operator 배포에서 작업 백로그를 유발함](#sidekiq-concurrency-limiter-causes-job-backlogs-on-helm-chart-and-operator-deployments) (Helm 차트, Operator)
- [18.10.0] - [시크릿 검색 거짓 양성 검색이 모든 프로젝트에서 기본적으로 활성화됨](#secret-detection-false-positive-detection-enabled-by-default-on-all-projects)
- [18.10.0] - [따옴표 없는 자리 표시자가 있는 사용자 정의 웹후크 템플릿을 저장할 수 없음](#custom-webhook-template-with-unquoted-placeholders-cannot-be-saved)
- [18.10.0] - [파이프라인 실행 정책의 Dotenv 변수는 `variables_override`을 준수함](#dotenv-variables-in-pipeline-execution-policies-respect-variables_override)

### 18.9로 업그레이드 {#upgrade-to-189}

GitLab 18.9로 업그레이드하기 전에 다음을 검토하세요:

- [18.9.1 - 18.9.5] - [SLES 12.5 RPM 패키지 설치 실패](#sles-125-rpm-package-installation-failure) (Linux 패키지)
- [18.9.0 - 18.9.5] - [아웃바운드 필터링을 사용할 때 Geo 사이트 URL이 차단됨](#geo-site-url-blocked-when-using-outbound-filtering) (Geo)
- [18.9.0 - 18.9.5] - [Geo 보조 사이트의 제한된 작업이 배출되지 않음](#geo-secondary-throttled-jobs-not-draining) (Geo)
- [18.9.0 - 18.9.5] - [Sidekiq 동시성 제한자가 Helm 차트 및 Operator 배포에서 작업 백로그를 유발함](#sidekiq-concurrency-limiter-causes-job-backlogs-on-helm-chart-and-operator-deployments) (Helm 차트, Operator)
- [18.9.0] - [18.9로의 업그레이드가 PostgreSQL CheckViolation으로 실패함](#upgrade-to-189-fails-with-postgresql-checkviolation)
- [18.9.0] - [따옴표 없는 자리 표시자가 있는 사용자 정의 웹후크 템플릿을 저장할 수 없음](#custom-webhook-template-with-unquoted-placeholders-cannot-be-saved)

### 18.8로 업그레이드 {#upgrade-to-188}

GitLab 18.8로 업그레이드하기 전에 다음을 검토하세요:

- [18.8.2] - [차단된 사용자의 배포 키 및 개인 액세스 토큰이 무효화됨](#deploy-keys-and-personal-access-tokens-for-blocked-users-invalidated)
- [18.8.0] - [머지 리퀘스트 병합 데이터를 위한 배치 백그라운드 마이그레이션](#batched-background-migration-for-merge-request-merge-data)
- [18.8.0] - [ClickHouse 사전 생성 오류](#clickhouse-dictionary-creation-error)
- [18.8.0] - [CI 데이터를 위한 배치 백그라운드 마이그레이션이 다시 도입됨](#batched-background-migration-for-ci-data-reintroduced)
- [18.8.0] - [따옴표 없는 자리 표시자가 있는 사용자 정의 웹후크 템플릿을 저장할 수 없음](#custom-webhook-template-with-unquoted-placeholders-cannot-be-saved)

### 18.7로 업그레이드 {#upgrade-to-187}

GitLab 18.7로 업그레이드하기 전에 다음을 검토하세요:

- [18.7.2] - [차단된 사용자의 배포 키 및 개인 액세스 토큰이 무효화됨](#deploy-keys-and-personal-access-tokens-for-blocked-users-invalidated)
- [18.7.0] - [CI 빌드 메타데이터 마이그레이션](#ci-builds-metadata-migration)
- [18.7.0] - [Geo ActionCable 허용 오리진 설정](#geo-actioncable-allowed-origins-setting) (Geo)

### 18.6으로 업그레이드 {#upgrade-to-186}

GitLab 18.6으로 업그레이드하기 전에 다음을 검토하세요:

- [18.6.5] - [Geo VerificationStateBackfillWorker 느린 쿼리 수정](#geo-verificationstatebackfillworker-slow-queries-fix) (Geo)
- [18.6.4] - [차단된 사용자의 배포 키 및 개인 액세스 토큰이 무효화됨](#deploy-keys-and-personal-access-tokens-for-blocked-users-invalidated)
- [18.6.2] - [커밋 및 파일 API 크기 및 속도 제한](#commits-and-files-api-size-and-rate-limits)
- [18.6.2] - [Duo Agent Platform 러너 제한](#duo-agent-platform-runner-restrictions)

### 18.5로 업그레이드 {#upgrade-to-185}

GitLab 18.5로 업그레이드하기 전에 다음을 검토하세요:

- [18.5.4] - [커밋 및 파일 API 크기 및 속도 제한](#commits-and-files-api-size-and-rate-limits)
- [18.5.0 - 18.5.1] - [Geo 로그 커서 마이그레이션 수정](#geo-log-cursor-migration-fix) (Geo)
- [18.5.0] - [디자인 관리 디자인 백필 완료](#finalize-design-management-designs-backfill)
- [18.5.0] - [NGINX 라우팅 변경으로 인해 404 오류 발생](#nginx-routing-changes-cause-404-errors) (Linux 패키지)

### 18.4로 업그레이드 {#upgrade-to-184}

GitLab 18.4로 업그레이드하기 전에 다음을 검토하세요:

- [18.4.6] - [커밋 및 파일 API 크기 및 속도 제한](#commits-and-files-api-size-and-rate-limits)
- [18.4.2 - 18.4.3] - [배치 백그라운드 마이그레이션 nil 오류](#batched-background-migration-nil-error)
- [18.4.1] - [서비스 거부 방지를 위한 JSON 입력 제한](#json-input-limits-for-denial-of-service-prevention)
- [18.4.0 - 18.4.3] - [Geo 로그 커서 마이그레이션 수정](#geo-log-cursor-migration-fix) (Geo)
- [18.4.0 - 18.4.1] - [Geo 복제 TypeError](#geo-replication-typeerror) (Geo)

### 18.3으로 업그레이드 {#upgrade-to-183}

GitLab 18.3으로 업그레이드하기 전에 다음을 검토하세요:

- [18.3.3] - [서비스 거부 방지를 위한 JSON 입력 제한](#json-input-limits-for-denial-of-service-prevention)
- [18.3.0] - [LdapAddOnSeatSyncWorker가 Duo 사용자를 제거함](#ldapaddonseatsyncworker-removes-duo-seats)
- [18.3.0] - [Geo Rake 확인 수정](#geo-rake-check-fix) (Geo)
- [18.3.0 - 18.3.2] - [Geo Pages 파일명 수정](#geo-pages-filename-fix) (Geo)

### 18.2로 업그레이드 {#upgrade-to-182}

GitLab 18.2로 업그레이드하기 전에 다음을 검토하세요:

- [18.2.7] - [서비스 거부 방지를 위한 JSON 입력 제한](#json-input-limits-for-denial-of-service-prevention)
- [18.2.0] - [18.1과 18.2 사이의 무중단 업그레이드 푸시 오류](#zero-downtime-upgrade-push-errors-between-181-and-182)
- [18.2.0 - 18.2.1] - [Geo VerificationStateBackfillService `ci_job_artifact_states`](#geo-verificationstatebackfillservice-ci_job_artifact_states) (Geo)
- [18.2.0 - 18.2.6] - [Geo Pages 파일명 수정](#geo-pages-filename-fix) (Geo)

### 18.1로 업그레이드 {#upgrade-to-181}

GitLab 18.1로 업그레이드하기 전에 다음을 검토하세요:

- [18.1.0] - [Elasticsearch `strict_dynamic_mapping_exception`](#elasticsearch-strict_dynamic_mapping_exception)
- [18.1.0 - 18.1.1] - [PostgreSQL `ci_job_artifacts` 오류](#postgresql-ci_job_artifacts-error)
- [18.1.0] - [머지 리퀘스트가 거의 준비 완료 버그](#merge-request-almost-ready-bug)
- [18.1.0] - [Geo HTTP 500 프록시 오류](#geo-http-500-proxy-errors) (Geo)
- [18.1.0 - 18.1.3] - [Geo VerificationStateBackfillService `ci_job_artifact_states`](#geo-verificationstatebackfillservice-ci_job_artifact_states) (Geo)
- [18.1.0] - [Geo Pages 파일명 수정](#geo-pages-filename-fix) (Geo)

### 18.0으로 업그레이드 {#upgrade-to-180}

GitLab 18.0으로 업그레이드하기 전에 다음을 검토하세요:

- [18.0.0] - [PostgreSQL 14는 지원되지 않음](#postgresql-14-not-supported)
- [18.0.0] - [`pg_dump` 이진 호환성](#pg_dump-binary-compatibility)
- [18.0.0] - [17.11에서 무중단 업그레이드 중 파이프라인 실패](#pipeline-failures-during-zero-downtime-upgrades-from-1711)
- [18.0.0] - [`git_data_dirs`에서 저장소로 Gitaly 구성 마이그레이션](#migrate-gitaly-configuration-from-git_data_dirs-to-storage) (Linux 패키지)
- [18.0.0 - 18.0.1] - [Geo CE에서 EE로 되돌리기 마이그레이션 오류](#geo-ce-to-ee-revert-migration-errors) (Geo)
- [18.0.0 - 18.0.2] - [Geo HTTP 500 프록시 오류](#geo-http-500-proxy-errors) (Geo)
- [18.0.0 - 18.0.5] - [Geo VerificationStateBackfillService `ci_job_artifact_states`](#geo-verificationstatebackfillservice-ci_job_artifact_states) (Geo)
- [18.0.0] - [Docker 설치에서 PRNG가 시드되지 않은 오류](#prng-is-not-seeded-error-on-docker-installations) (Docker)
- [17.11.0] - [Bitnami PostgreSQL 및 Redis 이미지 사용 중단](#bitnami-postgresql-and-redis-image-deprecation) (Helm 차트)

## 업그레이드 참고사항 {#upgrade-notes}

GitLab 18의 구체적인 업그레이드 참고사항

### 파이프라인 실행 정책의 Dotenv 변수는 `variables_override`을 준수합니다 {#dotenv-variables-in-pipeline-execution-policies-respect-variables_override}

{{< details >}}

- 티어: Ultimate

{{< /details >}}

- 영향을 받음: 파이프라인 실행 정책
- 영향을 받는 버전:

  | 릴리스     | 영향을 받는 패치 릴리스 |
  | ----------- | ----------------------- |
  | 18.10       | 18.10.0 이상       |

GitLab 18.10 이상에서는 dotenv 아티팩트의 변수(`artifacts:reports:dotenv`)가 파이프라인 실행 정책의 다른 변수와 동일한 `variables_override` 규칙을 따릅니다(기본적으로 안전). 이전에는 dotenv 변수가 `variables_override` 제한을 우회할 수 있었으며, 이는 정책의 보안 제어를 훼손했습니다.

파이프라인이 dotenv 변수를 사용하여 정책 정의 변수를 재정의했다면, `variables_override.allowed: false`이 설정되었을 때 해당 동작은 더 이상 작동하지 않습니다. 이전 동작을 복원하려면 새로운 `dotenv` 옵션을 `allow_override`으로 설정하세요:

```yaml
variables_override:
  allowed: false
  exceptions: []
  dotenv: allow_override
```

자세한 내용은 [파이프라인 실행 정책](../../user/application_security/policies/pipeline_execution_policies.md) 및 [머지 리퀘스트 214991](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/214991)을 참조하세요.

### Geo Blob 동기화 실패 `log_error` 파일 저장소의 NoMethodError {#geo-blob-sync-failures-with-log_error-nomethoderror-on-file-storage}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo (파일 저장소만)
- 영향을 받는 버전:

  | 릴리스           | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  | ----------------- |-------------------------|-------------------|
  | 18.11             | 18.11.0 - 18.11.2       | 18.11.3           |
  | 18.10             | 18.10.0 - 18.10.5       | 18.10.6           |
  | 18.0 - 18.9       | 모든 패치 릴리스      | 수정되지 않음         |

객체 저장소가 아닌 **파일 저장소**에 Blob을 저장하는 Geo 보조 사이트에서는 Blob 복제(예: 파이프라인 아티팩트, LFS 객체, 업로드 및 작업 아티팩트)가 다음과 같은 오류로 실패할 수 있습니다:

```plaintext
Error while attempting to sync: undefined method `log_error' for an instance of Gitlab::Geo::Replication::BlobDownloader
```

자세한 내용은 [이슈 598565](https://gitlab.com/gitlab-org/gitlab/-/work_items/598565)를 참조하세요.

### Geo 컨테이너 리포지토리 동기화가 OCI 이미지 인덱스 태그를 자동으로 건너뜀 {#geo-container-repository-sync-silently-skips-oci-image-index-tags}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo (컨테이너 레지스트리)
- 영향을 받는 버전:

  | 릴리스     | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  | ----------- | ----------------------- | ----------------- |
  | 18.11       | 18.11.0 - 18.11.4       | 18.11.5           |
  | 18.10       | 18.10.0 - 18.10.7       | 18.10.8           |
  | 18.0 - 18.9 | 모든 패치 릴리스      | 수정되지 않음         |

Geo 보조 사이트에서는 매니페스트가 OCI 이미지 인덱스(`application/vnd.oci.image.index.v1+json`)인 태그의 컨테이너 리포지토리 동기화가 자동으로 건너뛰었습니다. 멀티 아키텍처 이미지 및 BuildKit 캐시 태그는 일반적으로 이 매니페스트 유형을 사용합니다. 오류가 발생하지 않았고 태그 수가 일치했지만 보조 사이트에서 영향을 받은 태그의 `docker pull`는 `manifest unknown`을 반환했습니다. 동일한 근본 원인으로 인해 보조 사이트에서 동기화할 수 없는 고아 태그도 남겨졌습니다.

고정 버전으로 주 사이트와 보조 사이트를 모두 업그레이드한 후, 새로 동기화된 태그가 올바릅니다. 이전에 영향을 받은 리포지토리는 다음 검증 주기에 수렴되며, 이는 재검증 간격(기본값 90일)까지 걸릴 수 있습니다. 영향을 받은 리포지토리를 즉시 복구하려면 [보조 사이트에서 컨테이너 리포지토리 재동기화](../../administration/geo/replication/container_registry.md#manually-trigger-a-container-registry-sync-event)를 수행하세요.

자세한 내용은 [이슈 600486](https://gitlab.com/gitlab-org/gitlab/-/work_items/600486)을 참조하세요.

### 내부 및 공개 프로젝트에서 컨테이너 이미지를 가져오는 CI 작업 토큰 회귀 {#ci-job-token-regression-pulling-container-images-from-internal-and-public-projects}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  | ------- | ----------------------- | ----------------- |
  | 18.11   | 18.11.0 - 18.11.1       | 18.11.2           |

> [!warning]
> CI 작업이 `CI_JOB_TOKEN`를 사용하여 내부 또는 공개 프로젝트에서 컨테이너 이미지를 가져오는 경우 GitLab 18.11.0 또는 18.11.1로 업그레이드하지 마세요.

GitLab 18.11.0의 회귀로 인해 CI 작업이 `CI_JOB_TOKEN`를 사용하여 내부 또는 공개 프로젝트에서 컨테이너 이미지를 가져올 수 없습니다. 영향을 받은 파이프라인이 `denied: requested access to the resource is denied`로 인해 실패합니다. 수정은 `18-11-stable-ee`으로 백포트되었지만 18.11.1 태그를 자른 후에 적용되었으므로 18.11.0과 18.11.1 모두 영향을 받습니다.

이미 업그레이드한 운영자를 위한 사용 가능한 해결 방법:

1. 각 소비 프로젝트를 소스 프로젝트의 CI 작업 토큰 허용 목록에 추가하세요. [CI/CD 작업 토큰 보안](../../ci/jobs/ci_job_token.md#gitlab-cicd-job-token-security)을 참조하세요.
1. `CI_JOB_TOKEN` 대신 개인, 그룹 또는 프로젝트 액세스 토큰으로 컨테이너 풀을 인증하세요.
1. 백포트 커밋 [`e3c0f308`](https://gitlab.com/gitlab-org/gitlab/-/commit/e3c0f30800f803b8f519e9b937296b068d8f4cca)을 GitLab 인스턴스에 적용하세요.

자세한 내용은 [이슈 597223](https://gitlab.com/gitlab-org/gitlab/-/work_items/597223)을 참조하세요.

### SLES 12.5 RPM 패키지 설치 실패 {#sles-125-rpm-package-installation-failure}

- 영향을 받음: Linux 패키지
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스          | 설치 가능한 패치 수준 |
  | ------- | -------------------------------- | ----------------------- |
  | 18.10   | 18.10.0 - 18.10.3                | 18.10.4 - 18.10.5       |
  | 18.9    | 18.9.1 - 18.9.5                  | 18.9.0, 18.9.6          |

> [!warning]
> SLES 12.5에서는 GitLab 18.9.0, 18.10.4 및 18.11.2만 성공적으로 설치할 수 있습니다. 영향을 받는 범위의 다른 모든 패치 릴리스는 설치에 실패합니다.

SLES 12.5용 GitLab Linux 패키지는 `rpm` 또는 `zypper` 명령을 사용할 때 `error: install failed`로 설치하지 못합니다. 근본 원인은 SLES 12 SP5와 함께 제공되는 버전인 RPM 4.11.2의 16 MiB RPM 헤더 데이터 크기 제한(`HEADER_DATA_MAX`)입니다. GitLab 패키지의 파일 수가 증가함에 따라 직렬화된 RPM 헤더가 이 한계를 초과했으며, 이로 인해 설치 중 RPM 데이터베이스 트랜잭션이 자동으로 실패했습니다.

Linux 패키지의 파일 수를 줄여서 특정 패치 릴리스에서 문제가 해결되었습니다([머지 리퀘스트 9215](https://gitlab.com/gitlab-org/omnibus-gitlab/-/merge_requests/9215) 참조). 그러나 파일 수가 다시 증가하면 후속 패치 릴리스에서 재발할 수 있습니다. SLES 12.5에 GitLab을 설치하려면 위에 나열된 설치 가능한 패치 수준만 사용하세요.

SUSE 배포판은 [GitLab 18.9에서 사용되지 않으며 GitLab 19.0에서 제거 예정](../deprecations.md#linux-package-support-for-suse-distributions)입니다. 지원되는 운영 체제로 마이그레이션하는 것을 고려하세요.

자세한 내용은 [이슈 9647](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/9647)을 참조하세요.

### Mattermost 및 Spamcheck이 SLES 12.5 패키지에서 제거됨 {#mattermost-and-spamcheck-removed-from-sles-125-packages}

- 영향을 받음: Linux 패키지
- 영향을 받는 버전: 18.11.0 이상

[RPM 패키지 크기 제약으로 인해](https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/9716) Mattermost 및 Spamcheck이 SLES 12.5 Linux 패키지에서 제거되었습니다.

SUSE 배포판은 [GitLab 18.9에서 사용되지 않으며 GitLab 19.0에서 제거 예정](../deprecations.md#linux-package-support-for-suse-distributions)이며, [Mattermost](../deprecations.md#mattermost-bundled-with-linux-package) 및 [Spamcheck](../deprecations.md#spamcheck-support-in-the-linux-package-and-gitlab-helm-chart) 모두 GitLab 19.0에서 모든 배포판에서 제거 예정입니다.

SLES 12.5에서 Mattermost를 사용하는 경우 [Mattermost를 독립 실행형 배포로 마이그레이션](https://docs.mattermost.com/administration-guide/onboard/migrate-gitlab-omnibus.html)할 수 있습니다. SLES 12.5에서 Spamcheck을 사용하는 경우 [Docker를 사용하여 배포](../../administration/reporting/spamcheck.md)할 수 있습니다.

### Gitaly cgroup 메트릭이 변경되었으며 일부가 제거됨 {#gitaly-cgroup-metrics-changed-and-some-were-removed}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전:

  | 릴리스      | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  | ------------ | ------------------------ | ------------------ |
  | 18.11 - 19.2 | 모든 패치 릴리스       | 19.3.0             |

GitLab 18.11에서 Gitaly의 cgroup 메트릭이 새로운 `LoadMonitor` 구성 요소로 이동했습니다([Gitaly!8639](https://gitlab.com/gitlab-org/gitaly/-/merge_requests/8639) 참조). 결과적으로:

- 메트릭이 이제 리포지토리당 cgroup 대신 상위 Gitaly cgroup에 대해서만 보고됩니다.
- `[cgroups]` 아래의 `metrics_enabled` 설정은 더 이상 영향을 주지 않습니다.
- 다음 메트릭이 제거되었습니다: `gitaly_cgroup_cpu_usage_total`, `gitaly_cgroup_procs_total`, `gitaly_cgroup_cpu_cfs_periods_total`, `gitaly_cgroup_cpu_cfs_throttled_periods_total`, `gitaly_cgroup_cpu_cfs_throttled_seconds_total`, `gitaly_cgroup_memory_reclaim_attempts_total`, `gitaly_cgroup_memory_events_oom_total`, `gitaly_cgroup_memory_pgfault_total` 및 `gitaly_cgroup_memory_pgmajfault_total`.

또한 [Gitaly 이슈 7280](https://gitlab.com/gitlab-org/gitaly/-/work_items/7280)으로 인해 GitLab 18.11부터 19.2까지 어떤 종류의 Gitaly cgroup 메트릭도 내보내지지 않았습니다. 이는 GitLab 19.3에서 수정되었습니다.

제거된 메트릭을 사용하는 경우 [cAdvisor](https://github.com/google/cadvisor)와 같은 cgroup 인식 내보내기 도구를 사용하세요. 현재 메트릭 목록 및 제거된 메트릭의 cAdvisor 동등물 매핑을 보려면 [Gitaly cgroup 모니터링](../../administration/gitaly/monitoring.md#monitor-gitaly-cgroups)을 참조하세요.

### Geo 보조 사이트의 제한된 작업이 배출되지 않음 {#geo-secondary-throttled-jobs-not-draining}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  | ------- | ----------------------- | ----------------- |
  | 18.10   | 18.10.0 - 18.10.3       | 18.10.4           |
  | 18.9    | 18.9.0 - 18.9.5         | 18.9.6            |

Geo 보조 사이트가 `ConcurrencyLimit::ResumeWorker`을 비활성화했으며, 이로 인해 `Geo::EventWorker` 및 `Geo::SyncWorker` 작업이 Redis에서 배출되지 않은 채 누적됩니다. 이는 Geo 복제를 지연시키고 Redis 메모리 사용량을 증가시킬 수 있습니다.

자세한 내용은 [이슈 595824](https://gitlab.com/gitlab-org/gitlab/-/work_items/595824)를 참조하세요.

### 아웃바운드 필터링을 사용할 때 Geo 사이트 URL이 차단됨 {#geo-site-url-blocked-when-using-outbound-filtering}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  | ------- | ----------------------- | ----------------- |
  | 18.10   | 18.10.0 - 18.10.3       | 18.10.4           |
  | 18.9    | 18.9.0 - 18.9.5         | 18.9.6            |

아웃바운드 요청 필터링이 활성화되면 Geo 사이트 URL이 잘못 차단됩니다. 이로 인해 `Url is blocked: Requests to hosts and IP addresses not on the Allow List are denied`과 같은 메시지로 Geo 사이트를 저장할 때 유효성 검사 오류가 발생합니다.

이 문제는 Geo 사이트 URL이 아웃바운드 필터링이 구성될 때 아웃바운드 로컬 요청 허용 목록에 자동으로 추가되지 않아 발생합니다.

자세한 내용은 [이슈 544821](https://gitlab.com/gitlab-org/gitlab/-/issues/544821)을 참조하세요.

### Geo Blob 다운로드 시간 초과 설정 {#geo-blob-download-timeout-setting}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전: 18.10.0

현재 8시간(28,800초) 고정 Geo Blob 다운로드 시간 초과로 인해 더 긴 전송 시간이 필요한 매우 큰 LFS 객체(5GB 이상)의 동기화 실패가 발생하며, 이들은 '시작됨' 상태에서 멈춥니다. 새로운 `blob_download_timeout` 설정은 Blob 복제(LFS 객체, 업로드, 작업 아티팩트 등)에 대한 사이트별 시간 초과(초 단위)를 제어합니다. [Geo Sites API](../../api/geo_sites.md)를 통해 구성 가능합니다.

- 기본값: `28800` (8시간)
- 최대: `86400` (24시간)

### Geo Blob 다운로드 실패 {#geo-blob-download-failures}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  | ------- | ----------------------- | ----------------- |
  | 18.10   |  18.10.0 - 18.10.4      | 18.10.5           |

모든 Geo Blob 유형(업로드, LFS 객체, 작업 아티팩트 등)이 보조 사이트에서 동기화하지 못할 수 있습니다. 일시적인 네트워크 오류와 달리 이러한 실패는 모든 Blob 레코드에 영향을 미치고 재시도 시 복구되지 않습니다. 영향을 받은 보조 사이트는 Blob을 '실패' 상태로 표시하며, Sidekiq 로그에는 세그먼트 오류, `HPE_USER Span callback error in on_header_field` 오류 또는 예기치 않은 HTTP 상태 코드(예: `status_code: 32` 또는 `status_code: 34`)가 포함될 수 있습니다.

근본 원인은 `rugged` 1.9.0(GitLab 18.10에서 업그레이드됨)과 `llhttp-ffi` gem 간의 심볼 충돌입니다. `rugged.so`의 정적으로 연결된 `llhttp` 심볼이 `llhttp-ffi` 콜백을 재정의하여 HTTP 응답 구문 분석을 손상시킵니다. 자세한 내용은 [이슈 598564](https://gitlab.com/gitlab-org/gitlab/-/issues/598564)를 참조하세요.

GitLab 18.10.5에서 `rugged`은 충돌하는 심볼을 포함하지 않는 1.7.2로 다운그레이드됩니다. 업그레이드 후 조치가 필요하지 않습니다.

#### GitLab 18.10.4의 기능 플래그 해결 방법 {#feature-flag-workaround-for-gitlab-18104}

GitLab 18.10.4를 사용 중이고 GitLab 18.10.5로 업그레이드할 수 없으면 `geo_blob_download_with_gitlab_http` 기능 플래그를 활성화하세요. 이 플래그는 Blob 다운로드를 `Gitlab::HTTP` (`Net::HTTP`)를 사용하도록 전환하여 FFI 종속 `http` gem 대신 사용합니다:

1. 기능 플래그 활성화:

   ```shell
   sudo gitlab-rails console
   Feature.enable(:geo_blob_download_with_gitlab_http)
   exit
   ```

1. Sidekiq 재시작:

   ```shell
   sudo gitlab-ctl restart sidekiq
   ```

> [!note]
> 기능 플래그 해결 방법에는 알려진 제한 사항이 있습니다:
>
> - 60초를 초과하는 대용량 Blob 전송은 시간 초과될 수 있습니다([이슈 598020](https://gitlab.com/gitlab-org/gitlab/-/issues/598020)).
> - 컨테이너 레지스트리 복제는 이 플래그에 포함되지 않습니다.
> - 아웃바운드 요청 필터링이 있는 환경(`deny_all_requests_except_allowed`)은 추가 구성이 필요할 수 있습니다([이슈 598514](https://gitlab.com/gitlab-org/gitlab/-/issues/598514)).

자세한 내용은 [이슈 595139](https://gitlab.com/gitlab-org/gitlab/-/issues/595139)를 참조하세요.

### 18.9로의 업그레이드가 PostgreSQL CheckViolation으로 실패함 {#upgrade-to-189-fails-with-postgresql-checkviolation}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.9.0, 18.9.1

GitLab Self-Managed 인스턴스를 GitLab 18.9.0 또는 18.9.1로 업그레이드할 때 업그레이드가 데이터베이스 마이그레이션 중 다음으로 인해 실패합니다:

```plaintext
PG::CheckViolation: ERROR: check constraint "check_xxxxxxxx" of relation "tablename" is violated by some row
```

이 문제는 GitLab 18.10에서 수정된 버그로 인해 발생했습니다([머지 리퀘스트 224446](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/224446) 참조). 수정은 또한 백포트되었으며 다음 GitLab 18.9 패치 릴리스에 포함되어야 합니다([머지 리퀘스트 225026](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/225026) 참조).

그러나 버그로 인해 단일 레코드 버그로 인해 배치 백그라운드 마이그레이션이 자동으로 건너뛰어질 수 있습니다. v18.8로 업그레이드할 때, 단일 레코드가 있는 테이블을 대상으로 하는 배치 백그라운드 마이그레이션이 실행되지 않은 채 `finished`로 잘못 표시되었습니다. 이로 인해 데이터가 백필되지 않아 GitLab Self-Managed 인스턴스에서 업그레이드 실패가 발생했습니다.

제안된 수정([머지 리퀘스트 225461](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/225461) 참조)은 영향을 받는 배치 백그라운드 마이그레이션을 `finished`/`finalized`에서 `paused`로 재설정하여 스케줄러가 다시 실행되도록 합니다. `queued_migration_version`이 18.5와 18.8 사이이고 `min_value = max_value` 또는 `min_cursor = max_cursor`인 마이그레이션의 범위를 지정합니다.

두 가지 옵션이 있습니다:

- 지금 바로 해결 방법을 적용하여 업그레이드를 즉시 완료하세요.
- 완전한 수정을 기다리고 릴리스가 포함된 후에 업그레이드하세요.

다음 기술 자료 문서에서 5가지 알려진 증상에 대한 해결 방법을 설명합니다:

- [`PG::CheckViolation: ERROR: check constraint "check_96233d37c0" of relation "pool_repositories" is violated by some row`](https://support.gitlab.com/hc/en-us/articles/25929006135068-PG-CheckViolation-ERROR-check-constraint-check-96233d37c0-of-relation-pool-repositories-is-violated-by-some-row)
- [`PG::CheckViolation: ERROR: check constraint "check_f6590fe2c1" of relation "gpg_key_subkeys" is violated by some row`](https://support.gitlab.com/hc/en-us/articles/25756021007004-Upgrade-to-18-9-0-fails-with-PG-CheckViolation-on-gpg-key-subkeys)
- [`PG::CheckViolation: ERROR: check constraint "check_17a3a18e31" of relation "user_agent_details" is violated by some row`](https://support.gitlab.com/hc/en-us/articles/25994671144348-Upgrade-to-18-9-0-fails-with-PG-CheckViolation-on-user-agent-details)
- [`PG::CheckViolation: ERROR: check constraint "check_ddd6f289f4" of relation "commit_user_mentions" is violated by some row`](https://support.gitlab.com/hc/en-us/articles/25992549646364-Upgrade-to-18-9-0-fails-with-PG-CheckViolation-on-commit-user-mentions)
- [`PG::CheckViolation: ERROR: check constraint "check_e69372e45f" of relation "suggestions" is violated by some row`](https://support.gitlab.com/hc/en-us/articles/25771198648732-Upgrade-to-18-9-0-fails-with-PG-CheckViolation-on-suggestions)

### 차단된 사용자의 배포 키 및 개인 액세스 토큰이 무효화됨 {#deploy-keys-and-personal-access-tokens-for-blocked-users-invalidated}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 수준 | 수정된 패치 수준        |
  |---------|-----------------------|--------------------------|
  | 18.8    | 18.8.2 이상      | 해당 없음 (의도적 변경) |
  | 18.7    | 18.7.2 이상      | 해당 없음 (의도적 변경) |
  | 18.6    | 18.6.4 이상      | 해당 없음 (의도적 변경) |

GitLab 18.8.2, 18.7.2 및 18.6.4는 이제 차단된 사용자와 연결된 배포 키를 사용하는 API 요청을 거부합니다. 차단된 사용자와 연결된 배포 키가 있는 경우, 앞서 언급한 버전으로 업그레이드한 후 더 이상 작동하지 않습니다. 이는 차단된 사용자가 자신의 키와 토큰을 통해 GitLab 리소스에 액세스하는 것을 방지하기 위한 보안 수정입니다.

다음을 수행해야 합니다.

1. 차단된 사용자가 소유한 배포 키 또는 PAT를 식별하세요.
1. 청구 가능한 사용자에게 재할당하거나, 청구 가능한 사용자 또는 서비스 계정으로 삭제하고 새 키/토큰을 생성하세요.

다음 쿼리는 차단된 계정과 연결되고 지난 365일 동안 최소 한 번은 사용된 모든 배포 키를 식별하는 데 사용할 수 있습니다:

```sql
SELECT
  k.id,
  k.user_id,
  u.username,
  u.state as user_state,
  k.title,
  k.fingerprint,
  k.fingerprint_sha256,
  k.usage_type,
  k.last_used_at,
  k.created_at,
  k.updated_at
FROM keys k
INNER JOIN users u ON k.user_id = u.id
WHERE u.state IN ('blocked', 'ldap_blocked', 'blocked_pending_approval', 'banned')
  AND k.type = 'DeployKey'
  AND k.last_used_at >= NOW() - INTERVAL '365 days'
ORDER BY u.state, u.username, k.last_used_at DESC;
```

### ClickHouse 사전 생성 오류 {#clickhouse-dictionary-creation-error}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.8.0

[ClickHouse 통합](../../integration/clickhouse.md)이 활성화된 GitLab Self-Managed 고객은 누락된 권한(`DB::Exception: gitlab: Not enough privileges`)으로 인해 업그레이드 프로세스 중 ClickHouse 데이터베이스 마이그레이션 오류가 발생할 수 있습니다. 이 오류를 해결하려면 [데이터베이스 사전 읽기 지원 문제 해결 설명서](../../integration/clickhouse.md#database-dictionary-read-support)를 참조하세요.

### CI 데이터를 위한 배치 백그라운드 마이그레이션이 다시 도입됨 {#batched-background-migration-for-ci-data-reintroduced}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.8.0

[배치 백그라운드 마이그레이션](../background_migrations.md)은 [CI 빌드 메타데이터 마이그레이션](#ci-builds-metadata-migration)에서 도입되어 데이터 구조의 엣지 케이스를 처리하고 완료되도록 다시 도입되어야 했습니다.

### 따옴표 없는 자리 표시자가 있는 사용자 정의 웹후크 템플릿을 저장할 수 없음 {#custom-webhook-template-with-unquoted-placeholders-cannot-be-saved}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  | ------- | ----------------------- | ----------------- |
  | 18.10   | 모든 패치 릴리스      | 수정되지 않음         |
  | 18.9    | 모든 패치 릴리스      | 수정되지 않음         |
  | 18.8    | 모든 패치 릴리스      | 수정되지 않음         |

GitLab 18.8부터 18.10까지 [사용자 정의 웹후크 템플릿](../../user/project/integrations/webhooks.md#custom-webhook-template)은 따옴표 없는 페이로드 필드를 저장할 수 없습니다. 이 문제는 GitLab 18.11에서 해결되었습니다.

해결 방법으로 필드를 따옴표로 감싸세요. 예를 들어, `{"value": {{id}}}`는 `{"value": "{{id}}"}`가 됩니다.

따옴표가 있는 필드는 숫자 값 대신 문자열 값을 생성합니다. 이것이 웹후크와 호환되지 않으면 GitLab 18.11 이상으로 업그레이드하세요.

자세한 내용은 [웹후크 문제 해결 설명서](../../user/project/integrations/webhooks_troubleshooting.md#custom-webhook-template-with-unquoted-placeholders-cannot-be-saved)를 참조하세요.

### CI 빌드 메타데이터 마이그레이션 {#ci-builds-metadata-migration}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.7.0

[배포 후 마이그레이션](../../development/database/post_deployment_migrations.md)은 CI 빌드 메타데이터를 새로운 최적화된 테이블(`p_ci_job_definitions`)로 복사하기 위해 배치 [백그라운드 마이그레이션](../background_migrations.md)을 예약합니다. 이 마이그레이션은 결국 CI 데이터베이스 크기를 줄이기 위한 이니셔티브의 일부입니다([에픽 13886](https://gitlab.com/groups/gitlab-org/-/work_items/13886) 참조). 수백만 개의 작업이 있는 인스턴스가 있고 마이그레이션 속도를 높이려면 [마이그레이션할 데이터 선택](#ci-builds-metadata-migration-details)을 할 수 있습니다.

### Geo ActionCable 허용 오리진 설정 {#geo-actioncable-allowed-origins-setting}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전: 18.7.0

ActionCable 웹소켓 요청의 허용 오리진을 구성하기 위해 새로운 `action_cable_allowed_origins` 설정이 추가되었습니다. 적절한 교차 사이트 WebSocket 연결을 보장하기 위해 주 사이트를 구성할 때 허용된 URL을 지정하세요:

- [Linux 패키지의 Geo 설명서](../../administration/geo/replication/configuration.md#add-primary-and-secondary-urls-as-allowed-actioncable-origins)
- [Helm 차트의 Geo 설명서](https://docs.gitlab.com/charts/advanced/geo/#configure-primary-database)

### Geo VerificationStateBackfillWorker 느린 쿼리 수정 {#geo-verificationstatebackfillworker-slow-queries-fix}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전: 18.6.5

`Geo::VerificationStateBackfillWorker`이 `merge_request_diff_details` 테이블에 대한 큰 느린 쿼리를 생성한 Geo [이슈 587407](https://gitlab.com/gitlab-org/gitlab/-/work_items/587407)을 수정했습니다.

### 커밋 및 파일 API 크기 및 속도 제한 {#commits-and-files-api-size-and-rate-limits}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 수준 | 수정된 패치 수준        |
  |---------|-----------------------|--------------------------|
  | 18.6    | 18.6.2 이상      | 해당 없음 (의도적 변경) |
  | 18.5    | 18.5.4 이상      | 해당 없음 (의도적 변경) |
  | 18.4    | 18.4.6 이상      | 해당 없음 (의도적 변경) |

GitLab 18.6.2, 18.5.4 및 18.4.6은 다음 엔드포인트에 대한 요청에 크기 및 속도 제한을 도입했습니다:

- `POST /projects/:id/repository/commits` - [커밋 생성](../../api/commits.md#create-a-commit)
- `POST /projects/:id/repository/files/:file_path` - [리포지토리에 파일 생성](../../api/repository_files.md#create-a-file-in-a-repository)
- `PUT /projects/:id/repository/files/:file_path` - [리포지토리에서 파일 업데이트](../../api/repository_files.md#update-a-file-in-a-repository)

GitLab은 크기 제한을 초과하는 요청에 `413 Entity Too large` 상태로 응답하고, 속도 제한을 초과하는 요청에 `429 Too Many Requests` 상태로 응답합니다. 자세한 내용은 [커밋 및 파일 API 제한](../../administration/instance_limits.md#commits-and-files-api-limits)을 참조하세요

### Duo Agent Platform 러너 제한 {#duo-agent-platform-runner-restrictions}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.6.2

일부 [러너 제한](../../user/duo_agent_platform/flows/execution/_index.md#configure-runners-to-execute-flows)이 Duo Agent Platform에서 사용할 수 있는 러너와 관련하여 도입되었습니다.

### Geo 로그 커서 마이그레이션 수정 {#geo-log-cursor-migration-fix}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  |---------|-------------------------|-------------------|
  | 18.5    | 18.5.0 - 18.5.1         | 18.5.2            |
  | 18.4    | 18.4.0 - 18.4.3         | 18.4.4            |

Geo 로그 커서가 보조 사이트에서 시작되지 않도록 하는 누락된 Geo [마이그레이션](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/210512)이 수정되었습니다.

### 디자인 관리 디자인 백필 완료 {#finalize-design-management-designs-backfill}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.5.0

[배포 후 마이그레이션](../../development/database/post_deployment_migrations.md) `20250922202128_finalize_correct_design_management_designs_backfill`는 18.4에서 예약된 배치 [백그라운드 마이그레이션](../background_migrations.md)을 완료합니다. 업그레이드 경로에서 18.4를 건너뛴 경우, 배포 후 마이그레이션이 실행될 때 마이그레이션이 완전히 실행됩니다. 실행 시간은 `design_management_designs` 테이블의 크기와 직접적인 관계가 있습니다. 대부분의 인스턴스의 경우 마이그레이션은 2분 이상 걸리지 않지만 일부 큰 인스턴스의 경우 최대 10분이 걸릴 수 있습니다. 인내심을 가지고 마이그레이션 프로세스를 중단하지 마세요.

### NGINX 라우팅 변경으로 인해 404 오류 발생 {#nginx-routing-changes-cause-404-errors}

- 영향을 받음: Linux 패키지
- 영향을 받는 버전: 18.5.0

GitLab 18.5.0에서 도입된 NGINX 라우팅 변경은 `localhost` 또는 대체 도메인 이름과 같은 일치하지 않는 호스트 이름을 사용할 때 서비스에 액세스할 수 없게 만들 수 있습니다. 이 문제는 다음을 야기합니다:

- `/-/health` 같은 상태 확인 엔드포인트가 적절한 응답 대신 `404` 오류를 반환합니다.
- 구성된 FQDN 이외의 호스트 이름으로 액세스할 때 GitLab 웹 인터페이스가 `404` 오류 페이지를 표시합니다.
- GitLab Pages가 다른 서비스를 위한 트래픽을 받을 수 있습니다.
- 이전에 작동하던 대체 호스트 이름을 사용하는 모든 요청에 문제가 있습니다.

이 문제는 Linux 패키지의 [머지 리퀘스트 8805](https://gitlab.com/gitlab-org/omnibus-gitlab/-/merge_requests/8805)로 해결되며, 수정은 GitLab 18.5.2 및 18.6.0에서 사용할 수 있습니다.

클론, 푸시 및 풀과 같은 Git 작업은 이 문제의 영향을 받지 않습니다.

### 배치 백그라운드 마이그레이션 nil 오류 {#batched-background-migration-nil-error}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.4.2, 18.4.3

`18.4.2` 또는 `18.4.3`로 업그레이드하면 이러한 배치 백그라운드 마이그레이션에 대해 `no implicit conversion of nil into String` 오류로 인해 실패할 수 있습니다:

- `FixIncompleteInstanceExternalAuditDestinations`
- `FinalizeAuditEventDestinationMigrations`

이 문제를 해결하려면 최신 패치 릴리스로 업그레이드하거나 [이슈 578938의 해결 방법](https://gitlab.com/gitlab-org/gitlab/-/issues/578938#workaround)을 사용하세요.

### Geo 복제 TypeError {#geo-replication-typeerror}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  |---------|-------------------------|-------------------|
  | 18.4    | 18.4.0 - 18.4.1         | 18.4.2            |

보조 Geo 사이트에서 [버그](https://gitlab.com/gitlab-org/gitlab/-/issues/571455)로 인해 복제 이벤트가 `no implicit conversion of String into Array (TypeError)` 오류 메시지로 인해 실패합니다. 재검증과 같은 중복성은 최종 일관성을 보장하지만 RPO가 크게 증가합니다.

### 서비스 거부 방지를 위한 JSON 입력 제한 {#json-input-limits-for-denial-of-service-prevention}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 수준 | 수정된 패치 수준        |
  |---------|-----------------------|--------------------------|
  | 18.4    | 18.4.1 이상      | 해당 없음 (의도적 변경) |
  | 18.3    | 18.3.3 이상      | 해당 없음 (의도적 변경) |
  | 18.2    | 18.2.7 이상      | 해당 없음 (의도적 변경) |

GitLab 18.4.1, 18.3.3 및 18.2.7은 서비스 거부 공격을 방지하기 위해 JSON 입력에 제한을 도입했습니다. GitLab은 이러한 제한을 초과하는 HTTP 요청에 `400 Bad Request` 상태로 응답합니다. 자세한 내용은 [HTTP 요청 제한](../../administration/instance_limits.md#http-request-limits)을 참조하세요.

### LdapAddOnSeatSyncWorker가 Duo 사용자를 제거함 {#ldapaddonseatsyncworker-removes-duo-seats}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.3.0

`LdapAddOnSeatSyncWorker` 워커가 추가되어 LDAP이 활성화되면 매일 밤 GitLab Duo 사용자 수를 실수로 모두 제거할 수 있습니다. GitLab 18.4.0 및 18.3.2에서 이 문제가 수정되었습니다. 자세한 내용은 [이슈 565064](https://gitlab.com/gitlab-org/gitlab/-/issues/565064)를 참조하세요.

### Geo Rake 검사 수정 {#geo-rake-check-fix}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전: 18.3.0

Geo 보조 사이트 설치 시 `rake gitlab:geo:check`이 실패를 잘못 보고하는 원인이 된 [이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/545533)가 18.3.0에서 수정되었습니다.

### Geo Pages 파일 이름 수정 {#geo-pages-filename-fix}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 수준  | 수정된 패치 수준 |
  |---------|------------------------|-------------------|
  | 18.3    | 18.3.0 - 18.3.2        | 18.3.3            |
  | 18.2    | 18.2.0 - 18.2.6        | 18.2.7            |
  | 18.1    | 18.1.0 이후       | 18.1에서 수정되지 않음 |

GitLab 18.3.3 및 18.2.7 이상에는 긴 파일 이름을 가진 Pages 배포에 대해 Geo 검증이 실패할 수 있는 [이슈 559196](https://gitlab.com/gitlab-org/gitlab/-/issues/559196)에 대한 수정이 포함되어 있습니다. 이 수정은 복제 및 검증 중 일관성을 유지하기 위해 Geo 보조 사이트의 파일 이름 자르기를 방지합니다.

### 18.1과 18.2 사이의 무중단 업그레이드 푸시 오류 {#zero-downtime-upgrade-push-errors-between-181-and-182}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.2.0

18.1.x와 18.2.x 사이의 업그레이드는 업그레이드 중 기존 프로젝트에 코드를 푸시할 때 오류를 발생시키는 [알려진 이슈 567543](https://gitlab.com/gitlab-org/gitlab/-/issues/567543)의 영향을 받습니다. 버전 18.1.x와 18.2.x 사이의 업그레이드 중 무중단을 보장하려면 수정이 포함된 버전 18.2.6으로 직접 업그레이드하세요.

### Geo VerificationStateBackfillService `ci_job_artifact_states` {#geo-verificationstatebackfillservice-ci_job_artifact_states}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 수준 | 수정된 패치 수준 |
  |---------|------------------------|-------------------|
  | 18.2    | 18.2.0 - 18.2.1        | 18.2.2            |
  | 18.1    | 18.1.0 - 18.1.3        | 18.1.4            |
  | 18.0    | 18.0.0 - 18.0.5        | 18.0.6            |

영향 받는 버전은 `VerificationStateBackfillService`이 실행될 때 발생하는 알려진 이슈가 있으며, `ci_job_artifact_states`의 기본 키 변경으로 인한 것입니다. 수정된 패치 수준 릴리스로 업그레이드하여 해결하세요.

### Elasticsearch `strict_dynamic_mapping_exception` {#elasticsearch-strict_dynamic_mapping_exception}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.1.0

Elasticsearch 인덱싱이 Elasticsearch 버전 7에 대해 `strict_dynamic_mapping_exception` 오류로 실패할 수 있습니다. 해결하려면 [이슈 566413](https://gitlab.com/gitlab-org/gitlab/-/issues/566413)의 "가능한 수정" 섹션을 참조하세요.

### PostgreSQL `ci_job_artifacts` 오류 {#postgresql-ci_job_artifacts-error}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.1.0, 18.1.1

GitLab 버전 18.1.0 및 18.1.1은 PostgreSQL 로그에서 `ERROR:  relation "ci_job_artifacts" does not exist at ...`과 같은 오류를 표시합니다. 로그의 이러한 오류는 무시해도 안전하지만 Geo 사이트를 포함한 모니터링 알림을 트리거할 수 있습니다. 이 문제를 해결하려면 GitLab 18.1.2 이상으로 업데이트하세요.

### 머지 리퀘스트 거의 준비 완료 버그 {#merge-request-almost-ready-bug}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.1.0

일부 사용자의 커밋을 포함한 머지 리퀘스트가 진행되지 않고 계속해서 `Your merge request is almost ready`을 표시할 수 있습니다. [이슈 554613](https://gitlab.com/gitlab-org/gitlab/-/issues/554613)을 참조하세요. 또한 [`sidekiq/current` 로그](../../administration/logs/_index.md#sidekiq-logs)에는 `undefined method 'id' for nil:NilClass` 오류가 표시되며 `merge_request_diff_commit.rb`에 대한 것입니다. 이를 수정하려면 다음을 수행하세요:

1. [데이터베이스 콘솔](../../administration/troubleshooting/postgresql.md#start-a-database-console)을 시작하세요.
1. 다음 명령을 실행하세요:

   ```sql
   REINDEX TABLE CONCURRENTLY public.merge_request_diff_commit_users;
   ```

1. 영향을 받는 머지 리퀘스트를 닫았다가 다시 열어 주세요.

### Geo HTTP 500 프록시 오류 {#geo-http-500-proxy-errors}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  |---------|-------------------------|-------------------|
  | 18.1    | 18.1.0                  | 18.1.1            |
  | 18.0    | 18.0.0 - 18.0.2         | 18.0.3            |

위 표의 GitLab 버전에는 보조 Geo 사이트에서 프록시되는 Git 작업이 HTTP 500 오류로 실패하는 알려진 이슈가 있습니다. 해결하려면 수정된 패치 수준 릴리스로 업그레이드하세요.

### PostgreSQL 14는 지원되지 않음 {#postgresql-14-not-supported}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.0.0

[PostgreSQL 14는 GitLab 18부터 지원되지 않습니다](../deprecations.md#postgresql-14-and-15-no-longer-supported). GitLab 18.0 이상으로 업그레이드하기 전에 PostgreSQL을 최소한 버전 16.5로 업그레이드하세요. 자세한 내용은 [설치 요구 사항](../../install/requirements.md#postgresql)을 참조하세요.

> [!warning]
> Linux 패키지를 사용할 때 자동 데이터베이스 버전 업그레이드는 단일 노드 인스턴스에만 적용됩니다. Geo 인스턴스, Linux 패키지를 사용한 고가용성 PostgreSQL 또는 외부 PostgreSQL 데이터베이스(예: Amazon RDS)를 사용하는 경우 등 다른 모든 경우에는 PostgreSQL을 수동으로 업그레이드해야 합니다. 자세한 단계는 [Geo 인스턴스 업그레이드](https://docs.gitlab.com/omnibus/settings/database/#upgrading-a-geo-instance)를 참조하세요.

### `pg_dump` 바이너리 호환성 {#pg_dump-binary-compatibility}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.0.0

GitLab은 `pg_dump` 바이너리를 포함합니다. 외부 PostgreSQL 서버를 사용할 때, GitLab 데이터베이스 백업을 만들고 복원하기 위해 `pg_dump` 클라이언트 버전이 PostgreSQL 서버와 호환되는지 확인하세요.

### Bitnami PostgreSQL 및 Redis 이미지 지원 중단 {#bitnami-postgresql-and-redis-image-deprecation}

- 영향을 받음: Helm 차트
- 영향을 받는 버전: 17.11.0 이전

2025년 9월 29일부터 Bitnami는 태그가 지정된 PostgreSQL 및 Redis 이미지 제공을 중단합니다. GitLab 17.11 이상을 GitLab 차트와 함께 번들 Redis 또는 Postgres를 사용하여 배포하는 경우, 예기치 않은 중단을 방지하기 위해 레거시 리포지토리를 사용하도록 값을 수동으로 업데이트해야 합니다. 자세한 내용은 [이슈 6089](https://gitlab.com/gitlab-org/charts/gitlab/-/issues/6089)를 참조하세요.

### 17.11에서의 무중단 업그레이드 중 파이프라인 실패 {#pipeline-failures-during-zero-downtime-upgrades-from-1711}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.0.0

기능 플래그 `ci_only_one_persistent_ref_creation`는 Rails가 업그레이드되지만 Sidekiq가 버전 17.11에 유지될 때 무중단 업그레이드 중 파이프라인 실패를 발생시킵니다([이슈 558808](https://gitlab.com/gitlab-org/gitlab/-/issues/558808)의 세부 정보 참조).

**예방:** Rails 콘솔을 열고 업그레이드하기 전에 기능 플래그를 활성화하세요:

```shell
$ sudo gitlab-rails console
Feature.enable(:ci_only_one_persistent_ref_creation)
```

**이미 영향을 받는 경우:** 이 명령을 실행하고 실패한 파이프라인을 다시 시도하세요:

```shell
$ sudo gitlab-rails console
Rails.cache.delete_matched("pipeline:*:create_persistent_ref_service")
```

### Gitaly 구성을 `git_data_dirs`에서 스토리지로 마이그레이션 {#migrate-gitaly-configuration-from-git_data_dirs-to-storage}

- 영향을 받음: Linux 패키지
- 영향을 받는 버전: 18.0.0

GitLab 18.0 이상에서는 `git_data_dirs` 설정을 더 이상 사용하여 Gitaly 스토리지 위치를 구성할 수 없습니다.

여전히 `git_data_dirs`을 사용하고 있다면 GitLab 18.0으로 업그레이드하기 전에 [Gitaly 구성을 마이그레이션](https://docs.gitlab.com/omnibus/settings/configuration/#migrating-from-git_data_dirs)해야 합니다.

### Geo CE에서 EE로 되돌리기 마이그레이션 오류 {#geo-ce-to-ee-revert-migration-errors}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전: 18.0.0

GitLab Enterprise Edition을 배포한 후 GitLab Community Edition으로 되돌렸다면 데이터베이스 스키마가 GitLab 애플리케이션이 예상하는 스키마에서 벗어나서 마이그레이션 오류가 발생할 수 있습니다. 18.0.0으로 업그레이드할 때 4가지 특정 오류가 발생할 수 있습니다. 이 버전에 추가된 마이그레이션이 해당 열의 기본값을 변경하기 때문입니다.

오류는 다음과 같습니다:

- `No such column: geo_nodes.verification_max_capacity`
- `No such column: geo_nodes.minimum_reverification_interval`
- `No such column: geo_nodes.repos_max_capacity`
- `No such column: geo_nodes.container_repositories_max_capacity`

이 마이그레이션은 GitLab 18.0.2에서 패치되어 해당 열이 없으면 추가합니다. [이슈 #543146](https://gitlab.com/gitlab-org/gitlab/-/issues/543146)을 참조하세요.

**영향 받는 릴리스**:

| 영향 받는 부 릴리스 | 영향을 받는 패치 릴리스 | 수정됨 |
| ----------------------- | ----------------------- | -------- |
| 18.0                    |  18.0.0 - 18.0.1        | 18.0.2   |

### Docker 설치에서 PRNG 시드되지 않음 오류 {#prng-is-not-seeded-error-on-docker-installations}

- 영향을 받음: Docker
- 영향을 받는 버전: 18.0.0

FIPS 지원 호스트에서 Docker 설치로 GitLab을 실행하는 경우 SSH 키 생성이나 OpenSSH 서버(`sshd`)가 다음 오류 메시지로 시작하지 못할 수 있습니다:

```plaintext
PRNG is not seeded
```

GitLab 18.0은 [Ubuntu 22.04에서 24.04로 기본 이미지를 업데이트했습니다](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8928). Ubuntu 24.04는 더 이상 [FIPS 호스트가 비FIPS OpenSSL 공급자를 사용하도록 허용](https://github.com/dotnet/dotnet-docker/issues/5849#issuecomment-2324943811)하지 않기 때문에 이 오류가 발생합니다.

이 문제를 해결하는 방법은 몇 가지가 있습니다:

- 호스트 시스템에서 FIPS를 비활성화합니다.
- GitLab Docker 컨테이너의 FIPS 기반 커널 자동 감지를 비활성화합니다. 이는 GitLab 18.0.2 이상에서 `OPENSSL_FORCE_FIPS_MODE=0` 환경 변수를 설정하여 수행할 수 있습니다.
- GitLab Docker 이미지를 사용하는 대신 호스트에 [기본 FIPS 패키지](https://packages.gitlab.com/ui/browse/gitlab/gitlab-fips)를 설치합니다.

마지막 옵션은 FIPS 요구 사항을 충족하는 권장 옵션입니다. 기존 설치의 경우 처음 두 옵션을 임시방편으로 사용할 수 있습니다.

### CI 빌드 메타데이터 마이그레이션 세부 정보 {#ci-builds-metadata-migration-details}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.7.0

> [!note]
> GitLab 18.6부터 새 파이프라인은 새 형식으로만 데이터를 기록합니다([이슈 552065](https://gitlab.com/gitlab-org/gitlab/-/issues/552065) 참조). 이 마이그레이션은 기존 데이터를 이전 형식에서 새 형식으로만 복사합니다. 데이터가 삭제되지 않습니다.

마이그레이션되지 않은 데이터는 향후 릴리스에서 제거됩니다([에픽 18271](https://gitlab.com/groups/gitlab-org/-/work_items/18271) 참조).

마이그레이션 기간은 인스턴스의 총 CI 작업 수에 정확히 비례합니다. 작업은 최신 파티션에서 가장 오래된 파티션으로 처리되어 최근 데이터의 우선순위를 정합니다.

더 큰 프로젝트에서 [자동 파이프라인 정리](../../ci/pipelines/settings.md#automatic-pipeline-cleanup)를 활성화하여 업그레이드 전에 오래된 파이프라인을 삭제함으로써 마이그레이션할 작업 수를 줄일 수 있습니다.

마이그레이션은 두 가지 유형의 데이터를 복사합니다:

- **작업 처리 데이터**: `.gitlab-ci.yml`(예: `script`, `variables`)의 작업 실행 구성으로, 러너가 작업을 실행할 때만 필요하며 UI 또는 API에는 필요하지 않습니다.
- **사용자에게 표시되는 작업 데이터**: 모든 작업 데이터 중 이 마이그레이션은 작업 시간 초과 값, 작업 종료 코드 값, [노출된 아티팩트](../../ci/jobs/job_artifacts.md#link-to-job-artifacts-in-the-merge-request-ui) 및 [환경 연결](../../ci/yaml/_index.md#environment)에만 영향을 미칩니다.

대규모 CI 데이터 세트가 있는 GitLab Self-Managed 및 GitLab Dedicated 인스턴스의 경우 마이그레이션할 데이터의 범위를 줄여서 마이그레이션을 가속화할 수 있습니다. 범위를 제어하려면 아래에 정의된 설정을 사용하세요.

#### 작업 처리 데이터의 범위 제어 {#controlling-the-scope-for-jobs-processing-data}

기본적으로 마이그레이션은 기존의 모든 작업에 대해 처리 데이터를 복사합니다. 아래에 설명된 설정 중 하나를 사용하여 범위를 줄일 수 있습니다.

설정의 값은 유지하려는 작업 처리 데이터의 양을 제어합니다. 예를 들어, `6mo`로 설정하면 지난 6개월 동안 생성된 작업만 실행할 것으로 예상하는 경우([재시도](../../ci/jobs/_index.md#retry-jobs), [수동 작업 실행](../../ci/jobs/job_control.md#create-a-job-that-must-be-run-manually), [환경 자동 중지](../../ci/environments/_index.md#stopping-an-environment)를 통해)입니다.

GitLab은 우선순위 순서로 설정을 검색합니다:

1. [파이프라인 아카이빙](../../administration/settings/continuous_integration.md#archive-pipelines) 설정(권장 모범 사례). 아카이빙된 파이프라인은 작업을 수동으로 재시도하거나 다시 실행할 수 없음을 나타냅니다. 이 설정이 활성화되면 아카이빙된 작업의 처리 데이터를 마이그레이션할 필요가 없습니다.

   > [!note]
   > 파이프라인 아카이빙 범위가 나중에 확장되면 처리 데이터가 없는 작업은 실행 불가능한 상태로 유지됩니다.
1. `GITLAB_DB_CI_JOBS_PROCESSING_DATA_CUTOFF` [환경 변수](../../administration/environment_variables.md)(파이프라인 아카이빙이 구성되지 않았거나 이 마이그레이션에 대해 재정의해야 하는 경우). `1y`(1년), `6mo`(6개월), `90d`(90일)과 같은 기간 문자열을 허용합니다.
1. `GITLAB_DB_CI_JOBS_MIGRATION_CUTOFF` 환경 변수(위의 어느 것도 설정되지 않은 경우). `1y`(1년), `6mo`(6개월), `90d`(90일)과 같은 기간 문자열을 허용합니다. [사용자에게 표시되는 작업 데이터의 범위 제어](#controlling-the-scope-for-job-data-visible-to-users)를 참조하세요.
1. 구성을 찾을 수 없으면 모든 데이터가 복사됩니다.

#### 사용자에게 표시되는 작업 데이터의 범위 제어 {#controlling-the-scope-for-job-data-visible-to-users}

환경 변수 `GITLAB_DB_CI_JOBS_MIGRATION_CUTOFF`은 표시 데이터를 마이그레이션할 작업을 제어합니다.

예를 들어, `GITLAB_DB_CI_JOBS_MIGRATION_CUTOFF=1y`은 가장 최근 연도의 작업에 대해 영향을 받는 표시 데이터(시간 초과 값, 환경, 종료 코드 및 노출된 아티팩트의 메타데이터)를 복사합니다.

기본적으로 마감일이 없으며 모든 작업의 데이터가 마이그레이션됩니다.

#### 마이그레이션 영향 추정 {#estimating-migration-impact}

참고로 GitLab.com의 경우 약 2개월 동안 4억 개의 행을 마이그레이션할 것으로 예상됩니다.

인스턴스에 대한 마이그레이션 영향을 추정하려면 [PostgreSQL 콘솔](../../administration/troubleshooting/postgresql.md#start-a-database-console)에서 다음 쿼리를 실행할 수 있습니다:

{{< tabs >}}

{{< tab title="테이블 크기" >}}

```sql
SELECT n.nspname AS schema_name, c.relname AS partition_name,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total_size
FROM pg_inherits i
JOIN pg_class c ON c.oid = i.inhrelid
JOIN pg_namespace n ON n.oid = c.relnamespace
JOIN pg_class p ON p.oid = i.inhparent
WHERE p.relname = 'p_ci_builds_metadata'
ORDER BY pg_total_relation_size(c.oid) DESC;
```

새 테이블은 이 공간의 약 20%를 필요로 합니다.

{{< /tab >}}

{{< tab title="작업 수 추정" >}}

이는 PostgreSQL 통계 테이블의 추정값입니다.

```sql
SELECT SUM(c.reltuples)::bigint AS estimated_jobs_count
FROM pg_class c
JOIN pg_inherits i ON c.oid = i.inhrelid
WHERE i.inhparent = 'p_ci_builds'::regclass;
```

{{< /tab >}}

{{< tab title="시간대별 작업" >}}

특정 시간대에 생성된 작업 수를 찾으려면 테이블을 쿼리해야 합니다:

```sql
SELECT COUNT(*) FROM p_ci_builds WHERE created_at >= now() - '1 year'::interval;
```

쿼리가 시간 초과되면 [Rails 콘솔](../../administration/operations/rails_console.md)을 사용하여 데이터를 배치로 처리하세요:

```ruby
counts = []
CommitStatus.each_batch(of: 25000) do |batch|
  counts << batch.where(created_at: 1.year.ago...).count
end
counts.sum
```

{{< /tab >}}

{{< /tabs >}}

### 머지 리퀘스트 병합 데이터에 대한 배치 배경 마이그레이션 {#batched-background-migration-for-merge-request-merge-data}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.8.0

[배치 배경 마이그레이션](../background_migrations.md)은 `merge_requests` 테이블에서 새로운 전용 `merge_requests_merge_data` 테이블로 머지 리퀘스트 병합 관련 데이터를 복사합니다.

이 마이그레이션은 데이터베이스 스키마 최적화 이니셔티브의 일부로 병합 관련 특성을 별도 테이블로 정규화하여 쿼리 성능과 유지 보수성을 개선합니다.

#### 마이그레이션되는 데이터 {#what-data-is-migrated}

마이그레이션은 `merge_requests`에서 `merge_requests_merge_data`로 다음 열을 복사합니다:

- `merge_commit_sha`
- `merged_commit_sha`
- `merge_ref_sha`
- `squash_commit_sha`
- `in_progress_merge_commit_sha`
- `merge_status`
- `auto_merge_enabled`
- `squash`
- `merge_user_id`
- `merge_params`
- `merge_error`
- `merge_jid`

마이그레이션은 `merge_requests` 테이블을 처리하여 `merge_requests_merge_data`에 해당 항목이 없는 머지 리퀘스트의 데이터만 복사합니다.

GitLab 18.7부터 새 머지 리퀘스트는 애플리케이션 수준의 이중 쓰기 메커니즘을 통해 두 테이블에 데이터를 기록합니다([이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/560933) 참조). 이 마이그레이션은 이중 쓰기 구현 후 생성되거나 변경되지 않은 기존 데이터만 복사합니다.

이 마이그레이션 중 `merge_requests` 테이블에서 데이터가 삭제되지 않습니다.

마이그레이션은 GitLab 18.9에서 최종화될 계획입니다. 자세한 내용은 [이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/584459)를 참조하세요.

#### 마이그레이션 기간 추정 {#estimating-migration-duration}

마이그레이션 기간은 인스턴스의 머지 리퀘스트 수에 정확히 비례합니다.

영향을 추정하려면:

**PostgreSQL 쿼리:**

```sql
-- Count total merge requests
SELECT COUNT(*) FROM merge_requests;

-- Estimate table size
SELECT pg_size_pretty(pg_total_relation_size('merge_requests')) AS table_size;
```

**Rails 콘솔:**

```ruby
# Count total merge requests
MergeRequest.count

# Count remaining merge requests to migrate
MergeRequest.left_joins(:merge_data)
  .where(merge_requests_merge_data: { merge_request_id: nil })
  .count
```

마이그레이션은 머지 리퀘스트를 배치로 처리하며 대부분의 인스턴스에서 몇 시간에서 며칠 이내에 완료되어야 합니다.

### GitLab 18.11의 PostgreSQL 버전 17.7 업그레이드 {#postgresql-version-177-upgrade-on-gitlab-1811}

- 영향을 받음: Linux 패키지, Docker, Geo
- 영향을 받는 버전: 18.11.0

GitLab 18.11로 업그레이드하면 단일 노드 Linux 패키지 설치의 경우 [PostgreSQL 17.7](../../administration/package_information/postgresql_versions.md)로의 자동 업그레이드가 시작됩니다.

> [!warning]
> Linux 패키지를 사용할 때 자동 데이터베이스 버전 업그레이드는 단일 노드 인스턴스에만 적용됩니다. Geo 배포의 경우 주요 버전 업그레이드를 위해 PostgreSQL 복제를 Geo 보조 사이트에 다시 초기화해야 하기 때문에 PostgreSQL 업그레이드는 [의도적으로 계획되고 준비](../../administration/geo/replication/upgrading_the_geo_sites.md)되어야 합니다. 이는 예상보다 더 큰 중단을 초래할 수 있습니다.

### Helm 차트 및 Operator 배포에서 Sidekiq 동시성 제한기로 인한 작업 백로그 {#sidekiq-concurrency-limiter-causes-job-backlogs-on-helm-chart-and-operator-deployments}

- 영향을 받음: Helm 차트, Operator
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  | ------- | ----------------------- | ----------------- |
  | 18.10   | 18.10.0 - 18.10.3      | 18.10.4           |
  | 18.9    | 18.9.0 - 18.9.5        | 18.9.6            |

GitLab 18.9에서 GitLab Helm 차트는 기본적으로 `GITLAB_SIDEKIQ_MAX_REPLICAS`을 설정하기 시작했습니다([charts/GitLab 머지 리퀘스트 4348](https://gitlab.com/gitlab-org/charts/gitlab/-/merge_requests/4348)). KEDA 기반 자동 스케일링을 사용하지 않는 GitLab Self-Managed 및 GitLab Dedicated 환경에서는 Sidekiq 동시성 제한기가 예기치 않게 활성화되어 작업을 Redis 백업 스로틀 큐에 연기합니다.

이로 인해 다음과 같은 결과가 발생할 수 있습니다:

- Sidekiq 작업 백로그.
- Redis 메모리 증가.
- 작업 실행 지연.
- `WebHookWorker`, `AuditEvents::AuditEventStreamingWorker`, 및 Geo 복제 워커(`Geo::EventWorker`, `Geo::SyncWorker`)와 같은 워커에 영향을 미칩니다.

영향을 받는 경우 수정된 버전으로 업그레이드할 때까지 다음 임시 완화 방법 중 하나를 사용할 수 있습니다:

- 기능 플래그를 활성화하여 특정 워커의 동시성 제한기를 비활성화합니다. Sidekiq 파드에서 `exec`을 실행하여 Rails 콘솔을 엽니다:

  ```shell
  kubectl exec -it <sidekiq-pod-name> -- gitlab-rails console
  ```

  그런 다음 영향을 받는 워커에 대해 플래그를 활성화하세요:

  ```ruby
  Feature.enable(:"disable_sidekiq_concurrency_limit_middleware_<WorkerClass>")
  ```

  `<WorkerClass>`을 영향을 받는 워커 이름(예: `WebHookWorker`)으로 바꿉니다.

- Sidekiq 파드 환경 구성에서 `GITLAB_SIDEKIQ_MAX_REPLICAS=0`을 설정하여 모든 기본 동시성 제한을 비활성화합니다. 이는 기본 동시성 제한 계산을 완전히 비활성화합니다.

> [!warning]
> Geo를 사용하는 경우 보조 사이트의 이미 스로틀된 작업이 `ConcurrencyLimit::ResumeWorker`이 Geo 보조 사이트에서 실행되지 않기 때문에 자동으로 드레인되지 않을 수 있습니다. 스로틀된 큐를 정리하기 위해 수동 개입이 필요할 수 있습니다.

기능 플래그 뒤에 기본 동시성 제한 계산을 제어하는 수정 사항이 [머지 리퀘스트 230713](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/230713)에 병합되었으며 18.10.4([머지 리퀘스트 231085](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/231085)) 및 18.9.6([머지 리퀘스트 231297](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/231297))으로 역이식되었습니다.

### 모든 프로젝트에서 기본적으로 활성화된 시크릿 검색 오탐지 검사 {#secret-detection-false-positive-detection-enabled-by-default-on-all-projects}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 18.10.x

[시크릿 오탐지 검사](../../user/application_security/vulnerabilities/false_positive_detection.md)를 위한 기본 플로우를 활성화하려면 일반적으로 두 가지 단계가 필요합니다:

1. 그룹에 대한 기본 플로우를 허용합니다.
1. 개별 프로젝트에 대한 기본 플로우를 활성화합니다.

그러나 GitLab 18.10의 모든 버전으로 업그레이드하면 모든 프로젝트에 대해 시크릿 오탐지 검사의 기본 플로우가 활성화됩니다. 그룹에 대해 기본 플로우가 허용되면 그룹의 모든 프로젝트에 대해 이미 활성화됩니다.

그룹에 대해 시크릿 오탐지 검사의 기본 플로우를 허용하기 전에 그룹의 프로젝트 설정을 확인해야 합니다.

### 컴파일된 작업별 구성은 1MiB 크기 제한의 적용을 받습니다 {#compiled-per-job-config-is-subject-to-a-1-mib-size-limit}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  | ------- | ----------------------- | ----------------- |
  | 18.11   | 18.11.x                 | 수정되지 않음         |
  | 19.0    | 19.0.0 ~ 19.0.5         | 19.0.6            |
  | 19.1    | 19.1.0 ~ 19.1.3         | 19.1.4            |
  | 19.2    | 19.2.0 ~ 19.2.1         | 19.2.2            |

[JSON 스키마 검증을 강제하는 변경은 또한 컴파일된 작업별 구성의 1MiB 크기 제한을 강제합니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/218219). 작업의 컴파일된 구성(옵션, YAML 변수, 토큰, 비밀 등)이 이 제한을 초과하면 파이프라인 생성이 실패합니다: `Failed to persist the pipeline: Validation failed: Config is too large. Maximum size allowed is 1 MiB`. 임시방편은 작업의 구성 크기를 1MiB 미만으로 줄이는 것입니다.

수정된 버전으로 업그레이드한 후 [크기 제한은 구성 가능](../../administration/cicd/limits.md#maximum-size-of-the-entire-cicd-configuration)하며 `ci_max_total_yaml_size_bytes` 애플리케이션 설정을 사용합니다.
