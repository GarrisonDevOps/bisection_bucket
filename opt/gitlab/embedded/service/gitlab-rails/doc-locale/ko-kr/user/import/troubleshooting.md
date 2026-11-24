---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 문제 해결
---

{{< details >}}

티어: Free, Premium, Ultimate 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab으로 마이그레이션할 때 다음 문제가 발생할 수 있습니다.

## 가져온 리포지토리에서 브랜치가 누락됨 {#imported-repository-is-missing-branches}

가져온 리포지토리에 소스 리포지토리의 모든 브랜치가 포함되어 있지 않은 경우:

1. [환경 변수](../../administration/logs/_index.md#override-default-log-level) `IMPORT_DEBUG=true`를 설정합니다.
1. [다른 그룹, 하위 그룹 또는 프로젝트 이름](https://about.gitlab.com/releases/2023/02/22/gitlab-15-9-released/#re-import-projects-from-external-providers)으로 가져오기를 다시 시도합니다.
1. 일부 브랜치가 여전히 누락된 경우 [`importer.log`](../../administration/logs/_index.md#importerlog)을 검사합니다(예를 들어 [`jq`](../../administration/logs/log_parsing.md#parsing-gitlab-railsimporterlog) 사용).

## 예외: `Error Importing repository - No such file or directory @ rb_sysopen - (filename)` {#exception-error-importing-repository---no-such-file-or-directory--rb_sysopen---filename}

`tar.gz` 파일을 다운로드하여 리포지토리의 소스 코드를 가져오려고 시도하면 이 오류가 발생합니다.

가져오기에는 [GitLab 내보내기](../project/settings/import_export.md#export-a-project-and-its-data) 파일이 필요하며, 단순히 리포지토리 다운로드 파일이 아닙니다.

## 장시간 지속되는 가져오기 또는 실패한 가져오기 진단 {#diagnosing-prolonged-or-failed-imports}

파일 기반 가져오기, 특히 S3를 사용하는 가져오기에서 장시간 지연이나 실패를 경험하는 경우 다음이 문제의 근본 원인을 파악하는 데 도움이 될 수 있습니다:

- [가져오기 단계 확인](#check-import-status)
- [로그 검토](#review-logs)
- [일반적인 문제 파악](#identify-common-issues)

### 가져오기 상태 확인 {#check-import-status}

가져오기 상태를 확인합니다:

1. GitLab API를 사용하여 영향을 받는 프로젝트의 [가져오기 상태](../../api/project_import_export.md#retrieve-the-status-of-a-project-import)를 확인합니다.
1. 응답에서 오류 메시지 또는 상태 정보, 특히 `status` 및 `import_error` 값을 검토합니다.
1. 응답에서 `correlation_id`를 기록해 두세요. 추가 문제 해결에 중요합니다.

### 로그 검토 {#review-logs}

관련 정보에 대해 로그를 검색합니다:

GitLab Self-Managed 인스턴스의 경우:

1. [Sidekiq 로그](../../administration/logs/_index.md#sidekiqlog) 및 [`exceptions_json` 로그](../../administration/logs/_index.md#exceptions_jsonlog)를 확인합니다.
1. `RepositoryImportWorker`과 관련된 항목과 [가져오기 상태 확인](#check-import-status)에서 가져온 상관관계 ID를 검색합니다.
1. `job_status`, `interrupted_count` 및 `exception`과 같은 필드를 찾습니다.

GitLab.com의 경우(GitLab 팀 멤버만 해당):

1. [Kibana](https://log.gprd.gitlab.net/)를 사용하여 다음과 같은 쿼리로 Sidekiq 로그를 검색합니다:

   대상: `pubsub-sidekiq-inf-gprd*`

   ```plaintext
   json.class: "RepositoryImportWorker" AND json.correlation_id.keyword: "<CORRELATION_ID>"
   ```

   또는

   ```plaintext
   json.class: "RepositoryImportWorker" AND json.meta.project: "<project.full_path>"
   ```

1. GitLab Self-Managed 인스턴스에서 언급한 것과 동일한 필드를 찾습니다.

### 일반적인 문제 파악 {#identify-common-issues}

[로그 검토](#review-logs)에서 수집한 정보를 다음의 일반적인 문제와 비교합니다:

- 중단된 작업: 높은 `interrupted_count` 또는 실패를 나타내는 `job_status`가 표시되면 가져오기 작업이 여러 번 중단되어 데드 큐에 배치되었을 수 있습니다.
- S3 연결: S3를 사용하는 가져오기의 경우 로그에서 S3 관련 오류 메시지를 확인합니다.
- 대용량 리포지토리: 리포지토리가 매우 큰 경우 가져오기 시간이 초과될 수 있습니다. 이 경우 [직접 전송](../group/import/_index.md)을 사용하는 것을 고려하세요.

## 지원 기술 자료 {#support-knowledge-base}

문제가 계속되면 [GitLab 지원 기술 자료](https://support.gitlab.com/hc/en-us/)를 참조하세요.
