---
stage: Security Risk Management
group: Security Insights
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 보안 스캔 결과
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 17.9에서 `dependency_scanning_for_pipelines_with_cyclonedx_reports` [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/490334)되었습니다. 기본적으로 비활성화되었습니다.
- [GitLab.com 및 GitLab Self-Managed에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/490332) (GitLab 17.9)
- 기능 플래그 `dependency_scanning_for_pipelines_with_cyclonedx_reports` (17.10에서 제거됨)

{{< /history >}}

GitLab에서 파이프라인 보안 스캔의 결과를 확인하고 조치합니다. 보안 스캐너는 파이프라인에서 실행되고 보안 보고서를 출력합니다. 이 보고서의 내용은 GitLab에서 처리되고 표시됩니다.

결과를 생성하려면 프로젝트에 대해 보안 스캔을 구성해야 합니다. 보안 스캐너를 구성하는 방법에 대한 정보는 [보안 구성](security_configuration.md)을 참조하세요.

보안 스캔 결과를 이해하기 위한 주요 용어:

검색 결과: 검색 결과는 개발 브랜치에서 식별된 잠재적 취약성입니다. 브랜치가 기본 브랜치에 병합되면 검색 결과가 취약성이 됩니다: 검색 결과는 관련 CI/CD 작업 아티팩트가 만료되거나 파이프라인 생성 후 일정 기간이 지나면 만료됩니다. 관련 작업 아티팩트가 잠긴 경우에도 만료됩니다. GitLab.com에서는 기간이 30일입니다. GitLab Self-Managed 및 GitLab Dedicated에서는 기본값이 90일입니다. 관리자는 [보존 기간 변경](../../../administration/settings/security_and_compliance.md#security-scan-retention-period)할 수 있으며, 값을 7일부터 90일 사이로 설정할 수 있습니다.

취약성: 취약성은 기본 브랜치에서 식별된 소프트웨어 보안 약점입니다: 취약성 기록은 [보관](../vulnerability_archival/_index.md)될 때까지 유지됩니다. 기본 브랜치에서 취약성이 더 이상 감지되지 않는 경우에도 유지됩니다.

기본 브랜치에서 식별된 취약성은 [취약성 보고서](../vulnerability_report/_index.md)에 나열됩니다.

## 보안 보고서 아티팩트 {#security-report-artifacts}

보안 스캐너는 브랜치 파이프라인에서 실행되고, 활성화된 경우 머지 리퀘스트 파이프라인에서도 실행됩니다. 각 보안 스캐너는 특정 보안 스캐너에서 감지한 모든 검색 결과 또는 취약성의 세부 사항을 포함하는 보안 보고서 아티팩트를 출력합니다.

[하위 파이프라인](../../../ci/pipelines/downstream_pipelines.md#view-child-pipeline-reports-in-merge-requests)의 보안 보고서는 파이프라인 보안 보고서 및 머지 리퀘스트 보고서에 포함됩니다.

개발(기본이 아닌) 브랜치에서 검색 결과에는 개발 브랜치가 생성되었을 때 대상 브랜치에 있는 모든 취약성이 포함됩니다.

검색 결과는 관련 CI/CD 작업 아티팩트가 만료되거나 파이프라인 생성 후 일정 기간이 지나면 만료됩니다. 관련 작업 아티팩트가 잠긴 경우에도 만료됩니다. GitLab.com에서는 기간이 30일입니다. GitLab Self-Managed 및 GitLab Dedicated에서는 기본값이 90일이며, 관리자는 보존 기간을 7일부터 90일 사이의 값으로 변경할 수 있습니다. 만료된 검색 결과는 파이프라인의 **보안** 탭에 표시되지 않습니다. 이를 재현하려면 파이프라인을 다시 실행하세요.

### 보안 보고서 다운로드 {#download-a-security-report}

{{< details >}}

- 티어: Ultimate

{{< /details >}}

보안 보고서를 다운로드하여 GitLab 외부에서 분석하거나 보관할 수 있습니다. 보안 보고서는 JSON 파일입니다.

사전 요구 사항:

- 프로젝트에 대한 보안 관리자, 개발자, 유지 관리자 또는 소유자 역할입니다.

보안 보고서를 다운로드하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다.
1. 파이프라인을 선택합니다.
1. **보안** 탭을 선택합니다.
1. **결과 다운로드**를 선택한 다음 원하는 보안 보고서를 선택합니다.

선택한 보안 보고서가 기기에 다운로드됩니다.

![보안 보고서 목록](img/security_report_v18_1.png)

## 파이프라인 보안 보고서 {#pipeline-security-report}

{{< details >}}

- 티어: Ultimate

{{< /details >}}

파이프라인 보안 보고서는 해당 파이프라인 실행으로 감지된 모든 검색 결과 또는 취약성의 세부 사항을 포함합니다. 결과는 파이프라인이 실행된 커밋에서 브랜치의 상태를 반영합니다. 따라서 같은 브랜치에서 다른 파이프라인은 다른 결과를 표시할 수 있습니다. 기본 브랜치에 대해 실행된 파이프라인의 경우, 파이프라인 보안 보고서의 모든 취약성도 취약성 보고서에 있습니다.

![파이프라인 실행으로 감지된 검색 결과 목록](img/pipeline_security_report_v18_1.png)

### 파이프라인 보안 보고서 보기 {#view-pipeline-security-report}

파이프라인 보안 보고서를 확인하여 파이프라인 실행으로 감지된 모든 검색 결과 또는 취약성의 세부 사항을 확인합니다.

사전 요구 사항:

- 프로젝트에 대한 보안 관리자, 개발자, 유지 관리자 또는 소유자 역할입니다.

파이프라인 보안 보고서를 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다.
1. 최신 파이프라인을 선택합니다.

검색 결과 또는 취약성의 세부 사항을 확인하려면 설명을 선택합니다.

### 이슈 생성 {#create-an-issue}

검색 결과 또는 취약성의 수정 작업을 추적, 문서화 및 관리하기 위해 이슈를 생성합니다.

사전 요구 사항:

- 프로젝트에 대한 보안 관리자, 개발자, 유지 관리자 또는 소유자 역할입니다.

이슈를 생성하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다.
1. 파이프라인을 선택합니다.
1. **보안** 탭을 선택합니다.
1. 검색 결과의 설명을 선택합니다.
1. **이슈 만들기**를 선택합니다.

이슈가 프로젝트에서 생성되며, 검색 결과 또는 취약성의 설명에서 설명이 복사됩니다.

### 상태 변경 {#change-status}

파이프라인의 보안 탭에서 검색 결과 또는 취약성의 상태를 변경할 수 있습니다. 검색 결과에 대한 모든 변경 사항은 브랜치가 기본 브랜치에 병합될 때 유지됩니다.

사전 요구 사항:

- 프로젝트의 관리자 역할 또는 `admin_vulnerability` 사용자 지정 권한.

검색 결과 또는 취약성의 상태를 변경하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다.
1. 최신 파이프라인을 선택합니다.
1. **보안** 탭을 선택합니다.
1. 검색 결과 보고서에서:

     1. 변경하려는 검색 결과 또는 취약성을 선택합니다.

        - 개별 검색 결과 또는 취약성을 선택하려면 각 항목 옆의 확인란을 선택합니다.
        - 페이지의 모든 검색 결과 또는 취약성을 선택하려면 테이블 헤더의 확인란을 선택합니다.

     1. **동작 선택** 드롭다운 목록에서 **해지됨** 또는 **분류 필요** 중 하나를 선택합니다.
     1. **상태 변경**을 선택합니다.

### 보안 보고서 다운로드 {#download-a-security-report-1}

{{< details >}}

- 티어: Ultimate

{{< /details >}}

보안 보고서를 다운로드하여 GitLab 외부에서 분석하거나 보관할 수 있습니다. 보안 보고서는 JSON 파일입니다.

사전 요구 사항:

- 프로젝트에 대한 보안 관리자, 개발자, 유지 관리자 또는 소유자 역할입니다.

보안 보고서를 다운로드하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **빌드** > **파이프라인**을 선택합니다.
1. 파이프라인을 선택합니다.
1. **보안** 탭을 선택합니다.
1. **결과 다운로드**를 선택한 다음 원하는 보안 보고서를 선택합니다.

선택한 보안 보고서가 기기에 다운로드됩니다.

![보안 보고서 목록](img/security_report_v18_1.png)

## 머지 리퀘스트 보고서 {#merge-request-reports}

머지 리퀘스트의 보안 스캔 결과는 [머지 리퀘스트 보고서](../../project/merge_requests/reports.md)를 참조하세요.

## 문제 해결 {#troubleshooting}

보안 스캔을 사용할 때 다음 문제가 발생할 수 있습니다.

### 보고서 파싱 및 스캔 수집 오류 {#report-parsing-and-scan-ingestion-errors}

> [!note]
> 이 단계는 GitLab 지원팀에서 이러한 오류를 재현하는 데 사용됩니다.

일부 보안 스캔은 보고서 파싱 또는 스캔 수집과 관련된 파이프라인의 **보안** 탭에서 오류를 발생시킬 수 있습니다. 사용자로부터 프로젝트 사본을 얻을 수 없는 경우 스캔에서 생성된 보고서를 사용하여 오류를 재현할 수 있습니다.

오류를 재현하려면:

1. 사용자로부터 보고서 사본을 받습니다. 이 예에서 `gl-sast-report.json`.
1. 프로젝트를 생성합니다.
1. 보고서를 리포지토리에 커밋합니다.
1. `.gitlab-ci.yml` 파일을 추가하고 작업에서 보고서를 아티팩트로 설정합니다.

   예를 들어 SAST 작업으로 인한 오류를 재현하려면:

   ```yaml
   sample-job:
     script:
       - echo "Testing report"
     artifacts:
       reports:
         sast: gl-sast-report.json
   ```

1. 파이프라인이 완료된 후 파이프라인의 **보안** 탭의 내용에서 오류를 확인합니다.

`sast: gl-sast-report.json`를 각각의 [`artifacts:reports`](../../../ci/yaml/_index.md#artifactsreports) 유형으로 바꾸고 스캔에서 생성한 보고서에 따라 올바른 JSON 보고서 파일 이름을 입력할 수 있습니다.
