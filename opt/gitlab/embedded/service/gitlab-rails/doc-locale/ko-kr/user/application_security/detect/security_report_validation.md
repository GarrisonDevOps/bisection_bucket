---
stage: Application Security Testing
group: Static Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 보안 보고서 유효성 검사
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

보안 보고서는 내용이 데이터베이스에 추가되기 전에 유효성을 검사합니다. 이를 통해 손상된 취약성 데이터가 데이터베이스로 수집되는 것을 방지합니다. 유효성 검사에 실패한 보고서는 파이프라인의 **보안** 탭에 유효성 검사 오류 메시지와 함께 나열됩니다.

유효성 검사는 [보고서 스키마](https://gitlab.com/gitlab-org/security-products/security-report-schemas/-/tree/master/dist)에 대해 수행되며, 보고서에 선언된 스키마 버전에 따라 결정됩니다:

- 보안 보고서가 지원되는 스키마 버전을 지정하면 GitLab은 해당 버전을 사용하여 유효성을 검사합니다.
- 보안 보고서가 더 이상 지원되지 않는 버전을 사용하면 GitLab은 해당 버전에 대해 유효성 검사를 시도하고 유효성 검사 결과에 지원 중단 경고를 추가합니다.
- 보안 보고서가 지원되는 MAJOR-MINOR 버전의 보고서 스키마를 사용하지만 PATCH 버전이 판매 중인 어떤 버전과도 일치하지 않으면 GitLab은 스키마의 최신 판매 중인 PATCH 버전에 대해 유효성을 검사합니다.
  - 예: 보안 보고서는 버전 14.1.1을 사용하지만 최신 판매 중인 버전은 14.1.0입니다. GitLab은 스키마 버전 14.1.0에 대해 유효성을 검사합니다.
- 보안 보고서가 지원되지 않는 버전을 사용하면 GitLab은 설치에서 사용 가능한 가장 초기의 스키마 버전에 대해 유효성을 검사하지만 보고서를 수집하지 않습니다.
- 보안 보고서가 스키마 버전을 지정하지 않으면 GitLab은 GitLab에서 사용 가능한 가장 초기의 스키마 버전에 대해 유효성을 검사합니다. `version` 속성은 필수이므로 이 경우 유효성 검사는 항상 실패하지만 다른 유효성 검사 오류도 있을 수 있습니다.

지원되는 스키마 버전과 더 이상 지원되지 않는 스키마 버전의 세부 정보를 보려면 [스키마 유효성 검사기 소스 코드](https://gitlab.com/gitlab-org/ruby/gems/gitlab-security_report_schemas/-/blob/main/supported_versions)를 확인합니다.
