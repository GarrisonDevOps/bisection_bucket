---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 병합 요청은 CI/CD 파이프라인과 병합 가능성 테스트의 결과를 보고서 영역에 표시합니다.
title: 병합 요청 위젯
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

병합 요청의 개요 페이지는 병합 요청에 대한 작업을 수행하는 서비스의 상태 업데이트를 표시합니다. 모든 구독 수준에서 위젯 영역이 표시되지만, 해당 영역의 내용은 구독 수준과 프로젝트에 구성한 서비스에 따라 달라집니다.

## 파이프라인 정보 {#pipeline-information}

[GitLab CI/CD](../../../ci/_index.md)를 프로젝트에 설정했다면, [병합 요청](_index.md)은 **개요** 탭의 위젯 영역에 파이프라인 정보를 표시합니다:

- 머지 전 파이프라인과 머지 후 파이프라인, 그리고 환경 정보(있는 경우)
- 진행 중인 배포

애플리케이션이 [환경](../../../ci/environments/_index.md)에 성공적으로 배포되면, 배포된 환경과 [검토 앱](../../../ci/review_apps/_index.md)으로의 링크가 모두 표시됩니다.

파이프라인이 병합 요청에서 실패하지만 여전히 머지할 수 있으면, GitLab은 **머지**를 빨간색으로 표시합니다.

## 머지 후 파이프라인 상태 {#post-merge-pipeline-status}

병합 요청을 머지할 때, 병합 요청이 머지된 브랜치의 머지 후 파이프라인 상태를 확인할 수 있습니다. 예를 들어, 병합 요청이 [기본 브랜치](../repository/branches/default.md)로 머지되고 스테이징 환경으로의 배포를 트리거할 때입니다.

GitLab은 진행 중인 배포와 환경의 상태(배포 중 또는 배포됨)를 표시합니다. 브랜치의 첫 배포인 경우, 완료될 때까지 링크는 `404` 오류를 반환합니다. 배포 중에 GitLab은 중지 버튼을 비활성화합니다. 파이프라인이 배포에 실패하면, GitLab은 배포 정보를 숨깁니다.

![병합 요청 위젯에 머지 후 파이프라인 상태 표시](img/post_merge_pipeline_v16_0.png)

자세한 내용은 [파이프라인 읽기](../../../ci/pipelines/_index.md)를 참조하세요.

## 자동 머지 설정 {#set-auto-merge}

머지할 준비가 된 병합 요청을 [CI 파이프라인이 성공할 때 자동으로 머지](auto_merge.md)하도록 설정합니다.

## 검토 앱으로 라이브 미리보기 {#live-preview-with-review-apps}

프로젝트에 대해 [검토 앱](../../../ci/review_apps/_index.md)을 구성하여 병합 요청을 통해 피처 브랜치에 제출된 변경 사항을 브랜치 단위로 미리봅니다. 브랜치를 체크아웃하거나, 설치하거나, 로컬에서 미리볼 필요가 없습니다. 검토 앱 링크가 있는 모든 사용자가 변경 사항을 미리볼 수 있습니다.

GitLab [경로 맵](../../../ci/review_apps/_index.md#route-maps)을 설정하면, 병합 요청 위젯이 변경된 페이지로 직접 이동하므로 제안된 수정 사항을 더 쉽고 빠르게 미리볼 수 있습니다.

자세한 내용은 [검토 앱](../../../ci/review_apps/_index.md)을 참조하세요.

## 라이선스 준수 {#license-compliance}

병합 요청의 라이선스 준수 정보는 [병합 요청 보고서](reports.md)를 참조하세요.

## 보안 정책 {#security-policies}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

개발자가 취약점과 지원되지 않는 라이선스를 머지하는 것을 방지하거나 병합 요청에서 필수 승인을 강제하려면, [보안 정책](../../application_security/policies/merge_request_approval_policies.md)을 구성합니다. 프로젝트, 그룹 또는 인스턴스에 대해 보안 정책을 구성할 수 있습니다. 선택적으로, 보안 정책을 경고 모드로 설정하여 개발자가 머지하는 것을 방지하지 않으면서 발견 사항에 대한 인식을 높일 수 있습니다.

## 외부 상태 확인 {#external-status-checks}

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[외부 상태 확인](status_checks.md)을 구성했다면 병합 요청에서 [특정 위젯](status_checks.md#status-checks-widget) 내 이러한 확인의 상태를 확인할 수 있습니다.

## 애플리케이션 보안 스캔 {#application-security-scanning}

병합 요청의 애플리케이션 보안 스캔 결과는 [머지 리퀨스트 보고서](reports.md)를 참조하세요.
