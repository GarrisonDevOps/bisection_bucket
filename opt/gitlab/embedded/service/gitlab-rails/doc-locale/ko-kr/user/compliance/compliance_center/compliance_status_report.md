---
stage: Software Supply Chain Security
group: Compliance
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 규정준수 상태 보고서
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 17.11에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/186525) [기능 플래그](../../../administration/feature_flags/_index.md) `enable_standards_adherence_dashboard_v2`로 지정됨. 기본적으로 활성화됩니다.
- GitLab 18.3에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/535563)입니다. `enable_standards_adherence_dashboard_v2` 기능 플래그가 제거되었습니다.

{{< /history >}}

규정준수 상태 보고서는 프로젝트가 [규정준수 프레임워크 요구 사항](../compliance_frameworks/_index.md#requirements)을 따르지 않는 최근 인스턴스를 표시합니다. 규정준수 센터의 일부이며 프로젝트 전체에서 제어 구현의 격차를 빠르게 식별하고 시정하는 데 도움이 됩니다.

## 스캔 타이밍 및 트리거 {#scan-timing-and-triggers}

상태 보고서를 업데이트하는 규정준수 스캔은 다음과 같은 상황에서 자동으로 트리거됩니다:

- 프로젝트에 프레임워크가 추가됩니다.
- 관련된 프레임워크의 요구 사항이 수정됩니다.
- 예정된 스캔이 실행됩니다(12시간마다).

스캔이 트리거된 후 결과가 규정준수 상태 보고서에 표시되는 데 5~10분이 걸릴 수 있습니다.

규정준수 프레임워크에서 요구 사항과 컨트롤을 정의하는 방법에 대해 자세히 알아보려면 [규정준수 프레임워크 요구 사항 생성 및 관리](../compliance_frameworks/_index.md#add-requirements)를 참조하세요.

## 규정준수 상태 보고서 보기 {#view-the-compliance-status-report}

사전 요구 사항:

- 그룹의 관리자이거나 보안 관리자 또는 소유자 역할이 있어야 합니다.

규정준수 상태 보고서를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **안전함** > **규정준수 센터**를 선택합니다.
1. **규정준수 보고서** 섹션에서 **규정준수 상태 보고서**를 선택하세요.

## 보고서 세부 정보 {#report-details}

규정준수 상태 보고서는 프로젝트가 프레임워크 컨트롤을 따르거나 따르지 않는 최근 인스턴스를 표시합니다. 각 행은 특정 프로젝트의 컨트롤의 현재 상태에 대한 세부 정보를 제공하여 그룹 전체에서 규정준수를 모니터링하는 데 도움이 됩니다.

다음과 같이 수행할 수 있습니다.

- 프로젝트, 프레임워크 또는 컨트롤별로 보고서를 필터링합니다.
- 프로젝트의 규정준수 세부 정보 보기로 직접 이동합니다.
- 미준수가 처음 감지된 시점을 검토합니다.

규정준수 상태 보고서의 열은 다음과 같습니다:

- **프로젝트**: 미준수가 있는 프로젝트입니다.
- **프레임워크**: 컨트롤이 속한 규정준수 프레임워크입니다(예: GitLab 또는 SOC 2).
- **컨트롤**: 프로젝트가 따르지 않는 특정 컨트롤입니다(예: "최소 두 개의 승인").
- **감지된 시점**: 미준수가 처음 기록된 날짜 및 시간입니다.
- **더 많은 정보**: 프로젝트의 추가 컨텍스트 또는 관련 설정에 대한 링크입니다.

## 규정준수 상태 보고서 내보내기 {#export-compliance-status-report}

그룹의 프로젝트에 대한 상태 보고서의 내용을 내보냅니다. 보고서는 큰 이메일 첨부 파일을 피하기 위해 15MB로 잘립니다.

사전 요구 사항:

- 그룹의 관리자이거나 보안 관리자 또는 소유자 역할이 있어야 합니다.

그룹의 프로젝트에 대한 규정준수 상태 보고서를 내보내려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **안전함** > **규정준수 센터**를 선택합니다.
1. 오른쪽 위 모서리에서 **내보내기**를 선택하세요.
1. **규정준수 상태 보고서 내보내기**를 선택하세요.

보고서가 컴파일되어 첨부 파일로 이메일 받은 편지함에 전달됩니다.
