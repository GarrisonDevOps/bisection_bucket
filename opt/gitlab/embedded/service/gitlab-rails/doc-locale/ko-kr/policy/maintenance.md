---
stage: GitLab Delivery
group: Release and Deploy
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab 릴리스 및 유지 보수 정책
description: "버전 지원, 릴리스 주기 및 백포팅 정책입니다."
---

릴리스 및 배포 팀은 유지 보수 정책의 소유자이며 요청된 업데이트를 승인해야 합니다. 이는 DRI 모델을 따르며 고객의 예측 가능성을 보장하기 위한 것입니다.

GitLab은 메이저, 마이너, 패치 릴리스의 버전 명명 및 릴리스 속도를 관리하는 엄격한 정책을 가지고 있습니다. 새 릴리스는 [릴리스 정보](https://docs.gitlab.com/releases/)에 공지됩니다.

현재 정책은 다음과 같습니다:

- 언제든지 현재 안정 릴리스에만 버그 수정을 백포팅합니다. 아래의 [패치 릴리스](#patch-releases)를 참조하세요.
- 현재 안정 릴리스 외에 이전 두 개의 월간 릴리스에 보안 수정을 백포팅합니다. 특정 환경(아래의 [패치 릴리스](#patch-releases)에 설명됨)에서는 현재 안정 릴리스에만 보안 취약성을 해결하거나 정기 월간 릴리스 프로세스를 통해 백포트 없이 처리할 수 있습니다.

드문 경우이지만 최근 두 개 이상의 월간 릴리스로 백포팅하는 예외가 허용될 수 있습니다. 필요한 프로세스는 [정책 예외](#policy-exceptions)를 참조하세요.

## 버전 관리 {#versioning}

GitLab은 릴리스에 [시멘틱 버전 관리](https://semver.org/)를 사용합니다: `(Major).(Minor).(Patch)`.

예를 들어 GitLab 버전 18.3.2의 경우:

- `18`는 메이저 버전을 나타냅니다. 메이저 릴리스는 18.0.0이었지만 종종 18.0으로 불립니다.
- `3`는 마이너 버전을 나타냅니다. 마이너 릴리스는 18.3.0이었지만 종종 18.3으로 불립니다.
- `2`는 패치 번호를 나타냅니다.

버전 번호의 어떤 부분이라도 여러 자리 숫자로 증가할 수 있습니다. 예를 들어 18.3.11입니다.

다음 표는 버전 유형과 릴리스 주기를 설명합니다:

| 버전 유형 | 설명 | 주기 |
|:-------------|:------------|:--------|
| 메이저        | 중요한 변경 사항이 있거나 공개 API에 호환되지 않는 변경 사항이 도입될 때입니다. | 매년입니다. 다음 메이저 릴리스는 GitLab 20.0이며 2027년 5월 20일로 예정되어 있습니다. GitLab은 기본적으로 매년 5월에 [메이저 릴리스를 예정](https://handbook.gitlab.com/handbook/engineering/releases/monthly-releases/)합니다. |
| 마이너        | 공개 API에 새로운 호환 가능한 기능이 도입되거나, 마이너 기능이 도입되거나, 더 작은 기능 집합이 출시될 때입니다. | 매월, 매월 셋째 목요일에 예정되어 있습니다. |
| 패치        | 잘못된 동작을 수정하는 호환 가능한 버그 수정입니다. [패치 릴리스](#patch-releases)를 참조하세요. | 월 2회, 월간 마이너 릴리스 전주 수요일과 후주 수요일에 예정되어 있습니다. |

<!-- Do not edit the following section without consulting the Technical Writing team -->

<!-- vale gitlab_base.CurrentStatus = NO -->

## 유지 보수되는 버전 {#maintained-versions}

다음 GitLab 릴리스 버전은 현재 유지 보수되고 있습니다:

{{< maintained-versions >}}

<!-- vale gitlab_base.CurrentStatus = YES -->

<!-- END -->

> [!note]
> 예정된 패치 릴리스를 위해 유지 보수되는 버전을 찾는 GitLab 팀 멤버는 내부 `delivery: Release Information` Grafana 대시보드의 `Patch Release Information` 섹션 아래에서 [`Release Versions` 패널](https://dashboards.gitlab.net/goto/h228fPEHR?orgId=1)을 참조하세요. 활성 월간 릴리스 날짜가 활성 패치 릴리스 날짜보다 이전이면 버전이 위의 유지 보수되는 버전 목록과 다릅니다.
>
> 버그 수정 백포트는 현재(첫 번째) 버전에 유지 보수되고, 보안 수정 백포트는 모든 버전에 유지 보수됩니다.

## 업그레이드 권장 사항 {#upgrade-recommendations}

모든 사용자가 [최신 안정 릴리스](https://docs.gitlab.com/releases/)를 실행하여 가장 안전하고 기능이 풍부한 GitLab 경험으로 업그레이드할 수 있도록 권장합니다. 최신 안정 릴리스를 실행할 수 있도록 업데이트 프로세스를 안정적으로 유지하기 위해 노력하고 있습니다.

월간 릴리스 주기를 따를 수 없다면 고려해야 할 몇 가지 경우가 있습니다. [업그레이드 경로 가이드](../update/upgrade_paths.md)를 따라 버전 간에 안전하게 업그레이드하세요.

Linux 패키지에 대한 버전별 변경 사항 설명서가 제공됩니다:

- [GitLab 17](../update/versions/gitlab_17_changes.md)
- [GitLab 16](../update/versions/gitlab_16_changes.md)
- [GitLab 15](../update/versions/gitlab_15_changes.md)

Linux 패키지를 로컬로 다운로드하여 [수동으로 설치](../update/package/_index.md#upgrade-with-a-downloaded-package)하기 위한 지침을 사용할 수 있습니다.

[Linux 패키지 번들로 제공되는 PostgreSQL 업그레이드는 별도로 문서화](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server)되어 있습니다.

## 메이저 버전 업그레이드 {#upgrading-major-versions}

호환되지 않는 변경 사항과 마이그레이션은 메이저 버전용으로 예약되어 있습니다. 자세한 정보는 [GitLab 업그레이드 계획 작성](../update/plan_your_upgrade.md)을 참조하세요.

## 패치 릴리스 {#patch-releases}

패치 릴리스는 현재 안정 릴리스된 GitLab 버전의 버그 수정과 현재 안정 릴리스 외에 이전 두 개의 월간 릴리스의 보안 수정을 포함합니다.

이러한 정책이 마련된 이유는 다음과 같습니다:

1. GitLab은 커뮤니티 및 엔터프라이즈 배포판을 가지고 있으므로 소프트웨어를 테스트/릴리스하는 데 필요한 작업량이 두 배가 됩니다.
1. 더 오래된 릴리스로 백포팅하면 개발, 품질 보증 및 지원 비용이 많이 발생합니다.
1. 병렬 버전을 지원하면 증분 업그레이드가 억제되므로 시간이 지남에 따라 복잡도가 누적되고 모든 사용자에게 업그레이드 문제가 발생합니다. GitLab은 증분 업그레이드(및 설치)가 최대한 간단하도록 보장하는 전담 팀을 가지고 있습니다.
1. GitLab 애플리케이션에서 생성된 변경 사항의 수가 많아 더 오래된 릴리스로의 백포팅 복잡도가 높아집니다. 여러 경우에 백포팅은 새 변경 사항이 거치는 것과 동일한 검토 프로세스를 거쳐야 합니다.
1. 더 오래된 릴리스에서 테스트가 통과하도록 보장하는 것은 경우에 따라 상당한 어려움이 있으므로 매우 시간이 많이 소요됩니다.

패치 릴리스에 새 기능을 포함하는 것은 불가능합니다. 이는 [시멘틱 버전 관리](https://semver.org/)를 손상시키기 때문입니다. [시멘틱 버전 관리](https://semver.org/)를 손상시키면 다양한 내부 요구 사항(예: 조직 규정 준수, 새 기능 검증 등)을 준수해야 하는 사용자에게 다음과 같은 결과가 발생합니다:

1. 패치 버전에 포함된 버그 수정을 활용하기 위해 빠르게 업그레이드할 수 없습니다.
1. 패치 버전에 포함된 보안 수정을 활용하기 위해 빠르게 업그레이드할 수 없습니다.
1. 안정 GitLab 릴리스뿐 아니라 모든 패치 버전에 대한 광범위한 테스트가 필요합니다.

매우 심각한 보안 문제의 경우 더 이상의 이전 GitLab 릴리스 버전으로 보안 수정을 백포팅하는 [선례](https://about.gitlab.com/releases/2016/05/02/cve-2016-4340-patches/)가 있습니다. 필요한 프로세스는 [정책 예외](#policy-exceptions)를 참조하세요.

특정 환경에서는 활성 및 현재 안정 릴리스만 업데이트하여 정기 월간 릴리스 프로세스를 통해 취약성을 처리하도록 선택할 수 있으며, 백포트는 없습니다. 이러한 결정에 영향을 미치는 요소로는 악용 가능성이 매우 낮음, 취약성의 낮은 영향, 보안 수정의 복잡도, 최종적인 안정성 위험이 있습니다. 높음 및 중요 보안 문제는 항상 패치 릴리스로 처리합니다.

## 정책 예외 {#policy-exceptions}

특수한 환경에서는 이 유지 보수 정책에서의 편차가 필요할 수 있습니다. 여기에는 표준 정책에서 다루는 것보다 더 오래된 릴리스로의 수정 백포팅 요청 및 [릴리스 원칙](https://handbook.gitlab.com/handbook/engineering/releases/#what-each-release-type-contains)에서의 편차가 포함됩니다. 심각도 3 이하의 요청은 자동으로 거부됩니다.

정책 예외를 요청하려면 [예외 프로세스](https://handbook.gitlab.com/handbook/engineering/releases/#exception-process) 지침을 따르세요.

[릴리스 예외 프로세스](https://handbook.gitlab.com/handbook/engineering/releases/#exception-process)는 정책 예외를 요청하기 위한 지침을 설명합니다. 예외는 정책 소유자인 [릴리스 관리자](https://about.gitlab.com/community/release-managers/)의 재량에 따라 [SLO 약정](https://handbook.gitlab.com/handbook/engineering/releases/patch-releases/#slo-commitments)을 따라 부여됩니다.

## 추가 정보 {#more-information}

또한 다음을 읽어볼 수도 있습니다:

- 릴리스 절차를 설명하는 [릴리스 설명서](https://gitlab.com/gitlab-org/release/docs)
- 개발 설명서의 사용 중단 지침입니다.
- [책임 있는 공개 정책](https://about.gitlab.com/security/disclosure/)
