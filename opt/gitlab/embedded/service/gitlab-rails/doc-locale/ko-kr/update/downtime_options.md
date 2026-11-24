---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 업그레이드 다운타임 옵션 검토
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

업그레이드 중 다운타임 옵션은 인스턴스 유형에 따라 달라집니다:

- 단일 노드 인스턴스: 다운타임을 포함하여 업그레이드해야 합니다. 사용자는 **배포 진행 중** 메시지 또는 `502` 오류를 볼 수 있습니다.
- 다중 노드 인스턴스: 다운타임을 포함하거나 포함하지 않고 업그레이드 사이를 선택합니다.

여러 부 릴리스(예: 14.6에서 14.9)를 통해 업그레이드하려면 GitLab 인스턴스를 오프라인으로 전환하고 다운타임을 포함하여 업그레이드해야 합니다.

## 다운타임을 포함한 업그레이드 {#upgrades-with-downtime}

시작하기 전에 [업그레이드 경로](upgrade_paths.md)의 버전 관련 업그레이드 노트를 검토합니다:

- [GitLab 17 업그레이드 노트](versions/gitlab_17_changes.md)
- [GitLab 16 업그레이드 노트](versions/gitlab_16_changes.md)
- [GitLab 15 업그레이드 노트](versions/gitlab_15_changes.md)

단일 노드 인스턴스의 경우 [Linux 패키지 인스턴스 업그레이드](package/_index.md)를 참고합니다. 다중 노드 인스턴스의 경우 [다운타임을 포함하여 다중 노드 인스턴스 업그레이드](with_downtime.md)를 참고합니다.

## 무중단 업그레이드 {#zero-downtime-upgrades}

무중단 업그레이드를 사용하면 라이브 GitLab 환경을 오프라인으로 전환하지 않고 업그레이드할 수 있습니다.

무중단을 위해 GitLab 노드를 특정 순서로 업그레이드합니다. 로드 밸런싱, HA 시스템, 우아한 다시 로드를 사용하여 중단을 최소화합니다.

이 설명서는 핵심 GitLab 구성 요소만 다룹니다. AWS RDS와 같은 타사 서비스의 업그레이드 또는 관리는 해당 설명서를 참고합니다.

무중단 업그레이드를 수행하려면 설치 방법에 대한 설명서를 참고합니다: [Helm 차트](https://docs.gitlab.com/charts/installation/upgrade/), [GitLab Operator](https://docs.gitlab.com/operator/gitlab_upgrades/), 또는 [다중 노드 인스턴스](zero_downtime.md).
