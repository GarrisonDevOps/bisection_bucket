---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 업그레이드 경로 계획
description: 최신 버전 지침입니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

업그레이드 경로는 현재 GitLab 버전에서 업그레이드하려는 GitLab 버전으로 이동하기 위한 단계를 포함합니다. 업그레이드 경로를 결정하려면:

1. 업그레이드 경로에서 현재 버전이 있는 위치를 확인하세요(필수 업그레이드 중지점 포함).
1. [GitLab 업그레이드 정보](versions/_index.md)를 참조하세요.

명시적으로 지정되지 않은 경우에도 `major`.`minor` 릴리스의 최신 사용 가능한 패치 릴리스로 GitLab을 업그레이드하세요(첫 번째 패치 릴리스는 아님). 예를 들어 `16.8.7`을 `16.8.0` 대신 사용합니다.

일부 `major`.`minor` 버전은 업그레이드 프로세스와 관련된 문제를 해결하는 수정 사항이 있기 때문에 일부 또는 모든 환경에서 필수 중지점입니다.

## 필수 업그레이드 중지점 {#required-upgrade-stops}

업그레이드 경로는 필수 업그레이드 중지점을 포함하며, 이는 이후 버전으로 업그레이드하기 전에 업그레이드해야 하는 GitLab 버전입니다. 업그레이드 경로를 통해 이동할 때:

1. 현재 버전 이후의 필수 업그레이드 중지점으로 업그레이드합니다.
1. 업그레이드를 위한 백그라운드 마이그레이션이 완료될 때까지 기다립니다.
1. 다음 필수 업그레이드 중지점으로 업그레이드합니다.

GitLab 17.5 이상에서는 인스턴스 관리자에게 예측 가능한 업그레이드 일정을 제공하기 위해 필수 업그레이드 중지점이 `x.2.z`, `x.5.z`, `x.8.z`, `x.11.z` 버전에서 발생합니다.

특정 마이너 버전의 사용 가능한 패치 릴리스를 확인하려면 [GitLab 패키지 레지스트리](https://packages.gitlab.com/ui/browse/gitlab)에서 마이너 버전을 검색할 수 있습니다.

GitLab Helm 차트 인스턴스를 업그레이드하는 경우 [GitLab Helm 차트 매핑 목록](https://docs.gitlab.com/charts/installation/version_mappings/#previous-chart-versions)을 참조하세요.

### 필수 GitLab 19 업그레이드 중지점 {#required-gitlab-19-upgrade-stops}

> [!note]
> 이러한 버전 중 일부는 아직 릴리스되지 않았을 수 있습니다. 사용 가능한 버전을 확인하려면 [GitLab 19 릴리스 정보](../releases/19/_index.md)를 참조하세요.

필수 업그레이드 중지점은 다음 버전에서 발생합니다:

- `19.2`
- `19.5`
- `19.8`
- `19.11`

이후 버전으로 업그레이드하기 전에 GitLab 19의 해당 버전으로 업그레이드해야 합니다. 업그레이드하는 각 버전에 대해 [GitLab 19 업그레이드 정보](versions/gitlab_19_changes.md)를 참조하세요. 버전이 업그레이드 정보에 없으면 해당 버전에 대해 알아야 할 특정 사항이 없습니다.

GitLab 패키지 레지스트리에서 패치 릴리스를 검색합니다. 예를 들어 Ubuntu 24.04의 최신 GitLab 19.2 Enterprise Edition 버전을 검색하려면:

1. <https://packages.gitlab.com/ui/browse/gitlab/gitlab-ee/ubuntu/noble/pool/main/g/gitlab-ee>로 이동합니다.
1. 검색어로 `19.2`을 입력합니다.

### 필수 GitLab 18 업그레이드 중지점 {#required-gitlab-18-upgrade-stops}

필수 업그레이드 중지점은 `18.2`, `18.5`, `18.8`, `18.11` 버전에서 발생합니다.

이후 버전으로 업그레이드하기 전에 GitLab 18의 해당 버전으로 업그레이드해야 합니다. 업그레이드하는 각 버전에 대해 [GitLab 18 업그레이드 정보](versions/gitlab_18_changes.md)를 참조하세요. 버전이 업그레이드 정보에 없으면 해당 버전에 대해 알아야 할 특정 사항이 없습니다.

GitLab 패키지 레지스트리에서 패치 릴리스를 검색합니다. 예를 들어 Ubuntu 24.04의 최신 GitLab 18.2 Enterprise Edition 버전을 검색하려면:

1. <https://packages.gitlab.com/ui/browse/gitlab/gitlab-ee/ubuntu/noble/pool/main/g/gitlab-ee>로 이동합니다.
1. 검색어로 `18.2`을 입력합니다.

### 필수 GitLab 17 업그레이드 중지점 {#required-gitlab-17-upgrade-stops}

이후 버전으로 업그레이드하기 전에 GitLab 17의 해당 버전으로 업그레이드해야 합니다.

| 필수 버전 | 참고 |
|:-----------------|:------|
| 17.11.7          | 최신 GitLab 17.11 패치 릴리스로 업그레이드합니다. [GitLab 17.11.0 업그레이드 정보](versions/gitlab_17_changes.md#upgrades-to-17110)를 참조하세요. |
| 17.8.7           | 최신 GitLab 17.8 패치 릴리스로 업그레이드합니다. [GitLab 17.8.0 업그레이드 정보](versions/gitlab_17_changes.md#upgrades-to-1780)를 참조하세요. |
| 17.5.5           | 최신 GitLab 17.5 패치 릴리스로 업그레이드합니다. [GitLab 17.5.0 업그레이드 정보](versions/gitlab_17_changes.md#upgrades-to-1750)를 참조하세요. |
| 17.3.7           | 최신 GitLab 17.3 릴리스로 업그레이드합니다. [GitLab 17.3.0 업그레이드 정보](versions/gitlab_17_changes.md#upgrades-to-1730)를 참조하세요. |
| 17.1.8           | [`ci_pipeline_messages` 테이블이 큰 인스턴스의 경우에만 필수입니다.](versions/gitlab_17_changes.md#long-running-pipeline-messages-data-change) [GitLab 17.1.0 업그레이드 정보](versions/gitlab_17_changes.md#upgrades-to-1710)를 참조하세요.|

### 필수 GitLab 16 업그레이드 중지점 {#required-gitlab-16-upgrade-stops}

이후 버전으로 업그레이드하기 전에 GitLab 16의 해당 버전으로 업그레이드해야 합니다.

| 필수 버전 | 참고 |
|:-----------------|:------|
| 16.11.10         | [GitLab 16.11.0 업그레이드 정보](versions/gitlab_16_changes.md#16110)를 참조하세요. |
| 16.7.10          | [GitLab 16.8.0 업그레이드 정보](versions/gitlab_16_changes.md#1670) 및 이후 GitLab 16.7 버전을 참조하세요. |
| 16.3.9           | [GitLab 16.3.0 업그레이드 정보](versions/gitlab_16_changes.md#1630) 및 이후 GitLab 16.3 버전을 참조하세요. |
| 16.2.11          | [큰 파이프라인 변수 기록](versions/gitlab_16_changes.md#1630)이 있는 GitLab 인스턴스에만 필수입니다. [GitLab 16.2.0 업그레이드 정보](versions/gitlab_16_changes.md#1620)를 참조하세요. |
| 16.1.8           | [패키지 레지스트리에 NPM 패키지가 있는 GitLab 인스턴스의 경우에만 필수입니다.](versions/gitlab_16_changes.md#1610) [GitLab 16.1.0 업그레이드 정보](versions/gitlab_16_changes.md#1610)를 참조하세요. |
| 16.0.10          | [많은 사용자](versions/gitlab_16_changes.md#long-running-user-type-data-change) 또는 [큰 파이프라인 변수 기록](versions/gitlab_16_changes.md#1610)이 있는 GitLab 인스턴스에만 필수입니다. [GitLab 16.0.0 업그레이드 정보](versions/gitlab_16_changes.md#1600) 및 이후 GitLab 16.0 버전을 참조하세요. |

### 필수 GitLab 15 업그레이드 중지점 {#required-gitlab-15-upgrade-stops}

이후 버전으로 업그레이드하기 전에 GitLab 15의 해당 버전으로 업그레이드해야 합니다.

| 필수 버전 | 참고 |
|:-----------------|:------|
| 15.11.13         | [GitLab 15.11.0 업그레이드 정보](versions/gitlab_15_changes.md#15110) 및 이후 GitLab 15.11 버전을 참조하세요. |
| 15.4.6           | [GitLab 15.4.0 업그레이드 정보](versions/gitlab_15_changes.md#1540) 및 이후 GitLab 15.4 버전을 참조하세요. |
| 15.1.6           | 여러 웹 노드가 있는 GitLab 인스턴스에만 필수입니다. [GitLab 15.1.0 업그레이드 정보](versions/gitlab_15_changes.md#1510)를 참조하세요. |
| 15.0.5           | [GitLab 15.0 업그레이드 정보](versions/gitlab_15_changes.md#1500)를 참조하세요. |

## 업그레이드 경로 도구 {#upgrade-path-tool}

현재 및 원하는 대상 GitLab 버전을 기반으로 필요한 업그레이드 중지점을 빠르게 계산하려면 [업그레이드 경로 도구](https://gitlab-com.gitlab.io/support/toolbox/upgrade-path/)를 참조하세요. 이 도구는 GitLab 지원팀에서 유지 관리합니다.

피드백을 공유하고 도구 개선을 돕기 위해 [`upgrade-path` 프로젝트](https://gitlab.com/gitlab-com/support/toolbox/upgrade-path)에서 이슈 또는 머지 리퀘스트를 생성합니다.

## 이전 GitLab 버전 {#earlier-gitlab-versions}

이전 GitLab 버전으로 업그레이드하는 방법에 대한 정보는 [설명서 아카이브](https://archives.docs.gitlab.com)를 참조하세요. 아카이브의 설명서 버전은 이전 GitLab 버전의 버전별 정보를 포함합니다.
