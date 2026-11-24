---
stage: Software Supply Chain Security
group: Pipeline Security
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "GitLab 비밀 관리자가 어떻게 청구되는지, GitLab Credits를 어떻게 소비하는지, 그리고 어떻게 시험해 볼 수 있는지 알아봅니다."
title: GitLab 비밀 관리자 크레딧 사용
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

{{< history >}}

- [GitLab 19.3에서 GitLab.com용으로 도입됨](https://gitlab.com/groups/gitlab-org/-/work_items/10723)

{{< /history >}}

GitLab 비밀 관리자 사용은 [GitLab Credits](../../../subscriptions/gitlab_credits.md)를 두 가지 미터를 기준으로 소비합니다:

- 저장된 비밀: 비밀 관리자에 보관된 비밀의 수이며, 비밀당 월별로 측정됩니다.
- 비밀 작업: 비밀을 가져오기(파이프라인에서, Kubernetes 클러스터에서 또는 API에 의해)는 하나의 작업입니다. 비밀 업데이트 및 삭제는 작업으로 계산되지 않습니다.

## GitLab Credits 소비 {#gitlab-credits-consumption}

GitLab 비밀 관리자에 사용되는 GitLab Credits는 최상위 그룹(네임스페이스) 구독에서 제공되는 [월별 약정 풀](../../../subscriptions/gitlab_credits.md#monthly-commitment-pool)과 [주문형 크레딧](../../../subscriptions/gitlab_credits.md#on-demand-credits)에서 인출됩니다. 그룹의 프로젝트 및 하위 그룹 전체에서의 비밀 관리자 사용은 최상위 그룹의 크레딧을 소비합니다.

> [!note]
> [포함된 크레딧](../../../subscriptions/gitlab_credits.md#included-credits)은 각 사용자에게 할당되지만 GitLab 비밀 관리자에는 적용되지 않습니다.

GitLab Credits 사용량 제한은 비밀 관리자 사용을 제한하지 않습니다. 사용량이 개별 사용자에게 속하지 않으므로 사용자당 제한이 적용되지 않으며, 네임스페이스 지출 제한도 비밀 관리자 소비를 차단하지 않습니다.

크레딧은 이러한 요금을 기준으로 비밀 저장 및 작업에 대해 소비됩니다:

| 형식           | 요금                 | 크레딧 | 세부 정보 |
|----------------|-----------------------|---------|---------|
| 저장된 비밀 | 월별 하나의 비밀 | 1       | 크레딧 소비는 비밀이 존재하는 기간을 기준으로 일일 비례 배분됩니다. 예를 들어, 한 달의 절반 동안 저장된 두 개의 비밀은 하나의 크레딧을 소비합니다. |
| 비밀 읽기   | 2,500회 읽기       | 1       | 모든 비밀에 대한 비밀 읽기 작업입니다. CI/CD 작업, 비밀 관리자 API 또는 통합(ESO, Terraform, OpenBao CLI)을 사용하여 비밀을 검색하는 것을 포함합니다. |

[GitLab Credits 대시보드](../../../subscriptions/gitlab_credits_dashboard.md)에서 크레딧 사용을 보고 관리합니다.

### CI/CD 작업 {#in-cicd-jobs}

CI/CD 작업에서 성공적으로 가져온 각 비밀은 작업이 나중에 실패하더라도 하나의 읽기 작업으로 계산됩니다. 여러 비밀을 참조하는 작업은 각 비밀에 대해 하나의 읽기 작업을 수행합니다. 작업을 다시 시도하면 비밀이 다시 가져와집니다.

읽기 작업이 실패하는 경우 비밀 작업은 크레딧을 소비하지 않습니다. 다음과 같은 경우를 포함합니다:

- 참조된 비밀이 존재하지 않습니다.
- 권한 오류로 인해 읽기가 실패합니다.

### 예제 {#examples}

다양한 상황에서 비밀의 예상 월별 소비를 측정하는 데 도움을 주기 위해 다음과 같은 예시가 있습니다:

- 25개의 비밀이 저장되고 월별 500개의 파이프라인, 파이프라인당 5개의 비밀을 읽는 작은 팀입니다.
  - 저장: 25개 비밀 = 25 크레딧
  - 작업: 2,500회 읽기 = 1 크레딧
  - 월간 합계: 26 크레딧
- 개발, 스테이징, 프로덕션 환경 전반에 걸쳐 120개의 비밀이 있는 다중 환경 애플리케이션, 월별 2,000개의 파이프라인, 파이프라인당 5개의 비밀을 읽습니다.
  - 저장: 120개 비밀 = 120 크레딧
  - 작업: 10,000회 읽기 = 4 크레딧
  - 월간 합계: 124 크레딧
- 1,000개의 비밀이 저장되고 월별 50,000개의 파이프라인, 파이프라인당 10개의 비밀을 읽는 엔터프라이즈 수준의 사용입니다.
  - 저장: 1,000개 비밀 = 1,000 크레딧
  - 작업: 500,000회 읽기 = 200 크레딧
  - 월간 합계: 1,200 크레딧

## 구독이 종료될 때 {#when-your-subscription-ends}

네임스페이스에 대한 Premium 또는 Ultimate 구독이 취소되거나 만료되면 비밀 관리자는 구독 종료 날짜부터 시작하는 14일의 유예 기간에 진입합니다.

유예 기간 동안:

- 파이프라인 및 서비스 계정은 여전히 비밀 읽기 작업을 수행할 수 있습니다.
- 비밀을 생성, 업데이트 또는 삭제할 수 없습니다.

유예 기간이 종료되면 비밀 작업이 차단됩니다. GitLab은 비밀을 삭제하지 않으며 UI에서 계속 볼 수 있습니다.

전체 액세스를 복원하려면 구독을 갱신합니다.

## 베타 종료 {#end-of-beta}

GitLab 비밀 관리자의 베타 사용은 GitLab Credits를 소비하지 않습니다. GitLab.com의 베타는 2026년 9월 21일에 종료됩니다.

베타 종료 전 언제든지 시험을 시작하고 임시 평가 크레딧을 사용할 수 있습니다. 시험 종료 시 서비스 중단을 피하기 위해 구독에서 GitLab Credits를 사용할 수 있는지 확인해야 합니다.

시험을 시작하지 않으면 GitLab 비밀 관리자는 베타 종료 시 비활성화됩니다.

## 시험 시작 {#start-a-trial}

30일 무료 시험으로 GitLab 비밀 관리자를 평가할 수 있습니다. 시험은 저장된 비밀 및 비밀 작업을 위해 500개의 [임시 평가 크레딧](../../../subscriptions/gitlab_credits.md#temporary-evaluation-credits) 풀을 제공합니다.

다음 중 하나가 먼저 발생하면 시험이 종료됩니다:

- 활성화로부터 30일이 경과합니다.
- 모든 임시 평가 크레딧이 소비됩니다.

임시 평가 크레딧은 네임스페이스 전체에서 공유되며 사용자당 할당되지 않습니다. 이들은 이월되지 않으며 만료 후 사용할 수 없습니다.

구독에 대해 시험을 한 번만 활성화할 수 있습니다. 네임스페이스가 이전에 시험을 사용한 경우 다른 시험을 활성화할 수 없습니다.

전제 조건:

- 최상위 그룹에 대한 Owner 역할이 있어야 합니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 최상위 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **안전함** > **비밀 관리자**를 선택합니다.
1. **30일 시험 시작**을 선택합니다.

시험 종료 시:

- [GitLab Credits를 사용할 수 있으면](../../../subscriptions/gitlab_credits.md) 구독에서 월별 약정 풀을 먼저 사용한 다음 주문형 크레딧을 사용하여 사용이 중단 없이 계속됩니다.
- GitLab 크레딧에 접근할 수 없으면 비밀 관리자 작업이 차단되므로 읽기 작업 및 종속 파이프라인이 실패합니다. 액세스를 복원하려면 [GitLab Credits 구입](../../../subscriptions/gitlab_credits.md#buy-gitlab-credits)해야 합니다.
