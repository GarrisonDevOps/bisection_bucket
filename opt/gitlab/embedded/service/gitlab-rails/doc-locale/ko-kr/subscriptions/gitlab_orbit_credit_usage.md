---
stage: Orbit
group: Context Systems
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "GitLab Orbit이 GitLab Credits를 어떻게 사용하는지, 어떤 요청이 무료인지, 어느 그룹에 청구되는지 알아봅니다."
title: GitLab Orbit 크레딧 사용
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab Orbit 크레딧 사용이 GitLab 19.5에서 [도입되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/259054).

{{< /history >}}

REST API, GitLab MCP 서버 또는 GitLab Orbit MCP 엔드포인트를 통해 전송된 모든 쿼리는 [GitLab Credits](gitlab_credits.md)를 소비합니다.

클라이언트는 중요하지 않습니다. GitLab Duo, 자신의 에이전트, GitLab Orbit CLI, GitLab Orbit 대시보드 및 GitLab의 코드 탐색에서의 쿼리는 모두 크레딧을 소비합니다.

GitLab Orbit CLI가 컴퓨터에서 구축하는 로컬 그래프에 대한 쿼리는 크레딧을 소비하지 않습니다. 스키마 및 상태 요청과 같이 쿼리를 실행하지 않는 요청은 크레딧을 소비하지 않습니다.

## 크레딧 요율 {#credit-rate}

쿼리는 다음 요율로 크레딧을 소비합니다:

| 용도                           | 요율        | 크레딧 |
|---------------------------------|-------------|---------|
| GitLab Orbit API에 대한 쿼리 | 100개 쿼리 | 3       |

### 월간 소비 추정 예제 {#monthly-consumption-estimate-examples}

다음 예제를 사용하여 월간 소비를 추정합니다:

- GitLab Duo 또는 GitLab Orbit CLI를 통해 각각 월 500개의 쿼리를 실행하는 10명의 개발자 팀입니다.
  - 쿼리: 5,000
  - 월간 합계: 150 크레딧
- 각각 월 500개의 쿼리를 실행하는 100명의 개발자 그룹입니다.
  - 쿼리: 50,000
  - 월간 합계: 1,500 크레딧
- 월 5,000개의 머지 리퀘스트를 검토하고 각 검토당 30개의 쿼리를 실행하는 에이전트입니다.
  - 쿼리: 150,000
  - 월간 합계: 4,500 크레딧

## 그래프 용량 {#graph-capacity}

그래프 용량은 최상위 그룹의 GitLab Orbit 그래프 크기로, GiB 단위로 측정됩니다. GitLab.com 및 GitLab Dedicated에 포함된 그래프 용량 한계는 다음과 같습니다:

- Premium: 2 GiB.
- Ultimate: 5 GiB.

## 청구되는 그룹 {#billed-group}

사용량은 사용자의 기본 GitLab Orbit 그룹으로 청구됩니다. 사용자가 GitLab Orbit이 있는 최상위 그룹에 하나만 속하면 해당 그룹이 기본값입니다. 사용자가 두 개 이상에 속하면 [기본 그룹](../user/profile/preferences.md#choose-which-gitlab-duo-features-use-orbit)을 선택해야 합니다. GitLab.com에서는 선택할 때까지 쿼리가 실패합니다.

## 시험판 및 구매 {#trials-and-purchases}

GitLab.com에서 최상위 그룹의 소유자 역할을 가진 사용자는 무료 GitLab Orbit 시험판을 시작할 수 있습니다. GitLab Orbit을 구매하거나 GitLab Self-Managed 또는 GitLab Dedicated에서 사용하려면 [영업 팀에 문의하세요](https://about.gitlab.com/sales/).

## 사용량 추적 {#track-usage}

GitLab Orbit 사용량을 추적하려면 [GitLab Orbit 사용량](gitlab_credits_dashboard.md#gitlab-orbit-usage)을 참조하세요.
