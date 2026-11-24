---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab 배포 크기를 평가하고 계획하기 위한 가이드입니다.
title: 배포 크기 평가 및 계획
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

설치 전에 GitLab 환경의 워크로드를 평가하고 적절한 배포 요구 사항을 결정하거나, 기존 환경의 크기가 올바른지 평가할 때 이 가이드를 사용합니다.

## 워크로드 특성화 {#workload-characterization}

GitLab 환경은 유사한 사용자 수나 요청 볼륨이라도 인프라 필요 사항이 크게 다릅니다. Git 작업, CI/CD 활동, API 사용, 자동화의 조합은 어떤 구성 요소가 압력을 받는지, 그리고 어떻게 확장해야 하는지를 결정합니다.

환경을 고정된 크기 티어에 매핑하는 대신 워크로드 특성화는 환경의 프로필을 설명합니다. 환경을 측정한 후 얻은 특성화가 어떤 구성 요소 수준의 요구 사항과 확장 고려 사항을 적용할지 결정합니다.

| 특성화 | 일반적인 프로필 |
|:-----------------|:----------------|
| 소규모 | Git 활동이 적음, 최소 자동화, 낮은 CI/CD 동시성 |
| 중간 | 보통 Git 활동, 표준 CI/CD 사용, 일부 자동화 |
| 대규모 | 높은 CI/CD, 활동적인 모노레포, 상당한 API 자동화 |
| 초대규모 | 집약적 워크로드, 광범위한 통합, 모든 구성 요소에 걸친 높은 동시성 |

이러한 특성화는 설명적이며 처방적이지 않습니다. 이는 환경을 측정하여 도출한 결론이며, 미리 선택하는 범주가 아닙니다. 많은 환경이 단일 특성화에 명확하게 들어맞지 않습니다. 웹과 API 활동은 가볍지만 Git 작업이 많은 환경은 반대 프로필을 가진 환경과 다르게 작동합니다.

소규모 및 중규모 환경의 경우 이 페이지의 지침은 자립적으로 설계되었습니다. 대규모 및 초대규모 환경의 경우 운영 복잡성이 [Professional Services](https://about.gitlab.com/professional-services/)와의 협력이나 [GitLab Dedicated](../subscriptions/gitlab_dedicated/_index.md) 또는 GitLab.com을 운영 부담을 완전히 제거하는 대안으로 고려할 필요가 있습니다.

## 워크로드 고려 사항 {#workload-considerations}

일부 워크로드 패턴은 이 가이드에서 설명하는 표준 RPS 기반 방법론보다 더 많은 것이 필요합니다. 이 중 두 가지는 RPS 메트릭을 추출한 후 다루어집니다: [대규모 모노레포 및 기타 인프라별 요소](#assess-special-infrastructure-requirements) 및 [비정형 워크로드 패턴](#understanding-rps-composition-and-workload-patterns)(예: 과도한 자동화, CI/CD 사용 또는 보안 스캔)

GitLab Duo Agent Platform은 표준 워크로드 크기 조정 이상의 자체 인프라 고려 사항을 도입합니다. [GitLab Duo Agent Platform의 확장](../administration/reference_architectures/_index.md#scaling-for-gitlab-duo-agent-platform)을 참조한 후 이를 사용할 환경의 크기를 조정합니다.

### 자동 크기 조정 {#autoscaling}

Rails(Puma)와 Sidekiq은 상태 비저장이며 자동 크기 조정 그룹을 지원합니다. 이러한 구성 요소를 평균 지속적 부하에 맞게 크기 조정하고 자동 크기 조정이 피크를 처리하도록 합니다.

Gitaly는 상태 저장이며 자동 크기 조정을 지원하지 않습니다. 아래의 지침을 사용하여 Gitaly 노드를 피크 부하에 맞게 크기 조정합니다.

자동 크기 조정이 요구 사항인 경우 [클라우드 네이티브 배포](../administration/reference_architectures/_index.md#cloud-native)가 일반적으로 VM 기반 자동 크기 조정 그룹보다 선호됩니다. 데이터베이스 마이그레이션 및 [Mailroom](../administration/incoming_email.md)과 같이 단일 노드에서 실행해야 하는 구성 요소는 VM 자동 크기 조정 그룹보다 Kubernetes에서 더 안정적으로 처리되므로 VM 기반 자동 크기 조정을 선택하기 전에 이 제한 사항을 고려하십시오.

## 시작하기 전에 {#before-you-begin}

이러한 지침은 Prometheus 메트릭을 사용하여 환경을 정확하게 평가합니다. 환경이 간단한 경우 [참조 아키텍처](../administration/reference_architectures/_index.md)에서 이러한 수준의 분석 없이도 충분한 지침을 제공할 수 있습니다.

> [!note]
> 전문가 지도가 필요하신가요? 아키텍처를 올바르게 크기 조정하는 것은 최적의 성능을 위해 중요합니다. 당사의 [Professional Services](https://about.gitlab.com/professional-services/) 팀이 특정 아키텍처를 평가하고 성능, 안정성 및 가용성 최적화를 위한 맞춤형 권장 사항을 제공할 수 있습니다.

이 설명서를 따르려면 GitLab 인스턴스와 함께 Prometheus 모니터링을 배포해야 합니다. Prometheus는 올바른 크기 조정 평가에 필요한 정확한 메트릭을 제공합니다.

Prometheus를 아직 구성하지 않았다면:

1. [Prometheus](../administration/monitoring/prometheus/_index.md)를 사용하여 모니터링을 구성합니다. 참조 아키텍처 설명서는 각 환경 크기에 대한 Prometheus 구성에 대한 세부 정보를 제공합니다. 클라우드 네이티브 GitLab의 경우 [`kube-prometheus-stack`](https://artifacthub.io/packages/helm/prometheus-community/kube-prometheus-stack) Helm 차트를 사용하여 메트릭 스크래핑을 구성할 수 있습니다.
1. 의미 있는 데이터 패턴을 수집하기 위해 7-14일 동안 데이터를 수집합니다.
1. 이 정보의 나머지 부분을 읽으십시오.

Prometheus 모니터링을 구성할 수 없으면:

- [현재 환경](#analyze-current-environment-and-validate-recommendations) 사양을 가장 가까운 참조 아키텍처와 비교하여 크기 조정을 추정합니다.
- [GitLab RPS Analyzer](https://gitlab.com/gitlab-org/professional-services-automation/tools/utilities/gitlab-rps-analyzer#gitlab-rps-analyzer)를 사용하여 GitLabSOS 또는 KubeSOS 로그를 사용하는 참조 아키텍처 크기를 평가합니다. 그러나 이것은 메트릭보다 신뢰성이 낮습니다.

다른 플랫폼에서 마이그레이션하는 경우 다음 PromQL 쿼리는 기존 GitLab 메트릭 없이는 적용할 수 없습니다. 그러나 일반적인 평가 방법은 여전히 유효합니다:

1. 예상 워크로드를 기반으로 가장 가까운 참조 아키텍처를 추정합니다.
1. 예상되는 [추가 워크로드](../administration/reference_architectures/_index.md#additional-workloads)를 식별합니다.
1. 대규모 리포지토리의 수를 평가합니다
1. 성장 예측을 통합합니다.
1. [적절한 버퍼](../administration/reference_architectures/_index.md#if-in-doubt-start-large-monitor-and-then-scale-down)가 있는 참조 아키텍처를 선택합니다.

### PromQL 쿼리 실행 {#running-promql-queries}

PromQL 쿼리를 실행하는 것은 사용하는 모니터링 솔루션에 따라 다릅니다. [Prometheus 모니터링 설명서](../administration/monitoring/prometheus/_index.md#how-prometheus-works)에서 언급했듯이 모니터링 데이터는 Prometheus에 직접 연결하거나 Grafana와 같은 대시보드 도구를 사용하여 액세스할 수 있습니다.

## 기준 크기 결정 {#determine-your-baseline-size}

초당 요청 수(RPS)는 GitLab 인프라 크기 조정을 위한 기본 메트릭입니다. 다양한 트래픽 유형(API, 웹, Git 작업)은 다양한 구성 요소에 스트레스를 주므로 각각을 개별적으로 분석하여 실제 용량 요구 사항을 찾습니다.

### 피크 트래픽 메트릭 추출 {#extract-peak-traffic-metrics}

최대 부하를 파악하기 위해 이러한 쿼리를 실행합니다. 이러한 쿼리는 다음을 보여줍니다:

- 절대 피크, 즉 보았던 가장 높은 스파이크입니다. 절대 피크는 최악의 시나리오를 보여줍니다.
- 지속 피크, 즉 95번째 백분위수이며 일반적인 "바쁜" 수준으로 간주됩니다. 지속 피크는 일반적인 높은 부하 기간을 드러냅니다.

절대 피크가 드문 이상이라면 지속적 부하에 대해 크기 조정하는 것이 적절할 수 있습니다.

보유 기반 쿼리의 시간 범위를 조정합니다(`[7d]`에서 `[30d]`로 변경 더 오래된 기록이 있는 경우).

> [!note]
> 높은 활동 환경의 경우 `max_over_time` 또는 `quantile_over_time` 쿼리가 시간 초과될 수 있습니다. 이 경우 외부 집계 함수를 제거하고 내부 쿼리를 그래프로 시각화합니다. 예를 들어 API 트래픽 피크의 경우 다음을 사용합니다:
>
> ```prometheus
> sum(rate(gitlab_transaction_duration_seconds_count{controller=~"Grape", action!~".*/internal/.*"}[1m]))
> ```
>
> 모니터링 기간 동안 그래프된 결과에서 피크 값을 시각적으로 식별합니다.

#### 절대 피크 쿼리 {#query-absolute-peaks}

지정된 시간 기간 동안 관찰된 최대 RPS를 식별합니다:

1. 이러한 쿼리를 실행합니다:

   - API 트래픽 피크, 자동화, 외부 도구 및 웹후크의 피크 API 요청을 측정합니다:

     ```prometheus
     max_over_time(
       sum(rate(gitlab_transaction_duration_seconds_count{controller=~"Grape", action!~".*/internal/.*", action!="POST /api/jobs/request"}[1m]))[7d:1m]
     )
     ```

   - 웹 트래픽 피크, 브라우저의 사용자로부터의 피크 UI 상호 작용을 측정합니다:

     ```prometheus
     max_over_time(
       sum(rate(gitlab_transaction_duration_seconds_count{controller!~"Grape|HealthController|MetricsController|Repositories::GitHttpController|GraphqlController"}[1m]))[7d:1m]
     )
     ```

   - Git 풀 및 클론 피크, 피크 리포지토리 클론 및 페치 작업을 측정합니다:

     ```prometheus
     max_over_time(
       (sum(rate(gitlab_transaction_duration_seconds_count{action="git_upload_pack"}[1m])) or vector(0) +
       sum(rate(gitaly_service_client_requests_total{grpc_method="SSHUploadPack"}[1m])) or vector(0))[7d:1m]
     )
     ```

   - Git 푸시 피크, 피크 코드 푸시 작업을 측정합니다:

     ```prometheus
     max_over_time(
       (sum(rate(gitlab_transaction_duration_seconds_count{action="git_receive_pack"}[1m])) or vector(0) +
       sum(rate(gitaly_service_client_requests_total{grpc_method="SSHReceivePack"}[1m])) or vector(0))[7d:1m]
     )
     ```

1. 결과를 기록합니다.

#### 지속 피크 쿼리 {#query-sustained-peaks}

드문 스파이크를 필터링하여 일반적인 높은 부하 수준을 식별합니다:

1. 이러한 쿼리를 실행합니다:

   - API 지속 피크:

     ```prometheus
     quantile_over_time(0.95,
       sum(rate(gitlab_transaction_duration_seconds_count{controller=~"Grape", action!~".*/internal/.*", action!="POST /api/jobs/request"}[1m]))[7d:1m]
     )
     ```

   - 웹 지속 피크:

     ```prometheus
     quantile_over_time(0.95,
       sum(rate(gitlab_transaction_duration_seconds_count{controller!~"Grape|HealthController|MetricsController|Repositories::GitHttpController|GraphqlController"}[1m]))[7d:1m]
     )
     ```

   - Git 풀 및 클론 지속 피크:

     ```prometheus
     quantile_over_time(0.95,
       (sum(rate(gitlab_transaction_duration_seconds_count{action="git_upload_pack"}[1m])) or vector(0) +
       sum(rate(gitaly_service_client_requests_total{grpc_method="SSHUploadPack"}[1m])) or vector(0))[7d:1m]
     )
     ```

   - Git 푸시 지속 피크:

     ```prometheus
     quantile_over_time(0.95,
      (sum(rate(gitlab_transaction_duration_seconds_count{action="git_receive_pack"}[1m])) or vector(0) +
      sum(rate(gitaly_service_client_requests_total{grpc_method="SSHReceivePack"}[1m])) or vector(0))[7d:1m]
     )
     ```

1. 결과를 기록합니다.

### 트래픽을 참조 아키텍처에 매핑 {#map-traffic-to-reference-architectures}

트래픽을 참조 아키텍처에 매핑하는 방법은 배포 경로에 따라 다릅니다.

Linux 패키지(Omnibus) 또는 클라우드 네이티브 하이브리드:

1. [사용 가능한 참조 아키텍처](../administration/reference_architectures/_index.md#available-reference-architectures)를 참조하여 각 트래픽 유형이 제안하는 참조 아키텍처를 확인합니다.
1. 분석 테이블을 작성합니다. 다음 테이블을 가이드로 사용합니다:

   | 트래픽 유형       | 피크 RPS | 피크 제안된 RA     | 지속된 RPS | 지속된 제안된 RA |
   |:-------------------|:---------|:----------------------|:--------------|:-----------------------|
   | API                | ________ | _____ (최대 ___ RPS) | _____________ | _____ (최대 ____ RPS) |
   | 웹                | ________ | _____ (최대 ___ RPS) | _____________ | _____ (최대 ____ RPS) |
   | Git 풀 및 클론 | ________ | _____ (최대 ___ RPS) | _____________ | _____ (최대 ____ RPS) |
   | Git 푸시           | ________ | _____ (최대 ___ RPS) | _____________ | _____ (최대 ____ RPS) |

1. **피크 제안된 RA** 열의 모든 참조 아키텍처를 비교하고 가장 큰 크기를 선택합니다. **지속된 제안된 RA** 열에 대해 반복합니다.
1. 기준을 문서화합니다:
   - 제안된 가장 큰 피크 RA입니다.
   - 제안된 가장 큰 지속 RA입니다.

클라우드 네이티브:

클라우드 네이티브 아키텍처는 트래픽 유형별 대상이 아닌 단일 전체 RPS 대역으로 크기가 조정됩니다. API 트래픽이 일반적으로 부하의 대부분을 차지하기 때문입니다([요청 유형별 RPS 분석](#rps-breakdown-by-request-type) 참조).

1. 피크 및 지속된 전체 RPS를 사용 가능한 크기와 비교합니다:

   | 특성화 | 클라우드 네이티브 크기                                  | 대상 RPS |
   |:------------------|:----------------------------------------------------|:-----------|
   | 소규모             | [소규모(S)](../administration/reference_architectures/cloud_native.md#small-s)               | ≤100 RPS   |
   | 중간            | [중규모(M)](../administration/reference_architectures/cloud_native.md#medium-m)             | ≤200 RPS   |
   | 대규모             | [대규모(L)](../administration/reference_architectures/cloud_native.md#large-l)               | ≤500 RPS   |
   | 초대규모       | [초대규모(XL)](../administration/reference_architectures/cloud_native.md#extra-large-xl) | ≤1000 RPS  |

1. 기준을 문서화합니다:
   - 피크 제안된 크기입니다.
   - 지속된 제안된 크기입니다.

### 참조 아키텍처 선택 {#choose-a-reference-architecture}

이 시점에서 두 개의 후보 크기가 있습니다: 절대 피크 기반, 지속적 부하 기반입니다.

크기를 선택할 때:

1. 피크와 지속이 같은 크기를 제시하면 해당 크기를 사용합니다.
1. 피크가 지속보다 더 큰 크기를 제시하면 격차를 계산합니다. 피크 RPS가 지속된 크기의 상한의 10-15% 이내인가요?

일반 지침:

- 피크 RPS가 지속된 크기의 한계를 10-15% 미만으로 초과하면 참조 아키텍처에 내장된 헤드룸이 있기 때문에 지속된 크기를 허용 가능한 위험으로 간주할 수 있습니다.
- 15% 이상에서는 피크 기반 크기로 시작한 다음 메트릭이 다운사이징을 지원하면 모니터링하고 조정합니다.

Linux 패키지/클라우드 네이티브 하이브리드 예제:

- 피크가 110 RPS(최대 100 RPS의 5,000명 사용자 아키텍처) → 10% 초과 → 5,000명 사용자 아키텍처가 충분해야 합니다.
- 피크가 150 RPS(최대 100 RPS의 5,000명 사용자 아키텍처) → 50% 초과 → 10,000명 사용자 아키텍처 사용(최대 200 RPS).
- 피크는 100 RPS(5,000명 사용자 아키텍처)이지만 지속은 50 RPS(3,000명 사용자 아키텍처, 최대 60 RPS)입니다. 원시 RPS 그래프는 자동화 스파이크가 피크를 유발하지만 대부분의 시간 부하가 50 RPS 미만임을 보여줍니다. 5,000명 사용자 아키텍처로 보수적으로 시작한 다음 축소할지, 아니면 3,000명 사용자 아키텍처로 시작할지 평가합니다[워크로드별 확장](#identify-component-adjustments)(더 높은 위험).

클라우드 네이티브 예제:

- 피크는 120 RPS(중규모)이지만 지속은 80 RPS(소규모)입니다. 중규모로 보수적으로 시작한 다음 축소할지, 아니면 소규모로 시작할지 평가합니다[워크로드별 확장](#identify-component-adjustments)(더 높은 위험).

40 RPS 이하이고 고가용성(HA)이 요구 사항인 환경의 경우 [고가용성 섹션](../administration/reference_architectures/_index.md#high-availability-ha)을 참조하여 지원되는 감소가 있는 60 RPS/3,000명 사용자 아키텍처로 전환이 필요한지 확인합니다.

### 진행하기 전에 {#before-you-proceed}

이 섹션을 완료하면 기준 참조 아키텍처 크기를 설정했습니다. 이것이 기초를 형성하지만 다음 섹션에서는 특정 워크로드가 표준 구성 이상으로 구성 요소 조정이 필요한지 확인합니다.

진행하기 전에 이 섹션에서 수집한 세부 정보를 문서화했는지 확인합니다. 다음을 가이드로 사용할 수 있습니다:

```markdown
Reference architecture assessment summary:

- Selected reference architecture: _____
- Justification based on _____ RPS [absolute/sustained]

| Traffic Type       | Peak RPS | Sustained RPS (95th) |
|:-------------------|:---------|:---------------------|
| API                | ________ | ____________________ |
| Web                | ________ | ____________________ |
| Git pull and clone | ________ | ____________________ |
| Git push           | ________ | ____________________ |

Highest RPS Peak timestamp for workload analysis: _____
```

## RPS 구성 및 워크로드 패턴 이해 {#understanding-rps-composition-and-workload-patterns}

총 RPS는 기본 크기 조정 메트릭이지만 워크로드 구성은 구성 요소 리소스 요구 사항에 크게 영향을 미칩니다. 다양한 요청 유형은 다양한 강도로 다양한 구성 요소에 스트레스를 줍니다.

### 요청 유형별 RPS 분석 {#rps-breakdown-by-request-type}

참조 아키텍처 RPS 대상은 프로덕션 데이터를 기반으로 한 일반적인 워크로드 구성을 가정합니다:

- **API 요청**(총 RPS의 약 80%) - 자동화, 통합, 웹후크 및 API 기반 도구
- **웹 요청**(총 RPS의 약 10%) - UI 상호 작용, 페이지 탐색 및 사용자 기반 작업
- **Git 작업**(총 RPS의 약 10%) - 리포지토리 클론 및 풀, 낮은 푸시 속도

**비정형 구성** \- 한 요청 유형이 일반적인 비율을 크게 초과하는 환경(대상 RPS 범위 내에서도 구성 요소별 조정이 필요할 수 있음)

### 비정형 워크로드 패턴 식별 {#identifying-atypical-workload-patterns}

[피크 트래픽 메트릭 추출](#extract-peak-traffic-metrics)의 RPS 추출 쿼리를 사용하여 워크로드 구성을 이해합니다. 분포를 일반적인 패턴과 비교합니다:

**API 중심 워크로드**(API > 총 RPS의 90%):

- 과도한 자동화, 광범위한 통합 또는 API 기반 도구
- 주요 영향: Rails(Webservice), PostgreSQL, Gitaly
- 고려: 증가된 Webservice/Rails 용량, 데이터베이스 읽기 복제본

**웹 중심 워크로드**(웹 > 총 RPS의 20%):

- 광범위한 UI 상호 작용이 있는 활동적인 사용자 기반
- 주요 영향: Rails(Webservice), PostgreSQL
- 고려: 증가된 Webservice 용량, 데이터베이스 최적화

**Git 중심 워크로드**(Git > 총 RPS의 15% 또는 귀사 규모의 일반적인 것보다 현저히 높은 풀 속도):

- 빈번한 풀, 모노레포 패턴 또는 리포지토리 클론이 있는 CI/CD 중심 워크플로우가 있는 대규모 팀
- 주요 영향: Gitaly, 네트워크 대역폭
- 고려: Gitaly 수직 확장, 리포지토리 최적화, 네트워크 강화 VM

### 평가 접근 {#assessment-approach}

1. 제공된 PromQL 쿼리를 사용하여 RPS 분석을 추출합니다
1. 각 요청 유형에 대한 총 백분율을 계산합니다
1. 유형이 일반적인 비율을 크게 초과하는지 확인합니다
1. 비정형인 경우 [구성 요소 조정 식별](#identify-component-adjustments)을 참조하여 확장 지침을 확인합니다

> [!note]
> 작은 변동(모든 범주에서 5-10 RPS 차이)은 아키텍처 변경이 필요하지 않습니다. RPS 비교만을 기반으로 결정을 내리지 말고 프로덕션에서 실제 구성 요소 포화 메트릭(CPU, 메모리, 큐 깊이)을 모니터링합니다. 지속적 이용률이 70% 미만인 구성 요소는 일반적으로 사소한 RPS 변동과 관계없이 충분한 용량을 보유합니다.

## 구성 요소 조정 식별 {#identify-component-adjustments}

워크로드 평가는 기본 참조 아키텍처 이상의 구성 요소 조정이 필요한 특정 사용 패턴을 식별합니다. RPS는 전체 크기를 결정하지만 워크로드 패턴은 형태를 결정합니다. 동일한 RPS를 가진 두 환경은 매우 다른 리소스 요구 사항을 가질 수 있습니다.

다양한 워크로드는 GitLab 아키텍처의 다양한 부분에 스트레스를 줍니다:

- CI/CD 중심 환경은 적절한 RPS를 유지하면서 수천 개의 작업을 처리할 때 Sidekiq과 Gitaly에 스트레스를 줍니다.
- 광범위한 API 자동화를 갖춘 환경은 높은 RPS를 표시하지만 데이터베이스 및 Rails 계층에 부하를 집중시킵니다.

### 피크 부하 중 상단 끝점 분석 {#analyze-top-endpoints-during-peak-load}

이전 섹션의 피크 타임스탬프를 사용하여 최대 부하 중에 가장 많은 트래픽을 받은 끝점을 식별합니다.

> [!note]
> RPS 메트릭이 업무 외 시간 동안 지속적으로 높은 트래픽을 표시하는 경우(피크의 > 50%), 이는 일반적인 패턴을 벗어난 과도한 자동화를 제시합니다. 예를 들어 업무 시간 중 100 RPS에 도달하지만 밤과 주말에 50+ RPS를 유지하는 피크 트래픽은 상당한 자동화된 워크로드를 나타냅니다. [구성 요소 조정을 평가](#determine-component-adjustments)할 때 이를 고려합니다.

1. 시각화를 활성화한 상태로 이 쿼리를 실행합니다(시간에 따른 분포의 경우 막대 차트 또는 일반 분포의 경우 원형 차트):

   ```prometheus
   topk(20,
     sum by (controller, action) (
       rate(gitlab_transaction_duration_seconds_count{controller!~"HealthController|MetricsController", action!~".*/internal/.*"}[1m])
     )
   )
   ```

1. 절대 RPS 피크 중에 상단 끝점의 분포에 대한 결과를 검토합니다. 결과는 다음을 가질 수 있습니다:

   - 표시되는 끝점 패턴이 없습니다. 이 경우 이전에 선택한 참조 아키텍처를 계속 사용합니다. 워크로드 변경의 영향을 측정하기 위해 강력한 모니터링이 마련되어 있는지 확인합니다.
   - 비Git 트래픽에 대한 과도한 API 사용량의 대부분입니다. 이 경우 웹후크 및 이슈, 그룹, 프로젝트 API 호출은 데이터베이스 중심 패턴을 나타냅니다.
   - Git 또는 Sidekiq 관련 끝점의 대부분입니다. 이 경우 머지 리퀘스트 차이, 파이프라인 작업, 브랜치, 커밋, 파일 작업, CI/CD 작업, 보안 스캔 및 가져오기 작업은 Sidekiq/Gitaly 중심 패턴을 나타냅니다.

1. 결과를 기록합니다:

   ```markdown
   Workload pattern identified:

   - [ ] Database-intensive
   - [ ] Sidekiq- or Gitaly-intensive
   - [ ] None detected
   ```

### 구성 요소 조정 결정 {#determine-component-adjustments}

위의 지표는 추가 워크로드의 초기 신호를 제공합니다. 참조 아키텍처에 내장된 헤드룸으로 인해 이러한 워크로드는 조정 없이 처리될 수 있습니다. 그러나 강한 지표가 있고 높은 수준의 자동화가 알려진 경우 다음 조정을 고려합니다.

이전에 식별된 워크로드 패턴을 기반으로 다양한 구성 요소에 확장이 필요합니다:

| 워크로드 유형              | 적용할 때                                                                                                                                                                                | 확장할 구성 요소 |
|:---------------------------|:---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|:--------------------|
| 데이터베이스 중심         | <ul><li>웹후크, 이슈, 그룹 및 프로젝트에 대한 비Git 트래픽의 과도한 API 사용</li><li>알려진 [광범위한 자동화 또는 통합 워크로드](../administration/reference_architectures/_index.md#additional-workloads)</li></ul> | <ul><li>Rails 리소스 증가</li><li>[데이터베이스 확장](#database-scaling)</li></ul> |
| Sidekiq/Gitaly 중심\*\* | <ul><li>과도한 Git 작업, CI/CD 작업, 보안 스캔, 가져오기 작업 및 Git 서버 후크</li><li>알려진 CI/CD 중심 사용 패턴</li></ul>                                      | <ul><li>Sidekiq 사양 증가</li><li>Gitaly 수직 확장</li><li>[데이터베이스 확장](#database-scaling)</li><li>고급: 특정 [작업 클래스](../administration/sidekiq/processing_specific_job_classes.md) 구성</li></ul> |

#### 확장 지침 {#scaling-guidance}

리소스 조정은 워크로드 강도 및 포화 메트릭에 따라 다릅니다:

1. 현재 리소스의 1.25배-1.5배로 시작합니다.
1. 구현 후 모니터링 데이터를 기반으로 개선합니다.

클라우드 네이티브 GitLab을 배포하려는 경우 이 평가에서 식별된 워크로드 패턴은 Kubernetes 구성에 추가적인 영향을 미칩니다:

- 높은 업무 외 트래픽입니다. 조용한 기간 동안 0으로 확장할 수 있도록 허용하지 않고 기준 부하에 충분한 최소 포드 개수를 확인합니다. 예를 들어 업무 시간 중 100 RPS와 자동화로 인한 밤 중 일정한 50 RPS의 경우 최소 포드 개수 구성은 기준 업무 외 부하에 정렬되어야 합니다.
- 빠른 트래픽 스파이크입니다. 기본 HPA 설정이 충분히 빠르게 확장되지 않을 수 있습니다. 초기 롤아웃 중에 포드 확장 동작을 모니터링하여 이러한 전환 중에 요청 대기열링을 방지합니다. 예를 들어 조용한 시간에서 업무 시간으로 올라가거나 특정 자동화 스파이크로 인한 50에서 200 RPS로 빠른 스파이크입니다.

##### 데이터베이스 확장 {#database-scaling}

데이터베이스 확장 전략은 워크로드 특성에 따라 다르며 여러 접근 방식이 필요할 수 있습니다:

1. 즉각적인 용량 제약을 해결하기 위한 수직 확장, 다음을 포함합니다:
   - 복제본이 기본 부하를 줄이지 않기 때문에 쓰기 중심 워크로드에 필요합니다.
   - 읽기 및 쓰기 작업 모두에 대한 즉각적인 용량 증가를 제공합니다.
1. [데이터베이스 부하 분산](../administration/postgresql/database_load_balancing.md)(권장) 읽기 복제본 포함, 다음을 포함합니다:
   - 읽기 중심 워크로드(85-95% 읽기)에 특히 유용합니다.
   - 여러 노드에 걸쳐 읽기 트래픽을 분산합니다.
   - 수직 확장과 조합으로 추가할 수 있습니다.
1. 쓰기 성능이 여전히 병목 현상이 되면 수직 확장을 계속합니다.

이 Prometheus 쿼리를 사용하여 읽기/쓰기 분포를 식별합니다:

```prometheus
# Percentage of READ operations
(
  (sum(rate(gitlab_transaction_db_count_total[5m])) - sum(rate(gitlab_transaction_db_write_count_total[5m]))) /
  sum(rate(gitlab_transaction_db_count_total[5m]))
) * 100
```

### 진행하기 전에 {#before-you-proceed-1}

이 섹션을 완료하면 워크로드 패턴을 식별하고 필요한 구성 요소 조정을 결정했습니다.

진행하기 전에 완전한 워크로드 평가를 기록합니다:

```markdown
Workload pattern identified:

- [ ] Database-intensive
- [ ] Sidekiq- or Gitaly-intensive
- [ ] None detected
- Component adjustments needed: _____
```

다음 섹션에서 추가 인프라 고려 사항이 필요할 수 있는 특수 데이터 특성을 평가합니다.

## 특수 인프라 요구 사항 평가 {#assess-special-infrastructure-requirements}

리포지토리 특성 및 네트워크 사용 패턴은 RPS 메트릭이 드러내는 것 이상으로 GitLab 성능에 크게 영향을 미칠 수 있습니다.

대규모 모노레포, 광범위한 이진 파일 및 네트워크 집약적 작업은 표준 크기 조정이 설명하지 않는 인프라 조정이 필요합니다.

### 대규모 모노레포 {#large-monorepos}

대규모 모노레포(수 기가바이트 이상)는 Git 작업이 수행되는 방식을 근본적으로 변경합니다. 10GB 리포지토리의 단일 클론은 일반적인 리포지토리의 수백 개의 클론보다 더 많은 리소스를 소비합니다.

이러한 리포지토리는 워크로드에 따라 Gitaly뿐 아니라 Rails, Sidekiq 및 데이터베이스에 영향을 미칩니다.

프로파일링 프로세스는 일반적인 크기를 크게 초과하는 리포지토리를 식별하는 데 중점을 둡니다:

- 중규모 모노레포: 2GB - 10GB입니다. 이것들은 적당한 조정이 필요합니다.
- 대규모 모노레포: >10GB입니다. 이것들은 상당한 인프라 변경이 필요합니다.

리포지토리의 크기를 식별하려면:

1. 프로젝트의 [사용 할당량](../user/storage_usage_quotas.md#view-storage)으로 이동합니다.
1. [**리포지토리** 스토리지 유형](../user/project/repository/repository_size.md)을 검토합니다.
1. 2GB보다 크고 10GB보다 큰 리포지토리가 있는 프로젝트의 수를 계산합니다.
1. 결과를 기록합니다:

   ```plaintext
   Number of medium monorepos (2GB - 10GB): _____
   Number of large monorepos (>10GB): _____
   ```

#### 모노레포에 대한 인프라 조정 {#infrastructure-adjustments-for-monorepos}

대규모 리포지토리는 수직 확장 및 운영 조정이 모두 필요합니다. 이러한 리포지토리는 Git 작업 및 CPU 사용량부터 메모리 소비 및 네트워크 대역폭까지 전체 스택의 성능에 영향을 미칩니다.

| 시나리오                 | 구성 요소 조정 |
|:-------------------------|:----------------------|
| 여러 중규모 모노레포 | <ul><li>Gitaly: 1.5배-2배 사양</li><li>Rails: 1.25배-1.5배 사양</li></ul> |
| 대규모 모노레포          | <ul><li>Gitaly: 2배-4배 사양</li><li>Rails: 1.5배-2배 사양</li><li>모노레포 샤딩을 전용 Gitaly 노드로 고려합니다</li></ul> |

모노레포 환경에 대한 추가 최적화 전략은 [모노레포 성능 개선](../user/project/repository/monorepos/_index.md)에 설명되어 있으며, 이진 파일용 Git LFS 및 얕은 복제를 포함합니다.

### 네트워크 중심 워크로드 {#network-heavy-workloads}

네트워크 포화는 진단하기 어려운 고유한 문제를 야기합니다. 특정 작업에 영향을 미치는 CPU 또는 메모리 병목과 달리 네트워크 포화는 모든 GitLab 함수에서 겉보기에 무작위인 타임아웃을 야기할 수 있습니다.

일반적인 네트워크 부하 원본:

- 과도한 컨테이너 레지스트리 사용(대용량 이미지, 빈번한 풀).
- LFS 작업(이진 파일, 미디어 자산).
- 대규모 CI/CD 아티팩트(빌드 출력, 테스트 결과).
- 모노레포 클론(특히 CI/CD 파이프라인에서).

#### 네트워크 사용 측정 {#measure-network-usage}

피크 및 기준 네트워크 소비를 계산하여 잠재적 병목을 식별합니다. 둘 다 평가하여 때때로 스파이크(버스트 용량으로 처리)와 지속적인 높은 트래픽(네트워크 강화 VM 필요) 간의 차이를 구분합니다.

1. 다음 쿼리를 실행합니다:

   ```prometheus
   # Outbound traffic (Gbps) - top 10 nodes
   topk(10, sum by (instance) (rate(node_network_transmit_bytes_total{device!="lo"}[5m]) * 8 / 1000000000))


   # Inbound traffic (Gbps) - top 10 nodes
   topk(10, sum by (instance) (rate(node_network_receive_bytes_total{device!="lo"}[5m]) * 8 / 1000000000))

   ```

1. 모니터링 기간 동안 관찰된 피크 스파이크와 일반적인 기준을 모두 기록합니다:

   ```plaintext
   Peak outbound traffic: _____ Gbps (baseline: _____ Gbps)
   Peak inbound traffic: _____ Gbps (baseline: _____ Gbps)
   ```

#### 네트워크 용량 요구 사항 {#network-capacity-requirements}

아래 임계값은 근사값일 뿐입니다. 실제 네트워크 대역폭 보장은 클라우드 공급자 및 VM 유형에 따라 크게 다릅니다. 워크로드 패턴과 일치하도록 특정 인스턴스 유형에 대한 네트워크 사양(기준 및 버스트 한계)을 항상 확인합니다.

아웃바운드 및 인바운드 트래픽 측정을 기반으로:

| 네트워크 부하 | 임계값 | 이 임계값을 사용하는 이유                                                 | 필요한 조치 |
|:-------------|:----------|:-------------------------------------------------------------------|:----------------|
| 표준     | <1 Gbps   | 대부분의 표준 인스턴스의 기준 대역폭 범위 내               | 표준 인스턴스 충분 |
| 중간     | 1-3 Gbps  | AWS 기준을 초과할 수 있지만 GCP/Azure 표준 인스턴스 범위 내    | <ul><li>AWS: 조절을 모니터링하고 네트워크 강화가 필요할 수 있음</li><li>GCP/Azure: 표준 인스턴스 일반적으로 충분</li></ul> |
| 높음         | 3-10 Gbps | AWS 기준을 초과합니다. 일부 표준 인스턴스의 한계에 접근 | <ul><li>AWS: 네트워크 강화 VM 필요</li><li>GCP/Azure: 인스턴스 대역폭 사양 확인</li></ul> |
| 매우 높음    | >10 Gbps  | 대부분의 표준 인스턴스 기능을 초과합니다                        | <ul><li>모든 공급자에서 네트워크 강화 VM 필요</li><li>대규모 아티팩트의 경우 [객체 프록시 다운로드](../administration/object_storage.md#proxy-download) 비활성화</li></ul> |

### 진행하기 전에 {#before-you-proceed-2}

진행하기 전에 완전한 데이터 프로파일링 평가를 기록합니다:

```txt
Data Profile Summary:
- Medium monorepos (2GB-10GB): _____
- Large monorepos (>10GB): _____
- Gitaly adjustments needed: _____
- Rails adjustments needed: _____
- Peak outbound traffic: _____ Gbps (sustained baseline: _____ Gbps)
- Peak inbound traffic: _____ Gbps (sustained baseline: _____ Gbps)
- Network infrastructure changes: _____
```

## 현재 환경 분석 및 권장 사항 검증 {#analyze-current-environment-and-validate-recommendations}

기존 환경을 이해하는 것은 권장 사항에 중요한 컨텍스트를 제공합니다:

- 현재 환경이 성능 문제 없이 워크로드를 처리한다면 크기 조정 추정에 대한 귀중한 검증 역할을 합니다.
- 반대로 성능 문제가 있는 환경은 저크기 조정을 지속하기 위해 신중한 분석이 필요합니다.

### 현재 환경 문서화 {#document-the-current-environment}

현재 상태를 설정하기 위해 포괄적인 환경 데이터를 수집합니다:

- 아키텍처 세부 정보:
  - 유형: 고가용성(HA) 또는 비고가용성(비HA).
  - 배포 방법: Linux 패키지 또는 클라우드 네이티브 GitLab.
- 구성 요소 사양:
  - 각 구성 요소의 노드 개수 및 사양.
  - 사용자 지정 구성 또는 편차.

### 가장 가까운 참조 아키텍처 식별 {#identify-the-nearest-reference-architecture}

1. 현재 환경을 [사용 가능한 참조 아키텍처](../administration/reference_architectures/_index.md)와 비교합니다. 다음을 고려합니다:

   - 구성 요소당 총 컴퓨팅 리소스.
   - 노드 분포 및 아키텍처 패턴(HA 대 비HA).
   - 참조 아키텍처 크기를 기준으로 한 구성 요소 사양.

1. 결과를 기록합니다:

   ```plaintext
   Nearest Reference Architecture: _____
   Custom configurations or deviations:
   - _____
   - _____
   ```

### 현재 환경을 권장 아키텍처와 비교 {#compare-current-environment-to-recommended-architecture}

현재 환경을 이전 섹션에서 개발한 권장 참조 아키텍처와 비교합니다. 현재 환경이:

- 성능 문제가 없고 현재 리소스 < 권장 RA:
  - 권장 사항은 보수적이며 향후 헤드룸을 제공합니다.
  - 권장 RA로 진행합니다.
  - 구현 후 모니터링하여 잠재적인 최적화 기회를 확인합니다.
- 성능 문제가 없고 현재 리소스 ≈ 권장 RA:
  - 크기 조정 평가의 강력한 검증입니다.
  - 현재 환경이 권장 크기가 적절함을 확인합니다.
- 성능 문제가 없고 현재 리소스 > 권장 RA:
  - 현재 환경이 과도하게 프로비저닝되었거나 분석이 필요한 추가 리소스의 유효한 이유가 있을 수 있습니다. Rails, Gitaly, 데이터베이스 및 Sidekiq에서 CPU/메모리 [리소스 활용](../administration/monitoring/prometheus/_index.md#sample-prometheus-queries)을 확인합니다.

    낮은 이용률(<40%)은 과도한 프로비저닝을 시사합니다. 높은 이용률은 RPS 분석에서 캡처되지 않은 특정 워크로드 요구 사항을 나타낼 수 있습니다.
  - 발견되지 않은 요구 사항에 대해 권장 사항을 조정해야 하는지 검토합니다.

현재 환경에 성능 문제가 있는 경우:

- 현재 사양을 최소 기준선으로만 사용합니다. 이전 섹션의 권장 사항은 현재 사양을 초과해야 합니다.
- 권장 사항이 현재보다 현저히 낮은 경우 조사합니다:
  - 평가에서 캡처되지 않은 워크로드 패턴.
  - 대상 확장이 필요한 구성 요소별 병목 현상.

### 진행하기 전에 {#before-you-proceed-3}

이 섹션을 완료하면 현재 환경을 분석하고 권장 사항과 비교했습니다.

진행하기 전에 완전한 환경 비교를 기록합니다:

```plaintext
Current Environment Analysis:
- Current RA (nearest): _____
- Recommended RA (from RPS and workload analysis): _____
- Resource comparison: [ ] Current < Recommended [ ] Current ≈ Recommended [ ] Current > Recommended
- Performance status: [ ] No issues [ ] Has issues
- Adjustments needed: _____
- Notes: _____
```

다음 섹션에서 성장 예측을 평가하여 시간 경과에 따라 크기 조정이 적절하게 유지되도록 합니다.

## 향후 용량 계획 {#plan-for-future-capacity}

인프라 변경에는 조달, 마이그레이션 및 테스트에 상당한 시간이 필요합니다. 성장 추정은 권장 아키텍처가 구현 기간 및 그 이상으로 계속 실행 가능하도록 합니다.

과거 추세와 비즈니스 계획의 조합이 가장 정확한 성장 예측을 제공합니다.

### 역사적 성장 패턴 분석 {#analyze-historical-growth-patterns}

과거 성장 패턴은 비즈니스 예측보다 향후 궤적을 더 잘 예측할 수 있습니다:

1. [기준 크기](#determine-your-baseline-size)의 정보를 사용하여 현재 RPS를 6-12개월 전과 비교합니다.
1. 성장 가속화 또는 감속 추세를 식별합니다.

### 비즈니스 계획 요소 통합 {#incorporate-business-planning-factors}

인프라 요구 사항에 영향을 주는 예상되는 비즈니스 변경:

- 팀 확장 또는 통합.
- 새로운 프로젝트 개발.
- 기존 프로젝트의 개발 활동 증가.

이러한 요소(또는 기타 조직 변경)가 환경의 부하에 영향을 미칠 수 있고 인프라 조정이 필요한지 평가합니다. 관련 변경 사항 및 예상 시간 표를 문서화합니다.

#### 성장 버퍼 전략 결정 {#determine-growth-buffer-strategy}

역사적 추세 및 비즈니스 예측을 기반으로 적절한 성장 수용 전략을 선택합니다:

- 안정적 또는 최소 성장: 계속 모니터링합니다. 참조 아키텍처에는 내장된 헤드룸이 포함되어 있습니다.
- 적당한 성장: 예상 향후 RPS를 처리하기 위해 크기가 조정된 RA를 계획합니다.
- 상당한 성장이 예상됨: 현재 RPS가 아닌 예상 향후 RPS에 대해 크기 조정을 고려합니다.

### 진행하기 전에 {#before-you-proceed-4}

이 섹션을 완료하면 성장 예측이 크기 조정 결정에 통합됩니다.

완전한 성장 분석을 기록합니다:

```plaintext
Growth Assessment Summary:
- Historical RPS comparison: _____
- Business growth factors: _____
- Growth category: [ ] Stable/Minimal [ ] Moderate [ ] Significant
- Strategy: [ ] Current RA sufficient [ ] Size for projected growth
```

다음 섹션에서는 모든 결과를 최종 아키텍처 권장 사항으로 컴파일합니다.

## 결과 컴파일 {#compile-findings}

최적의 참조 아키텍처 및 필요한 조정을 결정하기 위해 모든 이전 섹션의 결과를 컴파일합니다.

### 최종 아키텍처 결정 {#determine-final-architecture}

크기 조정 결정을 형성하기 위해 각 섹션에서 주요 출력을 수집합니다:

1. [RPS 분석](#determine-your-baseline-size)에 따라 식별된 참조 아키텍처로 시작합니다.
1. [워크로드 패턴](#identify-component-adjustments) 및 [데이터 특성](#assess-special-infrastructure-requirements)을 기반으로 필요한 구성 요소 조정을 적용합니다. 패턴이 식별되지 않았거나 표준 구성이 충분한 경우 이 단계를 건너뜁니다.
1. [현재 상태](#analyze-current-environment-and-validate-recommendations)에 대해 검증합니다. 현재 환경이 잘 작동하지만 권장 사항을 초과하면 이유를 문서화합니다. 성능 문제가 있으면 권장 사항이 현재 사양을 초과하는지 확인합니다.
1. [향후 용량 계획의 성장](#plan-for-future-capacity)을 수용합니다. 현재 RA가 충분한지 또는 예상 성장에 대해 크기를 조정해야 하는지 결정합니다.

### 최종 권장 사항 문서화 {#document-final-recommendation}

포괄적인 평가를 기반으로 완전한 아키텍처 권장 사항을 기록합니다:

```plaintext
Final Architecture Recommendation
==================================

- Selected RA: [Size] based on [Absolute/Sustained] Peak RPS of [value]
- Component adjustments required:
  - [ ] No adjustments needed - standard RA configuration sufficient
  - [ ] Adjustments required:
      - Rails: _____
      - Sidekiq: _____
      - Database: _____
      - Gitaly: _____
      - Network considerations: □ Standard instances □ Network-optimized instances
- Selected RA is aligned with existing environment: [Yes/No/Not applicable]
- Growth accommodation: [Current RA sufficient / Sized up for growth]

Assessment Summary:
├── RPS Analysis
│   ├── Absolute Peak RPS: _____ → Baseline RA: _____
│   └── Sustained Peak RPS: _____ → Sustained RA: _____
├── Workload Type
│   └── Type: [ ] Database-Intensive [ ] Sidekiq-Intensive [ ] None
├── Data Profile
│   ├── Large repos (>2GB): _____ | Monorepos (>10GB): _____
│   └── Network: Peak _____ Gbps | Baseline _____ Gbps
├── Current State
│   ├── Nearest RA: _____
|   └── Discrepancies and customizations: _____
└── Growth
    ├── Growth projection: _____
    └── Growth buffer strategy: _____
```

모든 섹션을 완료하면 크기 조정 평가가 완료됩니다. 최종 권장 사항은 다음을 포함합니다:

- 기본 참조 아키텍처 크기.
- 구성 요소별 조정
- 성장 수용 전략.

정기적인 모니터링은 가정을 검증하고 워크로드 패턴이 진화함에 따라 인프라를 조정하는 데 필수적입니다.
