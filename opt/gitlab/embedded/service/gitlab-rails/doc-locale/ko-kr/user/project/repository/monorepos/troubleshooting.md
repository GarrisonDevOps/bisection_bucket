---
stage: Tenant Scale
group: Gitaly
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 모노레포 성능 문제 해결
---

모노레포의 성능 문제에 대한 다음 제안을 검토하세요.

## `git clone` 또는 `git fetch` 중 성능 저하 {#slowness-during-git-clone-or-git-fetch}

클론 및 페치 중 성능 저하의 몇 가지 주요 원인이 있습니다.

### 높은 CPU 사용률 {#high-cpu-utilization}

Gitaly 노드의 CPU 사용률이 높으면 [특정 값을 필터링하여](observability.md#cpu-and-memory) 클론으로 인한 CPU 사용량을 확인할 수도 있습니다.

특히 `command.cpu_time_ms` 필드는 클론 및 페치로 인한 CPU 사용량을 나타낼 수 있습니다.

대부분의 경우 서버 부하는 클론 및 페치 중에 시작되는 `git-pack-objects` 프로세스에서 생성됩니다. 모노레포는 종종 매우 바쁘고 CI/CD 시스템은 많은 클론 및 페치 명령을 서버로 보냅니다.

높은 CPU 사용률은 성능 저하의 일반적인 원인입니다. 다음과 같은 상호 배타적이지 않은 원인이 가능합니다:

- [Gitaly가 처리할 수 있는 것보다 너무 많은 클론](#cause-too-many-large-clones).
- [Gitaly Cluster (Praefect)의 열악한 읽기 분산](#cause-poor-read-distribution).

#### 원인: 너무 많은 대규모 클론 {#cause-too-many-large-clones}

Gitaly가 처리할 수 있는 것보다 너무 많은 대규모 클론이 있을 수 있습니다. Gitaly는 여러 가지 요인으로 인해 따라가기 어려울 수 있습니다:

- 리포지토리의 크기.
- 클론 및 페치의 양.
- CPU 용량 부족.

Gitaly가 많은 대규모 클론을 처리하도록 돕기 위해 다음과 같은 최적화 전략을 통해 Gitaly 서버의 부담을 줄여야 할 수도 있습니다:

- [pack-objects-cache](../../../../administration/gitaly/configure_gitaly.md#pack-objects-cache)를 켜서 `git-pack-objects`가 수행해야 할 작업을 줄입니다.
- CI/CD 설정에서 [Git 전략](_index.md#use-git-fetch-in-cicd-operations)을 `clone`에서 `fetch` 또는 `none`로 변경합니다.
- [태그 페칭 중지](_index.md#change-git-fetch-behavior-with-flags)(테스트에 필요한 경우 제외).
- [얕은 클론 사용](_index.md#use-shallow-clones-and-filters-in-cicd-processes)(가능한 한).

다른 방법은 Gitaly 서버의 CPU 용량을 늘리는 것입니다.

#### 원인: 열악한 읽기 분산 {#cause-poor-read-distribution}

Gitaly Cluster (Praefect)에 읽기 분산이 불량할 수 있습니다.

대부분의 읽기 트래픽이 클러스터 전체에 분산되지 않고 기본 Gitaly 노드로 전송되는지 확인하려면 [읽기 분산 Prometheus 메트릭](observability.md#read-distribution)을 사용합니다.

보조 Gitaly 노드가 많은 트래픽을 수신하지 못하는 경우 보조 노드가 항상 동기화되지 않은 상태일 수 있습니다. 이 문제는 모노레포에서 악화됩니다.

모노레포는 종종 크고 바쁩니다. 이로 인해 두 가지 효과가 발생합니다. 첫째, 모노레포는 자주 푸시되고 많은 CI 작업이 실행됩니다. 브랜치 삭제와 같은 쓰기 작업이 보조 노드에 대한 프록시 호출에 실패할 수 있는 경우가 있습니다. 이는 Gitaly Cluster (Praefect)의 복제 작업을 트리거하므로 보조 노드가 결국 따라갑니다.

복제 작업은 기본적으로 보조 노드에서 기본 노드로의 `git fetch`이며, 모노레포는 종종 매우 크므로 이 페치에는 오래 걸릴 수 있습니다.

다음 호출이 이전 복제 작업이 완료되기 전에 실패하고 이 상황이 계속 발생하면 모노레포가 보조 노드에서 계속 지연된 상태가 될 수 있습니다. 이로 인해 모든 트래픽이 기본 노드로 전송됩니다.

이러한 실패한 프록시 쓰기의 한 가지 이유는 Git `$GIT_DIR/packed-refs` 파일의 알려진 문제입니다. 파일을 잠금하여 파일의 항목을 제거해야 하며, 이는 동시 삭제가 발생할 때 삭제가 실패하도록 하는 경합 조건으로 이어질 수 있습니다.

GitLab의 엔지니어는 참조 삭제를 일괄 처리하려고 시도하는 완화 방법을 개발했습니다.

다음 [기능 플래그](../../../../administration/feature_flags/_index.md)를 켜서 GitLab이 ref 삭제를 일괄 처리하도록 합니다. 이 기능 플래그는 활성화하기 위해 가동 중단 시간이 필요하지 않습니다.

- `merge_request_cleanup_ref_worker_async`
- `pipeline_cleanup_ref_worker_async`
- `pipeline_delete_gitaly_refs_in_batches`
- `merge_request_delete_gitaly_refs_in_batches`

[에픽 4220](https://gitlab.com/groups/gitlab-org/-/epics/4220)은 GitLab에 RefTable 지원을 추가할 것을 제안하며, 이는 장기적 솔루션으로 간주됩니다.
