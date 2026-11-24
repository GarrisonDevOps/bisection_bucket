---
stage: Verify
group: CI Platform
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 러너 플릿.
title: Google Kubernetes Engine에서 GitLab Runner 플릿 설계 및 구성
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

이 권장 사항을 사용하여 CI/CD 빌드 요구 사항을 분석하고 Google Kubernetes Engine(GKE)에서 호스팅되는 GitLab Runner 플릿을 설계, 구성 및 검증합니다.

다음 다이어그램은 러너 플릿 구현 여정의 경로를 보여줍니다. 이 가이드는 다음 단계를 따릅니다:

![러너 플릿 단계 다이어그램](img/runner_fleet_steps_diagram_v17_5.png)

이 프레임워크를 사용하여 단일 그룹 또는 전체 조직에 서비스를 제공하는 GitLab 인스턴스를 위한 러너 배포를 계획할 수 있습니다.

이 프레임워크에는 다음 단계가 포함됩니다:

1. [예상 CI/CD 워크로드 평가](#assess-the-expected-cicd-workloads)
1. [러너 플릿 구성 계획](#plan-the-runner-fleet-configuration)
1. [GKE에 러너 배포](#deploy-the-runner-on-gke)
1. [최적화](#optimize)

## 예상 CI/CD 워크로드 평가 {#assess-the-expected-cicd-workloads}

이 단계에서는 지원하는 개발 팀의 CI/CD 빌드 요구 사항을 수집합니다. 해당하는 경우 사용 중인 프로그래밍, 스크립팅 및 마크업 언어의 인벤토리를 작성합니다.

여러 개발 팀, 다양한 프로그래밍 언어 및 빌드 요구 사항을 지원할 수 있습니다. 심층 분석을 위해 하나의 팀, 하나의 프로젝트 및 하나의 CI/CD 빌드 요구 사항 세트로 시작합니다.

예상 CI/CD 워크로드를 평가하려면:

- 지원해야 할 CI/CD 작업 수요를 추정합니다(시간 단위, 일 단위, 주 단위).
- 특정 프로젝트에 대해 대표적인 CI/CD 작업 샘플의 CPU 및 RAM 리소스 요구 사항을 추정합니다. 이 추정값은 지원할 수 있는 다양한 프로필을 식별하는 데 도움이 됩니다. 이러한 프로필의 특성은 요구 사항을 지원하는 데 필요한 올바른 GKE 클러스터를 식별하는 데 중요합니다. CPU 및 RAM 요구 사항을 확인하는 방법에 대한 이 예제를 참조하세요.
- 특정 러너에 대한 액세스를 그룹 또는 프로젝트별로 분리해야 하는 보안 또는 정책 요구 사항이 있는지 확인합니다.

### CI/CD 작업의 CPU 및 RAM 요구 사항 추정 {#estimate-the-cpu-and-ram-requirements-for-a-cicd-job}

CPU 및 RAM 리소스 요구 사항은 프로그래밍 언어의 유형 또는 CI/CD 작업의 유형(빌드, 통합 테스트, 단위 테스트, 보안 스캔)과 같은 요소에 따라 달라집니다. 다음 섹션은 CI/CD 작업 CPU 및 리소스 요구 사항을 수집하는 방법을 설명합니다. 이 방법을 채택하고 자신의 필요에 맞게 확장할 수 있습니다.

예를 들어, FastAPI 프로젝트 포크에 정의된 것과 유사한 CI/CD 작업을 실행하려면: [`ra-group/fastapi`](https://gitlab.com/ra-group2/fastapi). 이 예제의 작업은 Python 이미지를 사용하고, 프로젝트의 요구 사항을 다운로드하며, 기존 단위 테스트를 실행합니다. 작업의 `.gitlab-ci.yml`은 다음과 같습니다:

```yaml
tests:
  image: python:3.11.10-bookworm
  parallel: 25
  script:
  - pip install -r requirements.txt
  - pytest
```

필요한 컴퓨팅 및 RAM 리소스를 식별하려면 Docker를 사용합니다:

- FastAPI 포크를 사용하고 CI/CD 작업 스크립트를 진입점으로 사용하는 특정 이미지를 만듭니다.
- 빌드된 이미지를 사용하는 컨테이너를 실행하고 리소스 사용량을 모니터링합니다.

필요한 컴퓨팅 및 RAM 리소스를 식별하려면 다음 단계를 완료합니다:

1. 모든 CI 명령을 포함하는 프로젝트에 스크립트 파일을 만듭니다. 스크립트 파일의 이름은 `entrypoint.sh`입니다.

   ```shell
   #!/bin/bash
   cd /fastapi || exit
   pip install -r requirements.txt
   pytest
   ```

1. `entrypoint.sh` 파일이 CI 스크립트를 실행하는 이미지를 만드는 Dockerfile을 만듭니다.

   ```dockerfile
   FROM python:3.11.10-bookworm
   RUN mkdir /fastapi
   COPY . /fastapi
   RUN chmod +x /fastapi/entrypoint.sh
   CMD [ "bash", "/fastapi/entrypoint.sh" ]
   ```

1. 이미지를 빌드합니다. 프로세스를 간단히 하려면 빌드, 저장 및 이미지 실행과 같은 모든 작업을 로컬에서 수행합니다. 이 방법은 이미지를 가져오고 푸시하기 위해 온라인 레지스트리가 필요하지 않습니다.

   ```shell
   ❯ docker build . -t my-project_dir/fastapi:testing
   ...
   Successfully tagged my-project_dir/fastapi:testing
   ```

1. 빌드된 이미지를 사용하는 컨테이너를 실행하고 컨테이너 실행 중에 리소스 사용량을 동시에 모니터링합니다. `metrics.sh` 이름의 스크립트를 다음 명령으로 만듭니다:

   ```shell
   #! /bin/bash

   container_id=$(docker run -d --rm my-project_dir/fastapi:testing)

   while true; do
       echo "Collecting metrics..."
       metrics=$(docker stats --no-trunc --no-stream --format "table {{.ID}}\t{{.CPUPerc}}\t{{.MemUsage}}" | grep "$container_id")
       if [ -z "$metrics" ]; then
           exit 0
       fi
       echo "Saving metrics..."
       echo "$metrics" >> metrics.log
       sleep 1
   done
   ```

   이 스크립트는 빌드된 이미지를 사용하는 분리된 컨테이너를 실행합니다. 그러면 컨테이너 ID를 사용하여 성공적으로 완료될 때까지 `CPU` 및 `Memory` 사용량을 수집합니다. 수집된 메트릭은 `metrics.log`이라는 파일에 저장됩니다.

   > [!note]
   > 이 예제에서 CI/CD 작업은 단기간만 실행되므로 각 컨테이너 폴링 간의 절전 시간은 1초로 설정됩니다. 이 값을 조정하여 필요에 더 잘 맞게 합니다.
1. `metrics.log` 파일을 분석하여 테스트 컨테이너의 피크 사용량을 식별합니다.

   이 예제에서 최대 CPU 사용량은 `107.50%`이고 최대 메모리 사용량은 `303.1Mi`입니다.

   ```log
   223e93dd05c6   94.98%    83.79MiB / 15.58GiB
   223e93dd05c6   28.27%    85.4MiB / 15.58GiB
   223e93dd05c6   53.92%    121.8MiB / 15.58GiB
   223e93dd05c6   70.73%    171.9MiB / 15.58GiB
   223e93dd05c6   20.78%    177.2MiB / 15.58GiB
   223e93dd05c6   26.19%    180.3MiB / 15.58GiB
   223e93dd05c6   77.04%    224.1MiB / 15.58GiB
   223e93dd05c6   97.16%    226.5MiB / 15.58GiB
   223e93dd05c6   98.52%    259MiB / 15.58GiB
   223e93dd05c6   98.78%    303.1MiB / 15.58GiB
   223e93dd05c6   100.03%   159.8MiB / 15.58GiB
   223e93dd05c6   103.97%   204MiB / 15.58GiB
   223e93dd05c6   107.50%   207.8MiB / 15.58GiB
   223e93dd05c6   105.96%   215.7MiB / 15.58GiB
   223e93dd05c6   101.88%   226.2MiB / 15.58GiB
   223e93dd05c6   100.44%   226.7MiB / 15.58GiB
   223e93dd05c6   100.20%   226.9MiB / 15.58GiB
   223e93dd05c6   100.60%   227.6MiB / 15.58GiB
   223e93dd05c6   100.46%   228MiB / 15.58GiB
   ```

### 수집된 메트릭 분석 {#analyzing-the-metrics-collected}

수집된 메트릭을 기반으로 이 작업 프로필의 경우 Kubernetes 실행기 작업을 `1 CPU` 및 `~304 Mi of Memory`로 제한할 수 있습니다. 이 결론이 정확하더라도 모든 사용 사례에 실용적이지 않을 수 있습니다.

`e2-standard-4` 노드의 노드 풀을 가진 클러스터를 사용하여 작업을 실행하면 `1 CPU` 제한으로 인해 12개의 작업만 동시에 실행할 수 있습니다(`e2-standard-4` 노드는 4 vCPU 및 16 GB 메모리를 갖습니다). 추가 작업은 실행 중인 작업이 완료되고 리소스를 해제할 때까지 기다립니다.

메모리가 중요한 이유는 Kubernetes가 클러스터에서 설정된 제한값보다 많은 메모리를 사용하는 모든 포드를 종료하기 때문입니다. 그러나 CPU 제한은 더 유연하지만 작업 기간에 영향을 줍니다. 더 낮은 CPU 제한을 설정하면 작업 완료에 걸리는 시간이 증가합니다. 이전 예제에서 CPU 제한을 `250m`(또는 `0.25`)로 설정하면 `1` 대신 작업 기간이 4배 증가합니다(약 2분에서 8~10분).

메트릭 수집 방법이 폴링 메커니즘을 사용하므로 식별된 최대 사용량을 올림합니다. 예를 들어 메모리 사용량을 `303 Mi` 대신 `400 Mi`로 올림합니다.

이전 예제에 대한 중요한 고려 사항:

- 메트릭은 Google Kubernetes Engine 클러스터와 같은 CPU 구성을 갖지 않는 로컬 머신에서 수집되었습니다. 그러나 이 메트릭은 `e2-standard-4` 노드를 사용하는 Kubernetes 클러스터에서 모니터링하여 검증되었습니다.
- 이러한 메트릭을 정확하게 나타내려면 Google Compute Engine VM에서 [평가 단계](#assess-the-expected-cicd-workloads)에 설명된 테스트를 실행합니다.

## 러너 플릿 구성 계획 {#plan-the-runner-fleet-configuration}

계획 단계에서 조직에 맞는 올바른 러너 플릿 구성을 매핑합니다. 러너 범위(인스턴스, 그룹, 프로젝트) 및 Kubernetes 클러스터 구성을 다음을 기반으로 고려합니다:

- CI/CD 작업 리소스 수요에 대한 평가
- CI/CD 작업 유형의 인벤토리

### 러너 범위 {#runner-scope}

러너 범위를 계획하려면 다음 질문을 고려합니다:

- 프로젝트 소유자 및 그룹 소유자가 자신의 러너를 만들고 관리하도록 하시겠습니까?

  - 기본적으로 프로젝트 및 그룹 소유자는 GitLab에서 러너 구성을 만들고 프로젝트 또는 그룹에 러너를 등록할 수 있습니다.
  - 이 설계를 통해 개발자는 빌드 환경을 빠르게 만들 수 있습니다. 이 방법은 GitLab CI/CD를 시작할 때 개발자 마찰을 줄입니다. 그러나 대규모 조직에서는 이 방법으로 인해 환경 전체에 활용도가 낮거나 사용되지 않는 많은 러너가 발생할 수 있습니다.
- 특정 유형의 러너에 대한 액세스를 특정 그룹 또는 프로젝트로 분리해야 하는 보안 또는 기타 정책이 조직에 있습니까?

GitLab Self-Managed 환경에서 러너를 배포하는 가장 직선적인 방법은 인스턴스를 위해 생성하는 것입니다. 인스턴스 범위의 러너는 기본적으로 모든 그룹 및 프로젝트에서 사용 가능합니다.

인스턴스 러너로 조직의 모든 요구 사항을 충족할 수 있다면 이 배포 패턴이 가장 효율적인 패턴입니다. 이를 통해 규모에 따라 CI/CD 빌드 플릿을 효율적이고 비용 효과적으로 운영할 수 있습니다.

특정 러너에 대한 액세스를 특정 그룹 또는 프로젝트로 분리하기 위한 요구 사항이 있으면 이를 계획 프로세스에 통합합니다.

#### 러너 플릿 구성 예제 - 인스턴스 러너 {#example-runner-fleet-configuration---instance-runners}

표의 구성은 조직을 위한 러너 플릿을 구성할 때 사용 가능한 유연성을 보여줍니다. 이 예제에서는 다양한 인스턴스 크기와 다양한 작업 태그를 가진 여러 러너를 사용합니다. 이러한 러너를 통해 각각 특정 CPU 및 RAM 리소스 요구 사항을 가진 다양한 유형의 CI/CD 작업을 지원할 수 있습니다. 그러나 Kubernetes를 사용할 때는 가장 효율적인 패턴이 아닐 수 있습니다.

| 러너 유형 | 러너 태그       | 범위                                                               | 제공할 러너 유형의 수 | 러너 워커 사양 | 러너 호스트 환경 | 환경 구성 |
|:------------|:-----------------|:--------------------------------------------------------------------|:------------------------------|:----------------------------|:------------------------|:--------------------------|
| 인스턴스    | ci-runner-small  | 기본적으로 모든 그룹 및 프로젝트에 대해 CI/CD 작업을 실행하는 데 사용할 수 있습니다. | 5                             | 2 vCPU, 8 GB RAM            | Kubernetes              | → 3개 노드 <br> → 러너 워커 컴퓨팅 노드 = `e2-standard-2` |
| 인스턴스    | ci-runner-medium | 기본적으로 모든 그룹 및 프로젝트에 대해 CI/CD 작업을 실행하는 데 사용할 수 있습니다. | 2                             | 4 vCPU, 16 GB RAM           | Kubernetes              | → 3개 노드 <br> → 러너 워커 컴퓨팅 노드 = `e2-standard-4` |
| 인스턴스    | ci-runner-large  | 기본적으로 모든 그룹 및 프로젝트에 대해 CI/CD 작업을 실행하는 데 사용할 수 있습니다. | 1                             | 8 vCPU, 32 GB RAM           | Kubernetes              | → 3개 노드 <br> → 러너 워커 컴퓨팅 노드 = `e2-standard-8` |

러너 플릿 구성 예제에는 총 3개의 러너 구성과 8개의 CI/CD 작업을 적극적으로 실행 중인 러너가 있습니다.

Kubernetes 실행기를 사용하면 Kubernetes 스케줄러를 사용하고 컨테이너 리소스를 덮어쓸 수 있습니다. 이론적으로 적절한 리소스를 가진 Kubernetes 클러스터에 단일 GitLab Runner를 배포할 수 있습니다. 그러면 컨테이너 리소스를 덮어써서 각 CI/CD 작업에 맞는 적절한 컴퓨팅 유형을 선택할 수 있습니다. 이 패턴을 구현하면 배포하고 운영해야 할 별도의 러너 구성 수를 줄입니다.

### 모범 사례 {#best-practices}

- 항상 러너 관리자에게 노드 풀을 전담합니다.
  - 로그 처리 및 캐시 또는 아티팩트 관리는 CPU를 많이 사용할 수 있습니다.
- 항상 `config.toml` 파일에서 기본 제한(Build/Helper/Service 컨테이너에 대한 CPU/메모리)을 설정합니다.
- 항상 `config.toml` 파일의 리소스에 대한 최대 덮어쓰기를 허용합니다.
- 작업 정의(`.gitlab-ci.yml`)에서 작업에 필요한 올바른 제한을 지정합니다.
  - 지정하지 않으면 `config.toml` 파일에 설정된 기본값이 사용됩니다.
  - 컨테이너가 메모리 제한을 초과하면 시스템은 OOM(Out of Memory) 킬 프로세스를 사용하여 자동으로 종료합니다.
- 기능 플래그 `FF_PRINT_POD_EVENTS` 및 구성 `print_pod_warning_events`을 사용합니다. 자세한 내용은 [기능 플래그 설명서](https://docs.gitlab.com/runner/configuration/feature-flags/) 및 [러너 API 권한 구성 설명서](https://docs.gitlab.com/runner/executors/kubernetes/#configure-runner-api-permissions)를 참조하세요.

## GKE에 러너 배포 {#deploy-the-runner-on-gke}

Google Kubernetes 클러스터에 GitLab Runner를 설치할 준비가 되면 여러 옵션이 있습니다. GKE에서 클러스터를 만들었으면 GitLab Runner Helm Chart 또는 Operator를 사용하여 클러스터에 러너를 설치할 수 있습니다.

GKE에서 아직 클러스터를 설정하지 않았으면 GitLab은 동시에 다음을 수행하는 GitLab Runner Infrastructure Toolkit(GRIT)을 제공합니다:

- 다중 노드 풀 GKE 클러스터를 만듭니다: 표준 에디션 및 표준 모드.
- GitLab Runner Kubernetes 연산자를 사용하여 클러스터에 GitLab Runner를 설치합니다.

다음 예제에서는 GRIT를 사용하여 Google Kubernetes 클러스터 및 GitLab Runner Manager를 배포합니다.

클러스터와 GitLab Runner를 잘 구성하려면 다음 정보를 고려합니다:

- 몇 개의 작업 유형을 처리해야 합니까?
  - 이 정보는 평가 단계에서 제공됩니다. 평가 단계는 메트릭을 집계하고 조직적 제약을 고려하여 결과 그룹의 수를 식별합니다. "작업 유형"은 평가 단계에서 식별된 분류된 작업의 모음입니다. 이 분류는 작업에 필요한 최대 리소스를 기반으로 합니다.
- 몇 개의 GitLab Runner Manager를 실행해야 합니까?
  - 이 정보는 계획 단계에서 제공됩니다. 조직에서 프로젝트를 별도로 관리하면 이 프레임워크를 각 프로젝트에 개별적으로 적용합니다. 이 방법은 여러 작업 프로필이 식별되고(전체 조직 또는 특정 프로젝트의 경우) 모두 개인 또는 GitLab Runner 플릿으로 처리되는 경우에만 관련이 있습니다. 기본 구성은 일반적으로 GKE 클러스터당 1개의 GitLab Runner Manager를 사용합니다.
- 예상되는 최대 동시 CI/CD 작업은 몇 개입니까?
  - 이 정보는 언제든지 실행되는 최대 동시 CI/CD 작업 수를 추정한 것입니다. 이 정보는 GitLab Runner Manager를 구성할 때 필요하며, `Prepare` 단계에서 대기하는 기간을 제공합니다: 리소스를 사용할 수 있는 제한이 있는 노드에 작업 포드를 스케줄링합니다.

### FastAPI 포크의 실제 응용 {#real-life-applications-for-the-fastapi-fork}

FastAPI 포크의 경우 다음 정보를 고려합니다:

- 몇 개의 작업 프로필을 처리해야 합니까?
  - 다음 특성을 가진 1개의 작업 프로필이 있습니다: `1 CPU` 및 `303 Mi` 메모리. [수집된 메트릭 분석](#analyzing-the-metrics-collected) 섹션에서 설명한 것처럼 이 원본 값은 다음과 같이 변경됩니다:
    - 메모리 제한에 대한 `400 Mi` (메모리 제한으로 인한 작업 실패를 방지하기 위해 `303 Mi` 대신).
    - CPU의 경우 `0.20` (`1 CPU` 대신). 이 예제에서는 작업을 완료할 때 속도보다 정확성과 품질을 우선시합니다.
- 몇 개의 GitLab Runner Manager를 실행해야 합니까?
  - 테스트에는 1개의 GitLab Runner Manager만으로 충분합니다.
- 예상되는 워크로드는 무엇입니까?
  - 언제든지 최대 20개의 작업을 동시에 실행하려고 합니다.

이러한 입력을 기반으로 다음 최소 특성을 가진 GKE 클러스터이면 충분합니다:

- 최소 CPU: `(0.20 + helper CPU usage) * number of jobs simultaneously`. 이 예제에서 헬퍼 컨테이너 제한이 `0.15 CPU`로 설정되면 `7 vCPU`을 얻습니다.
- 최소 메모리: `(400Mi + helper memory usage) * number of jobs simultaneously`. 이 예제에서 헬퍼 제한이 `100 Mi`로 설정되면 최소 `10 Gi`을 얻습니다.

필요한 최소 스토리지와 같은 기타 특성도 고려해야 합니다. 그러나 이 예제에서는 이를 고려하지 않습니다.

GKE 클러스터의 가능한 구성은 다음과 같습니다(두 구성 모두 20개 이상의 작업을 동시에 실행할 수 있음):

- `3 e2-standard-4` 노드의 노드 풀을 가진 GKE 클러스터 (총 `12 vCPU` 및 `48 GiB` 메모리)
- `e2-standard-8` 노드의 노드 풀을 가진 GKE 클러스터 (총 `8 vCPU` 및 `32 GiB` 메모리)

이 예제에서는 첫 번째 구성을 사용합니다. GitLab Runner Manager 로그 처리가 전체 로그 처리에 영향을 주지 않도록 GitLab Runner가 설치된 전용 노드 풀을 사용합니다.

#### GKE GRIT 구성 {#gke-grit-configuration}

GRIT의 결과 GKE 구성은 다음과 같습니다:

```terraform
google_project     = "GCLOUD_PROJECT"
google_region      = "GCLOUD_REGION"
google_zone        = "GCLOUD_ZONE"
name               = "my-grit-gke-cluster"
node_pools = {
  "runner-manager" = {
    node_count = 1,
    node_config = {
      machine_type = "e2-standard-2",
      image_type   = "cos_containerd",   #Linux OS container only. Change to windows_ltsc_containerd for Windows OS container
      disk_size_gb = 50,
      disk_type    = "pd-balanced",
      labels = {
        "app" = "gitlab-runner",
      }
    },
  },
  "worker-pool" = {
    node_count = 3,
    node_config = {
      machine_type = "e2-standard-4",    #4 vCPU, 16 GB each
      image_type   = "cos_containerd",   #Linux OS container only. Change to windows_ltsc_containerd for Windows OS container
      disk_size_gb = 150,
      disk_type    = "pd-balanced",
      labels = {
        "app" = "gitlab-runner-job"
      }
    },
  },
}
```

이전 구성에서:

- `runner-manager` 블록은 GitLab Runner가 설치된 노드 풀을 나타냅니다. 우리 예제에서는 `e2-standard-2`이면 충분합니다.
- `runner-manager` 블록의 레이블 섹션은 GitLab에서 GitLab Runner를 설치할 때 유용합니다. 노드 선택기는 연산자 구성을 통해 구성되어 GitLab Runner가 이 노드 풀의 노드에 설치되는지 확인합니다.
- `worker-pool` 블록은 CI/CD 작업 포드가 만들어지는 노드 풀을 나타냅니다. 제공된 구성은 `3 e2-standard-4` 노드의 노드 풀을 만들고 작업 포드를 호스팅하기 위해 `"app" = "gitlab-runner-job"`로 표시합니다.
- `image_type` 매개 변수를 사용하여 노드에서 사용하는 이미지를 설정할 수 있습니다. 워크로드가 주로 Windows 이미지에 의존하는 경우 `windows_ltsc_containerd`로 설정할 수 있습니다.

다음은 이 구성의 그림입니다:

![클러스터 구성의 그림](img/nodepool_illustration_example_v17_5.png)

#### GitLab Runner GRIT 구성 {#gitlab-runner-grit-configuration}

GRIT의 결과 GitLab Runner 구성은 다음과 같습니다:

```terraform
gitlab_pat         = "glpat-REDACTED"
gitlab_project_id  = GITLAB_PROJECT_ID
runner_description = "my-grit-gitlab-runner"
runner_image       = "registry.gitlab.com/gitlab-org/ci-cd/gitlab-runner-ubi-images/gitlab-runner-ocp:amd64-v17.3.1"
helper_image       = "registry.gitlab.com/gitlab-org/ci-cd/gitlab-runner-ubi-images/gitlab-runner-helper-ocp:x86_64-v17.3.1"
concurrent     = 20
check_interval = 1
runner_tags    = ["my-custom-tag"]
config_template    = <<EOT
[[runners]]
  name = "my-grit-gitlab-runner"
  shell = "bash"
  environment = [
    "FF_PRINT_POD_EVENTS=true",
  ]
  [runners.kubernetes]
    image = "alpine"
    cpu_limit = "0.25"
    memory_limit = "400Mi"
    helper_cpu = "150m"
    helper_memory = "150Mi"
    cpu_limit_overwrite_max_allowed = "0.25"
    memory_limit_overwrite_max_allowed = "400Mi"
    helper_cpu_limit_overwrite_max_allowed = "150m"
    helper_memory_limit_overwrite_max_allowed = "150Mi"
    print_pod_warning_events = true
  [runners.kubernetes.node_selector]
    "app" = "gitlab-runner-job"
EOT
pod_spec = [
  {
    name      = "selector",
    patchType = "merge",
    patch     = <<EOT
nodeSelector:
  app: "gitlab-runner"
EOT
  }
]
```

이전 구성에서:

- `pod_spec` 매개 변수를 통해 GitLab Runner를 실행하는 포드의 노드 선택기를 설정할 수 있습니다. 구성에서 노드 선택기는 `"app" = "gitlab-runner"`로 설정되어 GitLab Runner가 runner-manager 노드 풀에 설치되는지 확인합니다.
- `config_template` 매개 변수는 GitLab Runner Manager에서 실행하는 모든 작업에 대한 기본 제한을 제공합니다. 또한 설정된 값이 기본값보다 크지 않은 한 이 제한을 덮어쓸 수 있습니다.
- 기능 플래그 `FF_PRINT_POD_EVENTS` 및 구성 `print_pod_warning_events`은 또한 작업 실패 시 디버깅을 용이하게 하기 위해 설정됩니다. 자세한 내용은 [기능 플래그 설명서](https://docs.gitlab.com/runner/configuration/feature-flags/) 및 [러너 API 권한 구성 설명서](https://docs.gitlab.com/runner/executors/kubernetes/#configure-runner-api-permissions)를 참조하세요.

### 가상 사용 사례에 대한 실제 응용 {#real-life-applications-for-a-hypothetical-use-case}

다음 정보를 고려합니다:

- 몇 개의 작업 프로필을 처리해야 합니까?
  - 2개의 프로필(제공된 사양은 헬퍼 제한을 고려합니다):
    - 중간 작업: `300m CPU` 및 `200 MiB`
    - CPU 집약적 작업: `1 CPU` 및 `1 GiB`
- 몇 개의 GitLab Runner Manager를 실행해야 합니까?
  - 1개.
- 예상되는 워크로드는 무엇입니까?
  - 최대 50개의 중간 작업을 동시에
  - 최대 25개의 CPU 집약적 작업을 동시에

#### GKE 구성 {#gke-configuration}

- 중간 작업 필요:
  - CPU: `300m * 50 = 5 CPU` (대략)
  - 메모리: `200 MiB * 50 = 10 GiB`
- CPU 집약적 작업 필요:
  - CPU: `1 * 25 = 25`
  - 메모리: `1 GiB * 25 = 25 GiB`

GKE 클러스터는 다음을 가져야 합니다:

- GitLab Runner Manager의 노드 풀(로그 처리가 요구되지 않는다고 가정): `1 e2-standard-2` 노드
- 중간 작업을 위한 노드 풀: 3개의 `e2-standard-4` 노드
- CPU 집약적 작업을 위한 노드 풀: 1개의 `e2-highcpu-32` 노드(`32 vCPU` 및 `32 GiB` 메모리)

```terraform
google_project     = "GCLOUD_PROJECT"
google_region      = "GCLOUD_REGION"
google_zone        = "GCLOUD_ZONE"
name               = "my-grit-gke-cluster"
node_pools = {
  "runner-manager" = {
    node_count = 1,
    node_config = {
      machine_type = "e2-standard-2",
      image_type   = "cos_containerd",   #Linux OS container only. Change to windows_ltsc_containerd for Windows OS container
      disk_size_gb = 50,
      disk_type    = "pd-balanced",
      labels = {
        "app" = "gitlab-runner",
      }
    },
  },
  "medium-pool" = {
    node_count = 3,
    node_config = {
      machine_type = "e2-standard-4",    #4 vCPU, 16 GB each
      image_type   = "cos_containerd",   #Linux OS container only. Change to windows_ltsc_containerd for Windows OS container
      disk_size_gb = 150,
      disk_type    = "pd-balanced",
      labels = {
        "app" = "gitlab-runner-job"
      }
    },
  },
  "cpu-intensive-pool" = {
    node_count = 1,
    node_config = {
      machine_type = "e2-highcpu-32", #32 vCPU, 32 GB each
      image_type   = "cos_containerd",
      disk_size_gb = 150,
      disk_type    = "pd-balanced",
      labels = {
        "app" = "gitlab-runner-job"
      }
    },
  },
}
```

#### GitLab Runner 구성 {#gitlab-runner-configuration}

GRIT의 현재 구현은 한 번에 둘 이상의 러너 설치를 허용하지 않습니다. 제공된 `config_template`은 이전 예제에서와 같이 `node_selection` 및 기타 제한을 설정하지 않습니다. 간단한 구성을 통해 CPU 집약적 작업에 대한 최대 허용 덮어쓰기 값을 허용하고 `.gitlab-ci.yml` 파일에서 올바른 값을 설정합니다. 결과 GitLab Runner 구성은 다음과 같습니다:

```terraform
gitlab_pat         = "glpat-REDACTED"
gitlab_project_id  = GITLAB_PROJECT_ID
runner_description = "my-grit-gitlab-runner"
runner_image       = "registry.gitlab.com/gitlab-org/ci-cd/gitlab-runner-ubi-images/gitlab-runner-ocp:amd64-v17.3.1"
helper_image       = "registry.gitlab.com/gitlab-org/ci-cd/gitlab-runner-ubi-images/gitlab-runner-helper-ocp:x86_64-v17.3.1"
concurrent     = 100
check_interval = 1
runner_tags    = ["my-custom-tag"]
config_template    = <<EOT
[[runners]]
  name = "my-grit-gitlab-runner"
  shell = "bash"
  environment = [
    "FF_PRINT_POD_EVENTS=true",
  ]
  [runners.kubernetes]
    image = "alpine"
    cpu_limit_overwrite_max_allowed = "0.75"
    memory_limit_overwrite_max_allowed = "900Mi"
    helper_cpu_limit_overwrite_max_allowed = "250m"
    helper_memory_limit_overwrite_max_allowed = "100Mi"
    print_pod_warning_events = true
EOT
pod_spec = [
  {
    name      = "selector",
    patchType = "merge",
    patch     = <<EOT
nodeSelector:
  app: "gitlab-runner"
EOT
  }
]
```

`.gitlab-ci.yml` 파일은 다음과 같습니다:

- 중간 작업의 경우:

  ```yaml
  variables:
    KUBERNETES_CPU_LIMIT: "200m"
    KUBERNETES_MEMORY_LIMIT: "100Mi"
    KUBERNETES_HELPER_CPU_LIMIT: "100m"
    KUBERNETES_HELPER_MEMORY_LIMIT: "100Mi"

  tests:
    image: some-image:latest
    script:
    - command_1
    - command_2
    # ...
    - command_n
    tags:
      - my-custom-tag
  ```

- CPU 집약적 작업의 경우:

  ```yaml
  variables:
    KUBERNETES_CPU_LIMIT: "0.75"
    KUBERNETES_MEMORY_LIMIT: "900Mi"
    KUBERNETES_HELPER_CPU_LIMIT: "150m"
    KUBERNETES_HELPER_MEMORY_LIMIT: "100Mi"

  tests:
    image: custom-cpu-intensive-image:latest
    script:
    - cpu_intensive_command_1
    - cpu_intensive_command_2
    # ...
    - cpu_intensive_command_n
    tags:
      - my-custom-tag
  ```

> [!note]
> 더 쉬운 구성을 위해 각 작업 프로필에 대해 클러스터당 1개의 GitLab Runner를 사용합니다. 이 방법은 GitLab이 동일한 클러스터에서 여러 GitLab Runner 설치를 지원하거나 `config.toml` 템플릿에서 여러 `[[runners]]` 섹션을 지원할 때까지 권장됩니다.

### 모니터링 및 관찰성 설정 {#set-up-monitoring-and-observability}

배포 단계의 마지막 단계로 러너 호스트 환경 및 GitLab Runner를 모니터링하기 위한 솔루션을 구축해야 합니다. 인프라 수준, 러너 및 CI/CD 작업 메트릭은 CI/CD 빌드 인프라의 효율성과 안정성에 대한 통찰력을 제공합니다. 또한 Kubernetes 클러스터, GitLab Runner 및 CI/CD 작업 구성을 조정하고 최적화하는 데 필요한 통찰력을 제공합니다.

#### 모니터링 모범 사례 {#monitoring-best-practices}

- 작업 수준 메트릭 모니터링: 작업 기간, 작업 성공 및 실패율.
  - 작업 수준 메트릭을 분석하려면 가장 자주 실행되고 합계로 가장 많은 컴퓨팅 및 RAM 리소스를 소비하는 CI/CD 작업을 이해합니다. 이 작업 프로필은 최적화 기회를 평가하기 위한 좋은 출발점입니다.
- Kubernetes 클러스터 리소스 사용률 모니터링:
  - CPU 사용률
  - 메모리 사용률
  - 네트워크 사용률
  - 디스크 사용률

자세한 내용은 [GitLab Runner 모니터링 전담 페이지](https://docs.gitlab.com/runner/monitoring/)를 참조하세요.

## 최적화 {#optimize}

CI/CD 빌드 환경 최적화는 지속적인 프로세스입니다. CI/CD 작업의 유형과 볼륨은 지속적으로 변화하여 적극적인 참여가 필요합니다.

조직의 CI/CD 및 CI/CD 빌드 인프라에 대한 구체적인 목표가 있을 것입니다. 따라서 첫 번째 단계는 최적화 요구 사항 및 정량화 가능한 목표를 정의하는 것입니다.

다음은 고객 기반 전체의 최적화 요구 사항의 예입니다:

- CI/CD 작업 시작 시간
- CI/CD 작업 기간
- CI/CD 작업 안정성
- CI/CD 컴퓨팅 비용 최적화

다음 단계는 Kubernetes 클러스터의 인프라 메트릭과 함께 CI/CD 메트릭 분석을 시작하는 것입니다. 분석할 중요한 상관 관계는 다음과 같습니다:

- Kubernetes 네임스페이스별 CPU 사용률
- Kubernetes 네임스페이스별 메모리 사용률
- 노드별 CPU 사용률
- 노드별 메모리 사용률
- CI/CD 작업 실패율

일반적으로 Kubernetes에서 높은 CI/CD 작업 실패율(불안정한 테스트로 인한 실패와 독립적)은 Kubernetes 클러스터의 리소스 제약으로 인해 발생합니다. 이러한 메트릭을 분석하여 CI/CD 작업 시작 시간, 작업 기간, 작업 안정성 및 Kubernetes 클러스터 구성의 인프라 리소스 사용률의 최적 균형을 달성합니다.

### 모범 사례 {#best-practices-1}

- 작업 유형별로 조직 전체의 CI/CD 작업을 분류하는 프로세스를 설정합니다.
- 작업 유형 분류 프레임워크를 설정하여 모니터링 구성과 Kubernetes의 GitLab CI/CD 빌드 인프라 최적화 방법 및 CI/CD 작업 유형을 단순화합니다.
- 각 작업 유형을 클러스터의 자체 노드에 할당하면 CI/CD 작업 성능, 작업 안정성 및 인프라 사용률의 최적 균형을 얻을 수 있습니다.

CI/CD 빌드 환경에 대한 인프라 스택으로 Kubernetes를 사용하면 상당한 이점을 제공합니다. 그러나 Kubernetes 인프라의 지속적인 모니터링 및 최적화가 필요합니다. 관찰성 및 최적화 프레임워크를 설정한 후 월별로 수백만 개의 CI/CD 작업을 지원할 수 있습니다. 리소스 경합을 없애고, CI/CD 작업 실행을 결정적으로 달성하고, 최적의 리소스 사용을 달성할 수 있습니다. 이러한 개선으로 인해 운영 효율성과 비용 최적화가 실현됩니다.

## 다음 단계 {#next-steps}

더 나은 사용자 환경을 제공하기 위해 다음 단계를 수행합니다:

- 동일한 클러스터에서 여러 GitLab Runner 설치를 지원합니다. 이를 통해 여러 작업 프로필을 처리해야 하는 시나리오를 더 잘 관리할 수 있습니다(GitLab Runner를 적절히 구성하여 리소스 오용을 방지할 수 있음).
- GKE 노드 자동 크기 조정 지원. 이를 통해 GKE는 워크로드에 따라 규모를 확대하거나 축소할 수 있어 비용을 절감할 수 있습니다.
- 작업 메트릭 모니터링을 활성화합니다. 이를 통해 관리자는 실제 사용량을 기반으로 클러스터 및 GitLab Runner를 더 잘 최적화할 수 있습니다.
