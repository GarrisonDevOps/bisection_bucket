---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Carmen으로 클라우드 인프라 및 애플리케이션의 탄소 배출량을 측정합니다.
title: Carmen
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> Carmen은 Green Software Foundation에 의해 승인되거나 채택되지 않은 초안 소프트웨어입니다. 개발의 현재 상태 검토 외에 다른 목적으로 Carmen에 의존하지 마세요. GitLab은 이 도구를 유지 또는 지원하지 않으며, 이 도구가 규제 또는 규정 준수 요구 사항을 충족한다는 표현을 하지 않습니다. Carmen은 기업 ESG 보고, 규정 준수 공시 또는 마케팅 자료에 적합하지 않습니다.

[Carmen](https://github.com/Green-Software-Foundation/if-carmen)(탄소 측정 엔진)은 클라우드 인프라 및 애플리케이션의 탄소 배출량을 측정하는 오픈 소스 도구입니다.

Carmen은 두 가지 소스에서 탄소 배출량을 측정합니다:

- 인프라: CSV 형식의 VM 사용 데이터를 사용하여 가상 머신 및 클라우드 워크로드에서의 에너지 소비 및 탄소 배출량입니다.
- 애플리케이션: Prometheus 메트릭을 사용하여 Kubernetes 클러스터에서 실행 중인 개별 워크로드 및 포드의 탄소 배출량입니다.

Carmen은 Grafana, FinOps 대시보드 또는 자체 도구에서 사용할 수 있는 CSV 보고서를 출력합니다.

## 입력 데이터 형식 {#input-data-format}

Carmen 데몬은 CSV 형식의 VM 사용 데이터를 기대합니다. 로컬 파일의 경우 `config.yaml`을 CSV가 있는 경로로 지정합니다. Azure Blob Storage를 사용하는 경우 `config.yaml`에서 저장소 계정을 구성하면 Carmen이 데이터를 직접 읽습니다.

필수 필드는 다음과 같습니다:

| 필드                  | 설명                                                    | 예제 |
| ---------------------- | -------------------------------------------------------------- | ------- |
| `Time`                 | ISO 8601 형식의 타임스탬프입니다.                                  | `2024-10-15T14:30:00Z` |
| `Id`                   | VM의 고유 식별자(보고서 세분화도를 제어함)입니다.    | `vm-a1b2c3d4` |
| `Size`                 | VM 인스턴스 크기입니다.                                              | `Standard_D4s_v3` |
| `Region`               | VM이 배포된 영역입니다.                               | `eastus` |
| `Service`              | 클라우드 서비스 또는 제품 카테고리입니다.                             | `Compute` |
| `Component`            | VM이 제공하는 애플리케이션 계층입니다.                               | `api-gateway` |
| `Subscription`         | 클라우드 구독 식별자입니다.                                 | `prod-subscription-001` |
| `Name`                 | 사람이 읽을 수 있는 VM 이름입니다.                                        | `production-web-01` |
| `Instance`             | 배포 그룹의 VM에 대한 인스턴스 식별자입니다.            | `web-server-03` |
| `Environment`          | 배포 환경입니다.                                        | `production` |
| `Partition`            | 논리적 파티션 또는 테넌트입니다.                                   | `team-finance` |
| `AverageCpuPercentage` | 측정 기간 동안의 평균 CPU 사용률(0-100)입니다. | `45.7`  |
| `DiskSizeGb`           | 프로비저닝된 총 디스크 저장소(기가바이트 단위)입니다.                   | `128`   |

`Id` 필드는 보고서 세분화도를 제어합니다. `Id`의 각 고유값은 출력에서 하나의 구성 요소를 생성합니다. VM 단위가 일반적이지만 필요한 인사이트에 따라 더 낮은 수준의 식별자(서비스 단위) 또는 더 높은 수준의 식별자를 사용할 수 있습니다.

## 파이프라인에 Carmen 추가 {#add-carmen-to-your-pipeline}

Carmen을 CI/CD 작업으로 실행하여 VM 사용 데이터에서 탄소 배출 보고서를 생성하고 파이프라인 아티팩트로 저장할 수 있습니다.

전제 조건:

- 러너 환경에서 Python 3.12, pip, npm, Git, `lsb-release` 및 bash입니다.
- 필수 형식의 로컬 CSV 파일로 제공된 VM 사용 데이터입니다. Carmen은 또한 Azure Blob Storage에서 읽기를 지원합니다.
- 알려진 경로에 있는 `config.yaml` 파일입니다.

파이프라인에 Carmen을 추가하려면:

1. `.gitlab-ci.yml` 파일에 Carmen을 설치하고 Carmen과 함께 제공되는 예제 데이터에 대해 데몬을 실행하는 작업을 추가합니다:

   ```yaml
   carbon-report:
     image: python:3.12
     before_script:
       - apt-get update && apt-get install -y nodejs npm git lsb-release
       - git clone https://github.com/Green-Software-Foundation/if-carmen.git
       - npm install -g "@grnsft/if@1.0.0" "@grnsft/if-plugins@0.3.2" "@grnsft/if-unofficial-plugins@0.3.1"
       - pip install --upgrade pip && pip install -e $CI_PROJECT_DIR/if-carmen
     script:
       - cd $CI_PROJECT_DIR/if-carmen/example-data && carbon-daemon
     artifacts:
       paths:
         - if-carmen/example-data/output/
       expire_in: 1 week
   ```

1. 파이프라인을 실행하고 작업이 아티팩트에서 `CO2_<date>.csv` 파일을 생성하며 `EnergykWh` 및 `TotalCarbonGramsCO2eq` 열에 0이 아닌 값이 있는지 확인합니다.
1. 로컬 CSV 데이터를 지정하는 `config.yaml`을 리포지토리에 추가합니다:

   ```yaml
   carmen_daemon:
     source:
       type: local
       file_names:
         - "vm_metrics.csv"
       local:
         source_path: "data/vm-metrics"
     upload:
       type: local
       local:
         upload_path: "./output"
   ```

   Azure Blob Storage의 경우 `source.type`을 `azure`으로 설정하고 Azure 저장소 계정 설정 및 자격 증명을 추가합니다. 모든 옵션은 [Carmen 구성](https://github.com/Green-Software-Foundation/if-carmen/blob/dev/docs/configuration.md)을 참조하세요.

1. 작업의 `script` 및 `artifacts` 섹션을 바꿉니다:

   ```yaml
   script:
     - mkdir -p $CI_PROJECT_DIR/output
     - cd $CI_PROJECT_DIR && carbon-daemon
   artifacts:
     paths:
       - output/
     expire_in: 1 week
   ```

1. 파이프라인을 다시 실행하고 출력 `CO2_<date>.csv`이 자체 데이터를 포함하는지 확인합니다.

## 결과 보기 {#view-results}

Carmen은 하루당 구성 요소(VM) 당 한 행씩 CSV 보고서를 생성합니다. 출력 파일은 `CO2_<date>.csv` 명명 패턴을 따르며 `upload.local.upload_path`에 구성된 경로에 저장됩니다.

결과를 보려면:

1. 파이프라인으로 이동합니다.
1. `carbon-report` 작업을 선택합니다.
1. **작업 아티팩트** 아래에서 **탐색**을 선택합니다.
1. `CO2_<date>.csv` 파일을 엽니다.

보고서에는 다음 필드가 포함됩니다:

| 필드                         | 설명 |
| ----------------------------- | ----------- |
| `Date`                        | 24시간 보고 버킷입니다. |
| `Id`                          | 구성 요소(VM)의 고유 식별자입니다. |
| `Name`                        | VM의 사람이 읽을 수 있는 이름입니다. |
| `EnergykWh`                   | 킬로와트시로 소비된 총 에너지입니다. |
| `OperationalCarbonGramsCO2eq` | 운영 중 에너지 소비로 인한 탄소 배출량입니다. |
| `EmbodiedCarbonGramsCO2eq`    | 하드웨어 제조, 운송 및 처분으로 인한 탄소 배출량입니다. |
| `TotalCarbonGramsCO2eq`       | 운영 및 임베디드 탄소 배출량의 합입니다. |
| `CarbonIntensity`             | 지역 전력망의 탄소 강도(gCO2eq/kWh)입니다. |

## 애플리케이션 측정 {#application-measurement}

Kubernetes 클러스터의 개별 워크로드의 탄소 배출량 측정을 위해 Carmen을 Prometheus와 함께 사이드카 API 서비스로 배포할 수 있습니다. 이 모드는 구성 가능한 간격으로 포드당 CPU 및 메모리 메트릭을 가져옵니다.

이 배포에는 Helm, Prometheus, kube-state-metrics 및 cAdvisor가 있는 Kubernetes 클러스터가 필요합니다. 자세한 내용은 Carmen 리포지토리에서 [Carmen as a Service](https://github.com/Green-Software-Foundation/if-carmen/blob/dev/docs/carmen-as-a-service.md)를 참조하세요.

## 문제 해결 {#troubleshooting}

Carmen으로 작업할 때 다음 문제가 발생할 수 있습니다.

### 첫 번째 보고서 출력이 올바르지 않음 {#first-report-output-looks-incorrect}

탄소 배출 값이 예상보다 높거나 낮게 나타납니다.

이 문제는 실제 VM 사양이 제공되지 않았기 때문에 Carmen이 기본 벤치마크 하드웨어 구성으로 폴백할 때 발생합니다.

이 문제를 해결하려면 클라우드 공급자의 API에서 실제 VM 사양을 제공합니다.

### 출력에 VM당 한 행만 포함됨 {#output-contains-only-one-row-per-vm}

보고서의 행이 예상보다 적습니다.

이 문제는 여러 레코드가 동일한 `Id` 값을 공유할 때 발생합니다.

이 문제를 해결하려면 입력 CSV의 `Id` 열을 확인합니다. `Id`의 각 고유값은 출력에서 하나의 구성 요소를 생성합니다.

### Carmen이 출력을 생성하지 않음 {#carmen-produces-no-output}

`carbon-daemon`을 실행한 후 출력 디렉터리가 비어 있습니다.

이 문제는 Impact Framework가 전역으로 설치되지 않았거나 `config.yaml` 경로가 `carbon-daemon`을 실행하는 디렉터리에서 해석되지 않을 때 발생할 수 있습니다.

이 이슈를 해결하려면:

- `@grnsft/if`이 설치되어 있고 액세스 가능한지 확인합니다: `if-run --version`
- `config.yaml`의 경로가 작업 디렉터리에서 해석되는지 확인합니다.

### 측정값이 일일 합계로만 집계됨 {#measurements-aggregate-to-daily-totals-only}

시간별 또는 일별 이상의 탄소 배출 값이 필요합니다.

Carmen은 일일 합계로만 집계합니다. 시간별 해상도는 알려진 제한 사항입니다.
