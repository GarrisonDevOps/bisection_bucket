---
stage: ModelOps
group: MLOps
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 머신러닝 모델 실험
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 15.11에서 [도입됨](https://gitlab.com/groups/gitlab-org/-/work_items/9341).
- GitLab 17.8에서 [정식 출시됨](https://gitlab.com/groups/gitlab-org/-/work_items/9341).

{{< /history >}}

머신러닝 모델을 만들 때 모델의 성능을 개선하기 위해 다양한 매개변수, 구성 및 기능 엔지니어링으로 실험할 수 있습니다. 나중에 실험을 다시 실행하려면 메타데이터와 아티팩트를 효과적으로 추적해야 합니다. GitLab 모델 실험을 사용하여 매개변수, 지표 및 아티팩트를 GitLab에 직접 추적하고 기록합니다.

## 실험이란 무엇입니까? {#what-is-an-experiment}

프로젝트에서 실험은 비교 가능한 모델 실행의 컬렉션입니다. 실험은 오래 지속될 수 있으며(예: 사용 사례를 나타낼 때) 또는 단기간일 수 있으며(병합 요청으로 트리거된 하이퍼파라미터 튜닝 결과) 일반적으로 동일한 지표로 측정되는 유사한 매개변수 집합을 가진 모델 실행을 보유합니다.

![모델 실험 표 - 모델과 해당 모델의 실행 수, 작성자 및 마지막 작업을 보여줍니다.](img/experiments_v17_9.png)

## 모델 실행 {#model-run}

모델 실행은 머신러닝 모델의 훈련 변형으로 결국 모델의 버전으로 승격될 수 있습니다.

![실험 실행 목록 표 - 실행 ID, 생성 타임스탬프, 작성자 이름 및 상태를 표시합니다.](img/runs_v17_9.png)

데이터 과학자의 목표는 주어진 지표로 표시된 대로 최고의 모델 성능을 제공하는 매개변수 값을 가진 모델 실행을 찾는 것입니다.

![실험 상세 정보 및 메타데이터 페이지 - ML 플로우 실행 ID, 소스 정보 및 매개변수를 표시합니다.](img/run_v17_9.png)

매개변수 예:

- 알고리즘(예: 선형 회귀 또는 의사결정 나무).
- 알고리즘의 하이퍼파라미터(학습률, 트리 깊이, 에포크 수).
- 포함된 기능.

## 새 실험 및 실행 추적 {#track-new-experiments-and-runs}

실험 및 시도는 [MLflow](https://www.mlflow.org/docs/latest/tracking/) 클라이언트 호환성을 통해서만 추적할 수 있습니다. GitLab을 MLflow 클라이언트의 백엔드로 사용하는 방법에 대한 자세한 내용은 [MLflow 클라이언트 호환성](mlflow_client.md)을 참조하십시오.

## 모델 실행 살펴보기 {#explore-model-runs}

현재 활성 실험을 나열하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **분석** > **모델 실험기능**을 선택합니다.
1. 기록된 모든 실행을 해당 지표, 매개변수 및 메타데이터와 함께 표시하려면 실험을 선택합니다.
1. 실행에 대한 세부 정보를 표시하려면 **상세정보**를 선택합니다.

## 로그 아티팩트 보기 {#view-log-artifacts}

시험 아티팩트는 패키지로 저장됩니다. 아티팩트가 실행에 대해 기록된 후 실행에 대해 기록된 모든 아티팩트가 패키지 레지스트리에 나열됩니다. 실행의 패키지 이름은 `ml_experiment_<experiment_id>`이며, 여기서 버전은 실행 IID입니다. 아티팩트에 대한 링크는 **실험 실행** 목록 또는 **실행 상세**에서도 액세스할 수 있습니다.

## CI 정보 보기 {#view-ci-information}

실행을 생성한 CI 작업과 연결할 수 있으며, 이를 통해 파이프라인을 트리거한 병합 요청, 파이프라인 및 사용자에 대한 빠른 링크를 제공합니다:

![실행 상세 페이지 - 관련 CI 작업, 파이프라인 및 사용자 정보를 표시합니다.](img/run_detail_ci_v17_9.png)

## 기록된 지표 보기 {#view-logged-metrics}

실험을 실행하면 GitLab은 지표, 매개변수 및 메타데이터를 포함한 특정 관련 데이터를 기록합니다. 분석을 위해 차트에서 지표를 볼 수 있습니다.

기록된 지표를 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **분석** > **모델 실험기능**을 선택합니다.
1. 보려는 실험을 선택합니다.
1. **성능** 탭을 선택합니다.

![실험의 성능 그래프](img/metrics_v17_10.png)
