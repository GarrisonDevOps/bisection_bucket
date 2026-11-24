---
stage: ModelOps
group: MLOps
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: MLflow 클라이언트 호환성
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [도입됨](https://gitlab.com/groups/gitlab-org/-/epics/8560) GitLab 15.11.
- [일반 공급](https://gitlab.com/groups/gitlab-org/-/work_items/9341) GitLab 17.8.

{{< /history >}}

[MLflow](https://mlflow.org/)는 머신 러닝 실험 추적을 위한 인기 있는 오픈 소스 도구입니다. GitLab [모델 실험 추적](_index.md) 및 GitLab [모델 레지스트리](../model_registry/_index.md)는 MLflow 클라이언트와 호환됩니다. 설정을 위해 기존 코드에 최소한의 변경이 필요합니다.

## MLflow 클라이언트 통합 활성화 {#enable-mlflow-client-integration}

사전 요구 사항:

- GitLab 호환 Python 클라이언트:
  - 권장:  [GitLab MLOps Python 클라이언트](https://gitlab.com/gitlab-org/modelops/mlops/gitlab-mlops).
  - 또 다른 옵션은 MLflow 클라이언트 버전입니다. MLflow 클라이언트는 [GitLab과 호환됩니다](https://gitlab.com/gitlab-org/modelops/mlops/mlflow-compatibility-qa).
- [개인](../../../profile/personal_access_tokens.md), [프로젝트](../../settings/project_access_tokens.md), 또는 [그룹](../../../group/settings/group_access_tokens.md) 액세스 토큰(개발자, 유지보수자 또는 소유자 역할 및 `api` 범위 포함).
- 프로젝트 ID. 프로젝트 ID를 찾으려면:
  1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
  1. **설정** > **일반**을 선택합니다.

로컬 환경에서 MLflow 클라이언트 호환성을 사용하려면:

1. 코드를 실행하는 호스트에서 추적 URI 및 토큰 환경 변수를 설정합니다. 이는 로컬 환경, CI 파이프라인 또는 원격 호스트가 될 수 있습니다. 예를 들어:

   ```shell
   export MLFLOW_TRACKING_URI="<your gitlab endpoint>/api/v4/projects/<your project id>/ml/mlflow"
   export MLFLOW_TRACKING_TOKEN="<your_access_token>"
   ```

1. 학습 코드에 `mlflow.set_tracking_uri()`에 대한 호출이 포함되어 있으면 제거하세요.

모델 레지스트리에서 오른쪽 상단의 오버플로우 메뉴에서 추적 URI를 복사할 수 있습니다. 수직 줄임표({{< icon name="ellipsis_v" >}})를 선택합니다.

## 모델 실험 {#model-experiments}

학습 코드를 실행할 때, MLflow 클라이언트를 사용하여 실험, 실행, 모델 및 모델 버전을 생성할 수 있습니다. 이를 사용하여 매개변수, 메트릭, 메타데이터 및 아티팩트를 GitLab에 기록할 수도 있습니다.

실험이 기록된 후 `/<your project>/-/ml/experiments` 아래에 나열됩니다.

실행은 등록되며 실험, 모델 또는 모델 버전을 선택하여 탐색할 수 있습니다.

### 실험 생성 {#creating-an-experiment}

```python
import mlflow

# Create a new experiment
experiment_id = mlflow.create_experiment(name="<your_experiment>")

# Setting the active experiment also creates a new experiment if it doesn't exist.
mlflow.set_experiment(experiment_name="<your_experiment>")
```

### 실행 생성 {#creating-a-run}

```python
import mlflow

# Creating a run requires an experiment ID or an active experiment
mlflow.set_experiment(experiment_name="<your_experiment>")

# Runs can be created with or without a context manager
with mlflow.start_run() as run:
    print(run.info.run_id)
    # Your training code

with mlflow.start_run():
    # Your training code
```

### 매개변수 및 메트릭 기록 {#logging-parameters-and-metrics}

```python
import mlflow

mlflow.set_experiment(experiment_name="<your_experiment>")

with mlflow.start_run():
    # Parameter keys need to be unique in the scope of the run
    mlflow.log_param(key="param_1", value=1)

    # Metrics can be updated throughout the run
    mlflow.log_metric(key="metrics_1", value=1)
    mlflow.log_metric(key="metrics_1", value=2)
```

### 아티팩트 기록 {#logging-artifacts}

```python
import mlflow

mlflow.set_experiment(experiment_name="<your_experiment>")

with mlflow.start_run():
    # Plaintext text files can be logged as artifacts using `log_text`
    mlflow.log_text('Hello, World!', artifact_file='hello.txt')

    mlflow.log_artifact(
        local_path='<local/path/to/file.txt>',
        artifact_path='<optional relative path to log the artifact at>'
    )
```

### 모델 기록 {#logging-models}

모델은 지원되는 [MLflow 모델 특성](https://mlflow.org/docs/latest/models.html#built-in-model-flavors) 중 하나를 사용하여 기록할 수 있습니다. 모델 특성으로 기록하면 메타데이터를 기록하여 다양한 도구 및 환경에서 모델을 관리, 로드 및 배포하기가 더 쉬워집니다.

```python
import mlflow
from sklearn.ensemble import RandomForestClassifier

mlflow.set_experiment(experiment_name="<your_experiment>")

with mlflow.start_run():
    # Create and train a simple model
    model = RandomForestClassifier(n_estimators=10, random_state=42)
    model.fit(X_train, y_train)

    # Log the model using MLflow sklearn model flavor
    mlflow.sklearn.log_model(model, artifact_path="")
```

### 실행 로드 {#loading-a-run}

{{< history >}}

- GitLab 17.9에 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/509595)되었습니다.

{{< /history >}}

GitLab 모델 레지스트리에서 실행을 로드하여 예를 들어 예측을 만들 수 있습니다.

```python
import mlflow
import mlflow.pyfunc

run_id = "<your_run_id>"
download_path = "models"  # Local folder to download to

mlflow.pyfunc.load_model(f"runs:/{run_id}/", dst_path=download_path)

sample_input = [[1,0,3,4],[2,0,1,2]]
model.predict(data=sample_input)
```

### 실행을 CI/CD 작업에 연결 {#associating-a-run-to-a-cicd-job}

{{< history >}}

- [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/119454) GitLab 16.1.
- [변경됨](https://gitlab.com/groups/gitlab-org/-/work_items/9423) GitLab 17.1에서 베타로.

{{< /history >}}

학습 코드가 CI/CD 작업에서 실행되는 경우, GitLab은 해당 정보를 사용하여 실행 메타데이터를 향상시킬 수 있습니다. 실행을 CI/CD 작업에 연결하려면:

1. [프로젝트 CI 변수](../../../../ci/variables/_index.md)에 다음 변수를 포함합니다:
   - `MLFLOW_TRACKING_URI`: `"<your gitlab endpoint>/api/v4/projects/<your project id>/ml/mlflow"`
   - `MLFLOW_TRACKING_TOKEN`: `<your_access_token>`

1. 실행 컨텍스트 내의 학습 코드에 다음 코드 스니펫을 추가합니다:

   ```python
   import os
   import mlflow

   with mlflow.start_run(run_name=f"Run {index}"):
     # Your training code

     # Start of snippet to be included
     if os.getenv('GITLAB_CI'):
       mlflow.set_tag('gitlab.CI_JOB_ID', os.getenv('CI_JOB_ID'))
     # End of snippet to be included
   ```

## 모델 레지스트리 {#model-registry}

MLflow 클라이언트를 사용하여 모델 및 모델 버전을 관리할 수도 있습니다. 모델은 `/<your project>/-/ml/models` 아래에 등록됩니다.

### 모델 {#models}

#### 모델 생성 {#creating-a-model}

```python
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
description = 'Model description'
model = client.create_registered_model(model_name, description=description)
```

**참고**

- `create_registered_model` 인수 `tags`는 무시됩니다.
- `name`은 프로젝트 내에서 고유해야 합니다.
- `name`은 기존 실험의 이름이 될 수 없습니다.

#### 모델 가져오기 {#fetching-a-model}

```python
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
model = client.get_registered_model(model_name)
```

#### 모델 업데이트 {#updating-a-model}

```python
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
description = 'New description'
client.update_registered_model(model_name, description=description)
```

#### 모델 삭제 {#deleting-a-model}

```python
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
client.delete_registered_model(model_name)
```

### 모델에 실행 기록 {#logging-runs-to-a-model}

모든 모델은 `[model]`로 시작하는 이름과 동일한 이름의 관련 실험을 가집니다. 모델에 실행을 기록하려면 올바른 이름을 전달하여 실험을 사용합니다:

```python
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
exp = client.get_experiment_by_name(f"[model]{model_name}")
run = client.create_run(exp.experiment_id)
```

### 모델 버전 {#model-version}

#### 모델 버전 생성 {#creating-a-model-version}

```python
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
description = 'Model version description'
model_version = client.create_model_version(model_name, source="", description=description)
```

버전 매개변수가 전달되지 않으면 최신 업로드된 버전에서 자동으로 증가합니다. 모델 버전 생성 중에 태그를 전달하여 버전을 설정할 수 있습니다. 버전은 [SemVer](https://semver.org/) 형식을 따라야 합니다.

```python
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
version = '<your_version>'
tags = { "gitlab.version": version }
client.create_model_version(model_name, version, description=description, tags=tags)
```

**참고**

- 인수 `run_id`는 무시됩니다. 모든 모델 버전은 실행처럼 동작합니다. 실행에서 모델 버전을 생성하는 것은 아직 지원되지 않습니다.
- 인수 `source`는 무시됩니다. GitLab은 모델 버전 파일의 패키지 위치를 생성합니다.
- 인수 `run_link`는 무시됩니다.
- 인수 `await_creation_for`는 무시됩니다.

#### 모델 업데이트 {#updating-a-model-1}

```python
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
version = '<your_version>'
description = 'New description'
client.update_model_version(model_name, version, description=description)
```

#### 모델 버전 가져오기 {#fetching-a-model-version}

```python
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
version = '<your_version>'
client.get_model_version(model_name, version)
```

#### 모델의 최신 버전 가져오기 {#getting-latest-versions-of-a-model}

```python
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
client.get_latest_versions(model_name)
```

**참고**

- 인수 `stages`는 무시됩니다.
- 버전은 가장 높은 의미 버전 순서로 정렬됩니다.

#### 모델 버전 로드 {#loading-a-model-version}

```python
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
version = '<your_version'  # for example: '1.0.0'

# Alternatively search the version
version = mlflow.search_registered_models(filter_string="name='{model_name}'")[0].latest_versions[0].version

model = mlflow.pyfunc.load_model(f"models:/{model_name}/{latest_version}")

# Or load the latest version
model = mlflow.pyfunc.load_model(f"models:/{model_name}/latest")
```

#### 모델 버전에 메트릭 및 매개변수 기록 {#logging-metrics-and-parameters-to-a-model-version}

모든 모델 버전도 실행이며, 사용자가 매개변수 및 메트릭을 기록할 수 있습니다. 실행 ID는 GitLab의 모델 버전 페이지에서 찾거나 MLflow 클라이언트를 사용하여 찾을 수 있습니다:

```python
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
version = '<your_version>'
model_version = client.get_model_version(model_name, version)
run_id = model_version.run_id

# Your training code

client.log_metric(run_id, '<metric_name>', '<metric_value>')
client.log_param(run_id, '<param_name>', '<param_value>')
client.log_batch(run_id, metric_list, param_list, tag_list)
```

각 파일의 크기 제한이 5GB이므로 더 큰 모델을 분할해야 합니다.

#### 모델 버전에 아티팩트 기록 {#logging-artifacts-to-a-model-version}

GitLab은 MLflow 클라이언트가 파일을 업로드할 수 있는 패키지를 생성합니다.

```python
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
version = '<your_version>'
model_version = client.get_model_version(model_name, version)
run_id = model_version.run_id

# Your training code

client.log_artifact(run_id, '<local/path/to/file.txt>', artifact_path="")
client.log_figure(run_id, figure, artifact_file="my_plot.png")
client.log_dict(run_id, my_dict, artifact_file="my_dict.json")
client.log_image(run_id, image, artifact_file="image.png")
```

아티팩트는 `https://<your project>/-/ml/models/<model_id>/versions/<version_id>` 아래에서 사용 가능합니다.

#### 모델 버전을 CI/CD 작업에 연결 {#linking-a-model-version-to-a-cicd-job}

실행과 유사하게 모델 버전을 CI/CD 작업에 연결할 수도 있습니다:

```python
import os
from mlflow import MlflowClient

client = MlflowClient()
model_name = '<your_model_name>'
version = '<your_version>'
model_version = client.get_model_version(model_name, version)
run_id = model_version.run_id

# Your training code

if os.getenv('GITLAB_CI'):
    client.set_tag(model_version.run_id, 'gitlab.CI_JOB_ID', os.getenv('CI_JOB_ID'))
```

## 지원되는 MLflow 클라이언트 메서드 및 주의사항 {#supported-mlflow-client-methods-and-caveats}

GitLab은 MLflow 클라이언트의 다음 메서드를 지원합니다. [MLflow 문서](https://mlflow.org/docs/latest/index.html)에서 더 많은 정보를 찾을 수 있습니다. 아래 메서드의 MlflowClient 대응 메서드도 동일한 주의사항과 함께 지원됩니다.

| 메서드                   | 지원됨       | 추가된 버전 | 댓글                                                                                     |
|--------------------------|-----------------|---------------|----------------------------------------------------------------------------------------------|
| `create_experiment`      | 예             | 15.11         |                                                                                              |
| `get_experiment`         | 예             | 15.11         |                                                                                              |
| `get_experiment_by_name` | 예             | 15.11         |                                                                                              |
| `delete_experiment`      | 예             | 17.5          |                                                                                              |
| `set_experiment`         | 예             | 15.11         |                                                                                              |
| `get_run`                | 예             | 15.11         |                                                                                              |
| `delete_run`             | 예             | 17.5          |                                                                                              |
| `start_run`              | 예             | 15.11         | (16.3) 이름을 제공하지 않으면 실행이 임의의 별명을 받습니다.                        |
| `search_runs`            | 예             | 15.11         | (16.4) `experiment_ids`은 열 또는 메트릭의 순서로 단일 실험 ID만 지원합니다. |
| `log_artifact`           | 주의사항 포함 | 15.11         | (15.11) `artifact_path`은 비워져 있어야 합니다. 디렉토리를 지원하지 않습니다.                         |
| `log_artifacts`          | 주의사항 포함 | 15.11         | (15.11) `artifact_path`은 비워져 있어야 합니다. 디렉토리를 지원하지 않습니다.                         |
| `log_batch`              | 예             | 15.11         |                                                                                              |
| `log_metric`             | 예             | 15.11         |                                                                                              |
| `log_metrics`            | 예             | 15.11         |                                                                                              |
| `log_param`              | 예             | 15.11         |                                                                                              |
| `log_params`             | 예             | 15.11         |                                                                                              |
| `log_figure`             | 예             | 15.11         |                                                                                              |
| `log_image`              | 예             | 15.11         |                                                                                              |
| `log_text`               | 주의사항 포함 | 15.11         | (15.11) 디렉토리를 지원하지 않습니다.                                                        |
| `log_dict`               | 주의사항 포함 | 15.11         | (15.11) 디렉토리를 지원하지 않습니다.                                                        |
| `set_tag`                | 예             | 15.11         |                                                                                              |
| `set_tags`               | 예             | 15.11         |                                                                                              |
| `set_terminated`         | 예             | 15.11         |                                                                                              |
| `end_run`                | 예             | 15.11         |                                                                                              |
| `update_run`             | 예             | 15.11         |                                                                                              |
| `log_model`              | 부분         | 15.11         | (15.11) 아티팩트는 저장하지만 모델 데이터는 저장하지 않습니다. `artifact_path`은 비워져 있어야 합니다.          |
| `load_model`             | 예             | 17.5          |                                                                                              |
| `download_artifacts`     | 예             | 17.9          |                                                                                              |
| `list_artifacts`         | 예             | 17.9          |                                                                                              |

기타 MLflowClient 메서드:

| 메서드                    | 지원됨        | 추가된 버전 | 댓글                                         |
|---------------------------|------------------|---------------|--------------------------------------------------|
| `create_registered_model` | 주의사항 포함 | 16.8          | [참고 사항 확인](#creating-a-model)                   |
| `get_registered_model`    | 예              | 16.8          |                                                  |
| `delete_registered_model` | 예              | 16.8          |                                                  |
| `update_registered_model` | 예              | 16.8          |                                                  |
| `create_model_version`    | 주의사항 포함 | 16.8          | [참고 사항 확인](#creating-a-model-version)           |
| `get_model_version`       | 예              | 16.8          |                                                  |
| `get_latest_versions`     | 주의사항 포함 | 16.8          | [참고 사항 확인](#getting-latest-versions-of-a-model) |
| `update_model_version`    | 예              | 16.8          |                                                  |
| `create_registered_model` | 예              | 16.8          |                                                  |
| `create_registered_model` | 예              | 16.8          |                                                  |

## 알려진 이슈 {#known-issues}

- [지원되는 메서드](#supported-mlflow-client-methods-and-caveats)에 나열되지 않은 MLflow 클라이언트 메서드도 작동할 수 있지만 테스트되지 않았습니다.
- 실험 및 실행 생성 중에 ExperimentTags는 저장되지만 표시되지 않습니다.
