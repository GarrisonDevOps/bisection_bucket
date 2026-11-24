---
stage: AI Platform
group: AI Core Infra
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab Self-Managed 인스턴스에서 의미론적 코드 검색을 관리 및 구성합니다.
title: 의미론적 코드 검색 관리
---

{{< details >}}

- 티어: Premium, Ultimate
- 추가 기능: GitLab Duo Core, Pro 또는 Enterprise
- 제공 서비스: GitLab Self-Managed
- 상태: 베타

{{< /details >}}

{{< history >}}

- [도입됨](https://gitlab.com/groups/gitlab-org/-/work_items/16910) [베타](../policy/development_stages_support.md#beta)로 GitLab 18.7에서.
- [추가됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/588259) GitLab Duo Core의 GitLab 18.8에서.
- [추가됨](https://gitlab.com/gitlab-org/gitlab/-/issues/590394) GitLab Premium의 GitLab 18.9에서.

{{< /history >}}

> [!note]
> 사용자 설명서는 [의미론적 코드 검색](../user/gitlab_duo/semantic_code_search.md)을 참고하세요.

의미론적 코드 검색으로 AI 기반 GitLab Duo 기능은 리포지토리에서 관련 코드 스니펫을 찾을 수 있습니다.

## 전제 조건 {#prerequisites}

- [GitLab AI Gateway](gitlab_duo/gateway.md) 또는 [GitLab Duo Self-Hosted](gitlab_duo_self_hosted/_index.md)에 대한 접근 권한.
- 베타 및 실험 기능이 [인스턴스에 대해](../user/duo_agent_platform/turn_on_off.md#on-gitlab-self-managed-2) 활성화되어 있어야 합니다.
- [벡터 저장소가 구성됨](#vector-storage):
  - Elasticsearch 8.0 이상.
  - OpenSearch 2.0 이상.
  - [`pgvector`](https://github.com/pgvector/pgvector) 확장입니다.
- GitLab Duo Self-Hosted의 경우 [임베딩 모델이 구성되어야 함](#configure-an-embedding-model).

## 벡터 저장공간 {#vector-storage}

중형 또는 대형 리포지토리의 경우 Elasticsearch 또는 OpenSearch를 사용해야 합니다. `pgvector`를 사용하는 것은 적은 수의 소규모 리포지토리가 있는 설정에만 해당됩니다. 인덱싱 및 쿼리 성능이 `pgvector`로 제한될 수 있습니다.

### 고급 검색 클러스터에 연결 {#connect-to-the-advanced-search-cluster}

{{< history >}}

- GitLab 18.7에서 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/18905)되었습니다.

{{< /history >}}

GitLab 인스턴스가 [고급 검색](../user/search/advanced_search.md)을 위해 Elasticsearch 또는 OpenSearch를 사용하는 경우 동일한 클러스터에 연결하여 의미론적 코드 검색을 활성화할 수 있습니다:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **검색**을 선택합니다.
1. **시맨틱 검색**을 펼칩니다.
1. **벡터 저장공간**에서 **구성**을 선택합니다.
1. **벡터 저장공간** 페이지의 **고급 검색 클러스터** 아래에서 **연결**을 선택합니다.

### 사용자 지정 벡터 저장소 구성 {#configure-a-custom-vector-store}

{{< history >}}

- GitLab 19.2에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/585318)되었습니다.

{{< /history >}}

사용자 지정 벡터 저장소 연결을 구성하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **검색**을 선택합니다.
1. **시맨틱 검색**을 펼칩니다.
1. **벡터 저장공간**에서 **구성**을 선택합니다.
1. **검색 어댑터** 드롭다운 목록에서 **Elasticsearch**, **OpenSearch** 또는 **PostgreSQL**을 선택합니다.
1. 어댑터에 대한 필드를 완료합니다.
1. **변경 사항 저장**을 선택합니다.

#### Elasticsearch {#elasticsearch}

| 설정      | 설명 |
|--------------|-------------|
| **URL**      | Elasticsearch 클러스터의 URL 쉼표 구분 목록(예: `http://localhost:9200, http://localhost:9201`). |
| **사용자명** | 비밀번호로 보호된 Elasticsearch 서버의 사용자명. |
| **비밀번호** | 비밀번호로 보호된 Elasticsearch 서버의 패스워드. |

#### OpenSearch {#opensearch}

| 설정      | 설명 |
|--------------|-------------|
| **URL**      | OpenSearch 클러스터의 URL 쉼표 구분 목록(예: `http://localhost:9200, http://localhost:9201`). |
| **사용자명** | 비밀번호로 보호된 OpenSearch 서버의 사용자명. |
| **비밀번호** | 비밀번호로 보호된 OpenSearch 서버의 패스워드. |

AWS OpenSearch Service를 사용하려면 **IAM 자격 증명으로 AWS OpenSearch Service 사용**을 선택하고 필드를 완료합니다:

| 설정                   | 설명 |
|---------------------------|-------------|
| **AWS 영역**            | OpenSearch 도메인의 AWS 영역. |
| **AWS 엑세스 키**        | AWS 액세스 키 ID. 역할 인스턴스 자격 증명을 사용하지 않는 경우에만 필요합니다. |
| **AWS 비밀 액세스 키** | AWS 비밀 액세스 키. 역할 인스턴스 자격 증명을 사용하지 않는 경우에만 필요합니다. |
| **AWS 역할 ARN**          | AWS IAM 역할 ARN `AssumeRole` 계정 간 권한 부여. |

#### PostgreSQL `pgvector` {#postgresql-with-pgvector}

전제 조건:

- [`pgvector`](https://github.com/pgvector/pgvector) 확장을 PostgreSQL 데이터베이스에서 활성화합니다:

  ```sql
  CREATE EXTENSION vector;
  ```

| 설정      | 설명 |
|--------------|-------------|
| **호스트**     | PostgreSQL 서버의 호스트명. |
| **포트**     | PostgreSQL 서버의 포트. 기본값은 `5432`입니다. |
| **데이터베이스** | PostgreSQL 데이터베이스의 이름. |
| **사용자명** | PostgreSQL 사용자명. |
| **비밀번호** | PostgreSQL 패스워드. |

## 임베딩 모델 구성 {#configure-an-embedding-model}

임베딩 모델을 구성하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **검색**을 선택합니다.
1. **시맨틱 검색**을 펼칩니다.
1. **코드 임베딩**에서 **모델 설정**을 선택합니다. 이미 임베딩 모델을 구성한 경우 **모델 변경**이 대신 표시됩니다.
1. **시맨틱 검색 코드 임베딩** 페이지에서 임베딩 모델, 임베딩 차원, 임베딩 요청의 배치 크기 및 청킹 전략을 선택합니다.
1. **임베딩 설정**을 선택합니다. 이미 임베딩 모델을 구성한 경우 **임베딩을 업데이트하고 백필 프로세스를 시작**이 대신 표시됩니다.

> [!warning]
> 임베딩 모델 또는 차원을 변경할 때 코드베이스 크기에 따라 몇 시간이 걸릴 수 있는 백필이 실행됩니다. 이 프로세스 중에 의미론적 검색을 사용할 수 있습니다.

### 임베딩 모델 {#embedding-models}

#### GitLab 관리형 모델 {#gitlab-managed-models}

{{< history >}}

- `semantic_search_user_model_selection`라는 [기능 플래그](feature_flags/_index.md)로 GitLab 19.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/582638)되었습니다. 기본적으로 비활성화되었습니다.
- 기능 플래그 `semantic_search_user_model_selection` [제거됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246289) GitLab 19.3에서.

{{< /history >}}

전제 조건:

- [GitLab AI Gateway](gitlab_duo/gateway.md) 및 [GitLab Duo Self-Hosted](gitlab_duo_self_hosted/_index.md) 모두에 대한 접근 권한.

GitLab 관리 모델은 [GitLab AI Gateway](gitlab_duo/gateway.md)에서 제공됩니다. Gemini Enterprise Agent Platform에서 제공하는 `text-embedding-005` 모델을 선택합니다.

GitLab 관리 모델과 [GitLab Duo Self-Hosted](gitlab_duo_self_hosted/_index.md) 설정에 대한 자세한 정보는 [하이브리드 AI Gateway 및 모델 구성](gitlab_duo_self_hosted/_index.md#hybrid-ai-gateway-and-model-configuration)을 참고하세요.

> [!warning]
> GitLab 관리 모델을 사용할 때 GitLab은 인덱싱에 대한 임베딩 요청을 제한합니다. 이러한 속도 제한을 방지하려면 [자체 호스팅 모델](#self-hosted-models)을 구성하세요.
>
> GitLab이 선택한 모델을 더 이상 지원하지 않으면 다른 모델로 전환해야 합니다.

#### 자체 호스팅 모델 {#self-hosted-models}

{{< history >}}

- `semantic_search_user_model_selection`이라는 이름의 [기능 플래그](feature_flags/_index.md)와 함께 GitLab 19.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/588849)되었습니다. 기본적으로 비활성화되었습니다.
- 기능 플래그 `semantic_search_user_model_selection` [제거됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246289) GitLab 19.3에서.

{{< /history >}}

전제 조건:

- [GitLab Duo Self-Hosted](gitlab_duo_self_hosted/_index.md)에 대한 접근 권한.
- [자체 호스팅 베타 모델 및 기능이 활성화됨](gitlab_duo_self_hosted/configure_duo_features.md#turn-on-self-hosted-beta-models-and-features).

자체 호스팅 모델은 [자신의 인프라에서 호스팅되는](gitlab_duo_self_hosted/_index.md) AI 모델입니다.

자체 호스팅 모델을 선택하려면:

1. [GitLab Duo Self-Hosted](gitlab_duo_self_hosted/_index.md)를 설정합니다.
1. [자체 호스팅 모델 추가](gitlab_duo_self_hosted/configure_duo_features.md#add-a-self-hosted-model) [임베딩 모델 패밀리](gitlab_duo_self_hosted/configure_duo_features.md#embedding-model)를 추가합니다.

### 임베딩 요청에 대한 배치 크기 {#batch-size-for-embedding-requests}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246635)되었습니다.

{{< /history >}}

임베딩 요청의 배치 크기는 각 대량 임베딩 요청의 입력 수를 나타냅니다. 선택한 임베딩 모델의 대량 API 제한 범위 내에서 이 값을 유지하세요. 비워 두면 임베딩 모델의 기본 배치 크기가 사용됩니다. 임베딩 모델에 기본 배치 크기가 없으면 대신 30의 폴백 값이 사용됩니다.

#### 배치 크기 업데이트 {#update-batch-size}

임베딩 모델을 변경하지 않고 배치 크기를 업데이트하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **검색**을 선택합니다.
1. **시맨틱 검색**을 펼칩니다.
1. **코드 임베딩**에서 **모델 변경**을 선택합니다.
1. **시맨틱 검색 코드 임베딩** 페이지에서 **임베딩 요청의 배치 크기 업데이트** 섹션으로 이동합니다.
1. 새 값을 입력합니다:
   - 백필이 실행 중이 아닌 활성 임베딩 모델의 경우 현재 모델의 배치 크기를 업데이트합니다.
   - 백필이 실행 중인 새 임베딩 모델의 경우 다음 모델의 배치 크기를 업데이트합니다.
1. **배치 크기 업데이트**를 선택합니다.

### 청킹 전략 {#chunking-strategy}

{{< history >}}

- GitLab 19.2에서 `semantic_search_user_model_selection` [기능 플래그](feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/600201)되었습니다. 기본적으로 비활성화되었습니다.
- 기능 플래그 `semantic_search_user_model_selection` [제거됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/246289) GitLab 19.3에서.

{{< /history >}}

청킹 전략은 코드 파일을 임베딩을 위한 더 작은 스니펫으로 분할하는 데 사용되는 알고리즘입니다. 다음 전략 중 하나를 선택합니다:

- 코드 바이트: 코드 구조 또는 의미론을 고려하지 않고 코드를 고정 크기 바이트 청크로 분할합니다. 청크 크기는 청크당 최대 바이트 수를 나타냅니다. 이 전략을 다음과 같은 경우에 사용합니다:
  - 더 빠른 인덱싱 및 더 예측 가능한 청크 크기.
  - 다양한 파일 유형 및 언어가 있는 리포지토리.
- 코드 pre-BERT: BERT 기반 임베딩 모델에 최적화된 의미론적 경계를 사용하여 코드를 분할합니다. 청크 크기는 청크당 최대 토큰 수를 나타냅니다. 이 전략을 다음과 같은 경우에 사용합니다:
  - 더 나은 검색 품질 및 코드 구조를 준수하는 더 의미 있는 청크.
  - 잘 구조화된 코드가 있는 리포지토리.

> [!warning]
> 청킹 전략은 임베딩 모델을 처음 구성할 때만 선택할 수 있습니다. 인덱싱이 시작된 후 청킹 전략을 변경하려면 인스턴스를 완전히 다시 인덱싱해야 합니다. 자동 재인덱싱에 대한 지원은 [이슈 600200](https://gitlab.com/gitlab-org/gitlab/-/work_items/600200) 및 [이슈 602138](https://gitlab.com/gitlab-org/gitlab/-/work_items/602138)에 제안되어 있습니다.

## 의미론적 코드 검색 상태 확인 {#check-semantic-code-search-status}

{{< history >}}

- GitLab 19.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/596795)되었습니다.

{{< /history >}}

인덱싱 상태, 벡터 저장소 연결 세부 정보, 리포지토리 통계 및 임베딩 큐 크기를 포함한 의미론적 코드 검색의 상태를 확인하려면 이 Rake 작업을 실행합니다:

```shell
sudo gitlab-rake gitlab:semantic_search:code:info
```

상태를 지속적으로 모니터링하려면 초 단위의 조사 간격을 제공합니다:

```shell
sudo gitlab-rake "gitlab:semantic_search:code:info[5]"
```

이 작업은 지정된 간격으로 출력을 새로 고칩니다. 작업을 중지하려면 <kbd>Ctrl</kbd>+<kbd>C</kbd>를 누르세요.

## 데드 큐 관리 {#manage-the-dead-queue}

전제 조건:

- `admin_mode`, `ai_features` 및 `api` 범위가 있는 개인 액세스 토큰.

임베딩 생성이 실패하면 항목은 지연 증가(5분, 30분, 2시간, 8시간)를 통해 재시도 큐 체인으로 이동합니다. 모든 재시도에서 실패한 항목은 수동 개입을 위해 데드 큐로 이동됩니다. 속도 제한 오류로 인해 실패한 항목은 체인을 따르지 않습니다. 처음 재시도 큐로 돌아가며 속도 제한이 해제될 때까지 5분마다 재시도합니다. 데드 큐에 도달하지 않습니다. 데드 큐 크기는 `Embedding Queues` 섹션의 [상태 Rake 작업](#check-semantic-code-search-status) 출력에서 확인할 수 있습니다.

### 데드 큐 지우기 {#clear-the-dead-queue}

데드 큐에서 모든 항목을 삭제하려면 이 명령을 실행합니다:

```shell
curl --request DELETE \
  --header "PRIVATE-TOKEN: <your_token>" \
  "https://gitlab.example.com/api/v4/admin/active_context/dead_queue"
```

### 데드 큐 재시도 {#replay-the-dead-queue}

데드 큐 항목을 처리 큐로 이동하여 다시 시도하려면 `queue` 매개 변수를 사용하여 대상을 지정합니다. 유효한 값은 `retry_queue`, `second_retry_queue`, `third_retry_queue`, `fourth_retry_queue`, `code` 및 `code_backfill`입니다.

항목을 전체 재시도 체인을 통해 다시 실행하려면 `retry_queue`을 사용하세요:

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_token>" \
  --data "queue=retry_queue" \
  "https://gitlab.example.com/api/v4/admin/active_context/dead_queue/replay"
```

항목을 주요 코드 큐에 추가하려면 `code`을 사용하세요:

```shell
curl --request POST \
  --header "PRIVATE-TOKEN: <your_token>" \
  --data "queue=code" \
  "https://gitlab.example.com/api/v4/admin/active_context/dead_queue/replay"
```
