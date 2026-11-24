---
stage: Verify
group: Pipeline Execution
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 테스트 분산 API
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태: 실험

{{< /details >}}

{{< history >}}

- GitLab 19.4에서 `parallel_test_balancing`이라는 [기능 플래그](../administration/feature_flags/_index.md)와 함께 [도입](https://gitlab.com/gitlab-org/gitlab/-/work_items/607450)되었습니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요. 이 기능은 테스트용으로 사용 가능하지만 프로덕션 사용을 위한 준비가 되어 있지 않습니다.

이 API를 사용하여 [`parallel:`](../ci/yaml/_index.md#parallel) CI/CD 작업의 노드 전체에 테스트를 분산하여 모든 노드가 대략 같은 시간에 완료되도록 합니다.

테스트 분할은 노드 전체에 분산할 작업 단위입니다. 파일로 분할할 때 각 테스트 분할은 테스트 파일입니다. 노드는 정적 테스트 분할으로 공유 대기 풀을 시드한 다음 완료될 때마다 반복적으로 기간 예산 배치의 테스트 분할을 요청합니다. 더 빠른 노드가 더 많은 작업을 수행합니다. 노드를 다시 시도하면 원래 할당된 정확한 테스트 분할 세트를 받습니다.

두 엔드포인트 모두:

- 실행 중인 병렬 작업에서 호출되어야 하며 [CI/CD 작업 토큰](../ci/jobs/ci_job_token.md)(`CI_JOB_TOKEN`)으로 인증됩니다.
- 호출하는 작업이 `parallel:` 키워드를 사용하지 않을 때 `422 Unprocessable Entity`를 반환합니다.
- 7일 전에 생성된 파이프라인에 대해 `422 Unprocessable Entity`를 반환합니다. 테스트 분산 데이터는 재시도를 포함하여 파이프라인 생성으로부터 7일 동안 유지되기 때문입니다.

## 병렬 작업에 대한 테스트 분산 초기화 {#initialize-test-balancing-for-a-parallel-job}

작업 그룹의 공유 대기 풀을 호출자의 정적 테스트 분할로 시드하고 첫 번째 테스트 분할 배치를 청구합니다. 노드가 이미 테스트 분할을 청구한 경우(예: 작업이 다시 시도되거나 크래시에서 복구된 경우) 이전에 청구된 테스트 세트가 변경되지 않은 채로 반환되고 `test_splits` 매개변수는 무시됩니다.

이 엔드포인트는 시드가 작업 그룹의 공유 풀을 50,000개 테스트 분할을 초과하여 푸시할 때 `422 Unprocessable Entity`를 반환합니다.

```plaintext
POST /job/test_balancing/initialize
```

지원되는 속성:

| 속성                         | 형식            | 필수 | 설명 |
|-----------------------------------|-----------------|----------|-------------|
| `test_splits`                     | 해시 배열 | 예      | 이 노드에 할당된 정적 분할의 테스트 분할입니다. 최대 1,000개 항목입니다. |
| `test_splits[].path`              | 문자열          | 예      | 리포지토리 루트를 기준으로 한 테스트 분할의 경로입니다. 최대 1024자입니다. |
| `test_splits[].expected_duration` | float           | 아니요       | 테스트 분할의 예상 기간(초)입니다. 제공되지 않을 때 기본값은 300입니다. |

성공하면 [`201 Created`](rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성                         | 형식   | 설명 |
|-----------------------------------|--------|-------------|
| `mode`                            | 문자열 | `seed` 풀이 시드되고 첫 번째 배치가 청구되었거나 `retry` 이전에 청구된 테스트 세트가 재생되었을 때입니다. |
| `test_splits`                     | 배열  | 노드가 실행해야 할 테스트 분할입니다. `retry`에서 전체 원본 테스트 세트입니다. |
| `test_splits[].path`              | 문자열 | 리포지토리 루트를 기준으로 한 테스트 분할의 경로입니다. |
| `test_splits[].expected_duration` | float  | 시드 시간의 예상 기간(초)입니다. 제공되지 않을 때 기본값은 300입니다. |

요청 예:

```shell
curl --request POST \
  --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"test_splits": [{"path": "spec/models/user_spec.rb", "expected_duration": 12.5}]}' \
  --url "https://gitlab.example.com/api/v4/job/test_balancing/initialize"
```

응답 예:

```json
{
  "mode": "seed",
  "test_splits": [
    {
      "path": "spec/models/user_spec.rb",
      "expected_duration": 12.5
    }
  ]
}
```

## 다음 배치의 테스트 요청 {#request-the-next-batch-of-tests}

호출하는 노드에 대해 원자적으로 기간 예산 배치의 대기 중인 테스트 분할을 청구하며, 가장 느린 것부터 시작합니다. 빈 `test_splits` 배열은 큐가 비어 있고 노드가 배치 요청을 중지해야 함을 의미합니다.

서버는 공유 풀의 남은 예상 기간 전체를 기반으로 배치 크기를 자동으로 선택합니다. 남은 기간이 많을 때 서버는 요청 수를 줄이기 위해 더 큰 배치를 반환합니다. 풀이 비워지면 서버는 더 작은 배치를 반환하여 작업이 노드 전체에서 균형을 유지하도록 합니다.

요청을 안전하게 다시 시도하려면(예: 시간 초과 후) 동일한 `run_id` 및 `seq`를 다시 보냅니다:

- 서버가 이미 해당 요청에 대한 배치를 청구한 경우 새 배치를 청구하는 대신 동일한 배치를 반환합니다.
- 서버가 동일한 `run_id`에 대해 더 높은 `seq`의 요청을 이미 받은 경우 빈 `test_splits` 배열을 반환하고 테스트 분할을 청구하지 않습니다.

```plaintext
POST /job/test_balancing/request
```

지원되는 속성:

| 속성 | 형식    | 필수 | 설명 |
|-----------|---------|----------|-------------|
| `run_id`  | 문자열  | 아니요       | 요청을 보내는 프로세스에 대해 클라이언트가 생성한 ID입니다. 프로세스의 모든 요청에 동일한 값을 사용합니다. `seq`과(와) 함께 필수입니다. 최대 64자입니다. |
| `seq`     | 정수 | 아니요       | 실행 중인 요청의 시퀀스 번호입니다. 새 요청마다 값을 증가시키고 해당 요청을 다시 시도할 때만 값을 다시 사용합니다. `run_id`과(와) 함께 필수입니다. 최소 1입니다. |

성공하면 [`201 Created`](rest/troubleshooting.md#status-codes)와 다음 응답 속성을 반환합니다.

| 속성                         | 형식   | 설명 |
|-----------------------------------|--------|-------------|
| `test_splits`                     | 배열  | 노드가 실행해야 할 테스트 분할입니다. 큐가 비어 있을 때 비어 있습니다. |
| `test_splits[].path`              | 문자열 | 리포지토리 루트를 기준으로 한 테스트 분할의 경로입니다. |
| `test_splits[].expected_duration` | float  | 시드 시간의 예상 기간(초)입니다. 제공되지 않을 때 기본값은 300입니다. |

요청 예:

```shell
curl --request POST \
  --header "JOB-TOKEN: $CI_JOB_TOKEN" \
  --header "Content-Type: application/json" \
  --data '{"run_id": "3f2b8c1e-6d4a-4f0b-9a7e-2c5d8e1f4a6b", "seq": 1}' \
  --url "https://gitlab.example.com/api/v4/job/test_balancing/request"
```

응답 예:

```json
{
  "test_splits": [
    {
      "path": "spec/features/login_spec.rb",
      "expected_duration": 210.4
    }
  ]
}
```
