---
stage: Tenant Scale
group: Gitaly
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 모노레포 성능 측정을 위한 메트릭
---

모노레포의 서버 측 성능을 측정하려면 이러한 메트릭을 사용합니다. 이러한 메트릭은 Gitaly의 성능을 측정하기 위한 일반적인 메트릭이지만, 대규모 리포지토리에서 특히 관련이 있습니다.

클론 및 페치는 가장 빈번한 비용이 많이 드는 작업입니다. 소비되는 시스템 리소스의 백분율로 계산하면, 이러한 작업은 종종 Gitaly 노드의 시스템 리소스 90% 이상을 차지합니다. 로그와 메트릭은 리포지토리의 상태에 대한 단서를 제공합니다.

## CPU 및 메모리 {#cpu-and-memory}

두 가지 주요 RPC(원격 프로시저 호출)는 클론 및 가져오기를 처리합니다. Gitaly 로그에서 이 필드들을 사용하여 리포지토리 클론 및 가져오기가 시스템 리소스를 얼마나 많이 사용하고 있는지 확인합니다. Gitaly 로그를 이 필드들 중 하나로 필터링하여 자세히 알아보세요:

| 로그 필드                         | 필터링할 값                                                                          | 설명 |
|:----------------------------------|:---------------------------------------------------------------------------------------------|:------------|
| `json.grpc.method`                | `PostReceivePack`                                                                            | HTTP 클론 및 가져오기를 처리하는 RPC입니다. |
| `json.grpc.method`                | `SSHReceivePack`                                                                             | SSH 클론 및 가져오기를 처리하는 RPC입니다. |
| `json.grpc.code`                  | `OK`                                                                                         | RPC가 요청을 성공적으로 처리했는지 여부입니다. |
| `json.grpc.code`                  | `Canceled`                                                                                   | 클라이언트가 연결을 끊었는지 여부를 나타낼 수 있습니다. 종종 타임아웃으로 인한 것입니다. |
| `json.grpc.code`                  | `ResourceExhausted`                                                                          | 머신이 너무 많은 Git 프로세스를 동시에 생성하고 있는지를 나타냅니다. |
| `json.user_id`                    | 클론 또는 가져오기를 시작하는 `user_id`이(가) `user-<user_id>` 형식으로, 예: `user-22345` | 단일 사용자가 생성한 과도한 클론 또는 가져오기 작업을 찾습니다. |
| `json.username`                   | 클론 또는 가져오기를 시작한 사용자 이름입니다.                                               | 단일 사용자가 생성한 과도한 클론 또는 가져오기 작업을 찾습니다. |
| `json.grpc.request.glRepository`  | 리포지토리이며, `project-<project_id>` 형식으로, 예: `project-214`                      | 단일 리포지토리의 총 클론 및 가져오기 수를 찾습니다. |
| `json.grpc.request.glProjectPath` | 리포지토리이며, 프로젝트 경로 형식으로, 예: `my-org/coolproject`                       | 지정된 리포지토리의 총 클론 및 가져오기 수를 찾습니다. |

이 로그 항목 필드들은 CPU 및 메모리에 대한 정보를 제공합니다:

| 확인할 로그 필드       | 설명 |
|:---------------------------|:------------|
| `json.command.cpu_time_ms` | 이 RPC에서 생성된 서브프로세스가 사용한 CPU 시간입니다. |
| `json.command.maxrss`      | 이 RPC에서 생성된 서브프로세스의 메모리 사용량입니다. |

이 예에서 로그 메시지 `json.command.cpu_time_ms`은(는) `420`이고, `json.command.maxrss`은(는) `3342152`입니다:

```json
{
    "command.count":2,
    "command.cpu_time_ms":420,
    "command.inblock":0,
    "command.majflt":0,
    "command.maxrss":3342152,
    "command.minflt":24316,
    "command.oublock":56,
    "command.real_time_ms":626,
    "command.spawn_token_fork_ms":4,
    "command.spawn_token_wait_ms":0,
    "command.system_time_ms":172,
    "command.user_time_ms":248,
    "component":"gitaly.StreamServerInterceptor",
    "correlation_id":"20HCB3DAEPLV08UGNIYT9HJ4JW",
    "environment":"gprd",
    "feature_flags":"",
    "fqdn":"file-99-stor-gprd.c.gitlab-production.internal",
    "grpc.code":"OK",
    "grpc.meta.auth_version":"v2",
    "grpc.meta.client_name":"gitlab-workhorse",
    "grpc.meta.deadline_type":"none",
    "grpc.meta.method_operation":"mutator",
    "grpc.meta.method_scope":"repository",
    "grpc.meta.method_type":"bidi_stream",
    "grpc.method":"PostReceivePack",
    "grpc.request.fullMethod":"/gitaly.SmartHTTPService/PostReceivePack",
    "grpc.request.glProjectPath":"r2414/revenir/development/machinelearning/protein-ddg",
    "grpc.request.glRepository":"project-47506374",
    "grpc.request.payload_bytes":911,
    "grpc.request.repoPath":"@hashed/db/ab/dbabf83f57affedc9a001dc6c6f6b47bb431bd47d7254edd1daf24f0c38793a9.git",
    "grpc.request.repoStorage":"nfs-file99",
    "grpc.response.payload_bytes":54,
    "grpc.service":"gitaly.SmartHTTPService",
    "grpc.start_time":"2023-10-16T20:40:08.836",
    "grpc.time_ms":631.486,
    "hostname":"file-99-stor-gprd",
    "level":"info",
    "msg":"finished streaming call with code OK",
    "pid":1741362,
    "remote_ip":"108.163.136.48",
    "shard":"default",
    "span.kind":"server",
    "stage":"main",
    "system":"grpc",
    "tag":"gitaly",
    "tier":"stor",
    "time":"2023-10-16T20:40:09.467Z",
    "trace.traceid":"AAB3QAeD8G+H9VNmzOi2CztMAcJv1+g4+l1cAgA=",
    "type":"gitaly",
    "user_id":"user-14857500",
    "username":"ctx_ckottke",
  }
```

## 읽기 분포 {#read-distribution}

각 Gitaly 노드에 대한 읽기 수를 확인하려면 `gitaly_praefect_read_distribution`을(를) 확인합니다. 이 Prometheus 메트릭은 [카운터](https://prometheus.io/docs/concepts/metric_types/#counter)이며 두 개의 벡터를 가집니다:

| 메트릭 이름                         | 벡터            | 설명 |
|-------------------------------------|-------------------|-------------|
| `gitaly_praefect_read_distribution` | `virtual_storage` | [가상 스토리지](../../../../administration/gitaly/praefect/_index.md) 이름입니다. |
| `gitaly_praefect_read_distribution` | `storage`         | Gitaly 스토리지 이름입니다. |

## 팩 객체 캐시 {#pack-objects-cache}

[팩 객체 캐시](../../../../administration/gitaly/configure_gitaly.md#pack-objects-cache)를 확인하려면 로그 및 Prometheus 메트릭을 확인합니다:

| 로그 필드 이름                        | 설명 |
|:--------------------------------------|:------------|
| `pack_objects_cache.hit`              | 현재 팩 객체 캐시가 히트했는지 여부입니다. (`true` 또는 `false`) |
| `pack_objects_cache.key`              | 팩 객체 캐시에 사용된 캐시 키입니다. |
| `pack_objects_cache.generated_bytes`  | 작성 중인 새 캐시의 바이트 크기입니다. |
| `pack_objects_cache.served_bytes`     | 제공 중인 캐시의 바이트 크기입니다. |
| `pack_objects.compression_statistics` | 팩 객체 생성에 대한 통계입니다. |
| `pack_objects.enumerate_objects_ms`   | 클라이언트가 보낸 객체를 열거하는 데 소요된 총 시간(ms)입니다. |
| `pack_objects.prepare_pack_ms`        | 팩파일을 클라이언트로 보내기 전에 준비하는 데 소요된 총 시간(ms)입니다. |
| `pack_objects.write_pack_file_ms`     | 팩파일을 클라이언트로 보내는 데 소요된 총 시간(ms)입니다. 클라이언트의 인터넷 연결에 크게 좌우됩니다. |
| `pack_objects.written_object_count`   | Gitaly가 클라이언트로 보낸 총 객체 수입니다. |

로그 메시지 예:

```json
{
"bytes":26186490,
"correlation_id":"01F1MY8JXC3FZN14JBG1H42G9F",
"grpc.meta.deadline_type":"none",
"grpc.method":"PackObjectsHook",
"grpc.request.fullMethod":"/gitaly.HookService/PackObjectsHook",
"grpc.request.glProjectPath":"root/gitlab-workhorse",
"grpc.request.glRepository":"project-2",
"grpc.request.repoPath":"@hashed/d4/73/d4735e3a265e16eee03f59718b9b5d03019c07d8b6c51f90da3a666eec13ab35.git",
"grpc.request.repoStorage":"default",
"grpc.request.topLevelGroup":"@hashed",
"grpc.service":"gitaly.HookService",
"grpc.start_time":"2021-03-25T14:57:52.747Z",
"level":"info",
"msg":"finished unary call with code OK",
"peer.address":"@",
"pid":20961,
"span.kind":"server",
"system":"grpc",
"time":"2021-03-25T14:57:53.543Z",
"pack_objects.compression_statistics": "Total 145991 (delta 68), reused 6 (delta 2), pack-reused 145911",
"pack_objects.enumerate_objects_ms": 170,
"pack_objects.prepare_pack_ms": 7,
"pack_objects.write_pack_file_ms": 786,
"pack_objects.written_object_count": 145991,
"pack_objects_cache.generated_bytes": 49533030,
"pack_objects_cache.hit": "false",
"pack_objects_cache.key": "123456789",
"pack_objects_cache.served_bytes": 49533030,
"peer.address": "127.0.0.1",
"pid": 8813,
}
```

| Prometheus 메트릭 이름                    | 벡터   | 설명 |
|:------------------------------------------|:---------|:------------|
| `gitaly_pack_objects_served_bytes_total`  |          | 제공 중인 캐시의 크기(바이트)입니다. |
| `gitaly_pack_objects_cache_lookups_total` | `result` | 캐시 조회가 `hit` 또는 `miss`로 결과를 반환했는지 여부입니다. |
