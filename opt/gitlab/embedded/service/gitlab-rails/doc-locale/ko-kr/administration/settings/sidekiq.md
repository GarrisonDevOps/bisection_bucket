---
stage: Async
group: Async
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Sidekiq 백그라운드 작업
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

Sidekiq 작업 크기 제한 및 cron 작업 일정을 평가하는 데 사용되는 시간대를 구성합니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.

이러한 설정에 액세스하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **환경설정**을 선택합니다.
1. **Sidekiq 백그라운드 작업**을 확장합니다.

## 작업 크기 제한 {#job-size-limits}

[Sidekiq](../sidekiq/_index.md)는 작업을 Redis에 저장합니다. 과도한 Redis 메모리 사용을 방지하기 위해 GitLab은:

- 작업 인수를 Redis에 저장하기 전에 압축합니다.
- 압축 후 지정된 임계값을 초과하는 작업을 거부합니다.

압축 임계값 또는 크기 제한을 조정하려면 값을 업데이트합니다. 압축을 사용하지 않으려면 **추적** 모드를 선택합니다.

### 사용 가능한 설정 {#available-settings}

| 설정                                   | 기본값          | 설명                                                                                                                                                                   |
|-------------------------------------------|------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| 제한 모드                             | 압축         | 이 모드는 지정된 임계값에서 작업을 압축하고 압축 후 지정된 제한을 초과하는 경우 거부합니다.                                               |
| Sidekiq 작업 압축 임계값(바이트) | 100,000(100KB) | 인수 크기가 이 임계값을 초과하면 Redis에 저장하기 전에 압축됩니다.                                                                          |
| Sidekiq 작업 크기 제한(바이트)            | 0                | 압축 후 이 크기를 초과하는 작업은 거부됩니다. 이를 통해 Redis의 과도한 메모리 사용을 방지하여 불안정성을 방지합니다. 0으로 설정하면 작업 거부를 방지합니다.     |

이러한 값을 변경한 후 [Sidekiq를 다시 시작](../restart_gitlab.md)합니다.

## Cron 작업 시간대 {#cron-jobs-time-zone}

기본적으로 GitLab은 cron 작업 일정을 인스턴스 시간대(다르게 구성되지 않으면 UTC)에서 평가합니다. cron 작업을 다른 시간대에서 실행하려면 시간대 재정의를 설정합니다.

시간대를 설정하려면:

1. **Cron 작업 시간대** 드롭다운 목록에서 시간대를 선택하거나 **시스템 기본값**을 선택하여 인스턴스 시간대를 사용합니다.

이 값을 변경한 후 [Sidekiq를 다시 시작](../restart_gitlab.md)합니다.
