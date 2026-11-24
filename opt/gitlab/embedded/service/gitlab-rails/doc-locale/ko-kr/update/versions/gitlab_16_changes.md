---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab 16 업그레이드 노트
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

이 페이지는 GitLab 16의 마이너 및 패치 버전 업그레이드 정보를 포함합니다. 다음 사항을 검토했는지 확인하세요:

- 설치 유형.
- 현재 버전과 목표 버전 사이의 모든 버전.

Helm 차트 설치에 대한 추가 정보는 [Helm 차트 업그레이드 노트](https://docs.gitlab.com/charts/releases/)를 참조하세요.

## 15.11에서 업그레이드할 때 주의할 문제 {#issues-to-be-aware-of-when-upgrading-from-1511}

- [PostgreSQL 12는 GitLab 16부터 지원되지 않습니다](../deprecations.md#postgresql-12-deprecated). GitLab 16.0 이상으로 업그레이드하기 전에 PostgreSQL을 최소 버전 13.6으로 업그레이드하세요.
- GitLab 인스턴스가 15.11.0, 15.11.1 또는 15.11.2로 먼저 업그레이드된 경우 데이터베이스 스키마가 올바르지 않습니다. 16.x로 업그레이드하기 전에 [해결 방법](#undefined-column-error-upgrading-to-162-or-later)을 수행하세요.
- 16.0부터 GitLab Self-Managed 설치는 기본적으로 이전의 1개 대신 2개의 데이터베이스 연결을 갖습니다. 이 변경으로 PostgreSQL 연결 수가 두 배 증가합니다. 이렇게 하면 GitLab Self-Managed 인스턴스가 GitLab.com과 유사하게 작동하며, GitLab Self-Managed를 위해 CI 기능을 위한 별도의 데이터베이스를 활성화하는 단계입니다. 16.0으로 업그레이드하기 전에 [PostgreSQL의 최대 연결 수를 늘려야 할지](https://docs.gitlab.com/omnibus/settings/database/#configuring-multiple-database-connections) 결정하세요.
  - 이 변경은 Linux 패키지(Omnibus), GitLab Helm 차트, GitLab Operator, GitLab Docker 이미지 및 직접 컴파일된 설치를 포함한 설치 방법에 적용됩니다.
  - [두 번째 데이터베이스 연결을 비활성화할 수 있습니다](#disable-the-second-database-connection).
- 대부분의 설치는 16.0, 16.1 및 16.2를 건너뛸 수 있으며, 업그레이드 경로의 첫 번째 필수 중지점은 16.3입니다. 모든 경우에 이러한 중간 버전의 노트를 검토해야 합니다.

  일부 GitLab 설치는 사용되는 기능 및 환경의 크기에 따라 이러한 중간 버전에서 중지해야 합니다:

  - 16.0.8: 사용자 테이블에 많은 레코드가 있는 인스턴스. 자세한 정보는 [오래 실행되는 사용자 유형 데이터 변경](#long-running-user-type-data-change)을 참조하세요.
  - [16.1.5](#1610): NPM 패키지 레지스트리를 사용하는 인스턴스.
  - [16.2.8](#1620): 많은 파이프라인 변수(과거 파이프라인 포함)가 있는 인스턴스.

  인스턴스가 영향을 받으면서 이러한 중지점을 건너뛰는 경우:

  - 업그레이드를 완료하는 데 몇 시간이 걸릴 수 있습니다.
  - 모든 데이터베이스 변경이 완료될 때까지 인스턴스는 500 오류를 생성하고, 그 후 Puma와 Sidekiq을 다시 시작해야 합니다.
  - Linux 패키지 설치의 경우 시간 초과가 발생하고 [마이그레이션을 완료하기 위한 수동 해결 방법](../package/package_troubleshooting.md#error-command-timed-out-after-3600s)이 필요합니다.
- GitLab 16.0은 프로젝트 크기 제한 적용에 대한 변경 사항을 도입했습니다. GitLab Self-Managed에서 이러한 제한을 사용하는 경우, 제한에 도달한 프로젝트는 같은 그룹의 영향을 받지 않는 Git 리포지토리로 푸시할 때 오류 메시지를 발생시킵니다. 오류는 종종 0바이트 제한 초과(`limit of 0 B`)를 참조합니다.

  푸시가 성공하지만 오류는 그렇지 않다고 암시하며 자동화에 문제를 일으킬 수 있습니다. [문제에서 자세히 읽어보세요](https://gitlab.com/gitlab-org/gitlab/-/issues/416646). [버그가 GitLab 16.5 이상에서 수정되었습니다](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/131122).
- 일반적으로 PgBouncer가 있는 환경의 백업은 [`GITLAB_BACKUP_`로 시작하는 변수를 설정하여 PgBouncer를 우회](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer)해야 합니다. 그러나 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/422163)로 인해 `gitlab-backup`는 오버라이드에 정의된 직접 연결 대신 PgBouncer를 통한 일반 데이터베이스 연결을 사용하며 데이터베이스 백업이 실패합니다. 해결 방법은 `pg_dump`를 직접 사용하는 것입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  모두                    | 없음     |
  | 16.0                    |  모두                    | 없음     |
  | 16.1                    |  모두                    | 없음     |
  | 16.2                    |  모두                    | 없음     |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Linux 패키지 설치 {#linux-package-installations}

- Gitaly 및 Praefect 구성 구조는 GitLab 16으로 업그레이드하기 전에 변경되어야 합니다. 데이터 손실을 방지하려면 먼저 Praefect를 재구성하고 새로운 구성의 일부로 메타데이터 확인을 비활성화하세요. 자세히 읽어보세요:

  - [Praefect 구성 구조 변경](#praefect-configuration-structure-change).
  - [Gitaly 구성 구조 변경](#gitaly-configuration-structure-change).
- Gitaly를 재구성하여 Git 데이터를 `/var/opt/gitlab/git-data/repositories` 이외의 위치에 저장하는 경우, 패키지된 GitLab 16.0 이상은 디렉터리 구조를 자동으로 생성하지 않습니다. [자세한 정보와 해결 방법을 위해 문제를 읽어보세요](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8320).

## 16.11.0 {#16110}

- [`groups_direct` 필드가 추가](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/146881)되었으며, [JSON 웹 토큰(ID 토큰)](../../ci/secrets/id_token_authentication.md)에 추가되었습니다.
  - GitLab CI/CD ID 토큰을 사용하여 제3자 서비스로 인증하는 경우, 이 변경으로 인해 HTTP 헤더 크기가 증가할 수 있습니다. 프록시 서버는 헤더가 너무 크면 요청을 거부할 수 있습니다.
  - 가능하면 수신 시스템의 헤더 제한을 늘리세요.
  - 자세한 내용은 [문제 467253](https://gitlab.com/gitlab-org/gitlab/-/issues/467253)을 참조하세요.
- GitLab 16.11로 업그레이드한 후, 큰 환경 및 데이터베이스를 가진 일부 사용자는 웹 UI에서 소스 코드 페이지를 로드할 때 시간 초과를 경험합니다. 이러한 시간 초과는 내부 60초 시간 초과를 초과하는 파이프라인 데이터에 대한 느린 PostgreSQL 쿼리로 인해 발생합니다.
  - 여전히 Git 리포지토리를 복제할 수 있으며 리포지토리 데이터에 대한 다른 요청이 작동합니다.
  - [문제 472420](https://gitlab.com/gitlab-org/gitlab/-/issues/472420)에서 영향을 받는지 확인하는 단계와 데이터베이스를 지금 수정하기 위해 PostgreSQL에서 실행할 하우스키핑을 참조하세요.
  - [GitLab 17.4.0에서 수정](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/162894)되었으며, 더 이상 이러한 시간 초과를 일으키는 쿼리를 실행하지 않습니다.

### Linux 패키지 설치 {#linux-package-installations-1}

GitLab 16.11에서 PostgreSQL은 다음 경우를 제외하고 자동으로 14.x로 업그레이드됩니다:

- Patroni를 사용하여 고가용성 데이터베이스를 실행 중입니다.
- 데이터베이스 노드가 GitLab Geo 구성의 일부입니다.
- 명시적으로 [PostgreSQL 자동 업그레이드를 거부](https://docs.gitlab.com/omnibus/settings/database/#opt-out-of-automatic-postgresql-upgrades)했습니다.
- `postgresql['version'] = 13`이 `/etc/gitlab/gitlab.rb`에 있습니다.

결함 허용 및 Geo 설치는 PostgreSQL 14로의 수동 업그레이드를 지원하며, [HA/Geo 클러스터에 배포된 패키지된 PostgreSQL](https://docs.gitlab.com/omnibus/settings/database/#packaged-postgresql-deployed-in-an-hageo-cluster)을 참조하세요.

### Geo 설치 {#geo-installations}

- GitLab 16.5에서 도입되고 17.0에서 수정된 버그로 인해 [GitLab Pages](../../administration/pages/_index.md) 배포 파일이 보조 Geo 사이트에서 고아가 되고 있습니다. Pages 배포가 로컬에 저장된 경우, 이는 남은 저장소가 0이 되고 장애 조치 이벤트 시 이후 데이터 손실로 이어질 수 있습니다. 문제 및 해결 방법의 세부 정보는 [문제 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159)에서 확인하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

- GitLab 16.11부터 GitLab 17.2까지 누락된 PostgreSQL 인덱스로 인해 높은 CPU 사용량, 느린 작업 아티팩트 확인 진행률 및 느리거나 시간 초과 Geo 메트릭 상태 업데이트가 발생할 수 있습니다. 인덱스가 GitLab 17.3에서 추가되었습니다. 인덱스를 수동으로 추가하려면 [Geo 문제 해결 - 작업 아티팩트 확인 중 주 사이트의 높은 CPU 사용량](../../administration/geo/replication/troubleshooting/common.md#high-cpu-usage-on-primary-during-object-verification)을 참조하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  모두                    | 없음     |
  | 17.0                    |  모두                    | 없음     |
  | 17.1                    |  모두                    | 없음     |
  | 17.2                    |  모두                    | 없음     |

- Geo 복제가 작동 중이더라도 보조 사이트의 Geo 복제 세부 정보가 비어 있는 것으로 나타납니다. [문제 468509](https://gitlab.com/gitlab-org/gitlab/-/issues/468509)를 참조하세요. 알려진 해결 방법이 없습니다. 버그가 GitLab 17.4에서 수정되었습니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.11                   |  16.11.5 - 16.11.10     | 없음     |
  | 17.0                    |  모두                    | 17.0.7   |
  | 17.1                    |  모두                    | 17.1.7   |
  | 17.2                    |  모두                    | 17.2.5   |
  | 17.3                    |  모두                    | 17.3.1   |

## 16.10.0 {#16100}

GitLab 16.10 이상으로 업그레이드하는 동안 다음 오류가 발생할 수 있습니다:

```plaintext
PG::UndefinedColumn: ERROR:  column namespace_settings.delayed_project_removal does not exist
```

이 오류는 열을 제거하는 마이그레이션이 현재 삭제된 열을 참조하는 이후 마이그레이션 이전에 실행될 때 발생할 수 있습니다. 이 버그를 [수정](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/148135)하는 것이 16.11에서 릴리스될 예정입니다.

문제를 해결하려면:

1. 열을 임시로 다시 생성합니다. `gitlab-psql`을 사용하거나 수동으로 데이터베이스에 연결하여 다음을 실행합니다:

   ```sql
   ALTER TABLE namespace_settings ADD COLUMN delayed_project_removal BOOLEAN DEFAULT NULL;
   ```

1. 보류 중인 마이그레이션을 적용합니다:

   ```shell
   gitlab-ctl reconfigure
   ```

1. 최종 확인:

   ```shell
   gitlab-ctl upgrade-check
   ```

1. 열을 제거합니다. `gitlab-psql`을 사용하거나 수동으로 데이터베이스에 연결하여 다음을 실행합니다:

   ```sql
   ALTER TABLE namespace_settings DROP COLUMN delayed_project_removal;
   ```

### Linux 패키지 설치 {#linux-package-installations-2}

GitLab 16.10용 Linux 패키지 설치에는 Patroni의 새로운 주요 버전(2.1.0에서 3.0.1로)으로의 업그레이드가 포함됩니다.

[참조 아키텍처](../../administration/reference_architectures/_index.md) 중 하나를 사용하는 경우 [고가용성(HA)](../../administration/reference_architectures/_index.md#high-availability-ha)을 활성화(3k명 사용자 이상), [Linux 패키지 설치를 위한 PostgreSQL 복제 및 장애 조치](../../administration/postgresql/replication_and_failover.md)를 사용하고 있으며, 이는 Patroni를 사용합니다.

이 경우 [다운타임을 포함한 다중 노드 업그레이드](../with_downtime.md)를 읽고 다중 노드 인스턴스를 업그레이드하는 방법을 확인하세요.

버전 2.1.0과 3.0.1 사이에 도입된 변경 사항에 대한 자세한 정보는 [Patroni 릴리스 노트](https://patroni.readthedocs.io/en/latest/releases.html)를 참조하세요.

### Geo 설치 {#geo-installations-1}

- GitLab 16.5에서 도입되고 17.0에서 수정된 버그로 인해 [GitLab Pages](../../administration/pages/_index.md) 배포 파일이 보조 Geo 사이트에서 고아가 되고 있습니다. Pages 배포가 로컬에 저장된 경우, 이는 남은 저장소가 0이 되고 장애 조치 이벤트 시 이후 데이터 손실로 이어질 수 있습니다. 문제 및 해결 방법의 세부 정보는 [문제 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159)에서 확인하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

## 16.9.0 {#1690}

GitLab 16.9.0으로 업그레이드하는 동안 다음 오류가 발생할 수 있습니다:

```plaintext
PG::UndefinedTable: ERROR:  relation "p_ci_pipeline_variables" does not exist
```

모든 마이그레이션이 완료되고 모든 Rails 및 Sidekiq 노드를 다시 시작했는지 확인하세요. 이 버그를 [수정](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/144952)하는 것이 16.9.1에서 릴리스될 예정입니다.

### Geo 설치 {#geo-installations-2}

- [컨테이너 복제의 버그](https://gitlab.com/gitlab-org/gitlab/-/issues/431944)로 인해 잘못 구성된 보조는 실패한 컨테이너 복제를 성공한 것으로 표시할 수 있습니다. 후속 확인은 컨테이너를 체크섬 불일치로 인해 실패한 것으로 표시합니다. 해결 방법은 보조 구성을 수정하는 것입니다. **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 모두                     |  모두                    | 16.10.2  |

- GitLab 16.5에서 도입된 버그로 인해 [개인 스니펫](../../user/snippets.md)이 보조 Geo 사이트로 복제되지 않습니다. 이는 Geo 장애 조치 이벤트 시 개인 스니펫 데이터 손실로 이어질 수 있습니다. 문제 및 해결 방법의 세부 정보는 [문제 439933](https://gitlab.com/gitlab-org/gitlab/-/issues/439933)에서 확인하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  모두                    | 없음     |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- 주 사이트와 보조 사이트 간 체크섬 불일치로 인해 컨테이너 레지스트리 이미지의 하위 집합에 대한 확인 실패가 발생할 수 있습니다. [문제 442667](https://gitlab.com/gitlab-org/gitlab/-/issues/442667)는 세부 정보를 설명합니다. 데이터가 보조 사이트로 올바르게 복제되고 있으므로 직접적인 데이터 손실 위험은 없지만 성공적으로 확인되지 않습니다. 현재 알려진 해결 방법이 없습니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- GitLab 16.5에서 도입되고 17.0에서 수정된 버그로 인해 [GitLab Pages](../../administration/pages/_index.md) 배포 파일이 보조 Geo 사이트에서 고아가 되고 있습니다. Pages 배포가 로컬에 저장된 경우, 이는 남은 저장소가 0이 되고 장애 조치 이벤트 시 이후 데이터 손실로 이어질 수 있습니다. 문제 및 해결 방법의 세부 정보는 [문제 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159)에서 확인하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

### Linux 패키지 설치 {#linux-package-installations-3}

- Sidekiq `min_concurrency` 및 `max_concurrency` 옵션은 GitLab 16.9.0에서 사용 중지되었으며 GitLab 17.0.0에서 제거될 예정입니다. GitLab 16.9.0 이상에서 GitLab 17.0.0의 변경 사항 중단을 피하려면 새 [`concurrency`](../../administration/sidekiq/extra_sidekiq_processes.md#manage-thread-counts-with-concurrency-field) 옵션을 설정하고 `min_concurrency` 및 `max_concurrency` 옵션을 제거하세요.

## 16.8.0 {#1680}

- GitLab 16.8.0 및 16.8.1은 일시적으로 Redis 6.2를 필요로 합니다. GitLab 16.8.2는 [Redis 6.0과의 호환성](https://gitlab.com/gitlab-org/gitlab/-/issues/439418)을 복원했습니다.
- 일반적으로 PgBouncer가 있는 환경의 백업은 [`GITLAB_BACKUP_`로 시작하는 변수를 설정하여 PgBouncer를 우회](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer)해야 합니다. 그러나 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/422163)로 인해 `gitlab-backup`는 오버라이드에 정의된 직접 연결 대신 PgBouncer를 통한 일반 데이터베이스 연결을 사용하며 데이터베이스 백업이 실패합니다. 해결 방법은 `pg_dump`를 직접 사용하는 것입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  모두                    | 없음     |
  | 16.0                    |  모두                    | 없음     |
  | 16.1                    |  모두                    | 없음     |
  | 16.2                    |  모두                    | 없음     |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Geo 설치 {#geo-installations-3}

- PostgreSQL 버전 14는 GitLab 16.7 이상의 새 설치에서 기본값입니다. 알려진 문제로 인해 기존 Geo 보조 사이트를 PostgreSQL 버전 14로 업그레이드할 수 없습니다. 자세한 정보는 [문제 7768](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7768#note_1652076255)을 참조하세요. 모든 Geo 사이트는 동일한 버전의 PostgreSQL을 실행해야 합니다. GitLab 16.7부터 16.8.1까지 새 Geo 보조 사이트를 추가하려면 구성에 따라 다음 작업 중 하나를 수행해야 합니다:

  - 첫 번째 Geo 보조 사이트를 추가하려면: 새 Geo 보조 사이트를 설정하기 전에 [주 사이트를 PostgreSQL 14로 업그레이드](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server)하세요. 주 사이트가 이미 PostgreSQL 14를 실행 중인 경우 특별한 조치가 필요하지 않습니다.
  - 이미 하나 이상의 Geo 보조가 있는 배포에 새 Geo 보조 사이트를 추가하려면:
    - 모든 기존 사이트가 PostgreSQL 13을 실행 중인 경우 [PostgreSQL 버전 13을 고정한 새 Geo 보조 사이트를 설치](https://docs.gitlab.com/omnibus/settings/database/#pin-the-packaged-postgresql-version-fresh-installs-only)하세요.
    - 모든 기존 사이트가 PostgreSQL 14를 실행 중인 경우: 특별한 조치가 필요하지 않습니다.
    - 새 Geo 보조 사이트를 배포에 추가하기 전에 모든 기존 사이트를 GitLab 16.8.2 이상 및 PostgreSQL 14로 업그레이드하세요.
- GitLab 16.5에서 도입된 버그로 인해 [개인 스니펫](../../user/snippets.md)이 보조 Geo 사이트로 복제되지 않습니다. 이는 Geo 장애 조치 이벤트 시 개인 스니펫 데이터 손실로 이어질 수 있습니다. 문제 및 해결 방법의 세부 정보는 [문제 439933](https://gitlab.com/gitlab-org/gitlab/-/issues/439933)에서 확인하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  모두                    | 없음     |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- 주 사이트와 보조 사이트 간 체크섬 불일치로 인해 컨테이너 레지스트리 이미지의 하위 집합에 대한 확인 실패가 발생할 수 있습니다. [문제 442667](https://gitlab.com/gitlab-org/gitlab/-/issues/442667)는 세부 정보를 설명합니다. 데이터가 보조 사이트로 올바르게 복제되고 있으므로 직접적인 데이터 손실 위험은 없지만 성공적으로 확인되지 않습니다. 현재 알려진 해결 방법이 없습니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- GitLab 16.5에서 도입되고 17.0에서 수정된 버그로 인해 [GitLab Pages](../../administration/pages/_index.md) 배포 파일이 보조 Geo 사이트에서 고아가 되고 있습니다. Pages 배포가 로컬에 저장된 경우, 이는 남은 저장소가 0이 되고 장애 조치 이벤트 시 이후 데이터 손실로 이어질 수 있습니다. 문제 및 해결 방법의 세부 정보는 [문제 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159)에서 확인하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

## 16.7.0 {#1670}

- GitLab 16.7은 필수 업그레이드 중지점입니다. 이렇게 하면 GitLab 16.7 이상에 도입된 모든 데이터베이스 변경 사항이 모든 GitLab Self-Managed 인스턴스에 구현되었음을 보장합니다. 종속적인 변경 사항은 GitLab 16.8 이상에서 릴리스될 수 있습니다. [문제 429611](https://gitlab.com/gitlab-org/gitlab/-/issues/429611)은 더 많은 세부 정보를 제공합니다.

  - 업그레이드 경로에서 16.6을 건너뛰면, 인스턴스가 GitLab 16.6 릴리스의 배경 데이터베이스 마이그레이션을 처리할 때 16.7로 업그레이드한 후 성능 문제가 발생할 수 있습니다. `ci_builds` 마이그레이션에 대해 자세히 읽고 [16.6.0 업그레이드 노트](#1660)를 참조하세요.
- 일반적으로 PgBouncer가 있는 환경의 백업은 [`GITLAB_BACKUP_`로 시작하는 변수를 설정하여 PgBouncer를 우회](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer)해야 합니다. 그러나 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/422163)로 인해 `gitlab-backup`는 오버라이드에 정의된 직접 연결 대신 PgBouncer를 통한 일반 데이터베이스 연결을 사용하며 데이터베이스 백업이 실패합니다. 해결 방법은 `pg_dump`를 직접 사용하는 것입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  모두                    | 없음     |
  | 16.0                    |  모두                    | 없음     |
  | 16.1                    |  모두                    | 없음     |
  | 16.2                    |  모두                    | 없음     |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Linux 패키지 설치 {#linux-package-installations-4}

특정 정보는 Linux 패키지 설치에 적용됩니다:

- GitLab 16.7부터 PostgreSQL 14는 Linux 패키지와 함께 설치된 기본 버전입니다. 패키지 업그레이드 중에 데이터베이스가 PostgreSQL 14로 업그레이드되지 않습니다. PostgreSQL 14로 업그레이드하려면 [수동으로 수행해야 합니다](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server).

  PostgreSQL 13을 사용하려면 `postgresql['version'] = 13`을 `/etc/gitlab/gitlab.rb`에 설정해야 합니다.

### Geo 설치 {#geo-installations-4}

- PostgreSQL 버전 14는 GitLab 16.7 이상의 새 설치에서 기본값입니다. 알려진 문제로 인해 기존 Geo 보조 사이트를 PostgreSQL 버전 14로 업그레이드할 수 없습니다. 자세한 정보는 [문제](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/7768#note_1652076255)를 참조하세요. 모든 Geo 사이트는 동일한 버전의 PostgreSQL을 실행해야 합니다. GitLab 16.7부터 16.8.1까지 새로운 Geo 보조 사이트를 추가하려면 구성에 따라 다음 작업 중 하나를 수행해야 합니다:

  - 첫 번째 Geo 보조 사이트를 추가 중: 새 Geo 보조 사이트를 설정하기 전에 [주 사이트를 PostgreSQL 14로 업그레이드](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server)하세요. 주 사이트가 이미 PostgreSQL 14를 실행 중인 경우 특별한 조치가 필요하지 않습니다.
  - 이미 하나 이상의 Geo 보조가 있는 배포에 새 Geo 보조 사이트를 추가 중:
    - 모든 기존 사이트가 PostgreSQL 13을 실행 중: [PostgreSQL 버전 13을 고정한 새 Geo 보조 사이트를 설치](https://docs.gitlab.com/omnibus/settings/database/#pin-the-packaged-postgresql-version-fresh-installs-only)하세요.
    - 모든 기존 사이트가 PostgreSQL 14를 실행 중인 경우: 특별한 조치가 필요하지 않습니다.
    - 새 Geo 보조 사이트를 배포에 추가하기 전에 모든 기존 사이트를 GitLab 16.8.2 이상 및 PostgreSQL 14로 업그레이드하세요.
- 주 사이트와 보조 사이트 간 체크섬 불일치로 인해 프로젝트의 하위 집합에 대한 확인 실패가 발생할 수 있습니다. 세부 정보는 이 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/427493)에 기록되어 있습니다. 데이터가 보조 사이트로 올바르게 복제되고 있으므로 데이터 손실 위험이 없습니다. Geo 보조 사이트에서 영향을 받는 프로젝트를 복제하는 사용자는 항상 주 사이트로 리다이렉트됩니다. 현재 알려진 해결 방법이 없습니다. 현재 적극적으로 수정 작업 중입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  16.6.0 - 16.6.5        | 16.6.6   |
  | 16.7                    |  16.7.0 - 16.7.3        | 16.7.4   |

- GitLab 16.5에서 도입된 버그로 인해 [개인 스니펫](../../user/snippets.md)이 보조 Geo 사이트로 복제되지 않습니다. 이는 Geo 장애 조치 이벤트 시 개인 스니펫 데이터 손실로 이어질 수 있습니다. 문제 및 해결 방법의 세부 정보는 [문제 439933](https://gitlab.com/gitlab-org/gitlab/-/issues/439933)에서 확인하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  모두                    | 없음     |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- GitLab 16.5에서 도입되고 17.0에서 수정된 버그로 인해 [GitLab Pages](../../administration/pages/_index.md) 배포 파일이 보조 Geo 사이트에서 고아가 되고 있습니다. Pages 배포가 로컬에 저장된 경우, 이는 남은 저장소가 0이 되고 장애 조치 이벤트 시 이후 데이터 손실로 이어질 수 있습니다. 문제 및 해결 방법의 세부 정보는 [문제 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159)에서 확인하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

## 16.6.0 {#1660}

- GitLab 16.6은 CI 작업 테이블(`ci_builds`)의 모든 행을 다시 작성하는 배경 마이그레이션을 도입하며, 이는 주 키를 64비트로 업그레이드하는 것의 일부입니다. `ci_builds`는 대부분의 GitLab 인스턴스에서 가장 큰 테이블 중 하나이므로, 이 마이그레이션은 합리적인 시간이 걸리도록 평소보다 더 공격적으로 실행됩니다. 배경 마이그레이션은 일반적으로 행 배치 사이에 일시 중지되지만, 이 마이그레이션은 그렇지 않습니다.

  이는 GitLab Self-Managed 환경에서 성능 문제를 일으킬 수 있습니다:

  - 디스크 I/O가 평소보다 높아집니다. 이는 디스크 I/O가 제한되는 클라우드 제공자가 호스팅하는 인스턴스에 특히 문제가 될 것입니다.
  - Autovacuum은 오래된 행(죽은 튜플)을 제거하고 관련 하우스키핑을 수행하기 위해 배경에서 더 자주 실행될 수 있습니다.
  - PostgreSQL에서 선택한 비효율적인 쿼리 계획으로 인해 쿼리가 일시적으로 느리게 실행될 수 있습니다. 이는 테이블의 변경 량에 의해 트리거될 수 있습니다.

  해결 방법:

  - [**운영자** 영역](../background_migrations.md#from-the-gitlab-ui)에서 실행 중인 마이그레이션을 일시 중지하세요.
  - 올바른 쿼리 계획이 선택되도록 [데이터베이스 콘솔](../../administration/troubleshooting/postgresql.md#start-a-database-console)에서 테이블 통계를 수동으로 다시 생성하세요:

    ```sql
    SET statement_timeout = 0;
    VACUUM FREEZE VERBOSE ANALYZE public.ci_builds;
    ```

- GitLab 16.6으로 업그레이드한 후 오래된 [CI 환경 소멸 작업이 생성될 수 있습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/433264#).
- 일반적으로 PgBouncer가 있는 환경의 백업은 [`GITLAB_BACKUP_`로 시작하는 변수를 설정하여 PgBouncer를 우회](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer)해야 합니다. 그러나 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/422163)로 인해 `gitlab-backup`는 오버라이드에 정의된 직접 연결 대신 PgBouncer를 통한 일반 데이터베이스 연결을 사용하며 데이터베이스 백업이 실패합니다. 해결 방법은 `pg_dump`를 직접 사용하는 것입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  모두                    | 없음     |
  | 16.0                    |  모두                    | 없음     |
  | 16.1                    |  모두                    | 없음     |
  | 16.2                    |  모두                    | 없음     |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Geo 설치 {#geo-installations-5}

- 주 사이트와 보조 사이트 간 체크섬 불일치로 인해 프로젝트의 하위 집합에 대한 확인 실패가 발생할 수 있습니다. 세부 정보는 이 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/427493)에 기록되어 있습니다. 데이터가 보조 사이트로 올바르게 복제되고 있으므로 데이터 손실 위험이 없습니다. Geo 보조 사이트에서 영향을 받는 프로젝트를 복제하는 사용자는 항상 주 사이트로 리다이렉트됩니다. 현재 알려진 해결 방법이 없습니다. 현재 적극적으로 수정 작업 중입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  16.6.0 - 16.6.5        | 16.6.6   |
  | 16.7                    |  16.7.0 - 16.7.3        | 16.7.4   |

- GitLab 16.5에서 도입된 버그로 인해 [개인 스니펫](../../user/snippets.md)이 보조 Geo 사이트로 복제되지 않습니다. 이는 Geo 장애 조치 이벤트 시 개인 스니펫 데이터 손실로 이어질 수 있습니다. 문제 및 해결 방법의 세부 정보는 [문제 439933](https://gitlab.com/gitlab-org/gitlab/-/issues/439933)에서 확인하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  모두                    | 없음     |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- GitLab 16.5에서 도입되고 17.0에서 수정된 버그로 인해 [GitLab Pages](../../administration/pages/_index.md) 배포 파일이 보조 Geo 사이트에서 고아가 되고 있습니다. Pages 배포가 로컬에 저장된 경우, 이는 남은 저장소가 0이 되고 장애 조치 이벤트 시 이후 데이터 손실로 이어질 수 있습니다. 문제 및 해결 방법의 세부 정보는 [문제 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159)에서 확인하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

## 16.5.0 {#1650}

- Git 2.42.0 이상이 Gitaly에 필요합니다. 자체 컴파일된 설치의 경우 [Gitaly에서 제공하는 Git 버전](../../install/self_compiled/_index.md#git)을 사용해야 합니다.
- 회귀로 인해 경우에 따라 [그룹을 탐색할 때 HTTP 500 오류](https://gitlab.com/gitlab-org/gitlab/-/issues/431659)가 발생할 수 있습니다. GitLab 16.6 이상으로 업그레이드하면 문제가 해결됩니다.
- 회귀로 인해 [선택하지 않은 고급 검색 패싯이 로드되지 않을 수 있습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/428246). 16.6 이상으로 업그레이드하면 문제가 해결됩니다.
- `unique_batched_background_migrations_queued_migration_version` 인덱스가 16.5에 도입되었으며, 배포 후 마이그레이션 `DeleteOrphansScanFindingLicenseScanningApprovalRules2`은 영배포 업그레이드 중 이 고유 제약 조건을 중단할 수 있습니다. 해결 방법은 [문제 #437291](https://gitlab.com/gitlab-org/gitlab/-/issues/437291#to-unblock)에서 제공되며 오류를 수정합니다:

  ```plaintext
  PG::UniqueViolation: ERROR:  duplicate key value violates unique constraint
  "unique_batched_background_migrations_queued_migration_version"
  DETAIL:  Key (queued_migration_version)=(20230721095222) already exists.
  ```

- 일반적으로 PgBouncer가 있는 환경의 백업은 [`GITLAB_BACKUP_`로 시작하는 변수를 설정하여 PgBouncer를 우회](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer)해야 합니다. 그러나 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/422163)로 인해 `gitlab-backup`는 오버라이드에 정의된 직접 연결 대신 PgBouncer를 통한 일반 데이터베이스 연결을 사용하며 데이터베이스 백업이 실패합니다. 해결 방법은 `pg_dump`를 직접 사용하는 것입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  모두                    | 없음     |
  | 16.0                    |  모두                    | 없음     |
  | 16.1                    |  모두                    | 없음     |
  | 16.2                    |  모두                    | 없음     |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Linux 패키지 설치 {#linux-package-installations-5}

- SSH 클론 URL은 `gitlab_rails['gitlab_ssh_host']`를 `/etc/gitlab/gitlab.rb`에 설정하여 사용자 지정할 수 있습니다. 이 설정은 이제 [유효한 호스트 이름](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/132238)이어야 합니다. 이전에는 리포지토리 클론 URL에서 사용자 지정 호스트 이름과 포트를 표시하는 데 사용되는 임의의 문자열일 수 있었습니다.

  예를 들어, GitLab 16.5 이전에는 다음 설정이 작동했습니다:

  ```ruby
  gitlab_rails['gitlab_ssh_host'] = "gitlab.example.com:2222"
  ```

  GitLab 16.5부터는 호스트 이름과 포트를 별도로 지정해야 합니다:

  ```ruby
  gitlab_rails['gitlab_ssh_host'] = "gitlab.example.com"
  gitlab_rails['gitlab_shell_ssh_port'] = 2222
  ```

  설정을 변경한 후 GitLab을 다시 구성해야 합니다:

  ```shell
  sudo gitlab-ctl reconfigure
  ```

### Geo 설치 {#geo-installations-6}

Geo를 사용하는 설치에 특정 정보가 적용됩니다:

- 많은 Prometheus 메트릭이 16.3.0에서 잘못 제거되어 대시보드와 경고가 손상될 수 있습니다:

  | 영향을 받는 메트릭                          | 16.5.2 이상에서 복원된 메트릭  | 16.3+에서 사용 가능한 대체 항목                 |
  | ---------------------------------------- | ------------------------------------ | ---------------------------------------------- |
  | `geo_repositories_synced`                | 예                                  | `geo_project_repositories_synced`              |
  | `geo_repositories_failed`                | 예                                  | `geo_project_repositories_failed`              |
  | `geo_repositories_checksummed`           | 예                                  | `geo_project_repositories_checksummed`         |
  | `geo_repositories_checksum_failed`       | 예                                  | `geo_project_repositories_checksum_failed`     |
  | `geo_repositories_verified`              | 예                                  | `geo_project_repositories_verified`            |
  | `geo_repositories_verification_failed`   | 예                                  | `geo_project_repositories_verification_failed` |
  | `geo_repositories_checksum_mismatch`     | 아니요                                   | 사용 가능한 항목 없음                                 |
  | `geo_repositories_retrying_verification` | 아니요                                   | 사용 가능한 항목 없음                                 |

  - 영향을 받는 버전:
    - 16.3.0 ~ 16.5.1
  - 수정 사항이 포함된 버전:
    - 16.5.2 이상

  자세한 내용은 [이슈 429617](https://gitlab.com/gitlab-org/gitlab/-/issues/429617)을 참조하세요.

- [객체 스토리지 검증](../../releases/16/gitlab-16-4-released.md#geo-verifies-object-storage)이 GitLab 16.4에 추가되었습니다. [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/429242)로 인해 일부 Geo 설치에서 높은 메모리 사용량이 보고되고 있어 GitLab 애플리케이션이 기본 서버에서 응답하지 않을 수 있습니다.

  설치를 [객체 스토리지](../../administration/object_storage.md)를 사용하도록 구성했고 [GitLab 관리 객체 스토리지 복제](../../administration/geo/replication/object_storage.md#enabling-gitlab-managed-object-storage-replication)를 활성화했다면 영향을 받을 수 있습니다.

  이 문제가 해결될 때까지 객체 스토리지 검증을 비활성화하는 것이 해결 방법입니다. 기본 사이트의 Rails 노드 중 하나에서 다음 명령을 실행하세요:

  ```shell
  sudo gitlab-rails runner 'Feature.disable(:geo_object_storage_verification)'
  ```

  이 문제는 다음 표에 나열된 패치 릴리스로 수정되었으며, GitLab 16.7.0에서 추가로 수정되었습니다. 객체 스토리지 검증을 비활성화했다면 수정된 릴리스로 업그레이드한 후 다시 활성화하세요:

  ```shell
  sudo gitlab-rails runner 'Feature.enable(:geo_object_storage_verification)'
  ```

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.4                    | 16.4.0 - 16.4.2         | 16.4.3   |
  | 16.5                    | 16.5.0 - 16.5.1         | 16.5.2   |

- [그룹 Wiki](../../user/project/wiki/group.md) 검증이 GitLab 16.3에 추가된 후, 누락된 그룹 Wiki 리포지토리가 검증 실패로 잘못 표시되고 있습니다. 이 문제는 실제 복제/검증 실패의 결과가 아니라 Geo 내 누락된 리포지토리에 대한 잘못된 내부 상태이며, 로그에 오류가 발생하고 검증 진행도가 이러한 그룹 Wiki 리포지토리에 대해 실패 상태를 보고합니다.

  [이슈 426571](https://gitlab.com/gitlab-org/gitlab/-/issues/426571)에서 문제 및 해결 방법의 세부 정보를 참조하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ------ | ------ | ------ |
  | 16.3   | 모두    | 없음   |
  | 16.4   | 모두    | 없음   |
  | 16.5   | 16.5.0 - 16.5.1    | 16.5.2   |

- 주 사이트와 보조 사이트 간 체크섬 불일치로 인해 프로젝트의 하위 집합에 대한 확인 실패가 발생할 수 있습니다. 세부 정보는 이 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/427493)에 기록되어 있습니다. 데이터가 보조 사이트로 올바르게 복제되고 있으므로 데이터 손실 위험이 없습니다. Geo 보조 사이트에서 영향을 받는 프로젝트를 복제하는 사용자는 항상 주 사이트로 리다이렉트됩니다. 현재 알려진 해결 방법이 없습니다. 현재 적극적으로 수정 작업 중입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  16.6.0 - 16.6.5        | 16.6.6   |
  | 16.7                    |  16.7.0 - 16.7.3        | 16.7.4   |

- GitLab 16.5에서 도입된 버그로 인해 [개인 스니펫](../../user/snippets.md)이 보조 Geo 사이트로 복제되지 않습니다. 이는 Geo 장애 조치 이벤트 시 개인 스니펫 데이터 손실로 이어질 수 있습니다. 문제 및 해결 방법의 세부 정보는 [문제 439933](https://gitlab.com/gitlab-org/gitlab/-/issues/439933)에서 확인하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  모두                    | 없음     |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |
  | 16.9                    |  16.9.0 - 16.9.1        | 16.9.2   |

- GitLab 16.5에서 도입되고 17.0에서 수정된 버그로 인해 [GitLab Pages](../../administration/pages/_index.md) 배포 파일이 보조 Geo 사이트에서 고아가 되고 있습니다. Pages 배포가 로컬에 저장된 경우, 이는 남은 저장소가 0이 되고 장애 조치 이벤트 시 이후 데이터 손실로 이어질 수 있습니다. 문제 및 해결 방법의 세부 정보는 [문제 457159](https://gitlab.com/gitlab-org/gitlab/-/issues/457159)에서 확인하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.7        | 16.7.8   |
  | 16.8                    |  16.8.0 - 16.8.7        | 16.8.8   |
  | 16.9                    |  16.9.0 - 16.9.8        | 16.9.9   |
  | 16.10                   |  16.10.0 - 16.10.6      | 16.10.7  |
  | 16.11                   |  16.11.0 - 16.11.3      | 16.11.4  |

## 16.4.0 {#1640}

- 그룹 경로 업데이트 시 [버그 수정](https://gitlab.com/gitlab-org/gitlab/-/issues/419289)이 적용되어 16.3에 도입된 데이터베이스 인덱스를 사용합니다.

  16.3 이하 버전에서 16.4로 업그레이드하는 경우, 사용하기 전에 데이터베이스에서 `ANALYZE packages_packages;`을 실행해야 합니다.
- GitLab 16.4 이상으로 업그레이드하는 동안 다음 오류가 발생할 수 있습니다:

  ```plaintext
  main: == 20230830084959 ValidatePushRulesConstraints: migrating =====================
  main: -- execute("SET statement_timeout TO 0")
  main:    -> 0.0002s
  main: -- execute("ALTER TABLE push_rules VALIDATE CONSTRAINT force_push_regex_size_constraint;")
  main:    -> 0.0004s
  main: -- execute("RESET statement_timeout")
  main:    -> 0.0003s
  main: -- execute("ALTER TABLE push_rules VALIDATE CONSTRAINT delete_branch_regex_size_constraint;")
  rails aborted!
  StandardError: An error has occurred, all later migrations canceled:

  PG::CheckViolation: ERROR:  check constraint "delete_branch_regex_size_constraint" of relation "push_rules" is violated by some row
  ```

  다음 제약 조건은 오류를 반환할 수 있습니다:

  - `author_email_regex_size_constraint`
  - `branch_name_regex_size_constraint`
  - `commit_message_negative_regex_size_constraint`
  - `commit_message_regex_size_constraint`
  - `delete_branch_regex_size_constraint`
  - `file_name_regex_size_constraint`
  - `force_push_regex_size_constraint`

  오류를 해결하려면 `push_rules` 테이블에서 511자를 초과하는 레코드를 찾으세요.

  ```sql
  -- replace `delete_branch_regex` with a name of the field used in constraint
  SELECT id FROM push_rules WHERE LENGTH(delete_branch_regex) > 511;
  ```

  푸시 규칙이 프로젝트, 그룹 또는 인스턴스에 속하는지 확인하려면 [Rails 콘솔](../../administration/operations/rails_console.md#starting-a-rails-console-session)에서 다음 스크립트를 실행하세요:

  ```ruby
  # replace `delete_branch_regex` with a name of the field used in constraint
  long_rules = PushRule.where("length(delete_branch_regex) > 511")

  array = long_rules.map do |lr|
    if lr.project
      "Push rule with ID #{lr.id} is configured in a project #{lr.project.full_name}"
    elsif lr.group
      "Push rule with ID #{lr.id} is configured in a group #{lr.group.full_name}"
    else
      "Push rule with ID #{lr.id} is configured on the instance level"
    end
  end

  puts "Total long rules: #{array.count}"
  puts array.join("\n")
  ```

  영향을 받는 푸시 규칙 레코드의 정규식 필드 길이를 줄인 후 마이그레이션을 다시 시도하세요.

  영향을 받는 푸시 규칙이 너무 많고 GitLab UI를 통해 업데이트할 수 없다면 [GitLab 지원](https://support.gitlab.com/)에 문의하세요.

- 일반적으로 PgBouncer가 있는 환경의 백업은 [`GITLAB_BACKUP_`로 시작하는 변수를 설정하여 PgBouncer를 우회](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer)해야 합니다. 그러나 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/422163)로 인해 `gitlab-backup`는 오버라이드에 정의된 직접 연결 대신 PgBouncer를 통한 일반 데이터베이스 연결을 사용하며 데이터베이스 백업이 실패합니다. 해결 방법은 `pg_dump`를 직접 사용하는 것입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  모두                    | 없음     |
  | 16.0                    |  모두                    | 없음     |
  | 16.1                    |  모두                    | 없음     |
  | 16.2                    |  모두                    | 없음     |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### 소스에서 컴파일한 설치 {#self-compiled-installations}

- GitLab 16.4 이상에서는 GitLab 보안 파일과 사용자 정의 훅에 대한 경로를 구성하는 새로운 방법이 선호됩니다:
  1. GitLab 보안 토큰의 경로를 구성하려면 설정 `[gitlab] secret_file`을 업데이트하세요.
  1. 사용자 정의 훅이 있다면 서버 쪽 사용자 정의 훅의 경로를 구성하려면 설정 `[hooks] custom_hooks_dir`을 업데이트하세요.
  1. `[gitlab-shell] dir` 구성을 제거하세요.

### Geo 설치 {#geo-installations-7}

Geo를 사용하는 설치에 특정 정보가 적용됩니다:

- 많은 Prometheus 메트릭이 16.3.0에서 잘못 제거되어 대시보드와 경고가 손상될 수 있습니다:

  | 영향을 받는 메트릭                          | 16.5.2 이상에서 복원된 메트릭  | 16.3+에서 사용 가능한 대체 항목                 |
  | ---------------------------------------- | ------------------------------------ | ---------------------------------------------- |
  | `geo_repositories_synced`                | 예                                  | `geo_project_repositories_synced`              |
  | `geo_repositories_failed`                | 예                                  | `geo_project_repositories_failed`              |
  | `geo_repositories_checksummed`           | 예                                  | `geo_project_repositories_checksummed`         |
  | `geo_repositories_checksum_failed`       | 예                                  | `geo_project_repositories_checksum_failed`     |
  | `geo_repositories_verified`              | 예                                  | `geo_project_repositories_verified`            |
  | `geo_repositories_verification_failed`   | 예                                  | `geo_project_repositories_verification_failed` |
  | `geo_repositories_checksum_mismatch`     | 아니요                                   | 사용 가능한 항목 없음                                 |
  | `geo_repositories_retrying_verification` | 아니요                                   | 사용 가능한 항목 없음                                 |

  - 영향을 받는 버전:
    - 16.3.0 ~ 16.5.1
  - 수정 사항이 포함된 버전:
    - 16.5.2 이상

  자세한 내용은 [이슈 429617](https://gitlab.com/gitlab-org/gitlab/-/issues/429617)을 참조하세요.

- [객체 스토리지 검증](../../releases/16/gitlab-16-4-released.md#geo-verifies-object-storage)이 GitLab 16.4에 추가되었습니다. [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/429242)로 인해 일부 Geo 설치에서 높은 메모리 사용량이 보고되고 있어 GitLab 애플리케이션이 기본 서버에서 응답하지 않을 수 있습니다.

  설치를 [객체 스토리지](../../administration/object_storage.md)를 사용하도록 구성했고 [GitLab 관리 객체 스토리지 복제](../../administration/geo/replication/object_storage.md#enabling-gitlab-managed-object-storage-replication)를 활성화했다면 영향을 받을 수 있습니다.

  이 문제가 해결될 때까지 객체 스토리지 검증을 비활성화하는 것이 해결 방법입니다. 기본 사이트의 Rails 노드 중 하나에서 다음 명령을 실행하세요:

  ```shell
  sudo gitlab-rails runner 'Feature.disable(:geo_object_storage_verification)'
  ```

  이 문제는 다음 표에 나열된 패치 릴리스로 수정되었으며, GitLab 16.7.0에서 추가로 수정되었습니다. 객체 스토리지 검증을 비활성화했다면 수정된 릴리스로 업그레이드한 후 다시 활성화하세요:

  ```shell
  sudo gitlab-rails runner 'Feature.enable(:geo_object_storage_verification)'
  ```

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.4                    | 16.4.0 - 16.4.2         | 16.4.3   |
  | 16.5                    | 16.5.0 - 16.5.1         | 16.5.2   |

- [동기화 상태가 대기 상태에서 멈춰](https://gitlab.com/gitlab-org/gitlab/-/issues/419370) 있으면 복제가 영향을 받는 항목에 대해 무한정 멈춰 있어 장애 조치 시 데이터 손실의 위험이 발생합니다. 주로 리포지토리 동기화에 영향을 주지만 컨테이너 레지스트리 동기화에도 영향을 미칠 수 있습니다. 데이터 손실 위험을 피하기 위해 수정된 버전으로 업그레이드하는 것이 좋습니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ------ | ------ | ------ |
  | 16.3   | 16.3.0 - 16.3.5    | 16.3.6   |
  | 16.4   | 16.4.0 - 16.4.1    | 16.4.2   |

- [그룹 Wiki](../../user/project/wiki/group.md) 검증이 GitLab 16.3에 추가된 후, 누락된 그룹 Wiki 리포지토리가 검증 실패로 잘못 표시되고 있습니다. 이 문제는 실제 복제/검증 실패의 결과가 아니라 Geo 내 누락된 리포지토리에 대한 잘못된 내부 상태이며, 로그에 오류가 발생하고 검증 진행도가 이러한 그룹 Wiki 리포지토리에 대해 실패 상태를 보고합니다.

  [이슈 426571](https://gitlab.com/gitlab-org/gitlab/-/issues/426571)에서 문제 및 해결 방법의 세부 정보를 참조하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ------ | ------ | ------ |
  | 16.3   | 모두    | 없음   |
  | 16.4   | 모두    | 없음   |
  | 16.5   | 16.5.0 - 16.5.1    | 16.5.2   |

- 주 사이트와 보조 사이트 간 체크섬 불일치로 인해 프로젝트의 하위 집합에 대한 확인 실패가 발생할 수 있습니다. 세부 정보는 이 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/427493)에 기록되어 있습니다. 데이터가 보조 사이트로 올바르게 복제되고 있으므로 데이터 손실 위험이 없습니다. Geo 보조 사이트에서 영향을 받는 프로젝트를 복제하는 사용자는 항상 주 사이트로 리다이렉트됩니다. 현재 알려진 해결 방법이 없습니다. 현재 적극적으로 수정 작업 중입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  16.6.0 - 16.6.5        | 16.6.6   |
  | 16.7                    |  16.7.0 - 16.7.3        | 16.7.4   |

## 16.3.0 {#1630}

- GitLab 16.3.5 이상으로 업데이트하세요. 이렇게 하면 GitLab 16.3.3 및 16.3.4에서 과도한 데이터베이스 디스크 공간 사용을 야기하는 [이슈 425971](https://gitlab.com/gitlab-org/gitlab/-/issues/425971)을 피할 수 있습니다.
- 데이터베이스에 중복 NPM 패키지가 없도록 고유 인덱스가 추가되었습니다. 중복 NPM 패키지가 있다면 먼저 16.1로 업그레이드하거나 다음 오류가 발생할 가능성이 있습니다: `PG::UniqueViolation: ERROR:  could not create unique index "idx_packages_on_project_id_name_version_unique_when_npm"`.
- Go 애플리케이션의 경우, [`crypto/tls`: 큰 RSA 키가 포함된 인증서 체인 검증이 느림(CVE-2023-29409)](https://github.com/golang/go/issues/61460)은 RSA 키에 대해 8192비트의 하드 제한을 도입했습니다. GitLab에서 Go 애플리케이션의 컨텍스트에서 RSA 키는 다음에 대해 구성할 수 있습니다:

  - [컨테이너 레지스트리](../../administration/packages/container_registry.md)
  - [Gitaly](../../administration/gitaly/tls_support.md)
  - [GitLab Pages](../../user/project/pages/custom_domains_ssl_tls_certification/_index.md#manually-add-ssltls-certificates)
  - Workhorse

  업그레이드하기 전에 RSA 키의 크기를 확인해야 합니다(`openssl rsa -in <your-key-file> -text -noout | grep "Key:"`).

- `BackfillCiPipelineVariablesForPipelineIdBigintConversion` 백그라운드 마이그레이션은 `EnsureAgainBackfillForCiPipelineVariablesPipelineIdIsFinished` 배포 후 마이그레이션과 함께 완료됩니다. GitLab 16.2.0은 [배치된 백그라운드 마이그레이션](../background_migrations.md#check-for-pending-database-background-migrations)을 도입했으며, `ci_pipeline_variables` 테이블에서 `bigint` `pipeline_id` 값을 [백필](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/123132)하기 위해 도입했습니다. 이 마이그레이션은 더 큰 GitLab 인스턴스에서 완료하는 데 오랜 시간이 걸릴 수 있습니다(한 경우 5천만 행을 처리하는 데 4시간 소요됨). 업그레이드 가동 중지 시간을 연장하지 않으려면 16.3으로 업그레이드하기 전에 마이그레이션이 성공적으로 완료되었는지 확인하세요.

  `ci_pipeline_variables` 테이블의 크기를 [데이터베이스 콘솔](../../administration/troubleshooting/postgresql.md#start-a-database-console)에서 확인할 수 있습니다:

  ```sql
  select count(*) from ci_pipeline_variables;
  ```

- 일반적으로 PgBouncer가 있는 환경의 백업은 [`GITLAB_BACKUP_`로 시작하는 변수를 설정하여 PgBouncer를 우회](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer)해야 합니다. 그러나 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/422163)로 인해 `gitlab-backup`는 오버라이드에 정의된 직접 연결 대신 PgBouncer를 통한 일반 데이터베이스 연결을 사용하며 데이터베이스 백업이 실패합니다. 해결 방법은 `pg_dump`를 직접 사용하는 것입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  모두                    | 없음     |
  | 16.0                    |  모두                    | 없음     |
  | 16.1                    |  모두                    | 없음     |
  | 16.2                    |  모두                    | 없음     |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Linux 패키지 설치 {#linux-package-installations-6}

특정 정보는 Linux 패키지 설치에 적용됩니다:

- GitLab 16.0에서 우리는 업그레이드된 기본 Docker 이미지를 [발표](../../releases/16/gitlab-16-0-released.md#omnibus-improvements)했으며, 이는 새 버전의 OpenSSH Server를 보유합니다. 새 버전의 의도하지 않은 결과는 기본적으로 SSH RSA SHA-1 서명 수락을 비활성화한다는 것입니다. 이 문제는 매우 오래된 SSH 클라이언트를 사용하는 사용자에게만 영향을 미칩니다.

  SHA-1 서명을 사용할 수 없는 문제를 피하려면 보안상의 이유로 SHA-1 서명 사용이 업스트림 라이브러리에서 권장되지 않으므로 사용자가 SSH 클라이언트를 업데이트해야 합니다.

  사용자가 SSH 클라이언트를 즉시 업그레이드할 수 없는 전환 기간을 허용하기 위해 GitLab 16.3 이상에서는 `Dockerfile` 내 `GITLAB_ALLOW_SHA1_RSA` 환경 변수를 지원합니다. `GITLAB_ALLOW_SHA1_RSA`을 `true`로 설정하면 이 더 이상 사용되지 않는 지원이 다시 활성화됩니다.

  보안 모범 사례를 권장하고 업스트림 권장 사항을 따르기 위해 이 환경 변수는 GitLab 17.0까지만 사용 가능하며, 이때 지원 중단을 계획하고 있습니다.

  자세한 정보는 다음을 참조하세요.

  - [OpenSSH 8.8 릴리스 정보](https://www.openssh.org/txt/release-8.8).
  - [비공식 설명](https://gitlab.com/gitlab-org/gitlab/-/issues/416714#note_1482388504).
  - `omnibus-gitlab` [머지 리퀘스트 7035](https://gitlab.com/gitlab-org/omnibus-gitlab/-/merge_requests/7035) (환경 변수를 도입함).

### Geo 설치 {#geo-installations-8}

Geo를 사용하는 설치에 특정 정보가 적용됩니다:

- Git 풀은 보조 Geo 사이트에 대해 기본 Geo 사이트로 프록시되고 있으며, 보조 사이트가 최신 상태일 때도 그렇습니다. Geo를 사용하여 원격 사용자가 보조 Geo 사이트에 대해 Git 풀 요청을 하도록 가속화하는 경우 영향을 받습니다.

  - 영향을 받는 버전:
    - 16.3.0 ~ 16.3.3
  - 수정 사항이 포함된 버전:
    - 16.3.4 이상

  자세한 내용은 [이슈 425224](https://gitlab.com/gitlab-org/gitlab/-/issues/425224)를 참조하세요.

- 많은 Prometheus 메트릭이 16.3.0에서 잘못 제거되어 대시보드와 경고가 손상될 수 있습니다:

  | 영향을 받는 메트릭                          | 16.5.2 이상에서 복원된 메트릭  | 16.3+에서 사용 가능한 대체 항목                 |
  | ---------------------------------------- | ------------------------------------ | ---------------------------------------------- |
  | `geo_repositories_synced`                | 예                                  | `geo_project_repositories_synced`              |
  | `geo_repositories_failed`                | 예                                  | `geo_project_repositories_failed`              |
  | `geo_repositories_checksummed`           | 예                                  | `geo_project_repositories_checksummed`         |
  | `geo_repositories_checksum_failed`       | 예                                  | `geo_project_repositories_checksum_failed`     |
  | `geo_repositories_verified`              | 예                                  | `geo_project_repositories_verified`            |
  | `geo_repositories_verification_failed`   | 예                                  | `geo_project_repositories_verification_failed` |
  | `geo_repositories_checksum_mismatch`     | 아니요                                   | 사용 가능한 항목 없음                                 |
  | `geo_repositories_retrying_verification` | 아니요                                   | 사용 가능한 항목 없음                                 |

  - 영향을 받는 버전:
    - 16.3.0 ~ 16.5.1
  - 수정 사항이 포함된 버전:
    - 16.5.2 이상

  자세한 내용은 [이슈 429617](https://gitlab.com/gitlab-org/gitlab/-/issues/429617)을 참조하세요.

- [동기화 상태가 대기 상태에서 멈춰](https://gitlab.com/gitlab-org/gitlab/-/issues/419370) 있으면 복제가 영향을 받는 항목에 대해 무한정 멈춰 있어 장애 조치 시 데이터 손실의 위험이 발생합니다. 주로 리포지토리 동기화에 영향을 주지만 컨테이너 레지스트리 동기화에도 영향을 미칠 수 있습니다. 데이터 손실 위험을 피하기 위해 수정된 버전으로 업그레이드하는 것이 좋습니다.
- 주 사이트와 보조 사이트 간 체크섬 불일치로 인해 프로젝트의 하위 집합에 대한 확인 실패가 발생할 수 있습니다. 세부 정보는 [이슈 427493](https://gitlab.com/gitlab-org/gitlab/-/issues/427493)에서 추적됩니다. 데이터가 보조 사이트로 올바르게 복제되고 있으므로 데이터 손실 위험이 없습니다. Geo 보조 사이트에서 영향을 받는 프로젝트를 복제하는 사용자는 항상 주 사이트로 리다이렉트됩니다. 알려진 해결 방법이 없으며, 수정이 포함된 버전으로 업그레이드해야 합니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  16.6.0 - 16.6.5        | 16.6.6   |
  | 16.7                    |  16.7.0 - 16.7.3        | 16.7.4   |

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ------ | ------ | ------ |
  | 16.3   | 16.3.0 - 16.3.5    | 16.3.6   |
  | 16.4   | 16.4.0 - 16.4.1    | 16.4.2   |

- [그룹 Wiki](../../user/project/wiki/group.md) 검증이 GitLab 16.3에 추가된 후, 누락된 그룹 Wiki 리포지토리가 검증 실패로 잘못 표시되고 있습니다. 이 문제는 실제 복제/검증 실패의 결과가 아니라 Geo 내 누락된 리포지토리에 대한 잘못된 내부 상태이며, 로그에 오류가 발생하고 검증 진행도가 이러한 그룹 Wiki 리포지토리에 대해 실패 상태를 보고합니다.

  [이슈 426571](https://gitlab.com/gitlab-org/gitlab/-/issues/426571)에서 문제 및 해결 방법의 세부 정보를 참조하세요.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ------ | ------ | ------ |
  | 16.3   | 모두    | 없음   |
  | 16.4   | 모두    | 없음   |
  | 16.5   | 16.5.0 - 16.5.1    | 16.5.2   |

## 16.2.0 {#1620}

- 레거시 LDAP 구성 설정은 [`NoMethodError: undefined method 'devise' for User:Class` 오류](https://gitlab.com/gitlab-org/gitlab/-/issues/419485)를 야기할 수 있습니다. 이 오류는 `ca_file`와 같은 TLS 옵션이 `tls_options` 해시에 지정되지 않았거나 레거시 `gitlab_rails['ldap_host']` 옵션을 사용하는 경우 발생합니다. 자세한 내용은 [구성 해결 방법](https://gitlab.com/gitlab-org/gitlab/-/issues/419485#workarounds)을 참조하세요.
- GitLab 데이터베이스가 15.11.0 - 15.11.2 버전으로 생성되거나 업그레이드된 경우, GitLab 16.2로 업그레이드하면 실패합니다:

  ```plaintext
  PG::UndefinedColumn: ERROR:  column "id_convert_to_bigint" of relation "ci_build_needs" does not exist
  LINE 1: ...db_config_name:main*/ UPDATE "ci_build_needs" SET "id_conver...
  ```

  [세부 정보 및 해결 방법](#undefined-column-error-upgrading-to-162-or-later)을 참조하세요.
- GitLab 16.2 이상으로 업그레이드하는 동안 다음 오류가 발생할 수 있습니다:

  ```plaintext
  main: == 20230620134708 ValidateUserTypeConstraint: migrating =======================
  main: -- execute("ALTER TABLE users VALIDATE CONSTRAINT check_0dd5948e38;")
  rake aborted!
  StandardError: An error has occurred, all later migrations canceled:
  PG::CheckViolation: ERROR:  check constraint "check_0dd5948e38" of relation "users" is violated by some row
  ```

  자세한 내용은 [이슈 421629](https://gitlab.com/gitlab-org/gitlab/-/issues/421629)를 참조하세요.
- GitLab 16.2 이상으로 업그레이드한 후 다음 오류가 발생할 수 있습니다:

  ```plaintext
  PG::NotNullViolation: ERROR:  null value in column "source_partition_id" of relation "ci_sources_pipelines" violates not-null constraint
  ```

  이 문제를 해결하려면 Sidekiq 및 Puma 프로세스를 다시 시작해야 합니다.
- 일반적으로 PgBouncer가 있는 환경의 백업은 [`GITLAB_BACKUP_`로 시작하는 변수를 설정하여 PgBouncer를 우회](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer)해야 합니다. 그러나 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/422163)로 인해 `gitlab-backup`는 오버라이드에 정의된 직접 연결 대신 PgBouncer를 통한 일반 데이터베이스 연결을 사용하며 데이터베이스 백업이 실패합니다. 해결 방법은 `pg_dump`를 직접 사용하는 것입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  모두                    | 없음     |
  | 16.0                    |  모두                    | 없음     |
  | 16.1                    |  모두                    | 없음     |
  | 16.2                    |  모두                    | 없음     |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Linux 패키지 설치 {#linux-package-installations-7}

특정 정보는 Linux 패키지 설치에 적용됩니다:

- GitLab 16.2부터 PostgreSQL 13.11과 14.8이 모두 Linux 패키지와 함께 제공됩니다. 패키지 업그레이드 중에 데이터베이스가 PostgreSQL 14로 업그레이드되지 않습니다. PostgreSQL 14로 업그레이드하려면 수동으로 업그레이드해야 합니다:

  ```shell
  sudo gitlab-ctl pg-upgrade -V 14
  ```

  PostgreSQL 14는 Geo 배포에서 지원되지 않으며 향후 릴리스를 위해 [계획](https://gitlab.com/groups/gitlab-org/-/work_items/9065)되고 있습니다.
- 16.2에서는 Redis를 6.2.11에서 7.0.12로 업그레이드합니다. 이 업그레이드는 완전히 역호환되도록 예상됩니다.

  Redis는 `gitlab-ctl reconfigure`의 일부로 자동으로 다시 시작되지 않습니다. 따라서 새로운 Redis 버전이 사용되도록 다시 구성 실행 후 `sudo gitlab-ctl restart redis`을 실행해야 합니다. 설치된 Redis 버전이 실행 중인 버전과 다름을 언급하는 경고가 다시 시작이 수행될 때까지 다시 구성 실행 끝에 표시됩니다.

  Redis HA 클러스터를 업그레이드하려면 [무중단 지침](../zero_downtime.md)을 따르세요.

### 소스에서 컴파일한 설치 {#self-compiled-installations-1}

- Git 2.41.0 이상이 Gitaly에서 필요합니다. [Gitaly에서 제공한 Git 버전](../../install/self_compiled/_index.md#git)을 사용해야 합니다.

### Geo 설치 {#geo-installations-9}

Geo를 사용하는 설치에 특정 정보가 적용됩니다:

- 작업 아티팩트가 객체 스토리지에 저장되도록 구성되고 `direct_upload`이 활성화된 경우 Geo에서 새 작업 아티팩트가 복제되지 않습니다. 이 버그는 GitLab 버전 16.1.4, 16.2.3, 16.3.0 이상에서 수정되었습니다.
  - 영향을 받는 버전: GitLab 버전 16.1.0 - 16.1.3 및 16.2.0 - 16.2.2.
  - 영향을 받는 버전을 실행하는 동안 동기화된 것처럼 나타나는 아티팩트가 실제로 보조 사이트에서 누락될 수 있습니다. 영향을 받는 아티팩트는 16.1.5, 16.2.5, 16.3.1, 16.4.0 이상으로 업그레이드할 때 자동으로 다시 동기화됩니다. 필요한 경우 [영향을 받는 작업 아티팩트를 수동으로 다시 동기화](https://gitlab.com/gitlab-org/gitlab/-/issues/419742#to-fix-data)할 수 있습니다.

#### 보조 사이트에서 LFS 객체 복제 {#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site}

Geo 프록싱 로직의 [버그](https://gitlab.com/gitlab-org/gitlab/-/issues/410413)로 인해 보조 사이트가 최신 상태일 때도 보조 사이트에 대한 모든 LFS 클론 요청이 기본 사이트로 프록시됩니다. 이로 인해 기본 사이트의 로드가 증가하고 보조 사이트에서 복제하는 사용자의 LFS 객체 액세스 시간이 길어질 수 있습니다.

GitLab 15.1에서 프록싱이 기본적으로 활성화되었습니다.

영향을 받지 않는 경우:

- 설치가 LFS 객체를 사용하도록 구성되지 않은 경우
- Geo를 사용하여 원격 사용자를 가속화하지 않는 경우
- Geo를 사용하여 원격 사용자를 가속화하지만 프록싱을 비활성화한 경우

| 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
|-------------------------|-------------------------|----------|
| 15.1 - 16.2             | 모두                     | 16.3 이상    |

해결 방법: 가능한 해결 방법은 [프록싱을 비활성화](../../administration/geo/secondary_proxy/_index.md#disable-secondary-site-http-proxying)하는 것입니다. 보조 사이트는 복제 시 복제되지 않은 LFS 파일을 제공하지 못합니다.

## 16.1.0 {#1610}

- `BackfillPreparedAtMergeRequests` 백그라운드 마이그레이션은 `FinalizeBackFillPreparedAtMergeRequests` 배포 후 마이그레이션과 함께 완료됩니다. GitLab 15.10.0은 [배치된 백그라운드 마이그레이션](../background_migrations.md#check-for-pending-database-background-migrations)을 도입했으며, [`merge_requests` 테이블에서 `prepared_at` 값을 백필](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/111865)하기 위해 도입했습니다. 이 마이그레이션은 더 큰 GitLab 인스턴스에서 완료하는 데 여러 날이 걸릴 수 있습니다. 16.1.0으로 업그레이드하기 전에 마이그레이션이 성공적으로 완료되었는지 확인하세요.
- GitLab 16.1.0은 [배치된 백그라운드 마이그레이션](../background_migrations.md#check-for-pending-database-background-migrations) `MarkDuplicateNpmPackagesForDestruction`을 포함하여 중복 NPM 패키지를 삭제 표시합니다. 16.3.0 이상으로 업그레이드하기 전에 마이그레이션이 성공적으로 완료되었는지 확인하세요.
- `BackfillCiPipelineVariablesForBigintConversion` 백그라운드 마이그레이션은 `EnsureBackfillBigintIdIsCompleted` 배포 후 마이그레이션과 함께 완료됩니다. GitLab 16.0.0은 [배치된 백그라운드 마이그레이션](../background_migrations.md#check-for-pending-database-background-migrations)을 도입했으며, `ci_pipeline_variables` 테이블에서 `bigint` `id` 값을 [백필](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/118878)하기 위해 도입했습니다. 이 마이그레이션은 더 큰 GitLab 인스턴스에서 완료하는 데 오랜 시간이 걸릴 수 있습니다(한 경우 5천만 행을 처리하는 데 4시간 소요됨). 업그레이드 가동 중지 시간을 연장하지 않으려면 16.1로 업그레이드하기 전에 마이그레이션이 성공적으로 완료되었는지 확인하세요.

  `ci_pipeline_variables` 테이블의 크기를 [데이터베이스 콘솔](../../administration/troubleshooting/postgresql.md#start-a-database-console)에서 확인할 수 있습니다:

  ```sql
  select count(*) from ci_pipeline_variables;
  ```

### 소스에서 컴파일한 설치 {#self-compiled-installations-2}

- `puma.rb` 구성 파일에서 Puma 워커 킬러와 관련된 모든 설정을 제거해야 하며, 이는 [제거](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/118645)되었습니다. 자세한 내용은 [`puma.rb.example` 파일](https://gitlab.com/gitlab-org/gitlab/-/blob/16-0-stable-ee/config/puma.rb.example)을 참조하세요.
- 일반적으로 PgBouncer가 있는 환경의 백업은 [`GITLAB_BACKUP_`로 시작하는 변수를 설정하여 PgBouncer를 우회](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer)해야 합니다. 그러나 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/422163)로 인해 `gitlab-backup`는 오버라이드에 정의된 직접 연결 대신 PgBouncer를 통한 일반 데이터베이스 연결을 사용하며 데이터베이스 백업이 실패합니다. 해결 방법은 `pg_dump`를 직접 사용하는 것입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  모두                    | 없음     |
  | 16.0                    |  모두                    | 없음     |
  | 16.1                    |  모두                    | 없음     |
  | 16.2                    |  모두                    | 없음     |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Geo 설치 {#geo-installations-10}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

Geo를 사용하는 설치에 특정 정보가 적용됩니다:

- 일부 프로젝트 가져오기에서는 프로젝트 생성 시 wiki 리포지토리를 초기화하지 않습니다. [세부 정보 및 해결 방법](#wiki-repositories-not-initialized-on-project-creation)을 참조하세요.
- 프로젝트 설계의 SSF로의 마이그레이션으로 인해 [누락된 설계 리포지토리가 검증 실패로 잘못 표시](https://gitlab.com/gitlab-org/gitlab/-/issues/414279)되고 있습니다. 이 문제는 실제 복제/검증 실패의 결과가 아니라 Geo 내 누락된 리포지토리에 대한 잘못된 내부 상태이며, 로그에 오류가 발생하고 검증 진행도가 이러한 설계 리포지토리에 대해 실패 상태를 보고합니다. 프로젝트를 가져오지 않았더라도 이 문제의 영향을 받을 수 있습니다.
  - 영향을 받는 버전: GitLab 버전 16.1.0 - 16.1.2
  - 수정 사항이 포함된 버전: GitLab 16.1.3 이상.
- 작업 아티팩트가 객체 스토리지에 저장되도록 구성되고 `direct_upload`이 활성화된 경우 Geo에서 새 작업 아티팩트가 복제되지 않습니다. 이 버그는 GitLab 버전 16.1.4, 16.2.3, 16.3.0 이상에서 수정되었습니다.
  - 영향을 받는 버전: GitLab 버전 16.1.0 - 16.1.3 및 16.2.0 - 16.2.2.
  - 영향을 받는 버전을 실행하는 동안 동기화된 것처럼 나타나는 아티팩트가 실제로 보조 사이트에서 누락될 수 있습니다. 영향을 받는 아티팩트는 16.1.5, 16.2.5, 16.3.1, 16.4.0 이상으로 업그레이드할 때 자동으로 다시 동기화됩니다. 필요한 경우 [영향을 받는 작업 아티팩트를 수동으로 다시 동기화](https://gitlab.com/gitlab-org/gitlab/-/issues/419742#to-fix-data)할 수 있습니다.
  - 보조 사이트가 완전히 동기화된 경우에도 보조 사이트에서 LFS 객체를 복제하면 기본 사이트에서 다운로드합니다. [세부 정보 및 해결 방법](#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site)을 참조하세요.

#### 프로젝트 생성 시 Wiki 리포지토리가 초기화되지 않음 {#wiki-repositories-not-initialized-on-project-creation}

| 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
|-------------------------|-------------------------|----------|
| 15.11                   | 모두                     | 없음     |
| 16.0                    | 모두                     | 없음     |
| 16.1                    | 16.1.0 - 16.1.2         | 16.1.3 이상 |

일부 프로젝트 가져오기에서는 프로젝트 생성 시 wiki 리포지토리를 초기화하지 않습니다. 프로젝트 wiki의 SSF로의 마이그레이션 이후, [누락된 wiki 리포지토리가 검증 실패로 잘못 표시](https://gitlab.com/gitlab-org/gitlab/-/issues/409704)되고 있습니다. 이는 실제 복제/검증 실패의 결과가 아니라 Geo 내 누락된 리포지토리에 대한 잘못된 내부 상태이며, 로그에 오류가 발생하고 검증 진행도가 이러한 wiki 리포지토리에 대해 실패 상태를 보고합니다. 프로젝트를 가져오지 않았다면 이 문제의 영향을 받지 않습니다.

## 16.0.0 {#1600}

- `/etc/gitlab/gitlab.rb` 파일에 ASCII가 아닌 문자가 있으면 Sidekiq이 충돌합니다. [이슈 412767](https://gitlab.com/gitlab-org/gitlab/-/issues/412767#note_1404507549)의 해결 방법을 따라 이 문제를 해결할 수 있습니다.
- 기본적으로 Sidekiq 작업은 `default` 및 `mailers` 큐로만 라우팅되므로 모든 Sidekiq 프로세스도 해당 큐를 수신하여 모든 큐에서 모든 작업이 처리되도록 합니다. 이 동작은 [라우팅 규칙](../../administration/sidekiq/processing_specific_job_classes.md#routing-rules)을 구성한 경우에는 적용되지 않습니다.
- GitLab Docker 이미지를 실행하려면 Docker 20.10.10 이상이 필요합니다. 이전 버전은 [시작 시 오류를 발생](../../install/docker/troubleshooting.md#threaderror-cant-create-thread-operation-not-permitted)합니다.
- Azure 스토리지를 사용하는 컨테이너 레지스트리가 비어 있을 수 있으며 태그가 0입니다. [주요 변경 사항 지침](../deprecations.md#azure-storage-driver-defaults-to-the-correct-root-prefix)을 따라 이 문제를 해결할 수 있습니다.
- 일반적으로 PgBouncer가 있는 환경의 백업은 [`GITLAB_BACKUP_`로 시작하는 변수를 설정하여 PgBouncer를 우회](../../administration/backup_restore/backup_gitlab.md#bypassing-pgbouncer)해야 합니다. 그러나 [문제](https://gitlab.com/gitlab-org/gitlab/-/issues/422163)로 인해 `gitlab-backup`는 오버라이드에 정의된 직접 연결 대신 PgBouncer를 통한 일반 데이터베이스 연결을 사용하며 데이터베이스 백업이 실패합니다. 해결 방법은 `pg_dump`를 직접 사용하는 것입니다.

  **영향을 받는 릴리스**:

  | 영향을 받는 마이너 릴리스 | 영향을 받는 패치 릴리스 | 다음에서 수정됨 |
  | ----------------------- | ----------------------- | -------- |
  | 15.11                   |  모두                    | 없음     |
  | 16.0                    |  모두                    | 없음     |
  | 16.1                    |  모두                    | 없음     |
  | 16.2                    |  모두                    | 없음     |
  | 16.3                    |  모두                    | 없음     |
  | 16.4                    |  모두                    | 없음     |
  | 16.5                    |  모두                    | 없음     |
  | 16.6                    |  모두                    | 없음     |
  | 16.7                    |  16.7.0 - 16.7.6        | 16.7.7   |
  | 16.8                    |  16.8.0 - 16.8.3        | 16.8.4   |

### Linux 패키지 설치 {#linux-package-installations-8}

특정 정보는 Linux 패키지 설치에 적용됩니다:

- PostgreSQL 12의 바이너리가 제거되었습니다.

  업그레이드하기 전에 Linux 패키지 설치 관리자는 설치가 [PostgreSQL 13](https://docs.gitlab.com/omnibus/settings/database/#upgrade-packaged-postgresql-server)을 사용 중인지 확인해야 합니다.
- GitLab과 함께 번들된 Grafana는 더 이상 사용되지 않으며 더 이상 지원되지 않습니다. GitLab 16.3에서 제거됩니다.
- 이는 `openssh-server`을 `1:8.9p1-3`로 업그레이드합니다.

  `ssh-keyscan -t rsa`을 사용하여 이전 OpenSSH 클라이언트로 공개 키 정보를 얻는 것은 더 이상 가능하지 않습니다. [OpenSSH 8.7 릴리스 정보](https://www.openssh.org/txt/release-8.7)에 나열된 사용 중단으로 인해.

  해결 방법은 다른 키 유형을 사용하거나 클라이언트 OpenSSH를 8.7 이상의 버전으로 업그레이드하는 것입니다.
- [Praefect 구성을 새 구조로 마이그레이션](#praefect-configuration-structure-change)하여 모든 `praefect['..']` 설정이 GitLab 16.0 이상에서 계속 작동하는지 확인하세요.
- [Gitaly 구성을 새 구조로 마이그레이션](#gitaly-configuration-structure-change)하여 모든 `gitaly['..']` 설정이 GitLab 16.0 이상에서 계속 작동하는지 확인하세요.

### 만료되지 않는 액세스 토큰 {#non-expiring-access-tokens}

만료 날짜가 없는 액세스 토큰은 무한정 유효하며, 액세스 토큰이 유출된 경우 보안 위험입니다.

GitLab 16.0 이상으로 업그레이드하면 만료 날짜가 없는 모든 [개인](../../user/profile/personal_access_tokens.md), [프로젝트](../../user/project/settings/project_access_tokens.md) 또는 [그룹](../../user/group/settings/group_access_tokens.md) 액세스 토큰이 업그레이드 날짜로부터 1년으로 자동 설정됩니다.

이 자동 만료 날짜가 적용되기 전에 다음을 수행하여 중단을 최소화해야 합니다:

1. [만료 날짜가 없는 액세스 토큰 확인](../../administration/raketasks/tokens/_index.md#find-tokens-the-rake-tasks-do-not-report).
1. [해당 토큰에 만료 날짜 부여](../../administration/raketasks/tokens/_index.md#extend-expiration-dates).

자세한 내용은 다음을 참조하세요:

- [사용 중단 및 제거 설명서](../deprecations.md#non-expiring-access-tokens).
- [사용 중단 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/369122).

### Geo 설치 {#geo-installations-11}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

Geo를 사용하는 설치에 특정 정보가 적용됩니다:

- 일부 프로젝트 가져오기에서는 프로젝트 생성 시 wiki 리포지토리를 초기화하지 않습니다. [세부 정보 및 해결 방법](#wiki-repositories-not-initialized-on-project-creation)을 참조하세요.
- 보조 사이트가 완전히 동기화된 경우에도 보조 사이트에서 LFS 객체를 복제하면 기본 사이트에서 다운로드합니다. [세부 정보 및 해결 방법](#cloning-lfs-objects-from-secondary-site-downloads-from-the-primary-site)을 참조하세요.

### Gitaly 구성 구조 변경 {#gitaly-configuration-structure-change}

Linux 패키지의 Gitaly 구성 구조는 GitLab 16.0에서 [변경](https://gitlab.com/gitlab-org/gitaly/-/issues/4467)되어 소스에서 컴파일한 설치에 사용되는 Gitaly 구성 구조와 일치합니다.

이 변경의 결과로 `gitaly['configuration']` 아래의 단일 해시가 대부분의 Gitaly 구성을 보유합니다. 일부 `gitaly['..']` 구성 옵션은 GitLab 16.0 이상에서 계속 사용됩니다:

- `enable`
- `dir`
- `bin_path`
- `env_directory`
- `env`
- `open_files_ulimit`
- `consul_service_name`
- `consul_service_meta`

기존 구성을 새 구조 아래로 이동하여 마이그레이션하세요. `git_data_dirs`은 [GitLab 18.0까지](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/8786) 지원됩니다. 새 구조는 GitLab 15.10부터 지원됩니다.

**새 구조로 마이그레이션**

> [!warning]
> Gitaly Cluster(Praefect)를 실행 중인 경우, [Praefect를 새 구성 구조로 먼저 마이그레이션](#praefect-configuration-structure-change)하세요. 이 변경이 테스트되면 Gitaly 노드로 진행하세요. Gitaly가 구성 구조 변경의 일부로 잘못 구성된 경우, [리포지토리 검증](../../administration/gitaly/praefect/configure.md#repository-verification)이 [Gitaly Cluster(Praefect)가 작동하는 데 필요한 메타데이터를 삭제](https://gitlab.com/gitlab-org/gitaly/-/issues/5529)합니다. 구성 실수로부터 보호하기 위해 Praefect에서 리포지토리 검증을 일시적으로 비활성화하세요.

1. Gitaly Cluster(Praefect)를 실행 중인 경우, 모든 Praefect 노드에서 리포지토리 검증이 비활성화되었는지 확인하세요. `verification_interval: 0`을 구성하고 `gitlab-ctl reconfigure`로 적용하세요.
1. 구성에 새 구조를 적용하려면:
   1. `...`을 이전 키의 값으로 바꾸세요.
   1. `git_data_dirs`를 대체하기 위해 `storage`을 구성할 때, 다음 스크립트에서 설명한 대로 `/repositories`을 `path`의 값에 추가하세요. 이 단계를 완료하지 않으면 구성이 수정될 때까지 Git 리포지토리에 액세스할 수 없습니다. 이 잘못된 구성으로 인해 메타데이터 삭제가 발생할 수 있습니다.
   1. 이전에 값을 구성하지 않은 키를 건너뛰세요.
   1. 권장하는 방식입니다. 키를 다시 정렬하거나 추가 키를 추가할 때 해시가 유효하도록 유지되도록 모든 해시 키에 대해 후행 쉼표를 포함하세요.
1. `gitlab-ctl reconfigure`로 변경을 적용하세요.
1. GitLab에서 Git 리포지토리 기능을 테스트하세요.
1. 마이그레이션 후 구성에서 이전 키를 제거한 후 `gitlab-ctl reconfigure`을 다시 실행하세요.
1. 권장됨, Gitaly Cluster(Praefect)를 실행 중인 경우. Praefect [리포지토리 검증](../../administration/gitaly/praefect/configure.md#repository-verification)을 `verification_interval: 0`를 제거하여 다시 시작하세요.

새 구조는 다음 스크립트에 문서화되며 이전 키는 새 키 위의 주석에 설명되어 있습니다.

> [!warning]
> `storage`로의 업데이트를 다시 확인하세요. `/repositories`을 `path`의 값에 추가해야 합니다.

```ruby
gitaly['configuration'] = {
  # gitaly['socket_path']
  socket_path: ...,
  # gitaly['runtime_dir']
  runtime_dir: ...,
  # gitaly['listen_addr']
  listen_addr: ...,
  # gitaly['prometheus_listen_addr']
  prometheus_listen_addr: ...,
  # gitaly['tls_listen_addr']
  tls_listen_addr: ...,
  tls: {
    # gitaly['certificate_path']
    certificate_path: ...,
    # gitaly['key_path']
    key_path: ...,
  },
  # gitaly['graceful_restart_timeout']
  graceful_restart_timeout: ...,
  logging: {
    # gitaly['logging_level']
    level: ...,
    # gitaly['logging_format']
    format: ...,
    # gitaly['logging_sentry_dsn']
    sentry_dsn: ...,
    # gitaly['logging_ruby_sentry_dsn']
    ruby_sentry_dsn: ...,
    # gitaly['logging_sentry_environment']
    sentry_environment: ...,
    # gitaly['log_directory']
    dir: ...,
  },
  prometheus: {
    # gitaly['prometheus_grpc_latency_buckets']. The old value was configured as a string
    # such as '[0, 1, 2]'. The new value must be an array like [0, 1, 2].
    grpc_latency_buckets: ...,
  },
  auth: {
    # gitaly['auth_token']
    token: ...,
    # gitaly['auth_transitioning']
    transitioning: ...,
  },
  git: {
    # gitaly['git_catfile_cache_size']
    catfile_cache_size: ...,
    # gitaly['git_bin_path']
    bin_path: ...,
    # gitaly['use_bundled_git']
    use_bundled_binaries: ...,
    # gitaly['gpg_signing_key_path']
    signing_key: ...,
    # gitaly['gitconfig']. This is still an array but the type of the elements have changed.
    config: [
      {
        # Previously the elements contained 'section', and 'subsection' in addition to 'key'. Now
        # these all should be concatenated into just 'key', separated by dots. For example,
        # {section: 'first', subsection: 'middle', key: 'last', value: 'value'}, should become
        # {key: 'first.middle.last', value: 'value'}.
        key: ...,
        value: ...,
      },
    ],
  },
  # Storage was previously configured with the gitaly['storage'] or 'git_data_dirs' parameters. Use
  # the following instructions to migrate. For 'git_data_dirs', migrate only the 'path' to the
  # gitaly['configuration'] and leave the rest untouched.
  storage: [
    {
      # gitaly['storage'][<index>]['name']
      #
      # git_data_dirs[<name>]. The storage name was configured as a key in the map.
      name: ...,
      # gitaly['storage'][<index>]['path']
      #
      # git_data_dirs[<name>]['path']. Use the value from git_data_dirs[<name>]['path'] and append '/repositories' to it.
      #
      # For example, if the path in 'git_data_dirs' was '/var/opt/gitlab/git-data', use
      # '/var/opt/gitlab/git-data/repositories'. The '/repositories' extension was automatically
      # appended to the path configured in `git_data_dirs`.
      path: ...,
    },
  ],
  hooks: {
    # gitaly['custom_hooks_dir']
    custom_hooks_dir: ...,
  },
  daily_maintenance: {
    # gitaly['daily_maintenance_disabled']
    disabled: ...,
    # gitaly['daily_maintenance_start_hour']
    start_hour: ...,
    # gitaly['daily_maintenance_start_minute']
    start_minute: ...,
    # gitaly['daily_maintenance_duration']
    duration: ...,
    # gitaly['daily_maintenance_storages']
    storages: ...,
  },
  cgroups: {
    # gitaly['cgroups_mountpoint']
    mountpoint: ...,
    # gitaly['cgroups_hierarchy_root']
    hierarchy_root: ...,
    # gitaly['cgroups_memory_bytes']
    memory_bytes: ...,
    # gitaly['cgroups_cpu_shares']
    cpu_shares: ...,
    repositories: {
      # gitaly['cgroups_repositories_count']
      count: ...,
      # gitaly['cgroups_repositories_memory_bytes']
      memory_bytes: ...,
      # gitaly['cgroups_repositories_cpu_shares']
      cpu_shares: ...,
    }
  },
  # gitaly['concurrency']. While the structure is the same, the string keys in the array elements
  # should be replaced by symbols as elsewhere. {'key' => 'value'}, should become {key: 'value'}.
  concurrency: ...,
  # gitaly['rate_limiting']. While the structure is the same, the string keys in the array elements
  # should be replaced by symbols as elsewhere. {'key' => 'value'}, should become {key: 'value'}.
  rate_limiting: ...,
  pack_objects_cache: {
    # gitaly['pack_objects_cache_enabled']
    enabled: ...,
    # gitaly['pack_objects_cache_dir']
    dir: ...,
    # gitaly['pack_objects_cache_max_age']
    max_age: ...,
  }
}
```

### Praefect 구성 구조 변경 {#praefect-configuration-structure-change}

Linux 패키지의 Praefect 구성 구조는 GitLab 16.0에서 [변경](https://gitlab.com/gitlab-org/gitaly/-/issues/4467)되어 소스에서 컴파일한 설치에 사용되는 Praefect 구성 구조와 일치합니다.

이 변경의 결과로 `praefect['configuration']` 아래의 단일 해시가 대부분의 Praefect 구성을 보유합니다. 일부 `praefect['..']` 구성 옵션은 GitLab 16.0 이상에서 계속 사용됩니다:

- `enable`
- `dir`
- `log_directory`
- `env_directory`
- `env`
- `wrapper_path`
- `auto_migrate`
- `consul_service_name`

기존 구성을 새 구조 아래로 이동하여 마이그레이션하세요. 새 구조는 GitLab 15.9부터 지원됩니다.

**새 구조로 마이그레이션**

> [!warning]
> Praefect를 새 구성 구조로 먼저 마이그레이션하세요. 이 변경 사항을 테스트한 후 [Gitaly 노드로 진행](#gitaly-configuration-structure-change)하세요. Gitaly가 구성 구조 변경의 일부로 잘못 구성된 경우, [리포지토리 검증](../../administration/gitaly/praefect/configure.md#repository-verification)이 [Gitaly Cluster(Praefect)가 작동하는 데 필요한 메타데이터를 삭제](https://gitlab.com/gitlab-org/gitaly/-/issues/5529)합니다. 구성 실수로부터 보호하기 위해 Praefect에서 리포지토리 검증을 일시적으로 비활성화하세요.

1. 새 구조를 구성에 적용할 때:
   - `...`을 이전 키의 값으로 바꾸세요.
   - `verification_interval: 0`을(를) 사용하여 리포지토리 검증을 비활성화하세요. 다음 스크립트에 표시된 대로 합니다.
   - 이전에 값을 구성하지 않은 키를 건너뛰세요.
   - 권장하는 방식입니다. 키를 다시 정렬하거나 추가 키를 추가할 때 해시가 유효하도록 유지되도록 모든 해시 키에 대해 후행 쉼표를 포함하세요.
1. `gitlab-ctl reconfigure`로 변경을 적용하세요.
1. GitLab에서 Git 리포지토리 기능을 테스트하세요.
1. 마이그레이션 후 구성에서 이전 키를 제거한 후 `gitlab-ctl reconfigure`을 다시 실행하세요.

새 구조는 다음 스크립트에 문서화되며 이전 키는 새 키 위의 주석에 설명되어 있습니다.

```ruby
praefect['configuration'] = {
  # praefect['listen_addr']
  listen_addr: ...,
  # praefect['socket_path']
  socket_path: ...,
  # praefect['prometheus_listen_addr']
  prometheus_listen_addr: ...,
  # praefect['tls_listen_addr']
  tls_listen_addr: ...,
  # praefect['separate_database_metrics']
  prometheus_exclude_database_from_default_metrics: ...,
  auth: {
    # praefect['auth_token']
    token: ...,
    # praefect['auth_transitioning']
    transitioning: ...,
  },
  logging: {
    # praefect['logging_format']
    format: ...,
    # praefect['logging_level']
    level: ...,
  },
  failover: {
    # praefect['failover_enabled']
    enabled: ...,
  },
  background_verification: {
    # praefect['background_verification_delete_invalid_records']
    delete_invalid_records: ...,
    # praefect['background_verification_verification_interval']
    #
    # IMPORTANT:
    # As part of reconfiguring Praefect, disable this feature.
    # Read about this as described previously.
    #
    verification_interval: 0,
  },
  reconciliation: {
    # praefect['reconciliation_scheduling_interval']
    scheduling_interval: ...,
    # praefect['reconciliation_histogram_buckets']. The old value was configured as a string
    # such as '[0, 1, 2]'. The new value must be an array like [0, 1, 2].
    histogram_buckets: ...,
  },
  tls: {
    # praefect['certificate_path']
    certificate_path: ...,
   # praefect['key_path']
    key_path: ...,
  },
  database: {
    # praefect['database_host']
    host: ...,
    # praefect['database_port']
    port: ...,
    # praefect['database_user']
    user: ...,
    # praefect['database_password']
    password: ...,
    # praefect['database_dbname']
    dbname: ...,
    # praefect['database_sslmode']
    sslmode: ...,
    # praefect['database_sslcert']
    sslcert: ...,
    # praefect['database_sslkey']
    sslkey: ...,
    # praefect['database_sslrootcert']
    sslrootcert: ...,
    session_pooled: {
      # praefect['database_direct_host']
      host: ...,
      # praefect['database_direct_port']
      port: ...,
      # praefect['database_direct_user']
      user: ...,
      # praefect['database_direct_password']
      password: ...,
      # praefect['database_direct_dbname']
      dbname: ...,
      # praefect['database_direct_sslmode']
      sslmode: ...,
      # praefect['database_direct_sslcert']
      sslcert: ...,
      # praefect['database_direct_sslkey']
      sslkey: ...,
      # praefect['database_direct_sslrootcert']
      sslrootcert: ...,
    }
  },
  sentry: {
    # praefect['sentry_dsn']
    sentry_dsn: ...,
    # praefect['sentry_environment']
    sentry_environment: ...,
  },
  prometheus: {
    # praefect['prometheus_grpc_latency_buckets']. The old value was configured as a string
    # such as '[0, 1, 2]'. The new value must be an array like [0, 1, 2].
    grpc_latency_buckets: ...,
  },
  # praefect['graceful_stop_timeout']
  graceful_stop_timeout: ...,
  # praefect['virtual_storages']. The old value was a hash map but the new value is an array.
  virtual_storage: [
    {
      # praefect['virtual_storages'][VIRTUAL_STORAGE_NAME]. The name was previously the key in
      # the 'virtual_storages' hash.
      name: ...,
      # praefect['virtual_storages'][VIRTUAL_STORAGE_NAME]['nodes'][NODE_NAME]. The old value was a hash map
      # but the new value is an array.
      node: [
        {
          # praefect['virtual_storages'][VIRTUAL_STORAGE_NAME]['nodes'][NODE_NAME]. Use NODE_NAME key as the
          # storage.
          storage: ...,
          # praefect['virtual_storages'][VIRTUAL_STORAGE_NAME]['nodes'][NODE_NAME]['address'].
          address: ...,
          # praefect['virtual_storages'][VIRTUAL_STORAGE_NAME]['nodes'][NODE_NAME]['token'].
          token: ...,
        },
      ],
    }
  ]
}
```

### 두 번째 데이터베이스 연결 비활성화 {#disable-the-second-database-connection}

GitLab 16.0에서는 기본적으로 같은 PostgreSQL 데이터베이스를 가리키는 두 개의 데이터베이스 연결을 사용합니다.

PostgreSQL을 `max_connections`의 더 큰 값으로 구성해야 할 수 있습니다. [이것이 필요한지 확인하는 Rake 작업이 있습니다](https://docs.gitlab.com/omnibus/settings/database/#configuring-multiple-database-connections).

PgBouncer를 배포한 경우:

- PgBouncer 서버의 프론트엔드 풀(파일 핸들 제한 및 `max_client_conn` 포함)을 [더 크게 조정해야 할 수 있습니다](../../administration/postgresql/pgbouncer.md#fine-tuning).
- PgBouncer는 단일 스레드입니다. 추가 연결이 단일 PgBouncer 데몬을 완전히 포화시킬 수 있습니다. 모든 규모의 GitLab 배포에 대해 [3개의 부하 분산 PgBouncer 서버를 실행하는 것을 권장합니다](../../administration/reference_architectures/5k_users.md#configure-pgbouncer). 이는 부분적으로 이 문제를 해결하기 위함입니다.

단일 데이터베이스 연결로 전환하려면 설치 유형에 따른 지침을 따르세요:

{{< tabs >}}

{{< tab title="Linux 패키지 및 Docker" >}}

1. `/etc/gitlab/gitlab.rb`에 이 설정을 추가하세요:

   ```ruby
   gitlab_rails['databases']['ci']['enable'] = false
   ```

1. `gitlab-ctl reconfigure`를 실행합니다.

다중 노드 환경에서는 모든 Rails 및 Sidekiq 노드에서 이 설정을 업데이트해야 합니다.

{{< /tab >}}

{{< tab title="Helm 차트(Kubernetes)" >}}

`ci.enabled` 키를 `false`로 설정하세요:

```yaml
global:
  psql:
    ci:
      enabled: false
```

{{< /tab >}}

{{< tab title="Self-compiled(소스)" >}}

`config/database.yml`에서 `ci:` 섹션을 제거하세요.

{{< /tab >}}

{{< /tabs >}}

## 장시간 실행되는 사용자 유형 데이터 변경 {#long-running-user-type-data-change}

GitLab 16.0은 `users` 테이블에 많은 레코드가 있는 대규모 GitLab 인스턴스의 필수 업그레이드 지점입니다.

임계값은 30,000명의 사용자이며, 다음을 포함합니다:

- 활성, 차단됨, 승인 대기 중을 포함한 모든 상태의 개발자 및 기타 사용자입니다.
- 프로젝트 및 그룹 액세스 토큰의 봇 계정입니다.

GitLab 16.0은 [배치 백그라운드 마이그레이션](../background_migrations.md#check-for-pending-database-background-migrations)을(를) 도입하여 [`user_type` 값을 `NULL`에서 `0`로 마이그레이션](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/115849)합니다. 이 마이그레이션은 대규모 GitLab 인스턴스에서 완료하는 데 여러 날이 걸릴 수 있습니다. 16.1.0 이상으로 업그레이드하기 전에 마이그레이션이 성공적으로 완료되었는지 확인하세요.

GitLab 16.1은 `FinalizeUserTypeMigration` 마이그레이션을 도입하며, 16.0 `MigrateHumanUserType` 백그라운드 마이그레이션이 완료되도록 보장하고, 완료되지 않은 경우 업그레이드 중에 16.0 변경 사항을 동기식으로 실행합니다.

GitLab 16.2는 [`NOT NULL` 데이터베이스 제약 조건을 구현](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/122454)하며, 16.0 마이그레이션이 완료되지 않으면 실패합니다.

16.0을 건너뛴 경우(또는 16.0 마이그레이션이 완료되지 않은 경우) 이후 Linux 패키지(Omnibus) 및 Docker 업그레이드가 1시간 후에 실패할 수 있습니다:

```plaintext
FATAL: Mixlib::ShellOut::CommandTimeout: rails_migration[gitlab-rails]
[..]
Mixlib::ShellOut::CommandTimeout: Command timed out after 3600s:
```

[이 문제에 대한 수정-전방 해결 방법이 있습니다](../package/package_troubleshooting.md#error-command-timed-out-after-3600s).

해결 방법이 데이터베이스 변경을 완료하는 동안 GitLab은 `500` 오류를 생성하는 사용 불가능한 상태에 있을 수 있습니다. 오류는 Sidekiq 및 Puma가 데이터베이스 스키마와 호환되지 않는 애플리케이션 코드를 실행하기 때문에 발생합니다.

해결 방법 프로세스의 끝에서 Sidekiq 및 Puma가 다시 시작되어 이 문제를 해결합니다.

## 16.2 이상으로 업그레이드할 때 정의되지 않은 열 오류 {#undefined-column-error-upgrading-to-162-or-later}

GitLab 15.11의 버그로 인해 GitLab Self-Managed 인스턴스의 데이터베이스 변경이 잘못 비활성화되었습니다. 자세한 내용은 [이슈 408835](https://gitlab.com/gitlab-org/gitlab/-/issues/408835)를 참조하세요.

GitLab 인스턴스가 먼저 15.11.0, 15.11.1 또는 15.11.2로 업그레이드된 경우 데이터베이스 스키마가 올바르지 않으며 GitLab 16.2 이상으로 업그레이드하면 오류가 발생합니다. 데이터베이스 변경을 위해서는 이전 수정 사항이 준비되어 있어야 합니다:

```plaintext
PG::UndefinedColumn: ERROR:  column "id_convert_to_bigint" of relation "ci_build_needs" does not exist
LINE 1: ...db_config_name:main*/ UPDATE "ci_build_needs" SET "id_conver...
```

GitLab 15.11.3은 이 버그에 대한 수정을 배포했지만 이미 이전 15.11 릴리스를 실행하는 인스턴스의 문제는 해결하지 않습니다.

인스턴스가 영향을 받는지 확실하지 않으면 [데이터베이스 콘솔](../../administration/troubleshooting/postgresql.md#start-a-database-console)에서 열을 확인하세요:

```sql
select pg_typeof (id_convert_to_bigint) from public.ci_build_needs limit 1;
```

해결 방법이 필요한 경우 이 쿼리가 실패합니다:

```plaintext
ERROR:  column "id_convert_to_bigintd" does not exist
LINE 1: select pg_typeof (id_convert_to_bigintd) from public.ci_buil...
```

영향을 받지 않은 인스턴스는 다음을 반환합니다:

```plaintext
 pg_typeof
-----------
 bigint
```

이 문제에 대한 해결 방법은 GitLab 인스턴스의 데이터베이스 스키마가 최근에 생성되었는지 여부에 따라 다릅니다:

| 설치 버전 | 해결 방법 |
| -------------------- | ---------- |
| 15.9 이하      | [15.9](#workaround-instance-created-with-159-or-earlier) |
| 15.10                | [15.10](#workaround-instance-created-with-1510) |
| 15.11                | [15.11](#workaround-instance-created-with-1511) |

대부분의 인스턴스는 15.9 절차를 사용해야 합니다. 매우 새로운 인스턴스만 15.10 또는 15.11 절차가 필요합니다. 백업 및 복원을 사용하여 GitLab을 마이그레이션한 경우 데이터베이스 스키마는 원본 인스턴스에서 나옵니다. 원본 인스턴스를 기반으로 해결 방법을 선택하세요.

다음 섹션의 명령은 Linux 패키지 설치용이며 다른 설치 유형과는 다릅니다:

{{< tabs >}}

{{< tab title="Docker" >}}

- `sudo`을(를) 생략하세요
- GitLab 컨테이너에 접속하여 동일한 명령을 실행하세요:

  ```shell
  docker exec -it <container-id> bash
  ```

{{< /tab >}}

{{< tab title="Self-compiled(소스)" >}}

- `sudo gitlab-rake` 대신 `sudo -u git -H bundle exec rake RAILS_ENV=production`을(를) 사용하세요
- [PostgreSQL 데이터베이스 콘솔](../../administration/troubleshooting/postgresql.md#start-a-database-console)에서 SQL을 실행하세요

{{< /tab >}}

{{< tab title="Helm 차트(Kubernetes)" >}}

- `sudo`을(를) 생략하세요.
- `toolbox` 팟(Pod)에 접속하여 Rake 명령을 실행하세요: `gitlab-rake`은(는) `PATH`에 없는 경우 `/usr/local/bin`에 있습니다.
  - 자세한 내용은 [Kubernetes 치트 시트](https://docs.gitlab.com/charts/troubleshooting/kubernetes_cheat_sheet/#gitlab-specific-kubernetes-information)를 참조하세요.
- [PostgreSQL 데이터베이스 콘솔](../../administration/troubleshooting/postgresql.md#start-a-database-console)에서 SQL을 실행하세요

{{< /tab >}}

{{< /tabs >}}

### 해결 방법: 15.9 이하로 생성된 인스턴스 {#workaround-instance-created-with-159-or-earlier}

```shell
# Restore schema
sudo gitlab-psql -c "DELETE FROM schema_migrations WHERE version IN ('20230130175512', '20230130104819');"
sudo gitlab-rake db:migrate:up VERSION=20230130175512
sudo gitlab-rake db:migrate:up VERSION=20230130104819

# Re-schedule background migrations
sudo gitlab-rake db:migrate:down VERSION=20230130202201
sudo gitlab-rake db:migrate:down VERSION=20230130110855
sudo gitlab-rake db:migrate:up VERSION=20230130202201
sudo gitlab-rake db:migrate:up VERSION=20230130110855
```

### 해결 방법: 15.10으로 생성된 인스턴스 {#workaround-instance-created-with-1510}

```shell
# Restore schema for sent_notifications
sudo gitlab-psql -c "DELETE FROM schema_migrations WHERE version = '20230130175512';"
sudo gitlab-rake db:migrate:up VERSION=20230130175512

# Re-schedule background migration for sent_notifications
sudo gitlab-rake db:migrate:down VERSION=20230130202201
sudo gitlab-rake db:migrate:up VERSION=20230130202201

# Restore schema for ci_build_needs
sudo gitlab-rake db:migrate:down VERSION=20230321163547
sudo gitlab-psql -c "INSERT INTO schema_migrations (version) VALUES ('20230321163547');"
```

### 해결 방법: 15.11로 생성된 인스턴스 {#workaround-instance-created-with-1511}

```shell
# Restore schema for sent_notifications
sudo gitlab-rake db:migrate:down VERSION=20230411153310
sudo gitlab-psql -c "INSERT INTO schema_migrations (version) VALUES ('20230411153310');"

# Restore schema for ci_build_needs
sudo gitlab-rake db:migrate:down VERSION=20230321163547
sudo gitlab-psql -c "INSERT INTO schema_migrations (version) VALUES ('20230321163547');"
```
