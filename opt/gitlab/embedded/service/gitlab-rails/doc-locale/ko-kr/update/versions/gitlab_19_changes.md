---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: GitLab 19 업그레이드 노트
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

이 페이지에는 GitLab 19의 마이너 및 패치 버전 업그레이드 정보가 포함되어 있습니다. 다음 항목에 대한 지침을 검토하세요:

- 설치 유형
- 현재 버전과 대상 버전 사이의 모든 버전

GitLab Runner를 GitLab과 함께 업그레이드할 계획이 있으면 GitLab Runner [CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/main/CHANGELOG.md)를 검토하여 설정에 영향을 줄 수 있는 변경 사항을 확인하세요.

Helm 차트 설치에 대한 추가 정보는 [Helm 차트 10.0 업그레이드 노트](https://docs.gitlab.com/charts/releases/10_0/)를 참조하세요.

## 필수 업그레이드 중지 {#required-upgrade-stops}

인스턴스 관리자에게 예측 가능한 업그레이드 일정을 제공하기 위해 필수 업그레이드 중지는 다음 버전에서 발생합니다:

- `19.2`
- `19.5`
- `19.8`
- `19.11`

## 업그레이드 참고사항 참고 {#upgrade-notes-reference}

다음은 각 마이너 GitLab 버전에 대한 업그레이드 참고사항의 참고 목록입니다. 각 목록 항목은 추가 정보를 포함하는 특정 섹션을 가리킵니다.

`(Geo)` 또는 `(Linux package)`와 같은 설치 방법으로 표시된 항목은 해당 방법에만 적용됩니다. 다른 모든 항목은 모든 설치 방법에 적용됩니다.

### 19.5로 업그레이드 {#upgrade-to-195}

GitLab 19.5로 업그레이드하기 전에 다음을 검토하세요:

- [19.5.0] - [Kubernetes용 Agent 주소가 기본적으로 기본 gRPC로 설정](#agent-for-kubernetes-address-defaults-to-native-grpc) (Linux 패키지, Helm 차트)
- [19.5.0] - [Duo Agent Platform 체크포인트 마이그레이션](#duo-agent-platform-checkpoint-migration)
- [19.5.0] - [Geo 업로드 체크섬이 업로드 유형별로 기본적으로 활성화](#geo-upload-checksumming-by-upload-type-enabled-by-default) (Geo)

### 19.4로 업그레이드 {#upgrade-to-194}

GitLab 19.4로 업그레이드하기 전에 다음을 검토하세요:

- [19.4.0] - [Geo SSH 프록시가 기본적으로 활성화](#geo-ssh-proxying-enabled-by-default)
- [19.4.0] - [`SKIP_REPOSITORIES_PATHS`를 사용하는 복원이 기존 리포지토리 유지](#restores-that-use-skip_repositories_paths-keep-existing-repositories)
- [19.4.0] - [신뢰할 수 없는 그룹 SAML ID가 신뢰할 수 있는 것으로 복원](#untrusted-group-saml-identities-are-restored-to-trusted)

### 19.3으로 업그레이드 {#upgrade-to-193}

GitLab 19.3으로 업그레이드하기 전에 다음을 검토하세요:

- [19.3.0 - 19.3.1] - [새 그룹에서는 머지 요청 API 호출에 SHA 매개변수 필요](#new-groups-require-sha-parameter-for-merge-requests-api-calls)
- [19.3.0] - [Geo 검증 동시성 제한이 글로벌 합계로 적용](#geo-verification-concurrency-limit-applied-as-a-global-total)

### 19.2로 업그레이드 {#upgrade-to-192}

GitLab 19.2로 업그레이드하기 전에 다음을 검토하세요:

- [19.2.0] - [GitLab Duo Self-Hosted AI Gateway URL이 업그레이드 후 초기화](#gitlab-duo-self-hosted-ai-gateway-urls-cleared-after-upgrade) (Linux 패키지)
- [19.2.0 - 19.2.5] - [새 그룹에서는 머지 요청 API 호출에 SHA 매개변수 필요](#new-groups-require-sha-parameter-for-merge-requests-api-calls)

### 19.0으로 업그레이드 {#upgrade-to-190}

GitLab 19.0으로 업그레이드하기 전에 다음을 검토하세요:

- [19.0.0 - 19.0.1] - [컨테이너 레지스트리 메타데이터 데이터베이스가 기본적으로 선호도 모드로 활성화](#container-registry-metadata-database-enabled-by-default-in-prefer-mode) (Linux 패키지, 자체 컴파일됨)
- [19.0.0] - [컨테이너 레지스트리 S3 스토리지 드라이버가 s3_v2로 교체](#container-registry-s3-storage-driver-replaced-by-s3_v2) (Linux 패키지, 자체 컴파일됨)
- [19.0.0 - 19.1.0] - [Linux 패키지 RPM 설치 시 `.agents` 및 `.claude` 디렉토리가 고아 상태](#orphaned-agents-and-claude-directories-on-linux-package-rpm-installs) (Linux 패키지)
- [19.0.0] - [PostgreSQL 17 최소 요구 사항](#postgresql-17-minimum-requirement)
- [19.0.0] - [웹훅 페이로드 타임스탬프가 ISO 8601 형식으로 변경](#webhook-payload-timestamps-changed-to-iso-8601-format)
- [19.0.0] - [Ubuntu 20.04에 대한 Linux 패키지 지원 중단](#linux-package-support-for-ubuntu-2004-discontinued) (Linux 패키지)
- [19.0.0] - [Redis 6 지원 제거](#redis-6-support-removed) (Linux 패키지)
- [19.0.0] - [Linux 패키지에서 Mattermost 제거](#mattermost-removed-from-the-linux-package) (Linux 패키지)
- [19.0.0] - [SUSE 배포판에 대한 Linux 패키지 지원 중단](#linux-package-support-for-suse-distributions-discontinued) (Linux 패키지)
- [19.0.0] - [Linux 패키지 및 GitLab Helm 차트에서 Spamcheck 제거](#spamcheck-removed-from-linux-package-and-gitlab-helm-chart) (Linux 패키지, Helm 차트)
- [19.0.0] - [NGINX Ingress가 Gateway API 및 Envoy Gateway로 교체](#nginx-ingress-replaced-by-gateway-api-with-envoy-gateway) (Helm 차트)
- [19.0.0] - [GitLab Helm 차트에서 번들로 제공되는 PostgreSQL, Redis 및 MinIO 제거](#bundled-postgresql-redis-and-minio-removed-from-gitlab-helm-chart) (Helm 차트)
- [19.0.0 - 19.0.1] - [Geo 컨테이너 리포지토리 동기화가 OCI 이미지 인덱스 태그를 자동으로 건너뜀](#geo-container-repository-sync-silently-skips-oci-image-index-tags) (Geo)
- [16.0.0 - 19.0.1] - [Geo 디자인 관리 복제 `NoMethodError` 프로젝트가 `nil`일 때](#geo-design-management-replication-nomethoderror-when-project-is-nil) (Geo)

## 업그레이드 참고사항 {#upgrade-notes}

GitLab 19의 구체적인 업그레이드 노트입니다.

### Kubernetes용 Agent 주소가 기본적으로 기본 gRPC로 설정 {#agent-for-kubernetes-address-defaults-to-native-grpc}

- 영향을 받음: Linux 패키지, Helm 차트
- 영향을 받는 버전: 19.5.0 이상

GitLab 19.5에서 Linux 패키지와 GitLab Helm 차트는 기본적으로 WebSocket 주소 대신 Kubernetes용 Agent에 기본 gRPC 주소를 광고합니다. 주소는 Agent 설치 지침에 표시되고 `gitlab_kas.external_url`에 저장됩니다.

- Linux 패키지: `wss://gitlab.example.com/-/kubernetes-agent/` 대신 `grpcs://gitlab.example.com`, `external_url`가 상대 URL 루트 없이 HTTPS를 사용하고 번들로 제공되는 NGINX가 HTTP/2로 TLS를 종료할 때
- Helm 차트: `wss://kas.example.com` 대신 `grpcs://kas.example.com`, Gateway API 또는 NGINX Ingress 공급자 사용

다른 구성에서는 WebSocket 주소가 유지됩니다. WebSocket을 통해 이미 연결된 Agent는 GitLab Relay(KAS)가 동일한 포트에서 두 프로토콜을 제공하기 때문에 영향을 받지 않습니다. 업그레이드 후 설치된 Agent는 gRPC를 통해 연결되며, 이는 끝 간 HTTP/2가 필요합니다. 클러스터와 GitLab 사이의 프록시가 HTTP/2를 전달하지 않으면 새 Agent는 연결에 실패하고 오류가 네트워크 문제처럼 보입니다. 예를 들어 WAF 또는 TLS 검사 프록시가 HTTP/1.1을 통해 GitLab에 연결할 수 있습니다. 이 경우 주소를 명시적으로 설정하여 WebSocket 광고를 유지하세요:

- Linux 패키지: `gitlab_rails['gitlab_kas_external_url']` (`/etc/gitlab/gitlab.rb`)에서
- Helm 차트: `global.appConfig.gitlab_kas.externalUrl`

자세한 정보는 [GitLab Relay(KAS)](../../administration/clusters/kas.md) 및 [KAS 차트 설명서](https://docs.gitlab.com/charts/charts/gitlab/kas/#agent-connection-protocol)를 참조하세요.

### Duo Agent Platform 체크포인트 마이그레이션 {#duo-agent-platform-checkpoint-migration}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 19.5.0

GitLab 19.5는 `BackfillDuoWorkflowsCheckpointHeadersAndBlobs`라는 배치 백그라운드 마이그레이션을 대기열에 추가합니다. GitLab Duo Agent Platform 세션 체크포인트를 `p_duo_workflows_checkpoints` 테이블에서 `p_duo_workflows_checkpoint_headers` 및 `p_duo_workflows_checkpoint_blobs` 테이블로 복사합니다. 이것은 응용 프로그램이 이제 쓰고 읽는 저장소 형식입니다.

마이그레이션은 업그레이드 후 백그라운드에서 실행됩니다. 새 형식으로 아직 저장되지 않은 행만 처리하며, 데이터가 보존 기간을 초과했기 때문에 30일보다 오래된 세션을 건너뜁니다.

업그레이드 전에 생성된 세션은 마이그레이션이 실행되는 동안 읽을 수 있습니다. 이후 GitLab 버전은 이전 테이블을 읽는 코드를 제거하므로 이 마이그레이션은 해당 업그레이드 전에 완료되어야 합니다. 19.5를 넘어 업그레이드하기 전에 **운영자 영역** > **백그라운드 마이그레이션** 페이지 (`/admin/background_migrations`)에서 마이그레이션 상태를 확인하세요. 상태를 확인하고 마이그레이션을 수동으로 완료하는 방법에 대한 자세한 정보는 [백그라운드 마이그레이션](../background_migrations.md)을 참조하세요.

마이그레이션이 소요되는 시간은 인스턴스가 지난 30일 동안 저장한 세션 수에 따라 달라집니다. 처리된 각 체크포인트는 여러 메가바이트일 수 있습니다.

### Geo 업로드 체크섬이 업로드 유형별로 기본적으로 활성화 {#geo-upload-checksumming-by-upload-type-enabled-by-default}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전: 19.5.0

GitLab 19.5에서 Geo는 업로드에 대해 23개의 새로운 데이터 유형을 추가합니다. 예를 들어 프로젝트 업로드 및 그룹 업로드와 같은 각 종류의 업로드에 대해 하나씩입니다. 기본 사이트만 새 데이터 유형을 사용하며 백그라운드에서 각각에 대한 업로드의 체크섬을 생성합니다. 보조 사이트는 기존 업로드 데이터 유형을 통해 업로드를 복제 및 확인하는 것을 계속합니다.

기본 사이트에서는 대부분의 업로드가 기존 업로드 데이터 유형의 체크섬을 재사용하므로 GitLab은 아직 체크섬이 성공하지 않은 파일만 읽습니다. 체크섬은 기본 사이트의 **검증 동시성 제한**을 다른 모든 데이터 유형과 공유합니다. 수백만 개의 업로드가 있는 사이트에서는 `1` 제한으로 체크섬이 며칠이 걸릴 수 있으며, 이는 이전 버전에서 업그레이드한 많은 사이트가 사용합니다. 체크섬 실행 중 제한을 높이거나 데이터베이스 부하를 모니터링하고 나중에 이전 값을 복원할 수 있습니다. GitLab 테스트에서 제한을 `1`에서 `10`로 높이면 업로드 체크섬이 약 8배 빨라지며 추가 데이터베이스 부하는 거의 없습니다. 자세한 정보는 [Geo 튜닝](../../administration/geo/replication/tuning.md#changing-the-syncverification-concurrency-values)을 참조하세요.

한 데이터 유형에 대한 체크섬을 중지하려면 [기능 플래그를 모두 비활성화](../../administration/feature_flags/_index.md#how-to-enable-and-disable-features-behind-flags)해야 합니다: `geo_<name>_upload_replication` 및 `geo_<name>_upload_force_primary_checksumming`, 여기서 `<name>`는 예를 들어 `project` 또는 `group`입니다. `_replication` 플래그만 비활성화하면 체크섬이 중지되지 않습니다.

### Geo SSH 프록시가 기본적으로 활성화 {#geo-ssh-proxying-enabled-by-default}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Helm 차트
- 영향을 받는 버전: 19.4.0

GitLab 19.4 이상에서 다음 기능 플래그는 기본적으로 활성화됩니다:

- `geo_proxy_fetch_ssh_to_primary`
- `geo_proxy_push_ssh_to_primary`

이 변경으로 인해 번들로 제공되는 NGINX Ingress를 사용하는 Cloud Native GitLab 배포는 다음 중 하나를 수행해야 합니다:

- 이 롤아웃 전에 [Gateway API를 Envoy Gateway와 함께](#nginx-ingress-replaced-by-gateway-api-with-envoy-gateway) 사용하도록 업그레이드하거나
- 롤아웃 후 두 기능 플래그를 비활성화합니다.

그렇지 않으면 Geo 보조 사이트를 통한 SSH 가져오기 및 푸시가 중단되거나 시간이 초과될 수 있습니다.

자세한 내용은 [Geo 문제 해결 설명서](../../administration/geo/replication/troubleshooting/ssh_proxying.md)에서 SSH 프록시를 참조하세요.

### `SKIP_REPOSITORIES_PATHS`를 사용하는 복원이 기존 리포지토리 유지 {#restores-that-use-skip_repositories_paths-keep-existing-repositories}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 19.4.0

GitLab 19.4 이상에서 복원은 `SKIP_REPOSITORIES_PATHS`이 해당 복원에서 리포지토리를 제외할 때 인스턴스에 이미 있는 리포지토리를 유지합니다. 이는 복원 옵션을 지정할 때와 백업으로 생성할 때 모두 적용되며, 이전 버전에서 생성한 백업도 포함됩니다. 복원이 백업 매니페스트 (`backup_information.yml`)에서 제외된 경로를 읽기 때문입니다.

이전에는 두 경우 모두에서 `REPOSITORIES_PATHS`도 지정되지 않은 경우 복원은 먼저 복원한 저장소의 모든 리포지토리를 제거했습니다. 제외된 리포지토리도 함께 제거되었고 복원 자체에서도 제외되었기 때문에 해당 백업은 이를 복구할 수 없었습니다.

`REPOSITORIES_PATHS` 또는 `SKIP_REPOSITORIES_PATHS`도 적용되지 않는 전체 복원은 여전히 백업의 일부가 아닌 리포지토리를 제거합니다.

복원 프로세스가 리포지토리를 지우기 위해 이전 동작을 사용하는 경우 전체 복원을 대신 실행하거나 복원 전에 해당 리포지토리를 제거하세요.

자세한 정보는 [특정 리포지토리 복원](../../administration/backup_restore/restore_gitlab.md#restore-specific-repositories) 및 [이슈 610910](https://gitlab.com/gitlab-org/gitlab/-/issues/610910)을 참조하세요.

### 신뢰할 수 없는 그룹 SAML ID가 신뢰할 수 있는 것으로 복원 {#untrusted-group-saml-identities-are-restored-to-trusted}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 19.4.0

GitLab 18.10, 18.11, 19.0, 19.1, 19.2 및 19.3에서 [SAML ID API](../../api/saml.md)로 그룹 SAML ID의 `extern_uid`을 업데이트하면 해당 ID가 신뢰할 수 없는 것으로 표시되었고 영향받는 사용자는 ID를 다시 연결할 때까지 SAML 싱글 사인온으로 로그인할 수 없었습니다.

GitLab 19.4는 이 동작을 되돌립니다. 그룹 소유자는 그룹 ID 공급자를 제어하므로 그룹 소유자는 이미 ID 공급자를 통해 모든 `NameID`을 주장할 수 있습니다. 배포 후 마이그레이션은 모든 그룹 SAML ID에 대해 `trusted_extern_uid`를 `true`으로 다시 설정하므로 영향받는 사용자는 SAML 싱글 사인온으로 다시 로그인할 수 있습니다.

자세한 정보는 [이슈 608236](https://gitlab.com/gitlab-org/gitlab/-/issues/608236)을 참조하세요.

### GitLab Duo Self-Hosted AI Gateway URL이 업그레이드 후 초기화 {#gitlab-duo-self-hosted-ai-gateway-urls-cleared-after-upgrade}

- 영향을 받음: Linux 패키지
- 영향을 받는 버전: 19.2.0
- 수정된 버전: 19.2.1

인스턴스를 GitLab 19.2.0으로 직접 업그레이드할 때 GitLab Duo Self-Hosted 서비스 엔드포인트 설정을 초기화할 수 있습니다. **운영자 영역** > **GitLab Duo** > **구성** > **서비스 엔드포인트** 아래의 다음 필드는 업그레이드 후 비어 있을 수 있습니다:

- **로컬 AI 게이트웨이 URL**
- **GitLab Duo Agent Platform 서비스의 로컬 URL**

다른 관련 설정도 기본값으로 되돌릴 수 있습니다. GitLab Duo Self-Hosted 기능은 URL을 수동으로 다시 입력할 때까지 작동하지 않습니다.

이 문제는 GitLab 19.2.1 이상으로 업그레이드할 때는 발생하지 않습니다.

19.2.0으로 이미 업그레이드했고 영향받는 경우 **운영자 영역** > **GitLab Duo** > **구성** > **서비스 엔드포인트**에서 올바른 AI Gateway 엔드포인트 URL을 복원하고 변경 사항을 저장합니다. 자세한 정보는 [이슈 606458](https://gitlab.com/gitlab-org/gitlab/-/work_items/606458)을 참조하세요.

### 새 그룹에서는 머지 요청 API 호출에 SHA 매개변수 필요 {#new-groups-require-sha-parameter-for-merge-requests-api-calls}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  | ------- | ----------------------- | ----------------- |
  | 19.2    | 19.2.0 - 19.2.5         | 19.2.6            |
  | 19.3    | 19.3.0 - 19.3.1         | 19.3.2            |

GitLab 19.2는 그룹 및 인스턴스 수준에서 `require_sha_for_merge` 설정을 도입합니다. 활성화되면 [머지 요청 병합](../../api/merge_requests.md#merge-a-merge-request) API 엔드포인트는 유효한 커밋 `sha` 매개변수를 포함하지 않는 호출을 거부합니다.

GitLab 19.2 및 19.3으로 업그레이드한 후 생성된 그룹에는 `require_sha_for_merge`이 기본적으로 활성화되어 있습니다. 단, 설정이 인스턴스 또는 `lock_require_sha_for_merge`를 사용하는 상위 그룹으로 잠긴 경우는 예외입니다. 설정이 잠긴 경우 새 그룹은 대신 잠긴 값을 상속합니다. 기존 그룹은 영향을 받지 않습니다.

19.2 또는 19.3으로 업데이트한 후 자동화 또는 API 클라이언트가 `sha` 매개변수 없이 병합 엔드포인트를 호출하면 요구 사항을 비활성화하고 설정을 잠그지 않으면 모든 새 그룹에 대해 해당 클라이언트가 실패합니다.

모든 새 그룹에 대해 이 요구 사항을 비활성화하려면 `require_sha_for_merge`을 `false`로 설정하고 [응용 프로그램 설정 API](../../api/settings.md#available-settings)를 통해 `lock_require_sha_for_merge`을 활성화하세요.

이 설정은 GitLab 19.2.6 및 GitLab 19.3.2에서 기본적으로 비활성화로 변경되었습니다.

### 컨테이너 레지스트리 메타데이터 데이터베이스가 기본적으로 선호도 모드로 활성화 {#container-registry-metadata-database-enabled-by-default-in-prefer-mode}

- 영향을 받음: Linux 패키지, 자체 컴파일됨
- 영향을 받는 버전: 19.0.0, 19.0.1

GitLab 19.0에서 컨테이너 레지스트리 메타데이터 데이터베이스는 `/etc/gitlab/gitlab.rb`에서 명시적으로 `registry['database']['enabled']`을 설정하지 않은 기존 설치에 대해 `prefer` 모드로 기본 설정됩니다. 선호도 모드에서 레지스트리는 메타데이터 데이터베이스를 사용하려고 시도합니다. 기존 레지스트리 데이터를 데이터베이스로 가져오지 않은 경우 레지스트리는 시작 시 레거시 파일 시스템 메타데이터로 폴백합니다.

버그로 인해 ([이슈 600955](https://gitlab.com/gitlab-org/gitlab/-/work_items/600955)) 레지스트리 라우터는 선호도-폴백 감지가 실행되기 전에 초기화되었습니다. 이로 인해 모든 `/gitlab/v1/` 경로에서 nil 포인터 역참조 패닉이 발생하여 레지스트리 UI가 그룹 수준 저장소 크기를 폴링할 때 `HTTP 500` 오류가 발생했습니다. 실제 Docker push 및 pull 프로토콜 (`/v2/`)은 이 버그의 영향을 받지 않습니다.

버그는 컨테이너 레지스트리 `v4.40.1-gitlab`을 포함하는 GitLab 19.0.2에서 수정됩니다.

19.0.0 또는 19.0.1을 실행 중이고 `runtime error: invalid memory address or nil pointer dereference` 패닉이 `/var/log/gitlab/registry/current`의 `handlers.(*repositoryHandler).HandleGetRepository`에서 반복되는 것을 보면 다음 해결 방법을 적용하세요:

1. 다음을 `/etc/gitlab/gitlab.rb`에 추가하세요:

   ```ruby
   registry['database'] = {
     'enabled' => false
   }
   ```

1. 레지스트리를 다시 구성하고 다시 시작하세요:

   ```shell
   sudo gitlab-ctl reconfigure
   sudo gitlab-ctl restart registry
   ```

19.0.2 이상으로 업그레이드한 후 재정의를 제거하고 기본 동작을 복원하려면 다시 구성하세요.

자세한 정보는 [컨테이너 레지스트리 메타데이터 데이터베이스 설명서](../../administration/packages/container_registry_metadata_database.md)를 참조하세요.

### 컨테이너 레지스트리 S3 스토리지 드라이버가 s3_v2로 교체 {#container-registry-s3-storage-driver-replaced-by-s3_v2}

- 영향을 받음: Linux 패키지, 자체 컴파일됨
- 영향을 받는 버전: 19.0.0

GitLab 19.0에서 레거시 `s3` 컨테이너 레지스트리 스토리지 드라이버(AWS SDK v1)가 제거됩니다. `s3` 및 `s3aws` 드라이버 이름은 이제 `s3_v2` 드라이버(AWS SDK v2)의 별칭입니다. 이전 드라이버 이름이 계속 작동하기 때문에 다시 구성되지 않은 인스턴스도 업그레이드할 때 AWS SDK v2로 이동합니다.

이 변경은 두 그룹의 설치에 영향을 미칩니다:

- Ceph RGW, MinIO 또는 OVH S3과 같은 S3 호환 객체 스토리지 백엔드를 사용하는 설치
- AWS S3을 사용하고 아웃바운드 네트워크 트래픽을 제한하는 설치 자세한 정보는 [AWS S3의 서명된 URL 호스트명](#presigned-url-hostnames-on-aws-s3)을 참조하세요.

`s3_v2` 드라이버는 AWS가 아닌 S3 호환 백엔드에 대해 두 가지 주요 변경 사항을 도입합니다:

- `regionendpoint`은 스키마를 포함한 전체 URI를 필요로 합니다. `s3_v2` 드라이버는 `regionendpoint` 값에 `https://` (또는 `http://`)을 필요로 합니다. `storage.example.com`과 같은 맨 호스트명은 더 이상 유효하지 않으며 시작 오류를 발생시킵니다:

  ```plaintext
  endpoint rule error, Custom endpoint `storage.example.com` was not a valid URI
  ```

  스키마를 포함하도록 구성을 업데이트하세요:

  ```ruby
  registry['storage'] = {
    's3_v2' => {
      'regionendpoint' => 'https://storage.example.com',
      # ...
    }
  }
  ```

- AWS SDK v2는 기본적으로 향상된 체크섬을 보냅니다. `s3_v2` 드라이버는 업로드 시 `x-amz-content-sha256` 및 CRC64NVME 체크섬을 보냅니다. Ceph RGW, 이전 MinIO 버전, OVH S3 및 기타 S3 호환 백엔드는 이를 HTTP 400 (`XAmzContentSHA256Mismatch`)으로 거부할 수 있습니다. `'checksum_disabled' => true`를 추가하여 이 동작을 비활성화하세요.

  `checksum_disabled` 설정은 업로드 (`PutObject`) 호출에서만 체크섬을 억제합니다. `DeleteObjects` 코드 경로는 일부 S3 호환 백엔드에서 지원하지 않는 CRC32 체크섬 헤더도 보냅니다. 백엔드가 이 헤더를 거부하면 blob 삭제를 트리거하는 이미지 푸시는 `checksum_disabled`이 `true`로 설정된 경우에도 `MissingContentMD5` 또는 `InvalidRequest` 오류가 발생하여 실패합니다.

  이 문제를 해결하려면 CRC32 체크섬 헤더를 지원하는 버전으로 S3 호환 스토리지 백엔드를 업그레이드하세요. 필요한 최소 버전에 대해 스토리지 공급자의 설명서를 참조하세요.

  `gitlab.rb` 구성 해결 방법은 `DeleteObjects` 코드 경로에 대해 없습니다. 자세한 정보는 [이슈 2309](https://gitlab.com/gitlab-org/container-registry/-/issues/2309)를 참조하세요.

Ceph RGW 및 대부분의 S3 호환 백엔드의 경우 다음과 같이 구성을 업데이트하세요:

```ruby
registry['storage'] = {
  's3_v2' => {
    'accesskey' => '<your-access-key>',
    'secretkey' => '<your-secret-key>',
    'bucket' => '<your-bucket>',
    'region' => '<your-region>',
    'regionendpoint' => 'https://<your-s3-endpoint>',
    'pathstyle' => true,
    'checksum_disabled' => true
  }
}
```

자세한 정보는 [컨테이너 레지스트리 객체 스토리지 설명서](../../administration/packages/container_registry.md#use-object-storage)를 참조하세요.

#### AWS S3의 서명된 URL 호스트명 {#presigned-url-hostnames-on-aws-s3}

레지스트리가 blob을 제공할 때 클라이언트를 서명된 S3 URL로 리디렉션합니다. AWS SDK v2는 레지스트리 구성의 영역에 대해 S3 엔드포인트를 확인하므로 이러한 서명된 URL은 AWS SDK v1이 반환할 수 있는 전역 `s3.amazonaws.com` 호스트명 대신 `s3.us-east-1.amazonaws.com`과 같은 지역 호스트명을 사용할 수 있습니다.

레지스트리 자체는 계속 작동하지만 클라이언트는 새 호스트명에 도달할 수 있어야 합니다. 프록시, 방화벽 또는 보안 웹 게이트웨이로 아웃바운드 트래픽을 필터링하는 환경에서 `s3.amazonaws.com`만 포함하는 허용 목록이 리디렉션 대상을 차단합니다. 그러면 이미지 풀이 S3이 아닌 필터링 장치에서 반환한 `403 Forbidden` 응답으로 실패합니다.

업그레이드하기 전에 컨테이너 이미지 클라이언트의 아웃바운드 트래픽을 필터링하는 모든 장치의 허용 목록에 버킷 영역의 지역 호스트명을 추가하세요. Amazon S3 전체를 포함하는 와일드카드 대신 영역에 대한 특정 지역 호스트명 (예: `s3.eu-west-2.amazonaws.com`)을 사용하세요.

인스턴스가 S3 VPC 엔드포인트 또는 다른 고정 엔드포인트를 사용하는 경우 `regionendpoint`을 해당 엔드포인트로 설정하여 서명된 URL이 제어하는 호스트명을 사용하도록 하세요. 자세한 정보는 [객체 스토리지 사용](../../administration/packages/container_registry.md#use-object-storage)을 참조하세요.

업그레이드 후 blob 풀의 유효성을 검사하려면:

1. 캐시에서 제공되기보다는 blob 리디렉션으로 제공되도록 몇 메가바이트보다 큰 이미지를 가져옵니다:

   ```shell
   docker pull gitlab.example.com:5050/mygroup/myproject/myimage:latest
   ```

1. 풀이 실패하면 리디렉션 대상을 보려면 blob을 직접 요청하세요:

   ```shell
   curl --head "https://gitlab.example.com:5050/v2/mygroup/myproject/myimage/blobs/<digest>"
   ```

   클라이언트가 리디렉션되는 호스트명에 대해 `location` 응답 헤더를 확인한 다음 해당 호스트명이 송신 제어에서 허용되는지 확인하세요.

### Geo 디자인 관리 복제 `NoMethodError` 프로젝트가 `nil` {#geo-design-management-replication-nomethoderror-when-project-is-nil}

- 영향을 받음: Geo
- 영향을 받는 버전: 16.0.0 - 19.0.1

Geo 보조 사이트에서 연결된 프로젝트가 삭제되어 고아 `DesignManagement::Repository` 레코드를 남길 때 디자인 관리 리포지토리 복제 중에 `NoMethodError`이 발생할 수 있습니다. GitLab 19.0.2는 이 문제를 수정합니다.

자세한 정보는 [이슈 597049](https://gitlab.com/gitlab-org/gitlab/-/issues/597049)를 참조하세요.

### PostgreSQL 17 최소 요구 사항 {#postgresql-17-minimum-requirement}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 19.0.0

이제 지원되는 최소 PostgreSQL 버전은 버전 17입니다. GitLab 19.0을 설치하기 전에:

- 패키지된 PostgreSQL 16을 사용하는 경우 [패키지된 PostgreSQL 서버를 업그레이드](https://docs.gitlab.com/omnibus/settings/database.html#upgrade-packaged-postgresql-server)하세요.
- [외부 PostgreSQL](../../administration/postgresql/external.md) 인스턴스를 사용하는 경우 PostgreSQL 17로 업그레이드하세요.

### 웹훅 페이로드 타임스탬프가 ISO 8601 형식으로 변경 {#webhook-payload-timestamps-changed-to-iso-8601-format}

- 영향을 받음: 모든 설치 방법
- 영향을 받는 버전: 19.0.0

GitLab 19.0 이전에 웹훅 페이로드의 타임스탬프 값 (예: `object_attributes.created_at`)은 `YYYY-MM-DD HH:MM:SS` 형식에 따라 시간대를 사용했습니다. 예를 들어, `2026-04-23 12:30:45 UTC`입니다. GitLab 19.0 이상에서 이러한 타임스탬프는 밀리초 정밀도 및 시간대 지정자와 함께 ISO 8601 형식을 사용합니다. 예를 들어, `2026-04-23T12:30:45.123Z`입니다.

이 변경은 프로젝트 웹훅, 그룹 웹훅 및 사용자 정의 웹훅 템플릿의 모든 타임스탬프에 적용되며 한 가지 예외가 있습니다. 파이프라인 이벤트는 `builds[]` 및 `bridges[]` 내부의 `created_at`, `started_at` 및 `finished_at` 필드에 대해 이전 형식을 유지합니다.

웹훅 수신기가 이러한 타임스탬프 필드를 구문 분석하는 경우 밀리초 정밀도와 함께 ISO 8601을 수락하도록 업데이트하세요. 각 필드의 형식은 [웹훅 이벤트](../../user/project/integrations/webhook_events.md)를 참조하세요.

이 변경은 [머지 요청 233400](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/233400)에서 도입되었습니다. [이슈 622832](https://gitlab.com/gitlab-org/gitlab/-/work_items/622832)에서 추적됩니다.

### Geo 컨테이너 리포지토리 동기화가 OCI 이미지 인덱스 태그를 자동으로 건너뜀 {#geo-container-repository-sync-silently-skips-oci-image-index-tags}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo (컨테이너 레지스트리)
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  | ------- | ----------------------- | ----------------- |
  | 19.0    | 19.0.0 - 19.0.1         | 19.0.2            |

Geo 보조 사이트에서는 매니페스트가 OCI 이미지 인덱스(`application/vnd.oci.image.index.v1+json`)인 태그의 컨테이너 리포지토리 동기화가 자동으로 건너뛰었습니다. 멀티 아키텍처 이미지 및 BuildKit 캐시 태그는 일반적으로 이 매니페스트 유형을 사용합니다. 오류가 발생하지 않았고 태그 수가 일치했지만 보조 사이트에서 영향을 받은 태그의 `docker pull`는 `manifest unknown`을 반환했습니다. 동일한 근본 원인으로 인해 보조 사이트에서 동기화할 수 없는 고아 태그도 남겨졌습니다.

고정 버전으로 주 사이트와 보조 사이트를 모두 업그레이드한 후, 새로 동기화된 태그가 올바릅니다. 이전에 영향을 받은 리포지토리는 다음 검증 주기에 수렴되며, 이는 재검증 간격(기본값 90일)까지 걸릴 수 있습니다. 영향을 받은 리포지토리를 즉시 복구하려면 [보조 사이트에서 컨테이너 리포지토리 재동기화](../../administration/geo/replication/container_registry.md#manually-trigger-a-container-registry-sync-event)를 수행하세요.

자세한 내용은 [이슈 600486](https://gitlab.com/gitlab-org/gitlab/-/work_items/600486)을 참조하세요.

### Geo 검증 동시성 제한이 글로벌 합계로 적용 {#geo-verification-concurrency-limit-applied-as-a-global-total}

{{< details >}}

- 티어: Premium, Ultimate

{{< /details >}}

- 영향을 받음: Geo
- 영향을 받는 버전: 19.3.0

**검증 동시성 제한** Geo 사이트 설정은 이제 사이트에서 동시에 실행되는 검증 작업 수에 대한 단일 전역 제한으로 모든 데이터 유형을 합쳐서 적용됩니다. 이전에는 적용되기 전에 구성된 값이 데이터 유형 수로 나누어졌으므로 효과적인 동시성이 더 낮았고 데이터 유형이 추가되거나 통합될 때 변경되었습니다.

사용 중인 효과적인 동시성을 보존하고 검증 부하의 급증을 피하기 위해 GitLab 19.3은 각 사이트의 저장된 **검증 동시성 제한**을 `max(1, floor(previous_value / number_of_data_types))`로 자동 재조정합니다. 결과적으로 Admin UI에 표시되고 API에서 반환된 값이 감소합니다. 업그레이드 후 설정을 검토하고 다시 튜닝하세요. API 또는 코드 기반 인프라를 통해 이 설정을 관리하는 경우 저장된 값을 업데이트하여 일치하도록 하세요.

자세한 정보는 [이슈 596579](https://gitlab.com/gitlab-org/gitlab/-/work_items/596579)를 참조하세요.

### Ubuntu 20.04에 대한 Linux 패키지 지원 중단 {#linux-package-support-for-ubuntu-2004-discontinued}

- 영향을 받음: Linux 패키지
- 영향을 받는 버전: 19.0.0

Ubuntu 20.04는 2025년 5월에 표준 지원 종료에 도달했습니다. GitLab 19.0부터는 Ubuntu 20.04에 대한 Linux 패키지가 더 이상 제공되지 않습니다. GitLab 18.11은 이 배포판에 대한 패키지가 포함된 마지막 릴리스입니다. GitLab 19.0으로 업그레이드하기 전에 Ubuntu 22.04 또는 다른 [지원되는 운영 체제](../../install/package/_index.md#supported-platforms)로 마이그레이션하세요.

### Redis 6 지원 제거됨 {#redis-6-support-removed}

- 영향을 받음: Linux 패키지
- 영향을 받는 버전: 19.0.0

Redis 6 지원은 GitLab 19.0에서 제거됩니다. 외부 Redis 6 배포를 사용하는 경우 업그레이드하기 전에 Redis 7.0 이상 또는 Valkey 7.2로 마이그레이션하세요. Redis 7.2 또는 Valkey 7.2를 권장합니다. Redis 7.0은 업스트림에서 지원 종료(EOL)에 도달했지만 Amazon ElastiCache for Redis 7.1과 같은 공급업체에서 일부 경우 활발히 유지 관리합니다. Linux 패키지에 포함된 번들 Redis는 GitLab 16.2부터 Redis 7을 사용했으며 영향을 받지 않습니다.

### Linux 패키지에서 Mattermost 제거됨 {#mattermost-removed-from-the-linux-package}

- 영향을 받음: Linux 패키지
- 영향을 받는 버전: 19.0.0

번들 Mattermost는 GitLab 19.0의 Linux 패키지에서 제거됩니다. 현재 번들로 제공되는 Mattermost를 사용하는 경우 마이그레이션 지침은 [Linux 패키지에서 Mattermost Standalone으로 마이그레이션](https://docs.mattermost.com/administration-guide/onboard/migrate-gitlab-omnibus.html)을 참조하세요. 번들로 제공되는 Mattermost를 사용하지 않으면 영향을 받지 않습니다.

GitLab 19.0으로 업그레이드하기 전에 `/etc/gitlab/gitlab.rb`에서 모든 `mattermost[...]` 설정을 제거하거나 주석 처리하세요. `mattermost[...]` 키가 남아 있으면 `gitlab-ctl reconfigure`는 패키지가 설치된 직후 중단되고:

```plaintext
RuntimeError: Removed configurations found in gitlab.rb. Aborting reconfigure.
```

> [!warning]
> 특정 18.11.x 버전에서 업그레이드할 때의 동작이 다릅니다:
>
> - 18.11.0 - 18.11.6: 업그레이드가 부실한 Mattermost 구성을 감지하지 못하므로 정리가 완료되지 않았더라도 업그레이드가 경고 없이 진행됩니다. `gitlab-ctl check-config --version 19.0.x`를 사용하여 업그레이드 전에 Mattermost 키 제거의 유효성을 검사하지 마세요 ([이슈 9916](https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/9916)).
> - 18.11.7: 모든 `mattermost[...]` 키가 `gitlab.rb`에서 제거되었더라도 업그레이드가 차단됩니다. 블록은 GitLab이 노드 캐시에서 무조건 생성한 부실한 Mattermost 비밀로 인한 거짓 양성입니다. 업그레이드 차단을 해제하려면 다음 옵션 중 하나를 사용하세요:
>   - 19.0으로 업그레이드하기 전에 18.11.9 이상으로 업그레이드하세요.
>   - [수동 해결 방법](https://gitlab.com/gitlab-org/omnibus-gitlab/-/work_items/10001#workaround)을 적용하세요.

### SUSE 배포판에 대한 Linux 패키지 지원 중단됨 {#linux-package-support-for-suse-distributions-discontinued}

- 영향을 받음: Linux 패키지
- 영향을 받는 버전: 19.0.0

SUSE 배포판에 대한 Linux 패키지 지원은 GitLab 19.0에서 종료되며, openSUSE Leap 15.6, SUSE Linux Enterprise Server 12.5 및 SUSE Linux Enterprise Server 15.6에 영향을 줍니다. GitLab 18.11은 이러한 배포판에 대한 Linux 패키지가 포함된 마지막 버전입니다. SUSE 배포판을 계속 사용하려면 [GitLab의 Docker 배포](../../install/docker/installation.md)로 마이그레이션하세요.

### Linux 패키지 및 GitLab Helm 차트에서 Spamcheck 제거됨 {#spamcheck-removed-from-linux-package-and-gitlab-helm-chart}

- 영향을 받음: Linux 패키지, Helm 차트
- 영향을 받는 버전: 19.0.0

[Spamcheck](../../administration/reporting/spamcheck.md)은 GitLab 19.0의 Linux 패키지 및 GitLab Helm 차트에서 제거됩니다. 현재 Spamcheck을 사용하지 않는 고객은 영향을 받지 않습니다. 번들 Spamcheck을 사용하는 경우 [Docker](https://gitlab.com/gitlab-org/gl-security/security-engineering/security-automation/spam/spamcheck)를 사용하여 별도로 배포할 수 있습니다. 데이터 마이그레이션은 필요하지 않습니다.

### NGINX Ingress가 Envoy Gateway를 사용한 Gateway API로 대체됨 {#nginx-ingress-replaced-by-gateway-api-with-envoy-gateway}

- 영향을 받음: Helm 차트
- 영향을 받는 버전: 19.0.0

Gateway API와 Envoy Gateway는 GitLab 19.0의 GitLab Helm 차트에서 기본 네트워킹 구성이 되며 2026년 3월에 수명이 끝난 NGINX Ingress를 대체합니다. Envoy Gateway로의 마이그레이션이 즉시 가능하지 않으면 번들로 제공되는 NGINX Ingress를 명시적으로 다시 활성화할 수 있으며, 이는 GitLab 20.0에서 제거될 때까지 계속 사용할 수 있습니다. 이 변경은 Linux 패키지에서 사용되는 NGINX 또는 외부 관리 Ingress 또는 Gateway API 컨트롤러를 사용하는 Helm 차트 인스턴스에는 영향을 주지 않습니다.

자세한 마이그레이션 단계는 [Helm 차트 10.0 업그레이드 노트](https://docs.gitlab.com/charts/releases/10_0/)를 참조하세요.

### GitLab Helm 차트에서 번들 PostgreSQL, Redis 및 MinIO 제거됨 {#bundled-postgresql-redis-and-minio-removed-from-gitlab-helm-chart}

- 영향을 받음: Helm 차트
- 영향을 받는 버전: 19.0.0

번들 Bitnami PostgreSQL, Bitnami Redis 및 MinIO 차트는 GitLab 19.0의 GitLab Helm 차트 및 GitLab Operator에서 제거되며 대체품이 없습니다. 이 구성 요소는 개념 증명 및 테스트 환경에만 사용되도록 의도되었으며 프로덕션 사용은 권장되지 않습니다. 이러한 번들 서비스 중 하나를 사용하는 인스턴스를 실행 중인 경우 GitLab 19.0으로 업그레이드하기 전에 [마이그레이션 가이드](https://docs.gitlab.com/charts/installation/migration/bundled_chart_migration/)를 따라 외부 서비스를 구성하세요.

### Linux 패키지 RPM 설치 시 `.agents` 및 `.claude` 디렉토리가 고아 상태 {#orphaned-agents-and-claude-directories-on-linux-package-rpm-installs}

- 영향을 받음: Linux 패키지(RPM)
- 영향을 받는 버전:

  | 릴리스 | 영향을 받는 패치 릴리스 | 수정된 패치 수준 |
  |:--------|:------------------------|:------------------|
  | 19.0    | 19.0.0 - 19.0.2         | 19.0.3            |
  | 19.1    | 19.1.0                  | 19.1.1            |

영향받는 패치 릴리스용 Linux 패키지는 실수로 `/opt/gitlab/embedded/service/gitlab-rails/` 아래에 두 디렉토리를 포함했습니다:

- `.agents/`
- `.claude/`

이 디렉토리는 고정된 패치 수준부터 패키지 페이로드에서 제외되며 GitLab 19.2 이상에서는 기본적으로 제외됩니다. 자세한 정보는 [이슈 603547](https://gitlab.com/gitlab-org/gitlab/-/issues/603547)을 참조하세요.

RPM 기반 배포에서 RPM은 디렉토리가 계속 파일을 포함하는 경우 더 이상 소유하지 않는 디렉토리를 제거하지 않습니다. 고정된 버전을 넘어 Linux 패키지 RPM 설치를 업그레이드한 후에도 이 디렉토리는 디스크에 남을 수 있습니다:

- `/opt/gitlab/embedded/service/gitlab-rails/.agents`
- `/opt/gitlab/embedded/service/gitlab-rails/.claude`

RPM은 이 고아 디렉토리를 자동으로 제거하지 않습니다. 이 디렉토리를 확인하고 있으면 수동으로 제거하세요:

1. 디렉토리가 있는지 확인하세요:

   ```shell
   ls -la /opt/gitlab/embedded/service/gitlab-rails/.agents \
          /opt/gitlab/embedded/service/gitlab-rails/.claude
   ```

1. 디렉토리가 있으면 제거하세요:

   ```shell
   sudo rm -rf /opt/gitlab/embedded/service/gitlab-rails/.agents \
               /opt/gitlab/embedded/service/gitlab-rails/.claude
   ```

DEB 기반 배포는 `dpkg`이 업그레이드 중 더 이상 소유하지 않는 디렉토리를 제거하기 때문에 영향을 받지 않습니다.
