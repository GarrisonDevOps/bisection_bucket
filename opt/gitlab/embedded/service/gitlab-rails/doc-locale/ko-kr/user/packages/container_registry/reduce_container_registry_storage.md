---
stage: Package
group: Container Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 컨테이너 레지스트리 스토리지 줄이기
description: GitLab 컨테이너 레지스트리의 스토리지 사용량을 모니터링하고 줄이기 위한 팁입니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

레지스트리 사용량을 관리하지 않으면 컨테이너 레지스트리는 시간이 지남에 따라 크기가 증가할 수 있습니다. 예를 들어 많은 수의 이미지 또는 태그를 추가하는 경우:

- 사용 가능한 태그 또는 이미지 목록을 검색하는 것이 더 느려집니다.
- 서버의 스토리지 공간을 많이 차지합니다.

불필요한 이미지 및 태그를 삭제하고 [컨테이너 레지스트리 정리 정책](#cleanup-policy)을 설정하여 컨테이너 레지스트리 사용량을 자동으로 관리해야 합니다.

## 컨테이너 레지스트리 사용량 보기 {#view-container-registry-usage}

{{< details >}}

- 티어: Free, Premium, Ultimate

{{< /details >}}

컨테이너 레지스트리 리포지토리의 스토리지 사용량 데이터를 봅니다.

### 프로젝트의 경우 {#for-a-project}

사전 요구 사항:

- GitLab Self-Managed 인스턴스의 경우 관리자가 [컨테이너 레지스트리 메타데이터 데이터베이스를 활성화](../../../administration/packages/container_registry_metadata_database.md)해야 합니다.
- 프로젝트에 대한 유지 관리자 또는 소유자 역할이거나 네임스페이스에 대한 소유자 역할이 있어야 합니다.

프로젝트의 스토리지 사용량을 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 다음 중 하나를 수행합니다:
   - 총 스토리지 사용량을 보려면 **설정** > **사용 할당량**을 선택합니다. **네임스페이스 항목** 아래에서 **컨테이너 레지스트리**를 선택하여 개별 리포지토리를 봅니다.
   - 리포지토리별 스토리지 사용량을 직접 보려면 **배포** > **컨테이너 레지스트리**를 선택합니다.

다음도 사용할 수 있습니다:

- 프로젝트 API를 사용하여 프로젝트의 총 컨테이너 레지스트리 스토리지를 가져옵니다. 자세한 내용은 [단일 프로젝트 가져오기](../../../api/projects.md#retrieve-a-project)를 참고하세요.
- 컨테이너 레지스트리 API를 사용하여 특정 리포지토리의 크기 데이터를 가져옵니다. 자세한 내용은 [단일 리포지토리의 세부 정보 검색](../../../api/container_registry.md#retrieve-details-of-a-single-repository)을 참고하세요.

### 그룹의 경우 {#for-a-group}

사전 요구 사항:

- GitLab Self-Managed 인스턴스의 경우 관리자가 [컨테이너 레지스트리 메타데이터 데이터베이스를 활성화](../../../administration/packages/container_registry_metadata_database.md)해야 합니다.
- 그룹의 Owner 역할이 있어야 합니다.

그룹의 스토리지 사용량을 보려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **사용 할당량**을 선택합니다.
1. **스토리지** 탭을 선택합니다.

[그룹 API](../../../api/groups.md#list-all-groups)를 사용하여 그룹의 모든 프로젝트에 대한 총 컨테이너 레지스트리 스토리지를 가져올 수도 있습니다.

### 스토리지 데이터 업데이트 {#storage-data-updates}

메타데이터 데이터베이스가 활성화되면:

- 새로운 컨테이너 이미지의 경우 푸시한 후 즉시 크기 데이터를 사용할 수 있습니다.
- 기존 컨테이너 이미지의 경우 크기 데이터는 백그라운드에서 계산되며 최대 24시간이 걸릴 수 있습니다.

스토리지 데이터 업데이트는 다음과 같이 발생합니다:

- 컨테이너 이미지를 푸시하거나 삭제할 때 즉시.
- 다음을 수행할 때 실시간으로:
  - UI에서 리포지토리 이미지 태그를 봅니다.
  - 컨테이너 레지스트리 API를 사용하여 [단일 리포지토리의 세부 정보를 검색합니다](../../../api/container_registry.md#retrieve-details-of-a-single-repository).
- 프로젝트의 컨테이너 리포지토리에서 태그를 푸시하거나 삭제할 때.
- 그룹의 경우 5분마다.

> [!note]
> GitLab Self-Managed 인스턴스의 경우 관리자가 메타데이터 데이터베이스를 활성화한 후 스토리지 데이터를 사용할 수 있습니다. GitLab.com에서는 메타데이터 데이터베이스가 기본적으로 활성화됩니다.

## 컨테이너 레지스트리 사용량 계산 방법 {#how-container-registry-usage-is-calculated}

컨테이너 레지스트리에 저장된 이미지 레이어는 루트 네임스페이스 수준에서 중복 제거됩니다.

이미지는 다음 경우에만 한 번 계산됩니다:

- 같은 리포지토리에서 같은 이미지를 두 번 이상 태그합니다.
- 같은 루트 네임스페이스 아래의 서로 다른 리포지토리에서 같은 이미지를 태그합니다.

이미지 레이어는 다음 경우에만 한 번 계산됩니다:

- 같은 컨테이너 리포지토리, 프로젝트 또는 그룹의 여러 이미지에서 이미지 레이어를 공유합니다.
- 서로 다른 리포지토리에서 이미지 레이어를 공유합니다.

태그된 이미지로 참조되는 레이어만 계산됩니다. 태그되지 않은 이미지 및 해당 이미지에서만 참조하는 레이어는 [온라인 가비지 수집](delete_container_registry_images.md#garbage-collection)의 대상입니다. 태그되지 않은 이미지 레이어는 해당 기간 동안 참조되지 않으면 24시간 후 자동으로 삭제됩니다.

이미지 레이어는 스토리지 백엔드에 원본(보통 압축된) 형식으로 저장됩니다. 이는 주어진 이미지 레이어의 측정된 크기가 해당 [이미지 매니페스트](https://github.com/opencontainers/image-spec/blob/main/manifest.md#example-image-manifest)에 표시된 크기와 일치해야 함을 의미합니다.

네임스페이스 사용량은 네임스페이스 아래의 컨테이너 리포지토리에서 태그를 푸시하거나 삭제한 후 몇 분 후에 새로 고쳐집니다.

### 지연된 새로 고침 {#delayed-refresh}

매우 큰 네임스페이스(약 1%의 네임스페이스)에 대해 실시간으로 최대 정밀도로 컨테이너 레지스트리 사용량을 계산할 수 없습니다. 이 네임스페이스의 유지 관리자가 사용량을 볼 수 있도록 지연된 폴백 메커니즘이 있습니다. 자세한 내용은 [에픽 9413](https://gitlab.com/groups/gitlab-org/-/epics/9413)을 참고하세요.

네임스페이스의 사용량을 정밀도 있게 계산할 수 없으면 GitLab은 지연된 방법으로 폴백됩니다. 지연된 방법에서 표시된 사용량은 네임스페이스의 모든 고유 이미지 레이어의 합입니다. 태그되지 않은 이미지 레이어는 무시되지 않습니다. 따라서 표시된 사용량은 태그를 삭제한 후 크게 변경되지 않을 수 있습니다. 대신 크기 값은 다음 경우에만 변경됩니다:

- 자동화된 [가비지 수집 프로세스](delete_container_registry_images.md#garbage-collection)가 실행되고 태그되지 않은 이미지 레이어를 삭제합니다. 사용자가 태그를 삭제한 후 가비지 수집 실행이 24시간 후에 시작되도록 예약됩니다. 이 실행 중에 이전에 태그된 이미지가 분석되고 다른 태그된 이미지로 참조되지 않으면 해당 레이어가 삭제됩니다. 레이어가 삭제되면 네임스페이스 사용량이 업데이트됩니다.
- 네임스페이스의 레지스트리 사용량이 줄어들어 GitLab이 최대 정밀도로 측정할 수 있습니다. 네임스페이스의 사용량이 줄어들면 측정이 지연된 방법에서 정확한 사용량 측정으로 자동으로 전환됩니다. 사용 중인 측정 방법을 결정할 수 있는 UI의 위치는 없지만 [이슈 386468](https://gitlab.com/gitlab-org/gitlab/-/issues/386468)에서는 이를 개선할 것을 제안합니다.

## 정리 정책 {#cleanup-policy}

정리 정책은 컨테이너 레지스트리에서 태그를 제거하는 데 사용할 수 있는 예약 작업입니다. 정의된 프로젝트의 경우 정규 표현식 패턴과 일치하는 태그가 제거됩니다. 기본 레이어 및 이미지는 유지됩니다.

태그와 연결되지 않은 기본 레이어 및 이미지를 삭제하려면 관리자가 [가비지 수집](../../../administration/packages/container_registry.md#removing-untagged-manifests-and-unreferenced-layers)을 `-m` 스위치와 함께 사용할 수 있습니다.

### 정리 정책 활성화 {#enable-the-cleanup-policy}

> [!warning]
> 성능상의 이유로 컨테이너 이미지가 없는 프로젝트의 활성화된 정리 정책이 자동으로 비활성화됩니다.

### 정리 정책의 작동 원리 {#how-the-cleanup-policy-works}

정리 정책은 컨테이너 레지스트리의 모든 태그를 수집하고 삭제하려는 태그만 남을 때까지 태그를 제외합니다.

정리 정책은 태그 이름을 기반으로 이미지를 검색합니다. 전체 경로 일치에 대한 지원은 [이슈 281071](https://gitlab.com/gitlab-org/gitlab/-/issues/281071)에서 추적됩니다.

정리 정책:

1. 주어진 리포지토리의 모든 태그를 목록으로 수집합니다.
1. `latest`이라는 태그를 제외합니다.
1. `name_regex`(만료할 태그)을 평가하고 일치하지 않는 이름을 제외합니다.
1. `name_regex_keep` 값(보존할 태그)과 일치하는 태그를 제외합니다.
1. 매니페스트가 없는 태그(UI의 옵션에 포함되지 않음)를 제외합니다.
1. 남은 태그를 `created_date`별로 정렬합니다.
1. `keep_n` 값(보존할 태그 수)을 기반으로 N개의 태그를 제외합니다.
1. `older_than` 값(만료 간격)보다 최근인 태그를 제외합니다.
1. [보호된 태그](protected_container_tags.md)를 제외합니다.
1. [불변 태그](immutable_container_tags.md)를 제외합니다.
1. 목록에서 남은 태그를 컨테이너 레지스트리에서 삭제합니다.

> [!warning]
> GitLab.com에서는 정리 정책의 실행 시간이 제한됩니다. 일부 태그가 정리 정책 실행 후 컨테이너 레지스트리에 남을 수 있습니다. 정리 정책이 다음에 실행될 때 남은 태그가 포함됩니다. 모든 태그를 삭제하려면 여러 번 실행해야 할 수 있습니다.
>
> GitLab Self-Managed 인스턴스는 [Docker Registry HTTP API V2](https://distribution.github.io/distribution/spec/api/) 사양을 준수하는 타사 컨테이너 레지스트리를 지원합니다. 하지만 이 사양에는 태그 삭제 작업이 포함되지 않습니다. 따라서 GitLab은 타사 컨테이너 레지스트리와 상호 작용할 때 태그를 삭제하기 위해 해결 방법을 사용합니다. 자세한 내용은 [이슈 15737](https://gitlab.com/gitlab-org/gitlab/-/issues/15737)을 참고하세요. 가능한 구현 변형으로 인해 이 해결 방법이 모든 타사 레지스트리에서 같은 방식으로 작동한다는 보장은 없습니다. GitLab 컨테이너 레지스트리를 사용하는 경우 GitLab이 특수 태그 삭제 작업을 구현했으므로 이 해결 방법이 필요하지 않습니다. 이 경우 정리 정책이 일관되고 예측 가능할 것으로 예상할 수 있습니다.

#### 정리 정책 워크플로우 예제 {#example-cleanup-policy-workflow}

정리 정책의 유지 규칙과 제거 규칙 간의 상호 작용은 복잡할 수 있습니다. 예를 들어, 다음 정리 정책 구성이 있는 프로젝트의 경우:

- **가장 최근 항목 유지**: 이미지 이름당 1개의 태그.
- **태그 일치 유지**: `production-.*`
- **다음보다 오래된 태그 제거**: 7일.
- **태그 일치 제거**: `.*`.

그리고 다음 태그가 있는 컨테이너 리포지토리:

- `latest`(2시간 전에 게시됨)
- `production-v44`(3일 전에 게시됨)
- `production-v43`(6일 전에 게시됨)
- `production-v42`(11일 전에 게시됨)
- `dev-v44`(2일 전에 게시됨)
- `dev-v43`(5일 전에 게시됨)
- `dev-v42`(10일 전에 게시됨)
- `v44`(어제 게시됨)
- `v43`(12일 전에 게시됨)
- `v42`(20일 전에 게시됨)

이 예제에서 다음 정리 실행 시 삭제할 태그는 `dev-v42`, `v43`, `v42`입니다. 규칙이 이 우선 순위로 적용되는 것으로 해석할 수 있습니다:

1. 유지 규칙의 우선 순위가 가장 높습니다. 태그는 규칙과 일치할 때 유지되어야 합니다.
   - `latest` 태그는 `latest` 태그가 항상 유지되므로 유지되어야 합니다.
   - `production-v44`, `production-v43`, `production-v42` 태그는 **태그 일치 유지** 규칙과 일치하므로 유지되어야 합니다.
   - `v44` 태그는 가장 최근이므로 **가장 최근 항목 유지** 규칙과 일치하므로 유지되어야 합니다.
1. 제거 규칙의 우선 순위가 낮으며 모든 규칙이 일치할 때만 태그가 삭제됩니다. 유지 규칙과 일치하지 않는 태그(`dev-v44`, `dev-v43`, `dev-v42`, `v43`, `v42`)의 경우:
   - `dev-v44` 및 `dev-v43`는 **다음보다 오래된 태그 제거**와 일치하지 않으며 유지됩니다.
   - `dev-v42`, `v43`, `v42`는 **다음보다 오래된 태그 제거** 및 **태그 일치 제거** 규칙과 모두 일치하므로 이 세 태그를 삭제할 수 있습니다.

### 정리 정책 만들기 {#create-a-cleanup-policy}

[API](#use-the-cleanup-policy-api) 또는 UI에서 정리 정책을 만들 수 있습니다.

UI에서 정리 정책을 만들려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **컨테이너 레지스트리**를 확장합니다.
1. **컨테이너 레지스트리 정리 정책** 아래에서 **정리 규칙 설정**을 선택합니다.
1. 필드를 완성합니다:

   | 필드                      | 설명 |
   |----------------------------|-------------|
   | **토글**                 | 정책을 켜거나 끕니다. |
   | **정리 실행**            | 정리 정책을 얼마나 자주 실행할지를 나타냅니다. |
   | **가장 최근 항목 유지**   | 각 이미지에 대해 항상 유지할 태그의 개수입니다. |
   | **태그 일치 유지**     | 보존할 태그를 결정하는 정규 표현식 패턴입니다. `latest` 태그는 항상 보존됩니다. 모든 태그의 경우 `.*`를 사용합니다. 다른 [정규 표현식 패턴 예제](#regex-pattern-examples)를 참고하세요. |
   | **다음보다 오래된 태그 제거** | X일보다 오래된 태그만 제거합니다. 첫 번째 정리 중에 가장 오래된 이미지만 삭제되도록 높은 숫자로 시작해야 합니다. 정리 백그라운드 워커에서 사용하는 리소스를 모니터링한 후 일 수를 점차 줄일 수 있습니다. |
   | **태그 일치 제거**   | 제거할 태그를 결정하는 정규 표현식 패턴입니다. 이 값은 공백일 수 없습니다. 첫 번째 정리 중에 몇 개의 이미지만 삭제되도록 비교적 구체적인 정규 표현식으로 시작해야 합니다. 정리 백그라운드 워커에서 사용하는 리소스를 모니터링한 후 정규 표현식을 더 일반적으로 조정합니다(모든 태그와 일치하려면 `.*`까지). 자세한 내용은 [정규 표현식 패턴 예제](#regex-pattern-examples)를 참고하세요. |

   > [!note]
   > 유지 및 제거 정규 표현식 패턴은 자동으로 `\A` 및 `\Z` 앵커로 둘러싸여 있으므로 포함할 필요가 없습니다. 그러나 정규 표현식 패턴을 선택하고 테스트할 때 이를 고려해야 합니다.

1. **저장**을 선택합니다.

정책은 선택한 예약 간격에 따라 실행됩니다.

> [!note]
> 정책을 편집하고 **저장**을 다시 선택하면 간격이 재설정됩니다.

### 정규식 패턴 예제 {#regex-pattern-examples}

정리 정책은 정규 표현식 패턴을 사용하여 UI와 API 모두에서 보존하거나 제거할 태그를 결정합니다.

GitLab은 정리 정책에서 정규 표현식에 [RE2 구문](https://github.com/google/re2/wiki/Syntax)을 사용합니다.

사용할 수 있는 정규 표현식 패턴의 예제는 다음과 같습니다:

- 모든 태그와 일치:

  ```plaintext
  .*
  ```

  이 패턴은 만료 정규 표현식의 기본값입니다.

- `v`로 시작하는 태그와 일치:

  ```plaintext
  v.+
  ```

- `main`이라는 태그만과 일치:

  ```plaintext
  main
  ```

- `release`이라는 이름이거나 시작하는 태그와 일치:

  ```plaintext
  release.*
  ```

- `v`로 시작하거나 `main`라는 이름이거나 `release`로 시작하는 태그와 일치:

  ```plaintext
  (?:v.+|main|release.*)
  ```

### 리소스 절약을 위해 정리 제한 설정 {#set-cleanup-limits-to-conserve-resources}

{{< details >}}

- 제공 서비스: GitLab Self-Managed

{{< /details >}}

정리 정책은 백그라운드 프로세스로 실행됩니다. 삭제할 태그의 개수에 따라 프로세스가 완료되는 데 시간이 걸릴 수 있습니다.

다음 애플리케이션 설정을 사용하여 서버 리소스 부족을 방지할 수 있습니다:

| 애플리케이션 설정 | 형식 | 설명 |
|---------|------|-------------|
| `container_registry_expiration_policies_worker_capacity` | 정수 | 동시에 실행 중인 정리 워커의 최대 개수입니다. `4`로 기본값 지정합니다. 이 값을 `0`로 설정하여 모든 워커를 제거하고 정리 정책이 실행되지 않도록 합니다. 낮은 숫자로 시작하고 백그라운드 워커에서 사용하는 리소스를 모니터링한 후 증가시킵니다. |
| `container_registry_delete_tags_service_timeout` | 정수 | 정리 프로세스가 태그 배치를 삭제하는 데 걸릴 수 있는 최대 시간(초)입니다. `250`로 기본값 지정합니다. |
| `container_registry_cleanup_tags_service_max_list_size` | 정수 | 단일 실행에서 삭제할 수 있는 태그의 최대 개수입니다. `200`로 기본값 지정합니다. 추가 태그는 다른 실행에서 삭제해야 합니다. 낮은 숫자로 시작하고 컨테이너 이미지가 제대로 삭제되었는지 확인한 후 증가시킵니다. |
| `container_registry_expiration_policies_caching` | 부울 | 정책 실행 중 태그 생성 타임스탬프 캐싱입니다. `true`로 기본값 지정합니다. 캐시된 타임스탬프는 Redis에 저장됩니다. |

사전 요구 사항:

- 관리자 액세스 권한이 있어야 합니다.

[Rails 콘솔](../../../administration/operations/rails_console.md#starting-a-rails-console-session)에서 이 설정을 변경할 수 있습니다. 예를 들어:

```ruby
ApplicationSetting.last.update(container_registry_expiration_policies_worker_capacity: 3)
```

**운영자** 영역에서 이 설정을 변경하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **컨테이너 레지스트리**를 확장합니다.

### 정리 정책 API 사용 {#use-the-cleanup-policy-api}

GitLab API를 사용하여 정리 정책을 설정, 업데이트 및 비활성화할 수 있습니다.

예:

- 모든 태그를 선택하고 이미지당 최소 1개의 태그를 유지하고 14일보다 오래된 태그를 정리하고 한 달에 한 번 실행하고 `main` 이름의 이미지를 보존하고 정책이 활성화되어 있습니다:

  ```shell
  curl --fail-with-body --request PUT --header 'Content-Type: application/json;charset=UTF-8'
       --header "PRIVATE-TOKEN: <your_access_token>" \
       --data-binary '{"container_expiration_policy_attributes":{"cadence":"1month","enabled":true,"keep_n":1,"older_than":"14d","name_regex":".*","name_regex_keep":".*-main"}}' \
       "https://gitlab.example.com/api/v4/projects/2"
  ```

API를 사용할 때 `cadence`의 유효한 값은:

- `1d`(매일)
- `7d`(매주)
- `14d`(2주마다)
- `1month`(매달)
- `3month`(분기별)

API를 사용할 때 `keep_n`(이미지 이름당 유지된 태그 개수)의 유효한 값은:

- `1`
- `5`
- `10`
- `25`
- `50`
- `100`

API를 사용할 때 `older_than`(태그가 자동으로 제거될 때까지의 일 수)의 유효한 값은:

- `1d`
- `3d`
- `7d`
- `14d`
- `30d`
- `60d`
- `90d`
- `180d`
- `365d`
- `730d`
- `1095d`

자세한 내용은 API 설명서를 참고하세요: [프로젝트 API 편집](../../../api/projects.md#update-a-project).

### 외부 컨테이너 레지스트리에서 사용 {#use-with-external-container-registries}

[외부 컨테이너 레지스트리](../../../administration/packages/container_registry.md#use-an-external-container-registry-with-gitlab-as-an-auth-endpoint)를 사용할 때 프로젝트에서 정리 정책을 실행하면 성능 위험이 있을 수 있습니다. 프로젝트가 수천 개의 태그를 제거하는 정책을 실행하면 GitLab 백그라운드 작업이 백업되거나 완전히 실패할 수 있습니다.

## 추가 컨테이너 레지스트리 스토리지 감소 옵션 {#more-container-registry-storage-reduction-options}

프로젝트가 사용하는 컨테이너 레지스트리 스토리지를 줄이기 위해 사용할 수 있는 몇 가지 다른 옵션은 다음과 같습니다:

- [GitLab UI](delete_container_registry_images.md#use-the-gitlab-ui)를 사용하여 개별 이미지 태그 또는 모든 태그가 포함된 전체 리포지토리를 삭제합니다.
- API를 사용하여 [개별 이미지 태그 삭제](../../../api/container_registry.md#delete-a-registry-repository-tag)합니다.
- API를 사용하여 [모든 태그가 포함된 전체 컨테이너 레지스트리 리포지토리 삭제](../../../api/container_registry.md#delete-registry-repository)합니다.
- API를 사용하여 [레지스트리 리포지토리 태그를 대량으로 삭제](../../../api/container_registry.md#delete-registry-repository-tags-in-bulk)합니다.

## 문제 해결 {#troubleshooting}

### 스토리지 크기를 사용할 수 없음 {#storage-size-is-not-available}

컨테이너 레지스트리 스토리지 크기 정보를 볼 수 없으면:

1. 관리자에게 [메타데이터 데이터베이스가 제대로 구성](../../../administration/packages/container_registry_metadata_database.md)되어 있는지 확인하도록 요청합니다.
1. 레지스트리 스토리지 백엔드가 올바르게 구성되고 액세스 가능한지 확인합니다.
1. 스토리지 관련 오류에 대해 레지스트리 로그를 확인합니다:

   ```shell
   sudo gitlab-ctl tail registry
   ```

### `Something went wrong while updating the cleanup policy.` {#something-went-wrong-while-updating-the-cleanup-policy}

이 오류 메시지가 표시되면 정규 표현식 패턴을 확인하여 유효한지 확인합니다.

[regex101 정규 표현식 테스터](https://regex101.com/)를 사용하여 `Golang` 방식으로 테스트할 수 있습니다. 일반적인 [정규 표현식 패턴 예제](#regex-pattern-examples)를 참고하세요.

### 정리 정책이 태그를 삭제하지 않음 {#the-cleanup-policy-doesnt-delete-any-tags}

이 이유는 여러 가지가 있을 수 있습니다:

- GitLab Self-Managed를 사용 중이고 컨테이너 리포지토리에 1000개 이상의 태그가 있으면 [컨테이너 레지스트리 토큰 만료 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/288814)가 발생할 수 있으며 로그에 `error authorizing context: invalid token`가 있습니다.

  이를 해결하려면 두 가지 해결 방법이 있습니다:

  - [정리 정책의 제한 설정](#set-cleanup-limits-to-conserve-resources)을 할 수 있습니다. 이는 정리 실행 시간을 제한하고 만료된 토큰 오류를 피합니다.

  - 컨테이너 레지스트리 인증 토큰의 [만료 지연 연장](../../../administration/packages/container_registry.md#increase-token-duration)을 수행합니다. 기본값은 5분입니다.

또는 삭제할 태그의 목록을 생성하고 해당 목록을 사용하여 태그를 삭제할 수 있습니다. 목록을 만들고 태그를 삭제하려면:

1. 다음 셸 스크립트를 실행합니다. `for` 루프 바로 앞의 명령은 루프를 시작할 때 `list_o_tags.out`가 항상 다시 초기화되도록 합니다. 이 명령을 실행한 후 모든 태그 이름이 `list_o_tags.out` 파일에 기록됩니다:

   ```shell
   # Get a list of all tags in a certain container repository while considering [pagination](../../../api/rest/_index.md#pagination)
   echo -n "" > list_o_tags.out; for i in {1..N}; do curl --fail-with-body --header 'PRIVATE-TOKEN: <PAT>' "https://gitlab.example.com/api/v4/projects/<Project_id>/registry/repositories/<container_repo_id>/tags?per_page=100&page=${i}" | jq '.[].name' | sed 's:^.\(.*\).$:\1:' >> list_o_tags.out; done
   ```

   Rails 콘솔 액세스가 있으면 다음 명령을 입력하여 날짜로 제한된 태그 목록을 검색할 수 있습니다:

   ```shell
   output = File.open( "/tmp/list_o_tags.out","w" )
   Project.find(<Project_id>).container_repositories.find(<container_repo_id>).tags.each do |tag|
     output << tag.name + "\n" if tag.created_at < 1.month.ago
   end;nil
   output.close
   ```

   이 명령 집합은 1개월보다 오래된 `created_at` 날짜의 모든 태그를 나열하는 `/tmp/list_o_tags.out` 파일을 만듭니다.

1. `list_o_tags.out` 파일에서 유지하려는 태그를 제거합니다. 예를 들어 `sed`를 사용하여 파일을 파싱하고 태그를 제거할 수 있습니다.

   {{< tabs >}}

   {{< tab title="Linux" >}}

   ```shell
   # Remove the `latest` tag from the file
   sed -i '/latest/d' list_o_tags.out

   # Remove the first N tags from the file
   sed -i '1,Nd' list_o_tags.out

   # Remove the tags starting with `Av` from the file
   sed -i '/^Av/d' list_o_tags.out

   # Remove the tags ending with `_v3` from the file
   sed -i '/_v3$/d' list_o_tags.out
   ```

   {{< /tab >}}

   {{< tab title="macOS" >}}

   ```shell
   # Remove the `latest` tag from the file
   sed -i .bak '/latest/d' list_o_tags.out

   # Remove the first N tags from the file
   sed -i .bak '1,Nd' list_o_tags.out

   # Remove the tags starting with `Av` from the file
   sed -i .bak '/^Av/d' list_o_tags.out

   # Remove the tags ending with `_v3` from the file
   sed -i .bak '/_v3$/d' list_o_tags.out
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. `list_o_tags.out` 파일을 다시 확인하여 삭제하려는 태그만 포함하는지 확인합니다.

1. `list_o_tags.out` 파일의 태그를 삭제하려면 이 셸 스크립트를 실행합니다:

   ```shell
   # loop over list_o_tags.out to delete a single tag at a time
   while read -r LINE || [[ -n $LINE ]]; do echo ${LINE}; curl --fail-with-body --request DELETE --header 'PRIVATE-TOKEN: <PAT>' "https://gitlab.example.com/api/v4/projects/<Project_id>/registry/repositories/<container_repo_id>/tags/${LINE}"; sleep 0.1; echo; done < list_o_tags.out > delete.logs
   ```
