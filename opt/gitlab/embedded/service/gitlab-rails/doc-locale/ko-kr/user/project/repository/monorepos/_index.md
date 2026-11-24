---
stage: Tenant Scale
group: Gitaly
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 모노리포 성능 개선
---

모노리포는 하위 프로젝트를 포함하는 리포지토리입니다. 단일 애플리케이션은 종종 상호 의존적인 프로젝트를 포함합니다. 예를 들어 백엔드, 웹 프론트엔드, iOS 애플리케이션, Android 애플리케이션이 있습니다. 모노리포는 일반적이지만 성능 위험을 초래할 수 있습니다. 일반적인 문제:

- 큰 바이너리 파일.
- 길은 히스토리가 있는 많은 파일.
- 많은 동시 클론 및 푸시.
- 수직 확장 제한.
- 네트워크 대역폭 제한.
- 디스크 대역폭 제한.

GitLab은 Git 기반입니다. Git 스토리지 서비스인 [Gitaly](https://gitlab.com/gitlab-org/gitaly)는 모노리포와 관련된 성능 제약을 겪습니다. 저희가 배운 것은 여러분의 모노리포를 더 잘 관리하는 데 도움이 될 수 있습니다.

- 리포지토리 특성이 성능에 미치는 영향.
- 모노리포를 최적화하기 위한 몇 가지 도구와 단계.

## 모노리포를 위해 Gitaly 최적화 {#optimize-gitaly-for-monorepos}

Git은 객체를 [packfile](https://git-scm.com/book/en/v2/Git-Internals-Packfiles)로 압축하여 공간을 절약합니다. 클론, 페치 또는 푸시할 때 Git은 packfile을 사용합니다. 이는 디스크 공간과 네트워크 대역폭을 줄이지만, packfile 생성에는 많은 CPU와 메모리가 필요합니다.

대규모 모노리포는 더 작은 리포지토리보다 더 많은 커밋, 파일, 브랜치 및 태그를 가집니다. 객체가 더 커지고 전송하는 데 더 오래 걸리면 packfile 생성은 더 비싸지고 느려집니다. Git에서 [`git-pack-objects`](https://git-scm.com/docs/git-pack-objects) 프로세스는 가장 리소스 집약적인 작업입니다. 이유는 다음과 같습니다:

1. 커밋 히스토리와 파일을 분석합니다.
1. 클라이언트로 보낼 파일을 결정합니다.
1. Packfile을 생성합니다.

`git clone` 및 `git fetch`에서의 트래픽은 서버에서 `git-pack-objects` 프로세스를 시작합니다. GitLab CI/CD 같은 자동화된 지속적 통합 시스템은 이러한 트래픽의 대부분을 유발할 수 있습니다. 높은 수준의 자동화된 CI/CD 트래픽은 많은 클론 및 페치 요청을 보내며, Gitaly 서버에 부담을 줄 수 있습니다.

Gitaly 서버의 부하를 줄이기 위해 다음 전략을 사용합니다.

### Gitaly `pack-objects` 캐시 활성화 {#enable-the-gitaly-pack-objects-cache}

클론 및 페치의 서버 부하를 줄이는 [Gitaly `pack-objects` 캐시](../../../../administration/gitaly/configure_gitaly.md#pack-objects-cache)를 활성화합니다.

Git 클라이언트가 클론 또는 페치 요청을 보내면, `git-pack-objects`에서 생성된 데이터를 재사용을 위해 캐시할 수 있습니다. 모노리포를 자주 클론하는 경우, [Gitaly `pack-objects` 캐시](../../../../administration/gitaly/configure_gitaly.md#pack-objects-cache)를 활성화하면 서버 부하가 감소합니다. 활성화되면 Gitaly는 각 클론 또는 페치 호출에 대해 응답 데이터를 재생성하는 대신 메모리 내 캐시를 유지합니다.

자세한 내용은 [Pack-objects 캐시](../../../../administration/gitaly/configure_gitaly.md#pack-objects-cache)를 참조합니다.

### Git bundle URI 구성 {#configure-git-bundle-uris}

[Git 번들](https://git-scm.com/docs/bundle-uri)을 CDN 같은 낮은 지연 시간의 타사 스토리지에 생성하고 저장합니다. Git은 먼저 번들에서 패키지를 다운로드하고, 그 다음 Git 원격에서 나머지 객체와 참조를 페치합니다. 이 방식은 객체 데이터베이스를 더 빠르게 부트스트랩하고 Gitaly의 부하를 줄입니다.

- GitLab 서버에 대한 네트워크 연결이 좋지 않은 사용자의 클론 및 페치 속도를 높입니다.
- 번들을 사전로드하여 CI/CD 작업을 실행하는 서버의 부하를 줄입니다.

자세히 알아보려면 [Bundle URI](../../../../administration/gitaly/bundle_uris.md)를 참조합니다.

### Gitaly 협상 타임아웃 구성 {#configure-gitaly-negotiation-timeouts}

리포지토리를 페치하거나 아카이브하려고 할 때, 다음이 있는 경우 `fatal: the remote end hung up unexpectedly` 오류가 발생할 수 있습니다:

- 큰 리포지토리.
- 병렬로 많은 리포지토리.
- 병렬로 동일한 큰 리포지토리.

이 문제를 완화하려면 [기본 협상 타임아웃 값](../../../../administration/settings/gitaly_timeouts.md#configure-the-negotiation-timeouts)을 늘립니다.

### 하드웨어를 올바르게 크기 조정 {#size-your-hardware-correctly}

모노리포는 일반적으로 많은 사용자를 보유한 더 큰 조직을 위한 것입니다. 모노리포를 지원하려면 GitLab 환경이 GitLab Test Platform 및 Support 팀에서 제공하는 [참조 아키텍처](../../../../administration/reference_architectures/_index.md) 중 하나와 일치해야 합니다. 이 아키텍처는 성능을 유지하면서 규모에 맞게 GitLab을 배포하는 권장 방법입니다.

### Git 참조 수 감소 {#reduce-the-number-of-git-references}

Git에서 [참조](https://git-scm.com/book/en/v2/Git-Internals-Git-References)는 특정 커밋을 가리키는 브랜치 및 태그 이름입니다. Git은 참조를 리포지토리의 `.git/refs` 폴더에 느슨한 파일로 저장합니다. 리포지토리의 모든 참조를 보려면 `git for-each-ref`을 실행합니다.

리포지토리의 참조 수가 증가하면, 특정 참조를 찾는 데 필요한 탐색 시간도 증가합니다. Git이 참조를 구문 분석할 때마다 증가된 탐색 시간으로 인해 지연 시간이 증가합니다.

이 문제를 해결하기 위해 Git은 [pack-refs](https://git-scm.com/docs/git-pack-refs)를 사용하여 해당 리포지토리의 모든 참조를 포함하는 단일 `.git/packed-refs` 파일을 생성합니다. 이 방법은 참조에 필요한 스토리지 공간을 줄입니다. 또한 단일 파일에서 탐색하는 것이 디렉터리의 모든 파일을 통해 탐색하는 것보다 빠르기 때문에 탐색 시간을 줄입니다.

Git은 새로 생성되거나 업데이트된 참조를 느슨한 파일로 처리합니다. `git pack-refs`을 실행할 때까지 `.git/packed-refs` 파일에 정리되고 추가되지 않습니다. Gitaly는 [하우스키핑](../../../../administration/housekeeping.md#heuristical-housekeeping) 중에 `git pack-refs`을 실행합니다. 이는 많은 리포지토리를 돕지만, 쓰기 집약적인 리포지토리는 여전히 이러한 성능 문제가 있습니다:

- 참조를 생성하거나 업데이트하면 새 느슨한 파일이 생성됩니다.
- 참조를 삭제하려면 기존 `packed-refs` 파일을 편집하여 기존 참조를 제거해야 합니다.

리포지토리를 페치하거나 클론할 때 Git은 모든 참조를 반복합니다. 서버는 각 참조의 내부 그래프 구조를 검토("walk")하고, 누락된 객체를 찾고, 클라이언트에 보냅니다. 반복 및 탐색 프로세스는 CPU 집약적이며 지연 시간을 증가시킵니다. 이 지연 시간은 활동이 많은 리포지토리에서 도미노 효과를 일으킬 수 있습니다. 각 작업이 더 느려지고 각 작업이 이후 작업을 지연시킵니다.

모노리포의 많은 참조의 영향을 완화하려면:

- 오래된 브랜치를 정리하기 위한 자동화된 프로세스를 생성합니다.
- 특정 참조가 클라이언트에 보이지 않아야 하는 경우 [`transfer.hideRefs`](https://git-scm.com/docs/git-config#Documentation/git-config.txt-transferhideRefs) 구성 설정을 사용하여 숨깁니다. Gitaly는 모든 온서버 Git 구성을 무시하므로 `/etc/gitlab/gitlab.rb`에서 Gitaly 구성 자체를 변경해야 합니다:

  ```ruby
  gitaly['configuration'] = {
    # ...
    git: {
      # ...
      config: [
        # ...
        { key: "transfer.hideRefs", value: "refs/namespace_to_hide" },
      ],
    },
  }
  ```

Git 2.42.0 이상에서는 다양한 Git 작업이 객체 그래프 탐색을 수행할 때 숨겨진 참조를 건너뛸 수 있습니다.

### 리포지토리 최적화 작업 예약 {#schedule-repository-optimization-tasks}

Git 리포지토리의 객체 데이터베이스에 데이터가 저장되는 방식은 시간이 지나면서 비효율적으로 될 수 있으며, 이는 Git 작업을 느리게 합니다. 최대 지속 시간을 사용하여 이러한 항목을 정리하고 성능을 개선하기 위해 [Gitaly가 일일 백그라운드 작업을 실행하도록 예약](../../../../administration/housekeeping.md#configure-scheduled-housekeeping)할 수 있습니다.

## 모노리포를 위해 CI/CD 최적화 {#optimize-cicd-for-monorepos}

GitLab을 모노리포로 확장 가능하게 유지하려면 CI/CD 작업이 리포지토리와 상호 작용하는 방식을 최적화합니다. 길고 긴 파이프라인은 모노리포의 일반적인 문제점입니다. 모노리포의 파이프라인 구성에서 변경된 항목의 유형을 감지하는 [빌드 규칙](../../../../ci/yaml/_index.md#rules)을 사용합니다:

- 불필요한 작업을 건너뜁니다.
- 자식 파이프라인에서 관련 작업만 실행합니다.

### CI/CD에서 동시 클론 감소 {#reduce-concurrent-clones-in-cicd}

CI/CD 파이프라인 동시성을 [예약된 파이프라인을 엇갈리게](../../../../ci/pipelines/schedules.md#distribute-pipeline-schedules-to-prevent-system-load) 하여 다양한 시간에 실행되도록 감소시킵니다. 몇 분 정도 떨어져 있어도 도움이 됩니다.

CI/CD 로드는 파이프라인이 [특정 시간에 예약](../../../../ci/pipelines/pipeline_efficiency.md#reduce-how-often-jobs-run)되기 때문에 종종 동시입니다. 이러한 시간에 리포지토리에 대한 Git 요청이 급증할 수 있으며, CI/CD 프로세스 및 사용자의 성능에 영향을 미칠 수 있습니다.

### CI/CD 프로세스에서 얕은 클론 및 필터 사용 {#use-shallow-clones-and-filters-in-cicd-processes}

CI/CD 시스템의 `git clone` 및 `git fetch` 호출의 경우, 전송되는 데이터의 양을 다음 옵션으로 제한할 수 있습니다:

- [`--depth`](https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---depthltdepthgt)
- [`--filter`](https://git-scm.com/docs/git-clone#Documentation/git-clone.txt---filterfilter-spec)

#### CI/CD에서 얕은 클론 {#shallow-clone-in-cicd}

`--depth` 필터는 소위 _얕은 클론_을 생성합니다. GitLab 및 GitLab Runner는 기본적으로 [얕은 클론](../../../../ci/pipelines/settings.md#limit-the-number-of-changes-fetched-during-clone)을 수행합니다.

클론 깊이는 `GIT_DEPTH`을 사용하여 GitLab CI/CD 파이프라인 구성에서 구성할 수 있습니다. 예를 들면:

```yaml
variables:
  GIT_DEPTH: 10

test:
  script:
    - ls -al
```

#### CI/CD에서 부분 클론 {#partial-clone-in-cicd}

`--filter` 옵션을 사용하여 _부분 클론_을 생성합니다. 이 인수를 `git-clone`에 전달하려면 `GIT_CLONE_EXTRA_FLAGS` 변수를 설정합니다. 예를 들어, blob의 최대 크기를 1MB로 제한하려면 다음을 추가합니다:

```yaml
variables:
  GIT_CLONE_EXTRA_FLAGS: --filter=blob:limit=1m
```

### 경로 및 객체 유형 필터링 {#filter-out-paths-and-object-types}

특정 유형의 객체를 필터링하거나 특정 경로에서 필터링하려면 `git sparse-checkout` 옵션을 사용합니다. 자세한 내용은 [파일 경로로 필터링](../../../../topics/git/clone.md#filter-by-file-path)을 참조합니다.

### CI/CD 작업에서 `git fetch` 사용 {#use-git-fetch-in-cicd-operations}

리포지토리의 작업 복사본을 유지할 수 있다면, CI/CD 시스템에서 `git clone` 대신 `git fetch`을 사용합니다. `git fetch`은 서버에서 더 적은 작업을 필요로 합니다:

- `git clone`은 전체 리포지토리를 처음부터 요청합니다. `git-pack-objects`은 모든 브랜치와 태그를 처리하고 전송해야 합니다.
- `git fetch`은 리포지토리에서 누락된 Git 참조만 요청합니다. `git-pack-objects`은 전체 Git 참조의 하위 집합만 처리합니다. 이 전략은 또한 전송되는 총 데이터를 줄입니다.

기본적으로 GitLab은 큰 리포지토리에 권장되는 [`fetch` Git 전략](../../../../ci/runners/configure_runners.md#git-strategy)을 사용합니다.

### `git clone` 경로 설정 {#set-a-git-clone-path}

모노리포가 포크 기반 워크플로우와 함께 사용되는 경우 [`GIT_CLONE_PATH`](../../../../ci/runners/configure_runners.md#custom-build-directories)를 설정하여 리포지토리를 클론할 위치를 제어하는 것을 고려합니다.

Git은 포크를 별도의 리포지토리와 별도의 워크트리로 저장합니다. GitLab Runner는 워크트리의 사용을 최적화할 수 없습니다. GitLab Runner 실행기를 주어진 프로젝트에만 구성하고 사용합니다. 프로세스를 더 효율적으로 만들려면 다양한 프로젝트에 걸쳐 공유하지 않습니다.

[`GIT_CLONE_PATH`](../../../../ci/runners/configure_runners.md#custom-build-directories)는 `$CI_BUILDS_DIR`에 설정된 디렉터리에 있어야 합니다. 디스크에서 임의의 경로를 선택할 수 없습니다.

### CI/CD 작업에서 `git clean` 비활성화 {#disable-git-clean-on-cicd-jobs}

`git clean` 명령은 작업 트리에서 추적되지 않은 파일을 제거합니다. 큰 리포지토리에서는 많은 디스크 I/O를 사용합니다. 기존 머신을 재사용하고 기존 워크트리를 재사용할 수 있다면 CI/CD 작업에서 비활성화하는 것을 고려합니다. 예를 들어 `GIT_CLEAN_FLAGS: -ffdx -e .build/`는 실행 간에 워크트리에서 디렉터리를 삭제하는 것을 방지할 수 있습니다. 이는 증분 빌드의 속도를 높일 수 있습니다.

CI/CD 작업에서 `git clean`을 비활성화하려면 [`GIT_CLEAN_FLAGS`](../../../../ci/runners/configure_runners.md#git-clean-flags)를 `none`로 설정합니다.

기본적으로 GitLab은 다음을 보장합니다:

- 주어진 SHA에 워크트리가 있습니다.
- 리포지토리가 깨끗합니다.

`GIT_CLEAN_FLAGS`에서 허용되는 정확한 매개변수는 [`git clean`](https://git-scm.com/docs/git-clean)에 대한 Git 설명서를 참조합니다. 사용 가능한 매개변수는 Git 버전에 따라 다릅니다.

### `git fetch` 동작을 플래그로 변경 {#change-git-fetch-behavior-with-flags}

`git fetch`의 동작을 변경하여 CI/CD 작업이 필요하지 않은 모든 데이터를 제외합니다. 프로젝트에 많은 태그가 있고 CI/CD 작업이 필요하지 않은 경우 `GIT_FETCH_EXTRA_FLAGS`를 사용하여 [`--no-tags`](https://git-scm.com/docs/git-fetch#Documentation/git-fetch.txt---no-tags)를 설정합니다. 이 설정은 페치를 더 빠르고 컴팩트하게 만들 수 있습니다.

리포지토리에 많은 태그가 없더라도 `--no-tags`는 경우에 따라 성능을 개선할 수 있습니다. 자세한 내용은 [이슈 746](https://gitlab.com/gitlab-com/gl-infra/observability/team/-/issues/746) 및 [`GIT_FETCH_EXTRA_FLAGS` Git 설명서](../../../../ci/runners/configure_runners.md#git-fetch-extra-flags)를 참조합니다.

### 러너에 대해 장시간 폴링 사용 {#use-long-polling-for-runners}

러너는 정기적으로 GitLab 인스턴스를 폴링하여 새 CI/CD 작업을 찾습니다. 폴링 간격은 다음 두 가지에 따라 달라집니다:

- `check_interval` 설정.
- 러너 구성 파일에서 구성된 러너의 수.

서버가 많은 러너를 처리하는 경우, 이 폴링은 더 긴 대기열 시간 및 더 높은 CPU 사용량 같은 GitLab 인스턴스의 성능 문제를 유발할 수 있습니다. 장시간 폴링은 새 작업이 준비될 때까지 러너의 작업 요청을 대기시킵니다.

구성 지침은 [장시간 폴링](../../../../ci/runners/long_polling.md)을 참조합니다.

## 모노리포를 위해 Git 최적화 {#optimize-git-for-monorepos}

GitLab을 모노리포로 확장 가능하게 유지하려면 리포지토리 자체를 최적화합니다.

### 개발을 위해 얕은 클론 피하기 {#avoid-shallow-clones-for-development}

개발을 위해 얕은 클론을 피합니다. 얕은 클론은 변경 사항을 푸시하는 데 필요한 시간을 크게 늘립니다. 얕은 클론은 CI/CD 작업에 잘 작동하는데, 이는 체크아웃 후 리포지토리 내용이 변경되지 않기 때문입니다.

로컬 개발의 경우 대신 [부분 클론](https://www.git-scm.com/docs/git-clone#Documentation/git-clone.txt---filterltfilter-specgt)을 사용하여:

- `git clone --filter=blob:none`을 사용하여 blob을 필터링합니다.
- `git clone --filter=tree:0`을 사용하여 트리를 필터링합니다.

자세한 내용은 [클론 크기 줄이기](../../../../topics/git/clone.md#reduce-clone-size)를 참조합니다.

### 리포지토리를 프로필링하여 문제 찾기 {#profile-your-repository-to-find-problems}

큰 리포지토리는 일반적으로 Git의 성능 문제를 경험합니다. [`git-sizer`](https://github.com/github/git-sizer) 프로젝트는 리포지토리를 프로필링하고 잠재적인 문제를 이해하는 데 도움이 됩니다. 성능 문제를 방지하기 위한 완화 전략을 개발하는 데 도움이 될 수 있습니다. 리포지토리를 분석하려면 모든 Git 참조가 있는지 확인하기 위해 전체 Git 미러 또는 베어 클론이 필요합니다.

`git-sizer`을 사용하여 리포지토리를 프로필링하려면:

1. [`git-sizer`](https://github.com/github/git-sizer?tab=readme-ov-file#getting-started)를 설치합니다.
1. 다음 명령을 실행하여 `git-sizer`과 호환되는 베어 Git 형식으로 리포지토리를 클론합니다:

   ```shell
   git clone --mirror <git_repo_url>
   ```

1. Git 리포지토리의 디렉터리에서 `git-sizer`을 모든 통계와 함께 실행합니다:

   ```shell
   git-sizer -v
   ```

처리 후 `git-sizer`의 출력은 다음 예와 같아야 합니다. 각 행에는 리포지토리의 해당 측면에 대한 **우려 수준**이 포함됩니다. 더 높은 우려 수준은 더 많은 별표로 표시됩니다. 매우 높은 우려 수준의 항목은 느낌표로 표시됩니다. 이 예에서 몇 가지 항목의 우려 수준이 높습니다:

```shell
Processing blobs: 1652370
Processing trees: 3396199
Processing commits: 722647
Matching commits to trees: 722647
Processing annotated tags: 534
Processing references: 539
| Name                         | Value     | Level of concern               |
| ---------------------------- | --------- | ------------------------------ |
| Overall repository size      |           |                                |
| * Commits                    |           |                                |
|   * Count                    |   723 k   | *                              |
|   * Total size               |   525 MiB | **                             |
| * Trees                      |           |                                |
|   * Count                    |  3.40 M   | **                             |
|   * Total size               |  9.00 GiB | ****                           |
|   * Total tree entries       |   264 M   | *****                          |
| * Blobs                      |           |                                |
|   * Count                    |  1.65 M   | *                              |
|   * Total size               |  55.8 GiB | *****                          |
| * Annotated tags             |           |                                |
|   * Count                    |   534     |                                |
| * References                 |           |                                |
|   * Count                    |   539     |                                |
|                              |           |                                |
| Biggest objects              |           |                                |
| * Commits                    |           |                                |
|   * Maximum size         [1] |  72.7 KiB | *                              |
|   * Maximum parents      [2] |    66     | ******                         |
| * Trees                      |           |                                |
|   * Maximum entries      [3] |  1.68 k   | *                              |
| * Blobs                      |           |                                |
|   * Maximum size         [4] |  13.5 MiB | *                              |
|                              |           |                                |
| History structure            |           |                                |
| * Maximum history depth      |   136 k   |                                |
| * Maximum tag depth      [5] |     1     |                                |
|                              |           |                                |
| Biggest checkouts            |           |                                |
| * Number of directories  [6] |  4.38 k   | **                             |
| * Maximum path depth     [7] |    13     | *                              |
| * Maximum path length    [8] |   134 B   | *                              |
| * Number of files        [9] |  62.3 k   | *                              |
| * Total size of files    [9] |   747 MiB |                                |
| * Number of symlinks    [10] |    40     |                                |
| * Number of submodules       |     0     |                                |
```

### 큰 바이너리 파일에 Git LFS 사용 {#use-git-lfs-for-large-binary-files}

바이너리 파일(패키지, 오디오, 비디오 또는 그래픽 같은)을 Git Large File Storage(Git LFS) 객체로 저장합니다.

사용자가 파일을 Git에 커밋하면 Git은 blob [객체 유형](https://git-scm.com/book/en/v2/Git-Internals-Git-Objects)을 사용하여 내용을 저장하고 관리합니다. Git은 큰 바이너리 데이터를 효율적으로 처리하지 않으므로 큰 blob은 Git의 문제입니다. `git-sizer`에서 10MB 이상의 blob을 보고하면, 일반적으로 리포지토리에 큰 바이너리 파일이 있습니다. 큰 바이너리 파일은 서버와 클라이언트 모두에 문제를 일으킵니다:

- 서버의 경우: 텍스트 기반 소스 코드와 달리 바이너리 데이터는 종종 이미 압축되어 있습니다. Git은 바이너리 데이터를 더 이상 압축할 수 없으므로 큰 packfile이 생깁니다. 큰 packfile은 생성하고 전송하는 데 더 많은 CPU, 메모리 및 대역폭이 필요합니다.
- 클라이언트의 경우: Git은 blob 콘텐츠를 packfile(일반적으로 `.git/objects/pack/`에 있음)과 일반 파일(에 있음)에 모두 저장합니다 [워크트리](https://git-scm.com/docs/git-worktree). 바이너리 파일은 텍스트 기반 소스 코드보다 훨씬 더 많은 공간이 필요합니다.

Git LFS는 객체 스토리지 같은 외부에 객체를 저장합니다. Git 리포지토리에는 바이너리 파일 자체가 아닌 객체의 위치에 대한 포인터가 포함되어 있습니다. 이는 리포지토리 성능을 개선할 수 있습니다. 자세한 내용은 [Git LFS 설명서](../../../../topics/git/lfs/_index.md)를 참조합니다.

## 관련 항목 {#related-topics}

- [Gitaly 구성](../../../../administration/gitaly/configure_gitaly.md)
