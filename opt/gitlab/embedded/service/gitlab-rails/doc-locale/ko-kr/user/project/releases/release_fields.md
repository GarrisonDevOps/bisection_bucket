---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 릴리스 필드
---

릴리스를 생성하거나 편집할 때 다음 필드를 사용할 수 있습니다.

## 제목 {#title}

릴리스 제목은 릴리스를 생성 또는 편집할 때 **릴리스 제목** 필드를 사용하여 사용자 지정할 수 있습니다. 제목을 제공하지 않으면 릴리스의 태그 이름이 대신 사용됩니다.

## 태그 이름 {#tag-name}

릴리스 태그 이름에는 릴리스 버전이 포함되어야 합니다. GitLab은 릴리스에 [시멘틱 버전 관리](https://semver.org/)를 사용하며, 사용자도 이를 사용할 수 있습니다. `(Major).(Minor).(Patch)`을(를) 사용합니다. 자세한 내용은 [GitLab 버전 관리 정책](../../../policy/maintenance.md#versioning)을(를) 참조하세요.

예를 들어 GitLab 버전 `16.10.1`의 경우:

- `16`는 주 버전을 나타냅니다. 주 릴리스는 `16.0.0`였지만 흔히 `16.0`이(가) 아닙니다.
- `10`는 부 버전을 나타냅니다. 부 릴리스는 `16.10.0`였지만 흔히 `16.10`이(가) 아닙니다.
- `1`는 패치 번호를 나타냅니다.

버전 번호의 어떤 부분이든 여러 자릿수가 될 수 있습니다(예: `16.10.11`).

## 릴리스 정보 설명 {#release-notes-description}

모든 릴리스에는 설명이 있습니다. 원하는 텍스트를 추가할 수 있지만, 릴리스 콘텐츠를 설명하는 변경 로그를 포함하는 것을 권장합니다. 이를 통해 사용자는 게시한 각 릴리스 간의 차이점을 빠르게 스캔할 수 있습니다.

[Git의 태깅 메시지](https://git-scm.com/book/en/v2/Git-Basics-Tagging)는 **릴리스 정보에 태그 메시지 포함**을(를) 선택하여 릴리스 정보 설명에 포함할 수 있습니다.

설명은 [마크다운](../../markdown.md)을(를) 지원합니다.

## 릴리스 자산 {#release-assets}

릴리스에는 다음과 같은 유형의 자산이 포함됩니다:

- [소스 코드](#source-code)
- [관련 자료로의 링크](#links)

### 소스 코드 {#source-code}

GitLab은 지정된 Git 태그에서 `zip`, `tar.gz`, `tar.bz2` 및 `tar` 아카이브된 소스 코드를 자동으로 생성합니다. 이러한 자산은 읽기 전용이며 [다운로드할 수 있습니다](../repository/_index.md#download-repository-source-code).

### 링크 {#links}

링크는 설명서, 빌드된 바이너리 또는 기타 관련 자료 등 원하는 모든 것을 가리킬 수 있는 URL입니다. 이는 GitLab 인스턴스의 내부 및 외부 링크 모두가 될 수 있습니다. URL은 `http`, `https` 또는 `ftp` 스키마 중 하나를 사용해야 합니다. 자산으로서의 각 링크에는 다음 속성이 있습니다:

| 속성   | 필수 | 설명 |
|-------------|----------|-------------|
| `name`      | 예      | 링크의 이름입니다. |
| `url`       | 예      | 파일을 다운로드할 URL입니다. |
| `filepath`  | 아니요       | `url`로의 리디렉션 링크입니다. 슬래시(`/`)로 시작해야 합니다. 자세한 내용은 [이 섹션](#permanent-links-to-release-assets)을(를) 참조하세요. |
| `link_type` | 아니요       | 사용자가 `url`로 다운로드할 수 있는 콘텐츠의 종류입니다. 자세한 내용은 [이 섹션](#link-types)을(를) 참조하세요. |

#### 릴리스 자산으로의 영구 링크 {#permanent-links-to-release-assets}

릴리스와 관련된 자산은 영구 URL을 통해 액세스할 수 있습니다. GitLab은 항상 이 URL을 실제 자산 위치로 리디렉션하므로, 자산이 다른 위치로 이동되더라도 동일한 URL을 계속 사용할 수 있습니다. 이는 [링크 생성](../../../api/releases/links.md#create-a-release-link) 중에 또는 [업데이트](../../../api/releases/links.md#update-a-release-link) 중에 `filepath` API 속성을 사용하여 정의됩니다.

URL의 형식은 다음과 같습니다:

```plaintext
https://host/namespace/project/-/releases/:release/downloads:filepath
```

예를 들어 `v16.9.0-rc2` 릴리스에 `gitlab-org` 네임스페이스 및 `gitlab-runner` 프로젝트의 자산이 `gitlab.com`에 있는 경우:

```json
{
  "name": "linux amd64",
  "filepath": "/binaries/gitlab-runner-linux-amd64",
  "url": "https://gitlab-runner-downloads.s3.amazonaws.com/v16.9.0-rc2/binaries/gitlab-runner-linux-amd64",
  "link_type": "other"
}
```

이 자산의 직접 링크는 다음과 같습니다:

```plaintext
https://gitlab.com/gitlab-org/gitlab-runner/-/releases/v16.9.0-rc2/downloads/binaries/gitlab-runner-linux-amd64
```

자산의 물리적 위치는 언제든지 변경될 수 있으며, 직접 링크는 변경되지 않습니다.

릴리스가 비공개인 경우, 요청을 할 때 `api` 또는 `read_api` 범위를 가진 개인 액세스 토큰을 `private_token` 쿼리 매개변수 또는 `HTTP_PRIVATE_TOKEN` 헤더를 사용하여 제공해야 합니다. 예를 들어:

```shell
curl --location --output filename "https://gitlab.example.com/my-group/my-project/-/releases/myrelease/downloads/<path-to-file>?private_token=<your_access_token>"
curl --location --output filename --header "PRIVATE-TOKEN: <your_access_token>" "https://gitlab.example.com/my-group/my-project/-/releases/myrelease/downloads/<path-to-file>"
```

#### 최신 릴리스 자산으로의 영구 링크 {#permanent-links-to-latest-release-assets}

[릴리스 자산으로의 영구 링크](#permanent-links-to-release-assets)에서 `filepath`을(를) 사용하여 [최신 릴리스로의 영구 링크](_index.md#permanent-link-to-latest-release)와 함께 조합할 수 있습니다. `filepath`는 슬래시(`/`)로 시작해야 합니다.

URL의 형식은 다음과 같습니다:

```plaintext
https://host/namespace/project/-/releases/permalink/latest/downloads:filepath
```

이 형식을 사용하여 최신 릴리스의 자산으로의 영구 링크를 제공할 수 있습니다.

예를 들어 `v16.9.0-rc2` 최신 릴리스에 [`filepath`](../../../api/releases/links.md#create-a-release-link)이(가) 있는 경우 `gitlab-org` 네임스페이스 및 `gitlab-runner` 프로젝트의 자산이 `gitlab.com`에 있습니다:

```json
{
  "name": "linux amd64",
  "filepath": "/binaries/gitlab-runner-linux-amd64",
  "url": "https://gitlab-runner-downloads.s3.amazonaws.com/v16.9.0-rc2/binaries/gitlab-runner-linux-amd64",
  "link_type": "other"
}
```

이 자산의 직접 링크는 다음과 같습니다:

```plaintext
https://gitlab.com/gitlab-org/gitlab-runner/-/releases/permalink/latest/downloads/binaries/gitlab-runner-linux-amd64
```

#### 링크 유형 {#link-types}

네 가지 유형의 링크는 "런북", "패키지", "이미지" 및 "기타"입니다. `link_type` 매개변수는 다음 네 가지 값 중 하나를 허용합니다:

- `runbook`
- `package`
- `image`
- `other` (기본값)

이 필드는 URL에 영향을 미치지 않으며, 프로젝트의 릴리스 페이지에서 시각적 목적으로만 사용됩니다.

#### 바이너리를 첨부하기 위해 일반 패키지 사용 {#use-a-generic-package-for-attaching-binaries}

개별 릴리스 항목에 바이너리 파일을 첨부하는 데도 사용할 수 있는 릴리스 또는 태그 파이프라인의 아티팩트를 저장하기 위해 [일반 패키지](../../packages/generic_packages/_index.md)를 사용할 수 있습니다. 기본적으로 다음을 수행해야 합니다:

1. [아티팩트를 일반 패키지 레지스트리로 푸시합니다](../../packages/generic_packages/_index.md#publish-a-package).
1. [패키지 링크를 릴리스에 첨부합니다](#links).

다음 예제에서는 릴리스 자산을 생성하고, 일반 패키지로 게시한 다음, 릴리스를 생성합니다:

```yaml
stages:
  - build
  - upload
  - release

variables:
  # Package version can only contain numbers (0-9), and dots (.).
  # Must be in the format of X.Y.Z, and should match the /\A\d+\.\d+\.\d+\z/ regular expression.
  # See https://docs.gitlab.com/user/packages/generic_packages/#publish-a-package
  PACKAGE_VERSION: "1.2.3"
  DARWIN_AMD64_BINARY: "myawesomerelease-darwin-amd64-${PACKAGE_VERSION}"
  LINUX_AMD64_BINARY: "myawesomerelease-linux-amd64-${PACKAGE_VERSION}"
  PACKAGE_REGISTRY_URL: "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/myawesomerelease/${PACKAGE_VERSION}"

build:
  stage: build
  image: alpine:latest
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - mkdir bin
    - echo "Mock binary for ${DARWIN_AMD64_BINARY}" > bin/${DARWIN_AMD64_BINARY}
    - echo "Mock binary for ${LINUX_AMD64_BINARY}" > bin/${LINUX_AMD64_BINARY}
  artifacts:
    paths:
      - bin/

upload:
  stage: upload
  image: curlimages/curl:latest
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - |
      curl --header "JOB-TOKEN: ${CI_JOB_TOKEN}" --upload-file bin/${DARWIN_AMD64_BINARY} "${PACKAGE_REGISTRY_URL}/${DARWIN_AMD64_BINARY}"
    - |
      curl --header "JOB-TOKEN: ${CI_JOB_TOKEN}" --upload-file bin/${LINUX_AMD64_BINARY} "${PACKAGE_REGISTRY_URL}/${LINUX_AMD64_BINARY}"

release:
  # Caution, as of 2021-02-02 these assets links require a login, see:
  # https://gitlab.com/gitlab-org/gitlab/-/issues/299384
  stage: release
  image: registry.gitlab.com/gitlab-org/cli:latest
  rules:
    - if: $CI_COMMIT_TAG
  script:
    - |
      glab release create "$CI_COMMIT_TAG" --name "Release $CI_COMMIT_TAG" \
        --assets-links="[{\"name\":\"${DARWIN_AMD64_BINARY}\",\"url\":\"${PACKAGE_REGISTRY_URL}/${DARWIN_AMD64_BINARY}\"},{\"name\":\"${LINUX_AMD64_BINARY}\",\"url\":\"${PACKAGE_REGISTRY_URL}/${LINUX_AMD64_BINARY}\"}]"
```

PowerShell 사용자는 `"` 큰따옴표를 JSON 문자열 내에서 `` ` ``(백틱)으로 이스케이프해야 할 수 있습니다. `--assets-link` 및 `ConvertTo-Json`의 경우 `release-cli`로 전달하기 전에 이를 수행합니다. 예를 들어:

```yaml
release:
  script:
    - $env:assets = "[{`"name`":`"MyFooAsset`",`"url`":`"https://gitlab.com/upack/artifacts/download/$env:UPACK_GROUP/$env:UPACK_NAME/$($env:GitVersion_SemVer)?contentOnly=zip`"}]"
    - $env:assetsjson = $env:assets | ConvertTo-Json
    - glab release create $env:CI_COMMIT_TAG --name "Release $env:CI_COMMIT_TAG" --notes "Release $env:CI_COMMIT_TAG" --ref $env:CI_COMMIT_TAG --assets-links=$env:assetsjson
```

> [!note]
> [작업 아티팩트](../../../ci/jobs/job_artifacts.md) 링크를 릴리스에 직접 첨부하는 것은 권장되지 않습니다. 아티팩트는 일시적이며 동일한 파이프라인에서 데이터를 전달하는 데 사용되기 때문입니다. 이는 아티팩트가 만료되거나 누군가 수동으로 삭제할 위험이 있다는 의미입니다.

### 새로운 기능과 총 기능의 수 {#number-of-new-and-total-features}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

[GitLab.com](https://gitlab.com/gitlab-org/gitlab/-/releases)에서 프로젝트의 새로운 기능과 총 기능의 수를 볼 수 있습니다.

![GitLab 릴리스의 새로운 기능과 총 기능의 수를 표시하는 배지입니다.](img/feature_count_v14_6.png "릴리스의 기능 수")

합계는 [shields](https://shields.io/)에 표시되며 [`www-gitlab-com` 리포지토리의 Rake 작업](https://gitlab.com/gitlab-com/www-gitlab-com/-/blob/master/lib/tasks/update_gitlab_project_releases_page.rake)에 의해 릴리스당 생성됩니다.

| 항목             | 공식                                                                            |
|------------------|------------------------------------------------------------------------------------|
| `New features`   | 프로젝트의 단일 릴리스에 대한 모든 계층의 릴리스 게시물 총수입니다. |
| `Total features` | 프로젝트의 모든 릴리스에 대해 역순으로 릴리스 게시물의 총 개수입니다.     |

개수도 라이선스 계층별로 표시됩니다.

| 항목             | 공식                                                                                             |
|------------------|-----------------------------------------------------------------------------------------------------|
| `New features`   | 프로젝트의 단일 릴리스에 대한 단일 계층의 릴리스 게시물 총수입니다.              |
| `Total features` | 프로젝트의 모든 릴리스에 대해 역순으로 단일 계층의 릴리스 게시물 총 개수입니다. |
