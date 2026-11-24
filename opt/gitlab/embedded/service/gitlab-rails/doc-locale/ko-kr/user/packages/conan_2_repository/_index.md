---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 패키지 레지스트리의 Conan 2 패키지
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  베타

{{< /details >}}

{{< history >}}

- GitLab 18.1에서 `conan_package_revisions_support` [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/519741)되었습니다. 기본적으로 비활성화되었습니다.
- [GitLab.com에서 활성화됨](https://gitlab.com/groups/gitlab-org/-/work_items/14896) GitLab 18.3에서 기능 플래그 `conan_package_revisions_support`이 제거되었습니다.

{{< /history >}}

프로젝트의 패키지 레지스트리에 Conan 2 패키지를 게시합니다. 그런 다음 패키지를 종속성으로 사용해야 할 때마다 설치합니다.

> [!warning]
> GitLab용 Conan 2 패키지 레지스트리는 개발 중이며 기능이 제한되어 프로덕션 사용을 위해 준비되지 않았습니다. 이 [에픽](https://gitlab.com/groups/gitlab-org/-/work_items/8258)은 프로덕션 준비를 위한 남은 작업 및 일정을 자세히 설명합니다.

Conan 2 패키지를 패키지 레지스트리에 게시하려면 패키지 레지스트리를 리모트로 추가하고 인증합니다.

그런 다음 `conan` 명령을 실행하고 패키지를 패키지 레지스트리에 게시할 수 있습니다.

> [!note]
> Conan 레지스트리는 FIPS 준수하지 않으며 FIPS 모드가 활성화되면 비활성화됩니다.

Conan 2 패키지 관리자 클라이언트가 사용하는 특정 API 엔드포인트의 문서는 [Conan v2 API](../../../api/packages/conan_v2.md)를 참조합니다.

[Conan 2 패키지를 빌드하는](../workflows/build_packages.md#conan-2) 방법을 알아봅니다.

## 패키지 레지스트리를 Conan 리모트로 추가 {#add-the-package-registry-as-a-conan-remote}

`conan` 명령을 실행하려면 프로젝트 또는 인스턴스에 대해 패키지 레지스트리를 Conan 리모트로 추가해야 합니다. 그런 다음 패키지 레지스트리에 패키지를 게시하고 패키지를 설치할 수 있습니다.

### 프로젝트에 대한 리모트 추가 {#add-a-remote-for-your-project}

모든 명령에서 리모트 이름을 지정할 필요 없이 프로젝트의 패키지로 작업할 수 있도록 리모트를 설정합니다.

프로젝트에 대한 리모트를 설정할 때 패키지 이름은 소문자여야 합니다. 또한 명령에는 예를 들어 `package_name/version@user/channel`과(와) 같은 사용자 및 채널을 포함한 전체 레시피가 포함되어야 합니다.

리모트를 추가하려면:

1. 터미널에서 다음 명령을 실행합니다:

   ```shell
   conan remote add gitlab https://gitlab.example.com/api/v4/projects/<project_id>/packages/conan
   ```

1. `--remote=gitlab`을(를) Conan 2 명령의 끝에 추가하여 리모트를 사용합니다.

   예를 들어:

   ```shell
   conan search hello* --remote=gitlab
   ```

## 패키지 레지스트리로 인증 {#authenticate-to-the-package-registry}

GitLab은 패키지를 업로드하고 비공개 및 내부 프로젝트에서 패키지를 설치하기 위해 인증이 필요합니다. (하지만 공개 프로젝트에서는 인증 없이 패키지를 설치할 수 있습니다.)

패키지 레지스트리에 인증하려면 다음 중 하나가 필요합니다:

- [개인 액세스 토큰](../../profile/personal_access_tokens.md)(범위가 `api`(으)로 설정됨)
- [배포 토큰](../../project/deploy_tokens/_index.md)(범위가 `read_package_registry`, `write_package_registry` 또는 둘 다로 설정됨)
- [CI 작업 토큰](#publish-a-conan-2-package-by-using-cicd)입니다.

> [!note]
> 비공개 및 내부 프로젝트의 패키지는 인증되지 않으면 숨겨집니다. 인증 없이 비공개 또는 내부 프로젝트에서 패키지를 검색하거나 다운로드하려고 하면 Conan 2 클라이언트에서 오류 `unable to find the package in remote`를 받습니다.

### GitLab 리모트에 자격 증명 추가 {#add-your-credentials-to-the-gitlab-remote}

모든 Conan 2 명령에 명시적으로 토큰을 추가할 필요가 없도록 토큰을 GitLab 리모트와 연결합니다.

사전 요구 사항:

- 인증 토큰이 있어야 합니다.
- Conan 리모트는 [구성되어야 합니다](#add-the-package-registry-as-a-conan-remote).

터미널에서 다음 명령을 실행합니다. 이 예에서 리모트 이름은 `gitlab`입니다. 리모트의 이름을 사용합니다.

```shell
conan remote login -p <personal_access_token or deploy_token> gitlab <gitlab_username or deploy_token_username>
```

`--remote=gitlab`로 명령을 실행하면 사용자 이름과 암호가 요청에 포함됩니다.

> [!note]
> GitLab 인증이 정기적으로 만료되므로 경우에 따라 개인 액세스 토큰을 다시 입력해야 할 수 있습니다.

## Conan 2 패키지 게시 {#publish-a-conan-2-package}

Conan 2 패키지를 패키지 레지스트리에 게시하여 프로젝트에 접근할 수 있는 모든 사용자가 패키지를 종속성으로 사용할 수 있도록 합니다.

사전 요구 사항:

- Conan 리모트는 [구성되어야 합니다](#add-the-package-registry-as-a-conan-remote).
- 패키지 레지스트리에 [인증](#authenticate-to-the-package-registry)이 구성되어야 합니다.
- 로컬 [Conan 2 패키지](../workflows/build_packages.md#conan-2)가 있어야 합니다.
- [프로젝트 개요 페이지](../../project/working_with_projects.md#find-the-project-id)에 표시된 프로젝트 ID가 있어야 합니다.

패키지를 게시하려면 `conan upload` 명령을 사용합니다:

```shell
conan upload hello/0.1@mycompany/beta -r gitlab
```

## CI/CD를 사용하여 Conan 2 패키지 게시 {#publish-a-conan-2-package-by-using-cicd}

[GitLab CI/CD](../../../ci/_index.md)에서 Conan 2 명령을 사용하려면 명령에서 개인 액세스 토큰 대신 `CI_JOB_TOKEN`을(를) 사용할 수 있습니다.

`.gitlab-ci.yml` 파일의 각 Conan 명령과 함께 `CONAN_LOGIN_USERNAME` 및 `CONAN_PASSWORD`를 제공할 수 있습니다. 예를 들어:

```yaml
create_package:
  image: <conan 2 image>
  stage: deploy
  script:
    - conan remote add gitlab ${CI_API_V4_URL}/projects/$CI_PROJECT_ID/packages/conan
    - conan new <package-name>/0.1
    - conan create . --channel=stable --user=mycompany
    - CONAN_LOGIN_USERNAME=ci_user CONAN_PASSWORD=${CI_JOB_TOKEN} conan upload <package-name>/0.1@mycompany/stable --remote=gitlab
  environment: production
```

[공식 가이드](https://docs.conan.io/2.17/examples/runners/docker/basic.html)를 따라 CI 파일의 기반으로 사용할 적절한 Conan 2 이미지를 생성합니다.

### 동일한 레시피를 사용한 패키지 재게시 {#re-publishing-a-package-with-the-same-recipe}

기존 패키지와 동일한 레시피(`package-name/version@user/channel`)를 가진 패키지를 게시할 때 이미 서버에 있으므로 Conan은 업로드를 건너뜁니다.

## Conan 2 패키지 설치 {#install-a-conan-2-package}

패키지 레지스트리에서 Conan 2 패키지를 설치하여 종속성으로 사용할 수 있습니다. 프로젝트의 범위에서 패키지를 설치할 수 있습니다. 여러 패키지가 동일한 레시피를 가지고 있으면 패키지를 설치할 때 가장 최근에 게시된 패키지가 검색됩니다.

Conan 2 패키지는 종종 `conanfile.txt` 파일을 사용하여 종속성으로 설치됩니다.

사전 요구 사항:

- Conan 리모트는 [구성되어야 합니다](#add-the-package-registry-as-a-conan-remote).
- 비공개 및 내부 프로젝트의 경우 패키지 레지스트리를 사용하여 [인증](#authenticate-to-the-package-registry)을 구성해야 합니다.

1. [Conan 2 패키지](../workflows/build_packages.md#conan-2) 가이드를 따라 다른 패키지를 생성합니다. 프로젝트의 루트에서 `conanfile.txt`라는 파일을 만듭니다.

1. 파일의 `[requires]` 섹션에 Conan 레시피를 추가합니다:

   ```plaintext
   [requires]
   hello/0.1@mycompany/beta
   ```

1. 프로젝트의 루트에서 `build` 디렉터리를 만들고 해당 디렉터리로 변경합니다:

   ```shell
   mkdir build && cd build
   ```

1. `conanfile.txt`에 나열된 종속성을 설치합니다:

   ```shell
   conan install ../conanfile.txt
   ```

> [!note]
> 이 자습서에서 생성한 패키지를 설치하려고 하면 패키지가 이미 있으므로 설치 명령은 적용되지 않습니다. 이 명령을 사용하여 로컬에서 기존 패키지를 제거한 후 다시 시도합니다:
>
> ```shell
> conan remove hello/0.1@mycompany/beta
> ```

## Conan 2 패키지 제거 {#remove-a-conan-2-package}

GitLab 패키지 레지스트리에서 Conan 2 패키지를 제거하는 두 가지 방법이 있습니다.

- Conan 2 클라이언트를 사용하는 명령줄에서:

  ```shell
  conan remove hello/0.1@mycompany/beta --remote=gitlab
  ```

  이 명령에서 리모트를 명시적으로 포함해야 하며, 그렇지 않으면 패키지는 로컬 시스템 캐시에서만 제거됩니다.

  > [!note]
  > 이 명령은 패키지 레지스트리에서 모든 레시피 및 이진 패키지 파일을 제거합니다.

- GitLab 사용자 인터페이스에서:

  프로젝트의 **배포** > **패키지 레지스트리**로 이동합니다. **리포지토리 제거** ({{< icon name="remove" >}})를 선택하여 패키지를 제거합니다.

## 패키지 레지스트리에서 Conan 2 패키지 검색 {#search-for-conan-2-packages-in-the-package-registry}

전체 또는 부분 패키지 이름으로 또는 정확한 레시피로 검색하려면 `conan search` 명령을 실행합니다.

- 특정 패키지 이름을 가진 모든 패키지를 검색하려면:

  ```shell
  conan search hello --remote=gitlab
  ```

- `he`로 시작하는 모든 패키지와 같이 부분 이름을 검색하려면:

  ```shell
  conan search "he*" --remote=gitlab
  ```

검색 범위는 Conan 리모트 구성에 따라 다릅니다. 검색에는 접근 권한이 있는 한 대상 프로젝트의 모든 패키지가 포함됩니다.

검색 결과의 제한은 500개 패키지이며 결과는 가장 최근에 게시된 패키지로 정렬됩니다.

> [!note]
> 패키지를 검색할 때 Conan v2 CLI는 Conan v2로 업로드된 패키지에 대해서만 패키지 세부 정보를 표시합니다. Conan v1로 업로드된 패키지는 검색 결과에 나타나지만 해당 세부 정보는 표시되지 않습니다. Conan v2 레시피는 Conan v1으로 업로드된 패키지에 있는 `recipe_hash` 필드가 없는 패키지 참조를 예상하기 때문입니다.

## Conan 2 패키지 다운로드 {#download-a-conan-2-package}

`conan download` 명령을 사용하는 설정을 사용하지 않고 Conan 2 패키지의 레시피 및 이진 파일을 로컬 캐시에 다운로드할 수 있습니다.

사전 요구 사항:

- Conan 리모트는 [구성되어야 합니다](#add-the-package-registry-as-a-conan-remote).
- 비공개 및 내부 프로젝트의 경우 패키지 레지스트리를 사용하여 [인증](#authenticate-to-the-package-registry)을 구성해야 합니다.

### 모든 이진 패키지 다운로드 {#download-all-binary-packages}

패키지 레지스트리에서 레시피와 관련된 모든 이진 패키지를 다운로드할 수 있습니다.

모든 이진 패키지를 다운로드하려면 다음 명령을 실행합니다:

```shell
conan download hello/0.1@mycompany/beta --remote=gitlab
```

### 레시피 파일 다운로드 {#download-recipe-files}

이진 패키지 없이 레시피 파일만 다운로드할 수 있습니다.

레시피 파일을 다운로드하려면 다음 명령을 실행합니다:

```shell
conan download hello/0.1@mycompany/beta --remote=gitlab --only-recipe
```

### 특정 이진 패키지 다운로드 {#download-a-specific-binary-package}

패키지 참조(Conan 2 문서에서 `package_id`로 알려짐)를 참조하여 단일 이진 패키지를 다운로드할 수 있습니다.

특정 이진 패키지를 다운로드하려면 다음 명령을 실행합니다:

```shell
conan download Hello/0.1@foo+bar/stable:<package_reference> --remote=gitlab
```

## 지원되는 CLI 명령 {#supported-cli-commands}

GitLab Conan 리포지토리는 다음 Conan 2 CLI 명령을 지원합니다:

- `conan upload`: 레시피 및 패키지 파일을 패키지 레지스트리에 업로드합니다.
- `conan install`: 패키지 레지스트리에서 Conan 2 패키지를 설치합니다. 여기에는 `conanfile.txt` 파일 사용이 포함됩니다.
- `conan download`: 패키지 레시피 및 이진 파일을 로컬 캐시에 다운로드합니다.
- `conan search`: 패키지 레지스트리에서 공개 패키지 및 보기 권한이 있는 비공개 패키지를 검색합니다.
- `conan list` : 기존 레시피, 개정판 또는 패키지를 나열합니다.
- `conan remove`: 패키지 레지스트리에서 패키지를 삭제합니다.

## Conan 개정판 {#conan-revisions}

Conan 개정판은 패키지 레지스트리에서 패키지 불변성을 제공합니다. 버전을 변경하지 않고 레시피 또는 패키지를 변경할 때 Conan은 이러한 변경을 추적하기 위해 고유 식별자(개정판)를 계산합니다.

### 개정판 유형 {#types-of-revisions}

Conan은 두 가지 유형의 개정판을 사용합니다:

- **레시피 개정판 (RREV)**: 레시피를 내보낼 때 생성됩니다. 기본적으로 Conan은 레시피 매니페스트의 체크섬 해시를 사용하여 레시피 개정판을 계산합니다.
- **패키지 개정판 (PREV)**: 패키지를 빌드할 때 생성됩니다. Conan은 패키지 내용의 해시를 사용하여 패키지 개정판을 계산합니다.

### 참조 개정판 {#reference-revisions}

다음 형식으로 패키지를 참조할 수 있습니다:

| 참조 | 설명 |
| --- | --- |
| `lib/1.0@conan/stable` | `lib/1.0@conan/stable`에 대한 최신 RREV입니다. |
| `lib/1.0@conan/stable#RREV` | `lib/1.0@conan/stable`에 대한 특정 RREV입니다. |
| `lib/1.0@conan/stable#RREV:PACKAGE_REFERENCE` | 특정 RREV에 속하는 이진 패키지입니다. |
| `lib/1.0@conan/stable#RREV:PACKAGE_REFERENCE#PREV` | 특정 RREV에 속하는 이진 패키지 개정판 PREV입니다. |

### 개정판 업로드 {#upload-revisions}

GitLab 패키지 레지스트리에 모든 개정판 및 해당 이진 파일을 업로드하려면:

```shell
conan upload "hello/0.1@mycompany/beta#*" --remote=gitlab
```

여러 개정판을 업로드할 때 가장 오래된 것부터 최신 것 순서로 업로드됩니다. 상대 순서는 레지스트리에 유지됩니다.

### 개정판 나열 {#list-revisions}

Conan 2에서 특정 레시피의 모든 개정판을 나열하려면:

```shell
conan list "hello/0.1@mycompany/beta#*" --remote=gitlab
```

이 명령은 지정된 레시피에 대한 모든 사용 가능한 개정판을 해당 개정판 해시 및 생성 날짜와 함께 표시합니다.

특정 개정판에 대한 자세한 정보를 얻으려면:

```shell
conan list "hello/0.1@mycompany/beta#revision_hash:*#*" --remote=gitlab
```

이 명령은 해당 개정판에 사용 가능한 특정 이진 패키지 및 패키지 개정판을 표시합니다.

### 개정판이 포함된 패키지 삭제 {#delete-packages-with-revisions}

다양한 수준의 세밀도에서 패키지를 삭제할 수 있습니다:

#### 특정 레시피 개정판 삭제 {#delete-a-specific-recipe-revision}

특정 레시피 개정판과 그 관련된 모든 이진 패키지를 삭제하려면:

```shell
conan remove "hello/0.1@mycompany/beta#revision_hash" --remote=gitlab
```

#### 특정 레시피 개정판에 대한 패키지 삭제 {#delete-packages-for-a-specific-recipe-revision}

특정 레시피 개정판과 관련된 모든 패키지를 삭제하려면:

```shell
conan remove "hello/0.1@mycompany/beta#revision_hash:*" --remote=gitlab
```

#### 개정판의 특정 패키지 삭제 {#delete-a-specific-package-in-a-revision}

레시피 개정판의 특정 패키지를 삭제하려면 다음을 사용할 수 있습니다:

```shell
conan remove "package_name/version@user/channel#revision_hash:package_id" --remote=gitlab
```

### 불변 개정판 워크플로우 {#immutable-revisions-workflow}

개정판은 불변으로 설계되었습니다. 레시피 또는 소스 코드를 수정할 때:

- 레시피를 내보낼 때 새 레시피 개정판이 생성됩니다.
- 이전 레시피 개정판에 속하는 기존 이진 파일은 포함되지 않습니다. 새 레시피 개정판에 대해 새 이진 파일을 빌드해야 합니다.
- 패키지를 설치할 때 Conan 2는 개정판을 지정하지 않으면 자동으로 최신 개정판을 검색합니다.

패키지 이진 파일의 경우 레시피 개정판 및 패키지 참조(Conan 2 문서에서 `package_id`로 알려짐)당 하나의 패키지 개정판만 포함해야 합니다. 동일한 레시피 개정판 및 패키지 ID의 여러 패키지 개정판은 패키지가 불필요하게 다시 빌드되었음을 나타냅니다.
