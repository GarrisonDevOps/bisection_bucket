---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 패키지 레지스트리의 Conan 1 패키지
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  베타

{{< /details >}}

> [!warning]
> GitLab용 Conan 패키지 레지스트리는 개발 중이며 제한된 기능으로 인해 프로덕션 사용에 준비되지 않았습니다. 이 [에픽](https://gitlab.com/groups/gitlab-org/-/work_items/6816)은 프로덕션 준비를 위한 남은 작업과 일정을 자세히 설명합니다.

프로젝트의 패키지 레지스트리에 Conan 패키지를 게시합니다. 그런 다음 종속성으로 사용해야 할 때마다 패키지를 설치합니다.

Conan 패키지를 패키지 레지스트리에 게시하려면 패키지 레지스트리를 원격으로 추가하고 인증합니다.

그러면 `conan` 명령을 실행하고 패키지를 패키지 레지스트리에 게시할 수 있습니다.

> [!note]
> Conan 레지스트리는 FIPS 호환이 아니며 FIPS 모드가 활성화되면 비활성화됩니다.

Conan 패키지 관리자 클라이언트가 사용하는 특정 API 엔드포인트 설명서는 [Conan v1 API](../../../api/packages/conan_v1.md) 또는 [Conan v2 API](../../../api/packages/conan_v2.md)를 참조하세요.

[Conan 1 패키지를 빌드하는](../workflows/build_packages.md#conan-1) 방법을 알아봅니다.

## 패키지 레지스트리를 Conan 원격으로 추가 {#add-the-package-registry-as-a-conan-remote}

`conan` 명령을 실행하려면 프로젝트 또는 인스턴스에 대해 패키지 레지스트리를 Conan 원격으로 추가해야 합니다. 그러면 패키지를 패키지 레지스트리에 게시하고 패키지를 설치할 수 있습니다.

### 프로젝트에 대한 원격 추가 {#add-a-remote-for-your-project}

원격을 설정하면 모든 명령에서 원격 이름을 지정할 필요 없이 프로젝트의 패키지로 작업할 수 있습니다.

프로젝트에 대한 원격을 설정할 때 패키지 이름에 제한이 없습니다. 그러나 명령에는 전체 레시피(예: `package_name/version@user/channel`)를 포함하여 사용자 및 채널을 포함해야 합니다.

원격을 추가하려면:

1. 터미널에서 이 명령을 실행합니다:

   ```shell
   conan remote add gitlab https://gitlab.example.com/api/v4/projects/<project_id>/packages/conan
   ```

1. Conan 명령의 끝에 `--remote=gitlab`을 추가하여 원격을 사용합니다.

   예를 들어:

   ```shell
   conan search Hello* --remote=gitlab
   ```

### 인스턴스에 대한 원격 추가 {#add-a-remote-for-your-instance}

단일 원격을 사용하여 전체 GitLab 인스턴스에서 패키지에 액세스합니다.

그러나 이 원격을 사용할 때 이러한 [패키지 이름 지정 제한사항](#package-recipe-naming-convention-for-instance-remotes)을 따라야 합니다.

원격을 추가하려면:

1. 터미널에서 이 명령을 실행합니다:

   ```shell
   conan remote add gitlab https://gitlab.example.com/api/v4/packages/conan
   ```

1. Conan 명령의 끝에 `--remote=gitlab`을 추가하여 원격을 사용합니다.

   예를 들어:

   ```shell
   conan search 'Hello*' --remote=gitlab
   ```

#### 인스턴스 원격에 대한 패키지 레시피 이름 지정 규칙 {#package-recipe-naming-convention-for-instance-remotes}

표준 Conan 레시피 규칙은 `package_name/version@user/channel`이지만 [인스턴스 원격](#add-a-remote-for-your-instance)을 사용 중인 경우 레시피 `user`은 더하기 기호(`+`) 구분 프로젝트 경로여야 합니다.

레시피 이름 예:

| 프로젝트                | 패키지                                        | 지원됨 |
| ---------------------- | ---------------------------------------------- | --------- |
| `foo/bar`              | `my-package/1.0.0@foo+bar/stable`              | 예       |
| `foo/bar-baz/buz`      | `my-package/1.0.0@foo+bar-baz+buz/stable`      | 예       |
| `gitlab-org/gitlab-ce` | `my-package/1.0.0@gitlab-org+gitlab-ce/stable` | 예       |
| `gitlab-org/gitlab-ce` | `my-package/1.0.0@foo/stable`                  | 아니요        |

[프로젝트 원격](#add-a-remote-for-your-project)은 더 유연한 이름 지정 규칙을 갖습니다.

## 패키지 레지스트리에 인증 {#authenticate-to-the-package-registry}

GitLab은 패키지 업로드 및 비공개/내부 프로젝트에서 패키지 설치를 위해 인증이 필요합니다. (그러나 인증 없이 공개 프로젝트에서 패키지를 설치할 수 있습니다.)

패키지 레지스트리에 인증하려면 다음 중 하나가 필요합니다:

- [개인 액세스 토큰](../../profile/personal_access_tokens.md)이며 범위를 `api`로 설정합니다.
- [배포 토큰](../../project/deploy_tokens/_index.md)이며 범위를 `read_package_registry`, `write_package_registry` 또는 둘 다로 설정합니다.
- [CI 작업 토큰](#publish-a-conan-package-by-using-cicd)입니다.

> [!note]
> 인증되지 않은 경우 비공개 및 내부 프로젝트의 패키지가 숨겨집니다. 인증 없이 비공개 또는 내부 프로젝트에서 패키지를 검색하거나 다운로드하려고 하면 Conan 클라이언트에서 `unable to find the package in remote` 오류를 받습니다.

### GitLab 원격에 자격증명 추가 {#add-your-credentials-to-the-gitlab-remote}

토큰을 GitLab 원격과 연결하여 모든 Conan 명령에 명시적으로 토큰을 추가할 필요가 없도록 합니다.

사전 요구 사항:

- 인증 토큰이 있어야 합니다.
- Conan 원격을 [구성해야](#add-the-package-registry-as-a-conan-remote) 합니다.

터미널에서 이 명령을 실행합니다. 이 예에서 원격 이름은 `gitlab`입니다. 원격의 이름을 사용하십시오.

```shell
conan user <gitlab_username or deploy_token_username> -r gitlab -p <personal_access_token or deploy_token>
```

이제 `--remote=gitlab`를 사용하여 명령을 실행하면 사용자 이름과 암호가 요청에 포함됩니다.

> [!note]
> GitLab에 대한 인증이 정기적으로 만료되므로 개인 액세스 토큰을 다시 입력해야 할 수도 있습니다.

### 프로젝트에 대한 기본 원격 설정(선택 사항) {#set-a-default-remote-for-your-project-optional}

원격을 지정하지 않고 GitLab 패키지 레지스트리와 상호 작용하려면 항상 패키지에 패키지 레지스트리를 사용하도록 Conan을 설정할 수 있습니다.

터미널에서 이 명령을 실행합니다:

```shell
conan remote add_ref Hello/0.1@mycompany/beta gitlab
```

> [!note]
> 패키지 레시피에 버전이 포함되어 있으므로 `Hello/0.1@user/channel`에 대한 기본 원격이 `Hello/0.2@user/channel`에서 작동하지 않습니다.

기본 사용자 또는 원격을 설정하지 않으면 여전히 명령에 사용자 및 원격을 포함할 수 있습니다:

```shell
CONAN_LOGIN_USERNAME=<gitlab_username or deploy_token_username> CONAN_PASSWORD=<personal_access_token or deploy_token> <conan command> --remote=gitlab
```

## Conan 패키지 게시 {#publish-a-conan-package}

패키지 레지스트리에 Conan 패키지를 게시하여 프로젝트에 액세스할 수 있는 모든 사람이 패키지를 종속성으로 사용할 수 있습니다.

사전 요구 사항:

- Conan 원격을 [구성해야](#add-the-package-registry-as-a-conan-remote) 합니다.
- 패키지 레지스트리를 통한 [인증](#authenticate-to-the-package-registry)을 구성해야 합니다.
- 로컬 [Conan 패키지](https://docs.conan.io/en/latest/creating_packages/getting_started.html)가 존재해야 합니다.
  - 인스턴스 원격의 경우 패키지는 [이름 지정 규칙](#package-recipe-naming-convention-for-instance-remotes)을 충족해야 합니다.
- 프로젝트 [개요 페이지](../../project/working_with_projects.md#find-the-project-id)에 표시되는 프로젝트 ID가 있어야 합니다.

패키지를 게시하려면 `conan upload` 명령을 사용합니다:

```shell
conan upload Hello/0.1@mycompany/beta --all
```

## CI/CD를 사용하여 Conan 패키지 게시 {#publish-a-conan-package-by-using-cicd}

[GitLab CI/CD](../../../ci/_index.md)에서 Conan 명령으로 작업하려면 명령에서 개인 액세스 토큰 대신 `CI_JOB_TOKEN`을 사용할 수 있습니다.

`.gitlab-ci.yml` 파일의 각 Conan 명령과 함께 `CONAN_LOGIN_USERNAME`과 `CONAN_PASSWORD`을 제공할 수 있습니다. 예를 들어:

```yaml
create_package:
  image: conanio/gcc7
  stage: deploy
  script:
    - conan remote add gitlab ${CI_API_V4_URL}/projects/$CI_PROJECT_ID/packages/conan
    - conan new <package-name>/0.1 -t
    - conan create . <group-name>+<project-name>/stable
    - CONAN_LOGIN_USERNAME=ci_user CONAN_PASSWORD=${CI_JOB_TOKEN} conan upload <package-name>/0.1@<group-name>+<project-name>/stable --all --remote=gitlab
  environment: production
```

CI 파일의 기초로 사용할 추가 Conan 이미지는 [Conan 설명서](https://docs.conan.io/en/latest/howtos/run_conan_in_docker.html#available-docker-images)에서 사용할 수 있습니다.

### 동일한 레시피로 패키지 재게시 {#re-publishing-a-package-with-the-same-recipe}

기존 패키지와 동일한 레시피(`package-name/version@user/channel`)를 가진 패키지를 게시할 때 중복 파일이 성공적으로 업로드되고 UI를 통해 액세스할 수 있습니다. 그러나 패키지가 설치될 때 가장 최근에 게시된 패키지만 반환됩니다.

## Conan 패키지 설치 {#install-a-conan-package}

패키지 레지스트리에서 Conan 패키지를 설치하여 종속성으로 사용할 수 있습니다. 인스턴스 또는 프로젝트의 범위에서 패키지를 설치할 수 있습니다. 여러 패키지가 동일한 레시피를 가진 경우 패키지를 설치할 때 가장 최근에 게시된 패키지를 검색합니다.

Conan 패키지는 종종 `conanfile.txt` 파일을 사용하여 종속성으로 설치됩니다.

사전 요구 사항:

- Conan 원격을 [구성해야](#add-the-package-registry-as-a-conan-remote) 합니다.
- 비공개 및 내부 프로젝트의 경우 패키지 레지스트리를 통한 [인증](#authenticate-to-the-package-registry)을 구성해야 합니다.

1. 패키지를 종속성으로 설치하려는 프로젝트에서 `conanfile.txt`을 엽니다. 또는 프로젝트의 루트에서 `conanfile.txt`이라는 파일을 만듭니다.

1. 파일의 `[requires]` 섹션에 Conan 레시피를 추가합니다:

   ```plaintext
   [requires]
   Hello/0.1@mycompany/beta

   [generators]
   cmake
   ```

1. 프로젝트의 루트에서 `build` 디렉터리를 만들고 해당 디렉터리로 변경합니다:

   ```shell
   mkdir build && cd build
   ```

1. `conanfile.txt`에 나열된 종속성을 설치합니다:

   ```shell
   conan install .. <options>
   ```

> [!note]
> 이 자습서에서 만든 패키지를 설치하려고 하면 패키지가 이미 존재하기 때문에 install 명령이 아무 영향을 주지 않습니다. `~/.conan/data`를 삭제하여 캐시에 저장된 패키지를 정리합니다.

## Conan 패키지 제거 {#remove-a-conan-package}

GitLab 패키지 레지스트리에서 Conan 패키지를 제거하는 방법은 두 가지입니다.

- Conan 클라이언트를 사용하여 명령줄에서:

  ```shell
  conan remove Hello/0.2@user/channel --remote=gitlab
  ```

  이 명령에서 원격을 명시적으로 포함해야 하며, 그렇지 않으면 패키지가 로컬 시스템 캐시에서만 제거됩니다.

  > [!note]
  > 이 명령은 패키지 레지스트리에서 모든 레시피 및 이진 패키지 파일을 제거합니다.

- GitLab 사용자 인터페이스에서:

  프로젝트의 **배포** > **패키지 레지스트리**로 이동합니다. **리포지토리 제거**({{< icon name="remove" >}})를 선택하여 패키지를 제거합니다.

## 패키지 레지스트리에서 Conan 패키지 검색 {#search-for-conan-packages-in-the-package-registry}

전체 또는 부분 패키지 이름으로 또는 정확한 레시피로 검색하려면 `conan search` 명령을 실행합니다.

- 특정 패키지 이름을 가진 모든 패키지를 검색하려면:

  ```shell
  conan search Hello --remote=gitlab
  ```

- `He`로 시작하는 모든 패키지 같은 부분 이름을 검색하려면:

  ```shell
  conan search He* --remote=gitlab
  ```

검색 범위는 Conan 원격 구성에 따라 다릅니다:

- 프로젝트에 대한 [인스턴스](#add-a-remote-for-your-instance) 원격이 구성되어 있으면 검색에 액세스 권한이 있는 모든 프로젝트가 포함됩니다. 여기에는 비공개 프로젝트와 모든 공개 프로젝트가 포함됩니다.

- [프로젝트](#add-a-remote-for-your-project) 에 대한 원격이 구성되어 있으면 검색에 액세스 권한이 있는 경우 대상 프로젝트의 모든 패키지가 포함됩니다.

검색 결과의 제한은 500개 패키지이며 결과는 가장 최근에 게시된 패키지순으로 정렬됩니다.

> [!note]
> 패키지를 검색할 때 Conan v1 CLI는 Conan v1로 업로드된 패키지에 대한 패키지 세부 정보만 표시합니다. Conan v2로 업로드된 패키지는 검색 결과에 나타나지만 세부 정보는 표시되지 않습니다. 이는 Conan v1이 패키지 레시피 메타데이터에 `recipe_hash` 필드를 예상하기 때문이며, 이는 Conan v1로 업로드된 패키지에만 있습니다.

## 패키지 레지스트리에서 Conan 패키지 정보 가져오기 {#fetch-conan-package-information-from-the-package-registry}

`conan info` 명령은 패키지에 대한 정보를 반환합니다:

```shell
conan info Hello/0.1@mycompany/beta
```

## Conan 패키지 다운로드 {#download-a-conan-package}

> [!note]
> [Conan info 메타데이터 추출](#extract-conan-metadata) 이전에 업로드된 패키지는 `conan download` CLI 명령으로 다운로드할 수 없습니다.

`conan download` 명령을 사용하는 설정을 사용하지 않고 로컬 캐시에 Conan 패키지의 레시피와 이진 파일을 다운로드할 수 있습니다.

사전 요구 사항:

- Conan 원격을 [구성해야](#add-the-package-registry-as-a-conan-remote) 합니다.
- 비공개 및 내부 프로젝트의 경우 패키지 레지스트리를 통한 [인증](#authenticate-to-the-package-registry)을 구성해야 합니다.

### 모든 이진 패키지 다운로드 {#download-all-binary-packages}

패키지 레지스트리에서 레시피와 관련된 모든 이진 패키지를 다운로드할 수 있습니다.

모든 이진 패키지를 다운로드하려면 다음 명령을 실행합니다:

```shell
conan download Hello/0.1@foo+bar/stable --remote=gitlab
```

### 레시피 파일 다운로드 {#download-recipe-files}

이진 패키지 없이 레시피 파일만 다운로드할 수 있습니다.

레시피 파일을 다운로드하려면 다음 명령을 실행합니다:

```shell
conan download Hello/0.1@foo+bar/stable --remote=gitlab --recipe
```

### 특정 이진 패키지 다운로드 {#download-a-specific-binary-package}

패키지 참조(Conan 설명서에서 `package_id`이라고 함)를 참조하여 단일 이진 패키지를 다운로드할 수 있습니다.

특정 이진 패키지를 다운로드하려면 다음 명령을 실행합니다:

```shell
conan download Hello/0.1@foo+bar/stable:<package_reference> --remote=gitlab
```

## 지원되는 CLI 명령 {#supported-cli-commands}

GitLab Conan 리포지토리는 다음 Conan CLI 명령을 지원합니다:

- `conan upload`: 레시피 및 패키지 파일을 패키지 레지스트리에 업로드합니다.
- `conan install`: 패키지 레지스트리에서 Conan 패키지를 설치합니다. 여기에는 `conanfile.txt` 파일을 사용하는 것이 포함됩니다.
- `conan download`: 설정을 사용하지 않고 패키지 레시피와 이진 파일을 로컬 캐시로 다운로드합니다.
- `conan search`: 공개 패키지 및 보기 권한이 있는 비공개 패키지에 대해 패키지 레지스트리를 검색합니다.
- `conan info`: 패키지 레지스트리에서 지정된 패키지의 정보를 봅니다.
- `conan remove`: 패키지 레지스트리에서 패키지를 삭제합니다.

## Conan 메타데이터 추출 {#extract-conan-metadata}

{{< history >}}

- GitLab 17.10에서 `parse_conan_metadata_on_upload`라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/178728)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.11에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/186292)입니다. 기능 플래그 `parse_conan_metadata_on_upload`이 제거되었습니다.

{{< /history >}}

Conan 패키지를 업로드할 때 GitLab은 `conaninfo.txt` 파일에서 메타데이터를 자동으로 추출합니다. 이 메타데이터는 다음을 포함합니다:

- 패키지 설정(`os`, `arch`, `compiler` 및 `build_type` 같은)
- 패키지 옵션
- 패키지 요구 사항 및 종속성

> [!note]
> 이 기능이 활성화되기 전에 업로드된 패키지(GitLab 17.10)에는 메타데이터가 추출되지 않습니다. 이러한 패키지의 경우 일부 검색 및 다운로드 기능이 제한됩니다.

## Conan 리비전 {#conan-revisions}

{{< history >}}

- GitLab 18.1에서 `conan_package_revisions_support` [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/519741)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.3에서 [GitLab.com에서 활성화됨](https://gitlab.com/groups/gitlab-org/-/work_items/14896)입니다. 기능 플래그 `conan_package_revisions_support`이 제거되었습니다.

{{< /history >}}

Conan 1 리비전은 패키지 레지스트리에서 패키지 불변성을 제공합니다. 버전을 변경하지 않고 레시피 또는 패키지를 수정할 때 Conan은 이러한 변경을 추적하기 위해 고유 식별자(리비전)를 계산합니다.

> [!note]
> Conan 1 리비전은 전체 [인스턴스](#add-a-remote-for-your-instance)가 아닌 [프로젝트](#add-a-remote-for-your-project)에 대해 원격이 설정된 경우에만 지원됩니다.

### 리비전 유형 {#types-of-revisions}

Conan은 두 가지 유형의 리비전을 사용합니다:

- **레시피 리비전(RREV)**: 레시피를 내보낼 때 생성됩니다. 기본적으로 Conan은 레시피 매니페스트의 체크섬 해시를 사용하여 레시피 리비전을 계산합니다.
- **패키지 리비전(PREV)**: 패키지를 빌드할 때 생성됩니다. Conan은 패키지 콘텐츠의 해시를 사용하여 패키지 리비전을 계산합니다.

### 리비전 활성화 {#enable-revisions}

리비전은 Conan 1.x에서 기본적으로 활성화되지 않습니다. 리비전을 활성화하려면 다음 중 하나를 수행해야 합니다:

- `_conan.conf_` 파일의 `[general]` 섹션에서 `revisions_enabled=1`을 추가합니다(권장).
- `CONAN_REVISIONS_ENABLED=1` 환경 변수를 설정합니다.

### 리비전 참조 {#reference-revisions}

다음 형식으로 패키지를 참조할 수 있습니다:

| 참조                                          | 설명                                                       |
| -------------------------------------------------- | ----------------------------------------------------------------- |
| `lib/1.0@conan/stable`                             | `lib/1.0@conan/stable`에 대한 최신 RREV입니다.                       |
| `lib/1.0@conan/stable#RREV`                        | `lib/1.0@conan/stable`에 대한 특정 RREV입니다.                     |
| `lib/1.0@conan/stable#RREV:PACKAGE_REFERENCE`      | 특정 RREV에 속하는 이진 패키지입니다.               |
| `lib/1.0@conan/stable#RREV:PACKAGE_REFERENCE#PREV` | 특정 RREV에 속하는 이진 패키지 리비전 PREV입니다. |

### 리비전 업로드 {#upload-revisions}

모든 리비전 및 해당 이진 파일을 GitLab 패키지 레지스트리에 업로드하려면:

```shell
conan upload package_name/version@user/channel#* --all --remote=gitlab
```

여러 리비전을 업로드할 때 가장 오래된 것부터 가장 최신 것으로 업로드됩니다. 상대 순서는 레지스트리에서 유지됩니다.

### 리비전 검색 {#search-for-revisions}

Conan v1에서 특정 레시피의 모든 리비전을 검색하려면:

```shell
conan search package_name/version@user/channel --revisions --remote=gitlab
```

이 명령은 리비전 해시 및 생성 날짜와 함께 지정된 레시피의 사용 가능한 모든 리비전을 표시합니다.

특정 리비전에 대한 자세한 정보를 얻으려면:

```shell
conan search package_name/version@user/channel#revision_hash --remote=gitlab
```

이 명령은 해당 리비전에 사용할 수 있는 특정 이진 패키지를 표시합니다.

### 리비전으로 패키지 삭제 {#delete-packages-with-revisions}

다양한 세분화 수준에서 패키지를 삭제할 수 있습니다:

#### 특정 레시피 리비전 삭제 {#delete-a-specific-recipe-revision}

특정 레시피 리비전 및 모든 관련 이진 패키지를 삭제하려면:

```shell
conan remove package_name/version@user/channel#revision_hash --remote=gitlab
```

#### 특정 레시피 리비전에 대한 패키지 삭제 {#delete-packages-for-a-specific-recipe-revision}

특정 레시피 리비전과 관련된 모든 패키지를 삭제하려면:

```shell
conan remove package_name/version@user/channel#revision_hash --packages --remote=gitlab
```

#### 리비전에서 특정 패키지 삭제 {#delete-a-specific-package-in-a-revision}

레시피 리비전에서 특정 패키지를 삭제하려면 다음 중 하나를 사용할 수 있습니다:

```shell
conan remove package_name/version@user/channel#revision_hash -p package_id --remote=gitlab
```

또는:

```shell
conan remove package_name/version@user/channel#revision_hash:package_id --remote=gitlab
```

> [!note]
> 리비전으로 패키지를 삭제할 때 `--remote=gitlab` 플래그를 포함해야 합니다. 그렇지 않으면 패키지가 로컬 시스템 캐시에서만 제거됩니다.

### 불변 리비전 워크플로우 {#immutable-revisions-workflow}

리비전은 불변이 되도록 설계되었습니다. 레시피 또는 소스 코드를 수정할 때:

- 레시피를 내보낼 때 새로운 레시피 리비전이 생성됩니다.
- 이전 레시피 리비전에 속하는 기존 이진 파일이 포함되지 않습니다. 새로운 레시피 리비전에 대해 새로운 이진 파일을 빌드해야 합니다.
- 패키지를 설치할 때 리비전을 지정하지 않으면 Conan이 최신 리비전을 자동으로 검색합니다.

패키지 이진 파일의 경우 레시피 리비전 및 패키지 참조(Conan 설명서에서 `package_id`이라고 함)마다 패키지 리비전 하나만 포함해야 합니다. 동일한 레시피 리비전 및 패키지 ID에 대한 여러 패키지 리비전은 패키지가 불필요하게 다시 빌드되었음을 나타냅니다.

## 문제 해결 {#troubleshooting}

### 출력 상세 정보 표시 {#make-output-verbose}

Conan 문제를 해결할 때 더 상세한 출력을 얻으려면:

```shell
export CONAN_TRACE_FILE=/tmp/conan_trace.log # Or SET in windows
conan <command>
```

[Conan 설명서](https://docs.conan.io/en/latest/mastering/logging.html)에서 더 많은 로깅 팁을 찾을 수 있습니다.

### SSL 오류 {#ssl-errors}

자체 서명된 인증서를 사용 중인 경우 Conan의 SSL 오류를 관리하는 두 가지 방법이 있습니다:

- `conan remote` 명령을 사용하여 SSL 확인을 비활성화합니다.
- 서버 `crt` 파일을 `cacert.pem` 파일에 추가합니다.

[Conan 설명서](https://docs.conan.io/en/latest/howtos/use_tls_certificates.html)에서 이에 대해 자세히 알아보세요.
