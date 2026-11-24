---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 패키지 레지스트리의 NuGet 패키지
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

프로젝트의 패키지 레지스트리에 NuGet 패키지를 게시합니다. 그 후 필요할 때마다 패키지를 의존성으로 사용하도록 설치합니다.

패키지 레지스트리는 다음과 호환됩니다:

- [NuGet CLI](https://learn.microsoft.com/en-us/nuget/reference/nuget-exe-cli-reference)
- [.NET Core CLI](https://learn.microsoft.com/en-us/dotnet/core/tools/)
- [Visual Studio](https://visualstudio.microsoft.com/vs/)

이러한 클라이언트가 사용하는 특정 API 엔드포인트에 대해 알아보려면 [NuGet API 참조](../../../api/packages/nuget.md)를 참조하세요.

[NuGet 설치](../workflows/build_packages.md#nuget) 방법을 알아보세요.

## 패키지 레지스트리에 인증 {#authenticate-to-the-package-registry}

GitLab 패키지 레지스트리에 액세스하려면 인증 토큰이 필요합니다. 토큰의 종류는 달성하려는 목표에 따라 다릅니다. 자세한 내용은 [토큰 가이드](../package_registry/supported_functionality.md#authenticate-with-the-registry)를 참조하세요.

- 조직에서 2단계 인증(2FA)을 사용하는 경우, 범위를 `api`로 설정한 [개인 액세스 토큰](../../profile/personal_access_tokens.md)을 사용해야 합니다.
- CI/CD 파이프라인으로 패키지를 게시하는 경우, 프라이빗 러너와 함께 [CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md)을 사용할 수 있습니다. 인스턴스 러너의 경우 [변수를 등록](https://docs.gitlab.com/runner/register/#register-with-a-runner-authentication-token)할 수도 있습니다.

## NuGet 패키지에 GitLab 엔드포인트 사용 {#use-the-gitlab-endpoint-for-nuget-packages}

GitLab 패키지 레지스트리와 상호 작용하려면 프로젝트 또는 그룹 엔드포인트를 사용할 수 있습니다:

- 프로젝트 엔드포인트: 같은 그룹에 없는 NuGet 패키지가 몇 개 있을 때 사용합니다.
- 그룹 엔드포인트: 같은 그룹에 있는 다양한 프로젝트에 많은 NuGet 패키지가 있을 때 사용합니다.

패키지 게시와 같은 일부 작업은 프로젝트 엔드포인트에서만 사용할 수 있습니다.

NuGet이 자격 증명을 처리하는 방식 때문에 패키지 레지스트리는 공개 그룹에 대한 익명 요청을 거부합니다.

## NuGet 패키지의 소스로 패키지 레지스트리 추가 {#add-the-package-registry-as-a-source-for-nuget-packages}

패키지를 패키지 레지스트리에 게시하고 설치하려면 패키지 레지스트리를 패키지의 소스로 추가해야 합니다.

사전 요구 사항:

- GitLab 사용자명
- 인증 토큰(다음 섹션에서는 개인 액세스 토큰을 가정)
- 소스의 이름
- 프로젝트 또는 그룹 ID

### 프로젝트 엔드포인트 사용 {#with-the-project-endpoint}

{{< tabs >}}

{{< tab title="NuGet CLI" >}}

NuGet CLI를 사용하여 패키지 레지스트리를 소스로 추가하려면 다음 명령을 실행합니다:

```shell
nuget source Add -Name <source_name> -Source "https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/index.json" -UserName <gitlab_username> -Password <personal_access_token>
```

바꾸기:

- `<source_name>`을 소스 이름으로 바꿉니다
- `<project_id>`을 [프로젝트 개요 페이지](../../project/working_with_projects.md#find-the-project-id)에서 찾은 프로젝트 ID로 바꿉니다
- `<gitlab_username>`을 GitLab 사용자명으로 바꿉니다
- `<personal_access_token>`을 개인 액세스 토큰으로 바꿉니다

예를 들어:

```shell
nuget source Add -Name "GitLab" -Source "https://gitlab.example.com/api/v4/projects/10/packages/nuget/index.json" -UserName carol -Password <your_access_token>
```

{{< /tab >}}

{{< tab title=".NET CLI" >}}

.NET CLI를 사용하여 패키지 레지스트리를 소스로 추가하려면 다음 명령을 실행합니다:

```shell
dotnet nuget add source "https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/index.json" --name <source_name> --username <gitlab_username> --password <personal_access_token>
```

바꾸기:

- `<source_name>`을 소스 이름으로 바꿉니다
- `<project_id>`을 [프로젝트 개요 페이지](../../project/working_with_projects.md#find-the-project-id)에서 찾은 프로젝트 ID로 바꿉니다
- `<gitlab_username>`을 GitLab 사용자명으로 바꿉니다
- `<personal_access_token>`을 개인 액세스 토큰으로 바꿉니다

운영 체제에 따라 `--store-password-in-clear-text`을 명령에 추가해야 할 수 있습니다.

예를 들어:

```shell
dotnet nuget add source "https://gitlab.example.com/api/v4/projects/10/packages/nuget/index.json" --name gitlab --username carol --password <your_access_token> --store-password-in-clear-text
```

{{< /tab >}}

{{< tab title="Chocolatey CLI" >}}

Chocolatey CLI를 사용하여 패키지 레지스트리를 소스 피드로 추가할 수 있습니다. Chocolatey CLI v1.X를 사용하는 경우 NuGet v2 소스 피드만 추가할 수 있습니다.

Chocolatey에 대한 패키지 레지스트리를 소스로 추가하려면 다음 명령을 실행합니다:

```shell
choco source add -n=<source_name> -s "'https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/v2'" -u=<gitlab_username> -p=<personal_access_token>
```

바꾸기:

- `<source_name>`을 소스 이름으로 바꿉니다
- `<project_id>`을 [프로젝트 개요 페이지](../../project/working_with_projects.md#find-the-project-id)에서 찾은 프로젝트 ID로 바꿉니다
- `<gitlab_username>`을 GitLab 사용자명으로 바꿉니다
- `<personal_access_token>`을 개인 액세스 토큰으로 바꿉니다

예를 들어:

```shell
choco source add -n=gitlab -s "'https://gitlab.example.com/api/v4/projects/10/packages/nuget/v2'" -u=carol -p=<your_access_token>
```

{{< /tab >}}

{{< tab title="Visual Studio" >}}

Visual Studio를 사용하여 패키지 레지스트리를 소스로 추가하려면:

1. [Visual Studio](https://visualstudio.microsoft.com/vs/)를 엽니다.
1. Windows에서 **도구** > **옵션**을 선택합니다. macOS에서 **Visual Studio** > **환경설정**을 선택합니다.
1. **NuGet** 섹션에서 **소스**를 선택하여 모든 NuGet 소스 목록을 봅니다.
1. **추가**를 선택합니다.
1. 다음 필드를 완성합니다:

   - **Name (이름)**: 소스의 이름입니다.
   - **소스**: `https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/index.json`, 여기서 `<project_id>`은 프로젝트 ID이고 `gitlab.example.com`는 도메인 이름입니다.

1. **저장**을 선택합니다.
1. 패키지에 액세스할 때 **사용자명**과 **비밀번호**를 입력해야 합니다:

   - **사용자명**: GitLab 사용자명입니다.
   - **비밀번호**: 개인 액세스 토큰입니다.

소스가 목록에 표시됩니다.

경고가 표시되면 **소스**, **사용자명**, **비밀번호**가 올바른지 확인합니다.

{{< /tab >}}

{{< tab title="구성 파일" >}}

.NET 구성 파일을 사용하여 패키지 레지스트리를 소스로 추가하려면:

1. 프로젝트 루트에서 `nuget.config`이라는 파일을 만듭니다.
1. 다음 구성을 추가합니다:

   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <configuration>
    <packageSources>
        <clear />
        <add key="gitlab" value="https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/index.json" />
    </packageSources>
    <packageSourceCredentials>
        <gitlab>
            <add key="Username" value="%GITLAB_PACKAGE_REGISTRY_USERNAME%" />
            <add key="ClearTextPassword" value="%GITLAB_PACKAGE_REGISTRY_PASSWORD%" />
        </gitlab>
    </packageSourceCredentials>
   </configuration>
   ```

1. 필요한 환경 변수를 구성합니다:

   ```shell
   export GITLAB_PACKAGE_REGISTRY_USERNAME=<gitlab_username>
   export GITLAB_PACKAGE_REGISTRY_PASSWORD=<personal_access_token>
   ```

{{< /tab >}}

{{< /tabs >}}

> [!note]
> 이전 예제 명령은 `gitlab`라는 소스를 추가합니다. 이후 예제 명령은 소스 이름(`gitlab`)을 참조하며, 소스 URL이 아닙니다.

### 그룹 엔드포인트 사용 {#with-the-group-endpoint}

{{< tabs >}}

{{< tab title="NuGet CLI" >}}

NuGet CLI를 사용하여 패키지 레지스트리를 소스로 추가하려면:

```shell
nuget source Add -Name <source_name> -Source "https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/nuget/index.json" -UserName <gitlab_username> -Password <personal_access_token>
```

바꾸기:

- `<source_name>`을 소스 이름으로 바꿉니다
- `<group_id>`을 [그룹 개요 페이지](../../group/_index.md#find-the-group-id)에서 찾은 그룹 ID로 바꿉니다
- `<gitlab_username>`을 GitLab 사용자명으로 바꿉니다
- `<personal_access_token>`을 개인 액세스 토큰으로 바꿉니다

예를 들어:

```shell
nuget source Add -Name "GitLab" -Source "https://gitlab.example.com/api/v4/groups/23/-/packages/nuget/index.json" -UserName carol -Password <your_access_token>
```

{{< /tab >}}

{{< tab title=".NET CLI" >}}

.NET CLI를 사용하여 패키지 레지스트리를 소스로 추가하려면:

```shell
dotnet nuget add source "https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/nuget/index.json" --name <source_name> --username <gitlab_username> --password <personal_access_token>
```

바꾸기:

- `<source_name>`을 소스 이름으로 바꿉니다
- `<group_id>`을 [그룹 개요 페이지](../../group/_index.md#find-the-group-id)에서 찾은 그룹 ID로 바꿉니다
- `<gitlab_username>`을 GitLab 사용자명으로 바꿉니다
- `<personal_access_token>`을 개인 액세스 토큰으로 바꿉니다

`--store-password-in-clear-text` 플래그는 운영 체제에 따라 필요할 수 있습니다.

예를 들어:

```shell
dotnet nuget add source "https://gitlab.example.com/api/v4/groups/23/-/packages/nuget/index.json" --name gitlab --username carol --password <your_access_token> --store-password-in-clear-text
```

{{< /tab >}}

{{< tab title="Chocolatey CLI" >}}

Chocolatey CLI는 [프로젝트 엔드포인트](#with-the-project-endpoint)와만 호환됩니다.

{{< /tab >}}

{{< tab title="Visual Studio" >}}

Visual Studio를 사용하여 패키지 레지스트리를 소스로 추가하려면:

1. [Visual Studio](https://visualstudio.microsoft.com/vs/)를 엽니다.
1. Windows에서 **도구** > **옵션**을 선택합니다. macOS에서 **Visual Studio** > **환경설정**을 선택합니다.
1. **NuGet** 섹션에서 **소스**를 선택하여 모든 NuGet 소스 목록을 봅니다.
1. **추가**를 선택합니다.
1. 다음 필드를 완성합니다:

   - **Name (이름)**: 소스의 이름입니다.
   - **소스**: `https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/nuget/index.json`, 여기서 `<group_id>`은 그룹 ID이고 `gitlab.example.com`는 도메인 이름입니다.

1. **저장**을 선택합니다.
1. 패키지에 액세스할 때 **사용자명**과 **비밀번호**를 입력해야 합니다.

   - **사용자명**: GitLab 사용자명입니다.
   - **비밀번호**: 개인 액세스 토큰입니다.

소스가 목록에 표시됩니다.

경고가 표시되면 **소스**, **사용자명**, **비밀번호**가 올바른지 확인합니다.

{{< /tab >}}

{{< tab title="구성 파일" >}}

.NET 구성 파일을 사용하여 패키지 레지스트리를 소스로 추가하려면:

1. 프로젝트 루트에서 `nuget.config`이라는 파일을 만듭니다.
1. 다음 구성을 추가합니다:

   ```xml
   <?xml version="1.0" encoding="utf-8"?>
   <configuration>
    <packageSources>
        <clear />
        <add key="gitlab" value="https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/nuget/index.json" />
    </packageSources>
    <packageSourceCredentials>
        <gitlab>
            <add key="Username" value="%GITLAB_PACKAGE_REGISTRY_USERNAME%" />
            <add key="ClearTextPassword" value="%GITLAB_PACKAGE_REGISTRY_PASSWORD%" />
        </gitlab>
    </packageSourceCredentials>
   </configuration>
   ```

1. 필요한 환경 변수를 구성합니다:

   ```shell
   export GITLAB_PACKAGE_REGISTRY_USERNAME=<gitlab_username>
   export GITLAB_PACKAGE_REGISTRY_PASSWORD=<personal_access_token>
   ```

{{< /tab >}}

{{< /tabs >}}

> [!note]
> 이전 예제 명령은 `gitlab`라는 소스를 추가합니다. 이후 예제 명령은 소스 이름(`gitlab`)을 참조하며, 소스 URL이 아닙니다.

## 패키지 게시 {#publish-a-package}

사전 요구 사항:

- 패키지 레지스트리를 [소스](#add-the-package-registry-as-a-source-for-nuget-packages)로 설정합니다.
- [NuGet 패키지에 GitLab 프로젝트 엔드포인트 구성](#with-the-project-endpoint)을 합니다.

패키지를 게시할 때:

- GitLab 인스턴스의 최대 파일 크기 제한을 검토합니다:
  - [GitLab.com 인스턴스의 패키지 레지스트리 제한](../../gitlab_com/_index.md#package-registry-limits)은 파일 형식에 따라 다르며 구성할 수 없습니다.
  - [GitLab Self-Managed 인스턴스의 패키지 레지스트리 제한](../../../administration/instance_limits.md#file-size-limits)은 파일 형식에 따라 다르며 구성할 수 있습니다.
- 중복이 허용되고 같은 버전의 패키지를 여러 번 게시하면 각 연속 업로드는 별도의 파일로 저장됩니다. 패키지를 설치할 때 GitLab은 가장 최근 파일을 제공합니다.
- 대부분의 업로드된 패키지는 **패키지 레지스트리** 페이지에 즉시 표시되어야 합니다. 일부 패키지는 백그라운드에서 처리해야 하는 경우 표시되기까지 최대 10분이 걸릴 수 있습니다.

### NuGet CLI 사용 {#with-nuget-cli}

사전 요구 사항:

- [NuGet CLI로 생성된 NuGet 패키지](https://learn.microsoft.com/en-us/nuget/create-packages/creating-a-package)입니다.

패키지를 게시하려면 다음 명령을 실행합니다:

```shell
nuget push <package_file> -Source <source_name>
```

바꾸기:

- `<package_file>`을 패키지 파일명으로 바꾸고 `.nupkg`로 끝나야 합니다.
- `<source_name>`을 소스의 이름으로 바꿉니다.

예를 들어:

```shell
nuget push MyPackage.1.0.0.nupkg -Source gitlab
```

### .NET CLI 사용 {#with-net-cli}

사전 요구 사항:

- [.NET CLI로 생성된 NuGet 패키지](https://learn.microsoft.com/en-us/nuget/create-packages/creating-a-package-dotnet-cli)입니다.

패키지를 게시하려면 다음 명령을 실행합니다:

```shell
dotnet nuget push <package_file> --source <source_name>
```

바꾸기:

- `<package_file>`을 패키지 파일명으로 바꾸고 `.nupkg`로 끝나야 합니다.
- `<source_name>`을 소스의 이름으로 바꿉니다.

예를 들어:

```shell
dotnet nuget push MyPackage.1.0.0.nupkg --source gitlab
```

`--api-key` 옵션을 사용하여 패키지를 게시할 수 있으며, 대신 `username`와 `password`을 사용할 수 있습니다:

```shell
dotnet nuget push <package_file> --source <source_url> --api-key <personal_access_token>
```

바꾸기:

- `<package_file>`을 패키지 파일명으로 바꾸고 `.nupkg`로 끝나야 합니다.
- `<source_url>`을 NuGet 패키지 레지스트리의 URL로 바꿉니다.

예를 들어:

```shell
dotnet nuget push MyPackage.1.0.0.nupkg --source https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/index.json --api-key <personal_access_token>
```

### Chocolatey CLI 사용 {#with-chocolatey-cli}

사전 요구 사항:

- [프로젝트 엔드포인트](#with-the-project-endpoint)를 사용하는 소스입니다.

Chocolatey CLI로 패키지를 게시하려면 다음 명령을 실행합니다:

```shell
choco push <package_file> --source <source_url> --api-key <gitlab_personal_access_token, deploy_token or job token>
```

바꾸기:

- `<package_file>`을 패키지 파일명으로 바꾸고 `.nupkg`로 끝나야 합니다.
- `<source_url>`을 NuGet v2 피드 패키지 레지스트리의 URL로 바꿉니다.

예를 들어:

```shell
choco push MyPackage.1.0.0.nupkg --source "https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/v2" --api-key <personal_access_token>
```

### CI/CD 파이프라인 사용 {#with-a-cicd-pipeline}

GitLab CI/CD로 NuGet 패키지를 게시하는 경우 개인 액세스 토큰 또는 배포 토큰 대신 [`CI_JOB_TOKEN` 미리 정의된 변수](../../../ci/jobs/ci_job_token.md)를 사용할 수 있습니다. 작업 토큰은 파이프라인을 생성하는 사용자 또는 멤버의 권한을 상속합니다.

다음 섹션의 예제는 CI/CD 파이프라인을 사용할 때 일반적인 NuGet 게시 워크플로를 다룹니다.

#### 기본 브랜치가 업데이트될 때 패키지 게시 {#publish-packages-when-the-default-branch-is-updated}

`main` 브랜치가 업데이트될 때마다 새 패키지를 게시하려면:

1. 프로젝트의 `.gitlab-ci.yml` 파일에서 다음 `deploy` 작업을 추가합니다:

   ```yaml
   default:
     # Updated to a more current SDK version
     image: mcr.microsoft.com/dotnet/sdk:7.0

   stages:
     - deploy

   deploy:
     stage: deploy
     script:
       # Build the package in Release configuration
       - dotnet pack -c Release
       # Configure GitLab package registry as a NuGet source
       - dotnet nuget add source "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/nuget/index.json" --name gitlab --username gitlab-ci-token --password $CI_JOB_TOKEN --store-password-in-clear-text
       # Push the package to the project's package registry
       - dotnet nuget push "bin/Release/*.nupkg" --source gitlab
     rules:
       - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH  # Only run on the main branch
     environment: production
   ```

1. 변경 사항을 커밋하고 GitLab 리포지토리로 푸시하여 새 CI/CD 빌드를 트리거합니다.

#### Git 태그를 사용하여 버전이 지정된 패키지 게시 {#publish-versioned-packages-with-git-tags}

[Git 태그](../../project/repository/tags/_index.md)를 사용하여 버전이 지정된 NuGet 패키지를 게시하려면:

1. 프로젝트의 `.gitlab-ci.yml` 파일에서 다음 `deploy` 작업을 추가합니다:

   ```yaml
   publish-tagged-version:
     stage: deploy
     script:
       # Use the Git tag as the package version
       - dotnet pack -c Release /p:Version=${CI_COMMIT_TAG} /p:PackageVersion=${CI_COMMIT_TAG}
       # Configure GitLab package registry as a NuGet source
       - dotnet nuget add source "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/nuget/index.json" --name gitlab --username gitlab-ci-token --password $CI_JOB_TOKEN --store-password-in-clear-text
       # Push the package to the project's package registry
       - dotnet nuget push "bin/Release/*.nupkg" --source gitlab
     rules:
       - if: $CI_COMMIT_TAG  # Only run when a tag is pushed
   ```

1. 변경 사항을 커밋하고 GitLab 리포지토리로 푸시합니다.
1. Git 태그를 푸시하여 새 CI/CD 빌드를 트리거합니다.

#### 다양한 환경에 대해 조건부로 게시 {#publish-conditionally-for-different-environments}

사용 사례에 따라 CI/CD 파이프라인을 구성하여 NuGet 패키지를 다양한 환경에 조건부로 게시할 수 있습니다.

`development` 및 `production` 환경에 대해 NuGet 패키지를 조건부로 게시하려면:

1. 프로젝트의 `.gitlab-ci.yml` 파일에서 다음 `deploy` 작업을 추가합니다:

   ```yaml
     # Publish development/preview packages
   publish-dev:
     stage: deploy
     script:
       # Create a development version with pipeline ID for uniqueness
       - VERSION="0.0.1-dev.${CI_PIPELINE_IID}"
       - dotnet pack -c Release /p:Version=$VERSION /p:PackageVersion=$VERSION
       # Configure GitLab package registry as a NuGet source
       - dotnet nuget add source "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/nuget/index.json" --name gitlab --username gitlab-ci-token --password $CI_JOB_TOKEN --store-password-in-clear-text
       # Push the package to the project's package registry
       - dotnet nuget push "bin/Release/*.nupkg" --source gitlab
     rules:
       - if: $CI_COMMIT_BRANCH == "develop"
     environment: development

     # Publish stable release packages
   publish-release:
     stage: deploy
     script:
       - dotnet pack -c Release
       # Configure GitLab package registry as a NuGet source
       - dotnet nuget add source "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/nuget/index.json" --name gitlab --username gitlab-ci-token --password $CI_JOB_TOKEN --store-password-in-clear-text
       # Push the package to the project's package registry
       - dotnet nuget push "bin/Release/*.nupkg" --source gitlab
     rules:
       - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
     environment: production
   ```

1. 변경 사항을 커밋하고 GitLab 리포지토리로 푸시합니다.

   이 CI/CD 구성을 사용하면:

   - `develop` 브랜치로 NuGet 패키지를 푸시하면 `development` 환경의 패키지 레지스트리에 패키지를 게시합니다.
   - `main` 브랜치로 NuGet 패키지를 푸시하면 `production` 환경의 패키지 레지스트리에 NuGet 패키지를 게시합니다.

### 중복 NuGet 패키지 해제 {#turn-off-duplicate-nuget-packages}

{{< history >}}

- [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/370471)되어 필요한 역할이 GitLab 17.0의 유지 관리자에서 소유자로 변경되었습니다.

{{< /history >}}

같은 이름과 버전의 여러 패키지를 게시할 수 있습니다.

그룹 멤버와 사용자가 중복 NuGet 패키지를 게시하는 것을 방지하려면 **중복 허용** 설정을 해제합니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **NuGet** 행의 **중복 패키지** 테이블에서 **중복 허용** 토글을 해제합니다.
1. 선택 사항. **예외** 텍스트 상자에 패키지의 이름과 버전과 일치하는 정규식을 입력합니다.

[GraphQL API](../../../api/graphql/reference/_index.md#packagesettings)에서 `nuget_duplicates_allowed` 설정을 사용하여 중복 NuGet 패키지를 해제할 수도 있습니다.

> [!warning]
> `.nuspec` 파일이 패키지 루트 또는 아카이브 시작 부분에 없으면 패키지가 중복으로 즉시 인식되지 않을 수 있습니다. 결국 중복으로 인식되면 **패키지 관리자** 페이지에 오류가 표시됩니다.

## 패키지 설치 {#install-a-package}

GitLab 패키지 레지스트리는 같은 이름과 버전의 여러 패키지를 포함할 수 있습니다. 중복 패키지를 설치하면 가장 최근에 게시된 패키지가 검색됩니다.

사전 요구 사항:

- 패키지 레지스트리를 [소스](#add-the-package-registry-as-a-source-for-nuget-packages)로 설정합니다.
- [NuGet 패키지에 GitLab 엔드포인트 구성](#use-the-gitlab-endpoint-for-nuget-packages)을 합니다.

### 명령줄에서 {#from-the-command-line}

{{< tabs >}}

{{< tab title="NuGet CLI" >}}

다음 명령을 실행하여 패키지의 최신 버전을 설치합니다:

```shell
nuget install <package_id> -OutputDirectory <output_directory> \
  -Version <package_version> \
  -Source <source_name>
```

- `<package_id>`: 패키지 ID입니다.
- `<output_directory>`: 패키지가 설치되는 출력 디렉터리입니다.
- `<package_version>`: 선택 사항. 패키지 버전입니다.
- `<source_name>`: 선택 사항. 소스 이름입니다.
  - `nuget`은 요청된 패키지를 먼저 `nuget.org`에서 확인합니다. GitLab 패키지 레지스트리에 `nuget.org`과 같은 이름의 NuGet 패키지가 있으면 올바른 패키지를 설치하려면 소스 이름을 지정해야 합니다.

{{< /tab >}}

{{< tab title=".NET CLI" >}}

> [!note]
> GitLab 패키지 레지스트리에 다른 소스의 패키지와 같은 이름의 NuGet 패키지가 있으면 `dotnet`이 설치 중에 소스를 확인하는 순서를 확인합니다. 이 동작은 `nuget.config` 파일에 정의됩니다.

다음 명령을 실행하여 패키지의 최신 버전을 설치합니다:

```shell
dotnet add package <package_id> \
       -v <package_version>
```

- `<package_id>`: 패키지 ID입니다.
- `<package_version>`: 선택 사항. 패키지 버전입니다.

{{< /tab >}}

{{< /tabs >}}

### NuGet v2 피드 사용 {#with-nuget-v2-feed}

사전 요구 사항:

- Chocolatey에 대한 [v2 피드 소스](#with-the-project-endpoint)입니다.
- NuGet v2 피드를 사용하여 패키지를 설치하거나 업그레이드할 때 패키지 버전을 제공해야 합니다.

Chocolatey CLI를 사용하여 패키지를 설치하려면:

```shell
choco install <package_id> -Source <source_url> -Version <package_version>
```

- `<package_id>`: 패키지 ID입니다.
- `<source_url>`: NuGet v2 피드 패키지 레지스트리의 URL 또는 이름입니다.
- `<package_version>`: 패키지 버전입니다.

예를 들어:

```shell
choco install MyPackage -Source gitlab -Version 1.0.2

# or

choco install MyPackage -Source "https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/v2" -u <username> -p <personal_access_token> -Version 1.0.2
```

Chocolatey CLI를 사용하여 패키지를 업그레이드하려면:

```shell
choco upgrade <package_id> -Source <source_url> -Version <package_version>
```

- `<package_id>`: 패키지 ID입니다.
- `<source_url>`: NuGet v2 피드 패키지 레지스트리의 URL 또는 이름입니다.
- `<package_version>`: 패키지 버전입니다.

예를 들어:

```shell
choco upgrade MyPackage -Source gitlab -Version 1.0.3
```

## 패키지 삭제 {#delete-a-package}

> [!warning]
> 패키지를 삭제하는 것은 실행 취소할 수 없는 영구적 작업입니다.

사전 요구 사항:

- 프로젝트에서 최소한 [유지 관리자](../../permissions.md#project-permissions) 역할을 가지고 있어야 합니다.
- 패키지 이름과 버전을 모두 가지고 있어야 합니다.

NuGet CLI를 사용하여 패키지를 삭제하려면:

```shell
nuget delete <package_id> <package_version> -Source <source_name> -ApiKey <personal_access_token>
```

- `<package_id>`: 패키지 ID입니다.
- `<package_version>`: 패키지 버전입니다.
- `<source_name>`: 소스 이름입니다.

예를 들어:

```shell
nuget delete MyPackage 1.0.0 -Source gitlab -ApiKey <personal_access_token>
```

## 기호 패키지 {#symbol-packages}

GitLab은 NuGet 패키지 레지스트리에서 기호 파일을 사용할 수 있습니다. GitLab 패키지 레지스트리를 기호 서버로 사용하여 NuGet 패키지를 디버그할 수 있습니다.

NuGet 패키지 파일(`.nupkg`)을 게시할 때마다 기호 패키지 파일(`.snupkg`)이 NuGet 패키지 레지스트리에 자동으로 업로드됩니다.

수동으로 푸시할 수도 있습니다:

```shell
nuget push My.Package.snupkg -Source <source_name>
```

### 기호 파일에 GitLab 엔드포인트 사용 {#use-the-gitlab-endpoint-for-symbol-files}

GitLab 패키지 레지스트리는 프로젝트 또는 그룹 엔드포인트로 구성할 수 있는 특수한 `symbolfiles` 엔드포인트를 제공합니다:

- 프로젝트 엔드포인트:

  ```plaintext
  https://gitlab.example.com/api/v4/projects/<project_id>/packages/nuget/symbolfiles
  ```

  - `<project_id>`을 프로젝트 ID로 바꿉니다.
- 그룹 엔드포인트:

  ```plaintext
  https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/nuget/symbolfiles
  ```

  - `<group_id>`을 그룹 ID로 바꿉니다.

`symbolfiles` 엔드포인트는 구성된 디버거가 기호 파일을 푸시할 수 있는 소스입니다.

### 기호 서버로 패키지 레지스트리 사용 {#use-the-package-registry-as-a-symbol-server}

기호 서버를 사용하려면:

1. `nuget_symbol_server_enabled` 네임스페이스 설정을 [GraphQL API](../../../api/graphql/reference/_index.md#packagesettings)로 활성화합니다.
1. 기호 서버를 사용하도록 디버거를 구성합니다.

예를 들어 Visual Studio를 디버거로 구성하려면:

1. **도구** > **환경설정**을 선택합니다.
1. **디버거** > **기호 소스**를 선택합니다.
1. **추가**를 선택합니다.
1. 기호 서버 URL을 입력합니다.
1. **소스 추가**를 선택합니다.

디버거를 구성한 후 평소처럼 애플리케이션을 디버그할 수 있습니다. 디버거는 기호 파일을 사용할 수 있으면 패키지 레지스트리에서 기호 PDB 파일을 자동으로 다운로드합니다.

#### 기호 패키지 사용 {#consume-symbol-packages}

디버거가 기호 패키지를 사용하도록 구성되면 디버거는 요청에서 다음 정보를 전송합니다:

- `Symbolchecksum` 헤더: 기호 파일의 SHA-256 체크섬입니다.
- `file_name` 요청 매개변수: 기호 파일의 이름입니다. 예를 들어, `mypackage.pdb`입니다.
- `signature` 요청 매개변수: PDB 파일의 GUID 및 나이입니다.

GitLab 서버는 이 정보를 기호 파일과 일치시키고 반환합니다.

다음 사항을 염두에 두세요:

- 포터블 PDB 파일만 지원됩니다.
- 디버거가 인증 토큰을 제공할 수 없으므로 기호 서버 엔드포인트는 일반적인 인증 방법을 지원하지 않습니다. GitLab 서버는 올바른 기호 파일을 반환하려면 `signature`과 `Symbolchecksum`가 필요합니다.

## 지원되는 CLI 명령 {#supported-cli-commands}

GitLab NuGet 리포지토리는 NuGet CLI(`nuget`)와 .NET CLI(`dotnet`)에 대한 다음 명령을 지원합니다:

| NuGet | .NET | 설명 |
|-----------|----------|-------------|
| `nuget push` | `dotnet nuget push` | 레지스트리에 패키지를 업로드합니다. |
| `nuget install` | `dotnet add` | 레지스트리에서 패키지를 설치합니다. |
| `nuget delete` | `dotnet nuget delete` | 레지스트리에서 패키지를 삭제합니다. |

## 문제 해결 {#troubleshooting}

NuGet 패키지로 작업할 때 다음과 같은 문제가 발생할 수 있습니다.

### NuGet 캐시 지우기 {#clear-the-nuget-cache}

성능을 향상시키기 위해 NuGet은 패키지 파일을 캐시합니다. 저장소 문제가 발생하면 다음 명령으로 캐시를 지웁니다:

```shell
nuget locals all -clear
```

### Docker 기반 GitLab 설치에서 NuGet 패키지를 게시할 때 발생하는 오류 {#errors-when-publishing-nuget-packages-in-a-docker-based-gitlab-installation}

NuGet 패키지를 게시할 때 다음과 같은 오류 메시지가 표시될 수 있습니다:

- `Error publishing`
- `Invalid Package: Failed metadata extraction error`

웹후크 요청은 내부 웹 서비스의 악용을 방지하기 위해 로컬 네트워크 주소로 차단됩니다.

이러한 오류를 해결하려면 네트워크 설정을 변경하여 [웹후크 및 통합 요청을 로컬 네트워크에서 허용](../../../security/webhooks.md#allow-requests-to-the-local-network-from-webhooks-and-integrations)하세요.
