---
stage: Verify
group: Runner Core
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 배포 토큰
description: "리포지토리 복제, 토큰 생성 및 컨테이너 레지스트리"
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

배포 토큰은 개별 사용자 계정에 권한을 연결하지 않고 GitLab 리소스에 대한 보안 액세스를 제공합니다. Git 작업, 컨테이너 레지스트리 및 패키지 레지스트리에서 배포 자동화가 정확히 필요한 것에 액세스하도록 합니다.

배포 토큰을 사용하면 다음을 얻을 수 있습니다:

- 자동화 시스템에서 개인 자격 증명을 제거하여 더 안전한 배포
- 각 토큰에 대한 특정 권한으로 세밀한 액세스 제어
- 기본 제공 인증 변수가 있는 단순화된 CI/CD 파이프라인
- 팀 구성원이 변경될 때 중단되지 않는 안정적인 배포 프로세스
- 전용 토큰 ID를 통해 배포를 추적하여 더 나은 감사 추적
- 외부 빌드 시스템 및 배포 도구와의 원활한 통합

배포 토큰은 값의 쌍입니다:

- **사용자명**: `username` HTTP 인증 프레임워크입니다. 기본 사용자명 형식은 `gitlab+deploy-token-{n}`입니다. 배포 토큰을 만들 때 사용자 정의 사용자명을 지정할 수 있습니다.
- **토큰**: `password` HTTP 인증 프레임워크입니다.

배포 토큰은 [SSH 인증](../../ssh.md)을 지원하지 않습니다.

배포 토큰을 [HTTP 인증](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Authentication)에 다음 엔드포인트에 사용할 수 있습니다:

- GitLab 패키지 레지스트리 공개 API
- [Git 명령](https://git-scm.com/docs/gitcredentials#_description)
- [GitLab 가상 레지스트리 패키지 작업](../../../api/maven_virtual_registries.md#manage-package-operations)

프로젝트 또는 그룹 수준에서 배포 토큰을 만들 수 있습니다:

- **프로젝트 배포 토큰**: 권한은 프로젝트에만 적용됩니다.
- **그룹 배포 토큰**: 권한은 그룹의 모든 프로젝트에 적용됩니다.

기본적으로 배포 토큰은 만료되지 않습니다. 만든 때 선택적으로 만료 날짜를 설정할 수 있습니다. 만료는 해당 날짜의 자정(UTC)에 발생합니다.

> [!warning]
> [외부 권한 부여](../../../administration/settings/external_authorization.md)가 활성화된 경우 Git 작업 및 패키지 레지스트리 작업에 새로운 또는 기존 배포 토큰을 사용할 수 없습니다.

## 범위 {#scope}

배포 토큰의 범위는 수행할 수 있는 작업을 결정합니다.

| 범위                    | 설명                                                                                                  |
|--------------------------|--------------------------------------------------------------------------------------------------------------|
| `read_repository`        | `git clone`을(를) 사용하여 리포지토리에 대한 읽기 전용 액세스                                                        |
| `read_registry`          | 프로젝트의 [컨테이너 레지스트리](../../packages/container_registry/_index.md)의 이미지에 대한 읽기 전용 액세스 |
| `write_registry`         | 프로젝트의 [컨테이너 레지스트리](../../packages/container_registry/_index.md)로 쓰기 액세스(푸시) 이미지를 푸시하려면 읽기 및 쓰기 액세스가 모두 필요합니다. |
| `read_virtual_registry`  | 그룹 수준 종속성 프록시 및 가상 레지스트리를 통해 컨테이너 이미지에 대한 읽기 전용(풀) 액세스 권한을 부여합니다. 프로젝트의 컨테이너 레지스트리에 대한 직접 액세스를 부여하지 않습니다. 종속성 프록시가 활성화된 경우에만 사용 가능합니다. |
| `write_virtual_registry` | 그룹 수준 종속성 프록시 캐시로 쓰기 액세스를 부여하고 암묵적으로 해당 캐시를 통한 풀을 허용합니다. 프로젝트의 컨테이너 레지스트리로 푸시 또는 삭제 액세스를 부여하지 않습니다. 종속성 프록시가 활성화된 경우에만 사용 가능합니다. |
| `read_package_registry`  | 프로젝트의 패키지 레지스트리에 대한 읽기 전용 액세스                                                          |
| `write_package_registry` | 프로젝트의 패키지 레지스트리로 쓰기 액세스                                                              |

## GitLab 배포 토큰 {#gitlab-deploy-token}

GitLab 배포 토큰은 특수한 유형의 배포 토큰입니다. `gitlab-deploy-token`이라는 배포 토큰을 만드는 경우 배포 토큰은 자동으로 프로젝트 CI/CD 작업에 변수로 노출됩니다:

- `CI_DEPLOY_USER`: 사용자명
- `CI_DEPLOY_PASSWORD`: 토큰

예를 들어 GitLab 토큰을 사용하여 GitLab 컨테이너 레지스트리에 로그인합니다:

```shell
echo "$CI_DEPLOY_PASSWORD" | docker login $CI_REGISTRY -u $CI_DEPLOY_USER --password-stdin
```

`gitlab-deploy-token`이 그룹에 정의된 경우 `CI_DEPLOY_USER` 및 `CI_DEPLOY_PASSWORD` CI/CD 변수는 그룹의 직접 하위 프로젝트에서만 사용할 수 있습니다.

## 배포 토큰 만료 {#deploy-token-expiration}

{{< history >}}

- 배포 토큰 만료에 대한 이메일 알림이 GitLab 18.3에 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/512197)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md) 이름은 `project_deploy_token_expiring_notifications`입니다. 기본적으로 비활성화되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

배포 토큰은 정의한 날짜의 00:00 UTC에 만료됩니다.

GitLab은 만료될 예정인 배포 토큰을 확인하기 위해 매일 01:00 AM UTC에 확인합니다. 프로젝트 소유자 및 유지관리자는 이러한 토큰이 만료되기 60, 30, 7일 전에 이메일로 알림을 받습니다.

이러한 이메일 알림은 활성(해지되지 않음) 배포 토큰의 간격마다 한 번만 전송됩니다.

### GitLab 배포 토큰 보안 {#gitlab-deploy-token-security}

GitLab 배포 토큰은 수명이 길어서 공격자에게 매력적입니다.

배포 토큰 누출을 방지하려면 [러너](../../../ci/runners/_index.md)를 안전하도록 구성해야 합니다:

- 머신을 재사용할 경우 Docker `privileged` 모드 사용을 피합니다.
- 작업이 같은 머신에서 실행될 때 [`shell` 실행기](https://docs.gitlab.com/runner/executors/shell/) 사용을 피합니다.

보안되지 않은 GitLab 러너 구성은 다른 작업에서 토큰을 도용할 위험을 증가시킵니다.

### GitLab 공개 API {#gitlab-public-api}

배포 토큰은 GitLab 공개 API와 함께 사용할 수 없습니다. 그러나 패키지 레지스트리의 토큰 등 일부 엔드포인트에서 배포 토큰을 사용할 수 있습니다. URL에 `packages/<format>` 문자열이 있으므로 엔드포인트가 패키지 레지스트리에 속하는지 알 수 있습니다. 예: `https://gitlab.example.com/api/v4/projects/24/packages/generic/my_package/0.0.1/file.txt`. 자세한 내용은 [레지스트리로 인증](../../packages/package_registry/supported_functionality.md#authenticate-with-the-registry)을 참조하세요.

## 배포 토큰 만들기 {#create-a-deploy-token}

사용자 계정과 무관하게 실행할 수 있는 배포 작업을 자동화하기 위해 배포 토큰을 만듭니다.

사전 요구 사항:

- 그룹 배포 토큰을 만들려면 그룹에 대한 소유자 역할이 있어야 합니다.
- 프로젝트 배포 토큰을 만들려면 프로젝트에 대한 유지관리자 또는 소유자 역할이 있어야 합니다.

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **배포 토큰**을 확장합니다.
1. **토큰 추가**를 선택합니다.
1. 필드를 완성하고 원하는 [범위](#scope)를 선택합니다.
1. **배포 토큰 만들기**를 선택합니다.

배포 토큰의 값을 기록합니다. 페이지를 나가거나 새로 고친 후에는 다시 액세스할 수 없습니다.

## 배포 토큰 해지 {#revoke-a-deploy-token}

더 이상 필요하지 않을 때 토큰을 해지합니다.

사전 요구 사항:

- 그룹 배포 토큰을 해지하려면 그룹에 대한 소유자 역할이 있어야 합니다.
- 프로젝트 배포 토큰을 해지하려면 프로젝트에 대한 유지관리자 또는 소유자 역할이 있어야 합니다.

배포 토큰을 해지하려면:

1. 상단 막대에서 **검색 또는 이동**을 선택하고 프로젝트 또는 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **배포 토큰**을 확장합니다.
1. **활성 배포 토큰** 섹션에서 해지할 토큰 옆에 **해지**를 선택합니다.

## 리포지토리 복제 {#clone-a-repository}

배포 토큰을 사용하여 리포지토리를 복제할 수 있습니다.

사전 요구 사항:

- `read_repository` 범위의 배포 토큰입니다.

배포 토큰을 사용하여 리포지토리를 복제하는 예:

```shell
git clone https://<username>:<deploy_token>@gitlab.example.com/tanuki/awesome_project.git
```

## 컨테이너 레지스트리에서 이미지 풀 {#pull-images-from-a-container-registry}

배포 토큰을 사용하여 컨테이너 레지스트리에서 이미지를 풀할 수 있습니다.

사전 요구 사항:

- `read_registry` 범위의 배포 토큰입니다.

배포 토큰을 사용하여 컨테이너 레지스트리에서 이미지를 풀하는 예:

```shell
echo "$DEPLOY_TOKEN" | docker login -u <username> --password-stdin registry.example.com
docker pull $CONTAINER_TEST_IMAGE
```

## 컨테이너 레지스트리로 이미지 푸시 {#push-images-to-a-container-registry}

배포 토큰을 사용하여 컨테이너 레지스트리로 이미지를 푸시할 수 있습니다.

사전 요구 사항:

- `read_registry` 및 `write_registry` 범위의 배포 토큰입니다.

배포 토큰을 사용하여 컨테이너 레지스트리로 이미지를 푸시하는 예:

```shell
echo "$DEPLOY_TOKEN" | docker login -u <username> --password-stdin registry.example.com
docker push $CONTAINER_TEST_IMAGE
```

## 패키지 레지스트리에서 패키지 풀 {#pull-packages-from-a-package-registry}

배포 토큰을 사용하여 패키지 레지스트리에서 패키지를 풀할 수 있습니다.

사전 요구 사항:

- `read_package_registry` 범위의 배포 토큰입니다.

[선택한 패키지 유형](../../packages/package_registry/supported_functionality.md#authenticate-with-the-registry)의 경우 배포 토큰에 대한 인증 지침을 따릅니다.

GitLab 레지스트리에서 NuGet 패키지를 설치하는 예:

```shell
nuget source Add -Name GitLab -Source "https://gitlab.example.com/api/v4/projects/10/packages/nuget/index.json" -UserName <username> -Password <deploy_token>
nuget install mypkg.nupkg
```

## 패키지 레지스트리로 패키지 푸시 {#push-packages-to-a-package-registry}

배포 토큰을 사용하여 GitLab 패키지 레지스트리로 패키지를 푸시할 수 있습니다.

사전 요구 사항:

- `write_package_registry` 범위의 배포 토큰입니다.

[선택한 패키지 유형](../../packages/package_registry/supported_functionality.md#authenticate-with-the-registry)의 경우 배포 토큰에 대한 인증 지침을 따릅니다.

패키지 레지스트리로 NuGet 패키지를 게시하는 예:

```shell
nuget source Add -Name GitLab -Source "https://gitlab.example.com/api/v4/projects/10/packages/nuget/index.json" -UserName <username> -Password <deploy_token>
nuget push mypkg.nupkg -Source GitLab
```

## 종속성 프록시에서 이미지 풀 {#pull-images-from-the-dependency-proxy}

배포 토큰을 사용하여 종속성 프록시에서 이미지를 풀할 수 있습니다. 사전 요구 사항:

- 종속성 프록시: `read_registry` 및 `write_registry` 범위입니다.
- 가상 레지스트리: `read_virtual_registry` 및 `write_virtual_registry` 범위입니다.

종속성 프록시 [인증 지침](../../packages/dependency_proxy/_index.md)을 따릅니다.
