---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 지원되는 패키지 관리자 및 기능
---

GitLab 패키지 레지스트리는 각 패키지 유형에 대해 다양한 기능을 지원합니다. 이 지원에는 패키지 발행 및 풀, 요청 전달, 중복 관리 및 인증이 포함됩니다.

## 지원되는 패키지 관리자 {#supported-package-managers}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> 모든 패키지 관리자 형식이 프로덕션 사용 준비가 완료된 것은 아닙니다.

패키지 레지스트리는 다음 패키지 관리자 유형을 지원합니다:

| 패키지 유형                                      | 상태 |
|---------------------------------------------------|--------|
| [Composer](../composer_repository/_index.md)      | [베타](https://gitlab.com/groups/gitlab-org/-/work_items/6817) |
| [Conan 1](../conan_1_repository/_index.md)            | [베타](https://gitlab.com/groups/gitlab-org/-/work_items/6816) |
| [Conan 2](../conan_2_repository/_index.md)            | [베타](https://gitlab.com/groups/gitlab-org/-/work_items/8258) |
| [Debian](../debian_repository/_index.md)          | [실험적 기능](https://gitlab.com/groups/gitlab-org/-/work_items/6057) |
| [일반 패키지](../generic_packages/_index.md) | 정식 출시(GA)     |
| [Go](../go_proxy/_index.md)                       | [실험적 기능](https://gitlab.com/groups/gitlab-org/-/work_items/3043) |
| [Helm](../helm_repository/_index.md)              | 정식 출시(GA)      |
| [Maven](../maven_repository/_index.md)            | 정식 출시(GA)      |
| [npm](../npm_registry/_index.md)                  | 정식 출시(GA)      |
| [NuGet](../nuget_repository/_index.md)            | 정식 출시(GA)      |
| [PyPI](../pypi_repository/_index.md)              | 정식 출시(GA)      |
| [Ruby gems](../rubygems_registry/_index.md)       | [실험적 기능](https://gitlab.com/groups/gitlab-org/-/work_items/3200) |

[각 상태의 의미 보기](../../../policy/development_stages_support.md).

[API](../../../api/packages.md)를 사용하여 패키지 레지스트리를 관리할 수 있습니다.

## 패키지 발행 {#publishing-packages}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

패키지를 프로젝트, 그룹 또는 인스턴스에 발행할 수 있습니다.

| 패키지 유형                                           | 프로젝트 | 그룹 | 인스턴스 |
|--------------------------------------------------------|---------|-------|----------|
| [Maven (`mvn`포함)](../maven_repository/_index.md)    | 예       | 아니요     | 아니요        |
| [Maven (`gradle`포함)](../maven_repository/_index.md) | 예       | 아니요     | 아니요        |
| [Maven (`sbt`포함)](../maven_repository/_index.md)    | 아니요        | 아니요     | 아니요        |
| [npm](../npm_registry/_index.md)                       | 예       | 아니요     | 아니요        |
| [NuGet](../nuget_repository/_index.md)                 | 예       | 아니요     | 아니요        |
| [PyPI](../pypi_repository/_index.md)                   | 예       | 아니요     | 아니요        |
| [일반 패키지](../generic_packages/_index.md)      | 예       | 아니요     | 아니요        |
| [Terraform](../terraform_module_registry/_index.md)    | 예       | 아니요     | 아니요        |
| [Composer](../composer_repository/_index.md)           | 아니요        | 예    | 아니요        |
| [Conan 1](../conan_1_repository/_index.md)             | 예       | 아니요     | 예       |
| [Conan 2](../conan_2_repository/_index.md)             | 예       | 아니요     | 아니요        |
| [Helm](../helm_repository/_index.md)                   | 예       | 아니요     | 아니요        |
| [Debian](../debian_repository/_index.md)               | 예       | 아니요     | 아니요        |
| [Go](../go_proxy/_index.md)                            | 예       | 아니요     | 아니요        |
| [Ruby gems](../rubygems_registry/_index.md)            | 예       | 아니요     | 아니요        |

## 패키지 풀 {#pulling-packages}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

패키지를 프로젝트, 그룹 또는 인스턴스에서 풀할 수 있습니다.

| 패키지 유형                                           | 프로젝트 | 그룹 | 인스턴스 |
|--------------------------------------------------------|---------|-------|----------|
| [Maven (`mvn`포함)](../maven_repository/_index.md)    | 예       | 예     | 예       |
| [Maven (`gradle`포함)](../maven_repository/_index.md) | 예       | 예     | 예       |
| [Maven (`sbt`포함)](../maven_repository/_index.md)    | 예       | 예     | 예       |
| [npm](../npm_registry/_index.md)                       | 예       | 예     | 예       |
| [NuGet](../nuget_repository/_index.md)                 | 예       | 예     | 아니요        |
| [PyPI](../pypi_repository/_index.md)                   | 예       | 예     | 아니요        |
| [일반 패키지](../generic_packages/_index.md)      | 예       | 아니요      | 아니요        |
| [Terraform](../terraform_module_registry/_index.md)    | 아니요        | 예     | 아니요        |
| [Composer](../composer_repository/_index.md)           | 예       | 예     | 아니요        |
| [Conan 1](../conan_1_repository/_index.md)             | 예       | 아니요      | 예       |
| [Conan 2](../conan_2_repository/_index.md)             | 예       | 아니요      | 아니요        |
| [Helm](../helm_repository/_index.md)                   | 예       | 아니요      | 아니요        |
| [Debian](../debian_repository/_index.md)               | 예       | 아니요      | 아니요        |
| [Go](../go_proxy/_index.md)                            | 예       | 아니요      | 예       |
| [Ruby gems](../rubygems_registry/_index.md)            | 예       | 아니요      | 아니요        |

## 요청 전달 {#forwarding-requests}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

사전 요구 사항:

- GitLab.com:  그룹의 소유자여야 합니다.
- GitLab Self-Managed:  관리자여야 합니다.

패키지가 프로젝트의 패키지 레지스트리에서 발견되지 않으면 요청이 패키지 관리자의 해당 공용 레지스트리로 전달됩니다.

기본 전달 동작은 패키지 유형에 따라 다르며 [종속성 혼동 취약성](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)을 발생시킬 수 있습니다. 다음 표는 어떤 패키지 관리자가 패키지 전달을 지원하는지 보여줍니다.

관련 보안 위험을 줄이려면:

- 패키지가 활발히 사용 중이 아닌지 확인합니다.
- Git과 같은 버전 제어 도구를 구현하여 패키지 변경 사항을 추적합니다.
- 요청 전달을 끕니다:
  - 인스턴스 관리자는 **운영자** 영역에서 전달을 비활성화할 수 있습니다. 자세한 내용은 [패키지 전달 제어](../../../administration/settings/continuous_integration.md#control-package-forwarding)를 참조하세요.
  - 그룹 소유자는 그룹 설정에서 패키지 전달을 끌 수 있습니다.

그룹에 대한 요청 전달을 끄려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **패키지 전달** 아래에서 다음 확인란 중 하나를 선택 해제합니다:
   - **npm 패키지 요청 전달**
   - **PyPI 패키지 요청 전달**
1. **변경 사항 저장**을 선택합니다.

| 패키지 유형                                           | 요청 전달 지원 | 보안 고려 사항 |
|--------------------------------------------------------|-----------------------------|------------------------|
| [Maven (`mvn`포함)](../maven_repository/_index.md)    | [예 (기본적으로 비활성화됨)](../../../administration/settings/continuous_integration.md#control-package-forwarding) | 보안을 위해 명시적인 옵트인이 필요합니다. |
| [Maven (`gradle`포함)](../maven_repository/_index.md) | [예 (기본적으로 비활성화됨)](../../../administration/settings/continuous_integration.md#control-package-forwarding) | 보안을 위해 명시적인 옵트인이 필요합니다. |
| [Maven (`sbt`포함)](../maven_repository/_index.md)    | [예 (기본적으로 비활성화됨)](../../../administration/settings/continuous_integration.md#control-package-forwarding) | 보안을 위해 명시적인 옵트인이 필요합니다. |
| [npm](../npm_registry/_index.md)                       | [예](../../../administration/settings/continuous_integration.md#control-package-forwarding) | 비공개 패키지에 대해 비활성화를 고려합니다. |
| [PyPI](../pypi_repository/_index.md)                   | [예](../../../administration/settings/continuous_integration.md#control-package-forwarding) | 비공개 패키지에 대해 비활성화를 고려합니다. |
| [NuGet](../nuget_repository/_index.md)                 | 아니요                           | 아니요 |
| [일반 패키지](../generic_packages/_index.md)      | 아니요                           | 아니요 |
| [Terraform](../terraform_module_registry/_index.md)    | 아니요                           | 아니요 |
| [Composer](../composer_repository/_index.md)           | 아니요                           | 아니요 |
| [Conan 1](../conan_1_repository/_index.md)               | 아니요                           | 아니요 |
| [Conan 2](../conan_2_repository/_index.md)               | 아니요                           | 아니요 |
| [Helm](../helm_repository/_index.md)                   | 아니요                           | 아니요 |
| [Debian](../debian_repository/_index.md)               | 아니요                           | 아니요 |
| [Go](../go_proxy/_index.md)                            | 아니요                           | 아니요 |
| [Ruby gems](../rubygems_registry/_index.md)            | 아니요                           | 아니요 |

## 패키지 삭제 {#deleting-packages}

패키지 요청이 공용 레지스트리로 전달될 때 패키지 삭제로 인해 [종속성 혼동 취약성](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)이 발생할 수 있습니다.

시스템이 삭제된 패키지를 풀하려고 하면 요청이 공용 레지스트리로 전달됩니다. 동일한 이름 및 버전의 패키지가 공용 레지스트리에 있으면 해당 패키지가 대신 풀됩니다. 레지스트리에서 풀한 패키지는 예상과 다를 수 있으며 악성일 수 있습니다.

관련 보안 위험을 줄이려면 패키지를 삭제하기 전에:

- 패키지가 활발히 사용 중이 아닌지 확인합니다.
- [요청 전달 비활성화](#forwarding-requests).

패키지를 삭제하려면:

- [UI에서 패키지 삭제](reduce_package_registry_storage.md#delete-a-package).
- [API를 사용하여 패키지 삭제](../../../api/packages.md#delete-a-project-package).

## 다른 리포지토리에서 패키지 가져오기 {#importing-packages-from-other-repositories}

GitLab 파이프라인을 사용하여 Maven Central 또는 Artifactory와 같은 다른 리포지토리에서 패키지를 가져올 수 있습니다. [패키지 가져오기 도구](https://gitlab.com/gitlab-org/ci-cd/package-stage/pkgs_importer)입니다.

| 패키지 유형                                           | 가져오기 도구 사용 가능? |
|--------------------------------------------------------|---------------------|
| [Maven (`mvn`포함)](../maven_repository/_index.md)    | 예                  |
| [Maven (`gradle`포함)](../maven_repository/_index.md) | 예                  |
| [Maven (`sbt`포함)](../maven_repository/_index.md)    | 예                  |
| [npm](../npm_registry/_index.md)                       | 예                  |
| [NuGet](../nuget_repository/_index.md)                 | 예                  |
| [PyPI](../pypi_repository/_index.md)                   | 예                  |
| [일반 패키지](../generic_packages/_index.md)      | 아니요                   |
| [Terraform](../terraform_module_registry/_index.md)    | 아니요                   |
| [Composer](../composer_repository/_index.md)           | 아니요                   |
| [Conan 1](../conan_1_repository/_index.md)             | 아니요                   |
| [Conan 2](../conan_2_repository/_index.md)             | 아니요                   |
| [Helm](../helm_repository/_index.md)                   | 아니요                   |
| [Debian](../debian_repository/_index.md)               | 아니요                   |
| [Go](../go_proxy/_index.md)                            | 아니요                   |
| [Ruby gems](../rubygems_registry/_index.md)            | 아니요                   |

## 중복 허용 또는 방지 {#allow-or-prevent-duplicates}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

기본적으로 GitLab 패키지 레지스트리는 특정 패키지 관리자 형식의 기본값에 따라 중복을 허용하거나 방지합니다.

| 패키지 유형                                           | 중복 허용? |
|--------------------------------------------------------|---------------------|
| [Maven (`mvn`포함)](../maven_repository/_index.md)    | 예 (구성 가능)   |
| [Maven (`gradle`포함)](../maven_repository/_index.md) | 예 (구성 가능)   |
| [Maven (`sbt`포함)](../maven_repository/_index.md)    | 예 (구성 가능)   |
| [npm](../npm_registry/_index.md)                       | 아니요                   |
| [NuGet](../nuget_repository/_index.md)                 | 예                  |
| [PyPI](../pypi_repository/_index.md)                   | 아니요                   |
| [일반 패키지](../generic_packages/_index.md)      | 예 (구성 가능)   |
| [Terraform](../terraform_module_registry/_index.md)    | 아니요                   |
| [Composer](../composer_repository/_index.md)           | 아니요                   |
| [Conan 1](../conan_1_repository/_index.md)             | 아니요                   |
| [Conan 2](../conan_2_repository/_index.md)             | 아니요                   |
| [Helm](../helm_repository/_index.md)                   | 예                  |
| [Debian](../debian_repository/_index.md)               | 예                  |
| [Go](../go_proxy/_index.md)                            | 아니요                   |
| [Ruby gems](../rubygems_registry/_index.md)            | 예                  |

## 레지스트리로 인증 {#authenticate-with-the-registry}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

인증은 사용 중인 패키지 관리자에 따라 다릅니다. 특정 패키지 유형에 대해 지원되는 인증 프로토콜을 알아보려면 [인증 프로토콜](#authentication-protocols)을 참조하세요.

대부분의 패키지 유형의 경우 다음 인증 토큰이 유효합니다:

- [개인 액세스 토큰](../../profile/personal_access_tokens.md)
- [프로젝트 배포 토큰](../../project/deploy_tokens/_index.md)
- [그룹 배포 토큰](../../project/deploy_tokens/_index.md)
- [CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md)

다음 표는 지정된 패키지 관리자에 대해 지원되는 인증 토큰을 나열합니다:

| 패키지 유형                                           | 지원되는 토큰                                                       |
|--------------------------------------------------------|------------------------------------------------------------------------|
| [Maven (`mvn`포함)](../maven_repository/_index.md)    | 개인 액세스, 작업 토큰, 배포 (프로젝트 또는 그룹), 프로젝트 액세스 |
| [Maven (`gradle`포함)](../maven_repository/_index.md) | 개인 액세스, 작업 토큰, 배포 (프로젝트 또는 그룹), 프로젝트 액세스 |
| [Maven (`sbt`포함)](../maven_repository/_index.md)    | 개인 액세스, 작업 토큰, 배포 (프로젝트 또는 그룹), 프로젝트 액세스 |
| [npm](../npm_registry/_index.md)                       | 개인 액세스, 작업 토큰, 배포 (프로젝트 또는 그룹), 프로젝트 액세스 |
| [NuGet](../nuget_repository/_index.md)                 | 개인 액세스, 작업 토큰, 배포 (프로젝트 또는 그룹), 프로젝트 액세스 |
| [PyPI](../pypi_repository/_index.md)                   | 개인 액세스, 작업 토큰, 배포 (프로젝트 또는 그룹), 프로젝트 액세스 |
| [일반 패키지](../generic_packages/_index.md)      | 개인 액세스, 작업 토큰, 배포 (프로젝트 또는 그룹), 프로젝트 액세스 |
| [Terraform](../terraform_module_registry/_index.md)    | 개인 액세스, 작업 토큰, 배포 (프로젝트 또는 그룹), 프로젝트 액세스 |
| [Composer](../composer_repository/_index.md)           | 개인 액세스, 작업 토큰, 배포 (프로젝트 또는 그룹), 프로젝트 액세스 |
| [Conan 1](../conan_1_repository/_index.md)                 | 개인 액세스, 작업 토큰, 프로젝트 액세스                            |
| [Conan 2](../conan_2_repository/_index.md)                 | 개인 액세스, 작업 토큰, 프로젝트 액세스                            |
| [Helm](../helm_repository/_index.md)                   | 개인 액세스, 작업 토큰, 배포 (프로젝트 또는 그룹)                 |
| [Debian](../debian_repository/_index.md)               | 개인 액세스, 작업 토큰, 배포 (프로젝트 또는 그룹)                 |
| [Go](../go_proxy/_index.md)                            | 개인 액세스, 작업 토큰, 프로젝트 액세스                            |
| [Ruby gems](../rubygems_registry/_index.md)            | 개인 액세스, 작업 토큰, 배포 (프로젝트 또는 그룹)                 |

> [!note]
> 패키지 레지스트리에 대한 인증을 구성할 때:
>
> - **패키지 레지스트리** 프로젝트 설정이 [꺼져](_index.md#turn-off-the-package-registry)있으면 소유자 역할이 있어도 패키지 레지스트리와 상호 작용할 때 `403 Forbidden` 오류가 발생합니다.
> - [외부 인증](../../../administration/settings/external_authorization.md)이 켜져 있으면 배포 토큰으로 패키지 레지스트리에 액세스할 수 없습니다.
> - 조직에서 2단계 인증(2FA)을 사용하면 범위가 `api`로 설정된 개인 액세스 토큰을 사용해야 합니다.
> - CI/CD 파이프라인을 사용하여 패키지를 발행하는 경우 CI/CD 작업 토큰을 사용해야 합니다.

### 인증 프로토콜 {#authentication-protocols}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

다음 인증 프로토콜이 지원됩니다:

| 패키지 유형                                           | 지원되는 인증 프로토콜                                    |
|--------------------------------------------------------|-------------------------------------------------------------|
| [Maven (`mvn`포함)](../maven_repository/_index.md)    | 헤더, 기본 인증, OAuth                                  |
| [Maven (`gradle`포함)](../maven_repository/_index.md) | 헤더, 기본 인증, OAuth                                  |
| [Maven (`sbt`포함)](../maven_repository/_index.md)    | 기본 인증 ([풀](#pulling-packages)만 해당)          |
| [npm](../npm_registry/_index.md)                       | OAuth                                                       |
| [NuGet](../nuget_repository/_index.md)                 | 기본 인증                                                  |
| [PyPI](../pypi_repository/_index.md)                   | 기본 인증                                                  |
| [일반 패키지](../generic_packages/_index.md)      | 기본 인증                                                  |
| [Terraform](../terraform_module_registry/_index.md)    | 토큰                                                       |
| [Composer](../composer_repository/_index.md)           | OAuth                                                       |
| [Conan 1](../conan_1_repository/_index.md)                 | OAuth, 기본 인증                                           |
| [Conan 2](../conan_2_repository/_index.md)                 | OAuth, 기본 인증                                           |
| [Helm](../helm_repository/_index.md)                   | 기본 인증                                                  |
| [Debian](../debian_repository/_index.md)               | 기본 인증                                                  |
| [Go](../go_proxy/_index.md)                            | 기본 인증                                                  |
| [Ruby gems](../rubygems_registry/_index.md)            | 토큰                                                       |

## 지원되는 해시 유형 {#supported-hash-types}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

해시 값은 올바른 패키지를 사용 중임을 보장하는 데 사용됩니다. [API](../../../api/packages.md)와 함께 사용자 인터페이스에서 이 값을 볼 수 있습니다.

패키지 레지스트리는 다음 해시 유형을 지원합니다:

| 패키지 유형                                           | 지원되는 해시                 |
|--------------------------------------------------------|----------------------------------|
| [Maven (`mvn`포함)](../maven_repository/_index.md)    | MD5, SHA1                        |
| [Maven (`gradle`포함)](../maven_repository/_index.md) | MD5, SHA1                        |
| [Maven (`sbt`포함)](../maven_repository/_index.md)    | MD5, SHA1                        |
| [npm](../npm_registry/_index.md)                       | SHA1                             |
| [NuGet](../nuget_repository/_index.md)                 | 해당 없음                   |
| [PyPI](../pypi_repository/_index.md)                   | MD5, SHA256                      |
| [일반 패키지](../generic_packages/_index.md)      | SHA256                           |
| [Composer](../composer_repository/_index.md)           | 해당 없음                   |
| [Conan 1](../conan_1_repository/_index.md)             | MD5, SHA1                        |
| [Conan 2](../conan_2_repository/_index.md)             | MD5, SHA1                        |
| [Helm](../helm_repository/_index.md)                   | 해당 없음                   |
| [Debian](../debian_repository/_index.md)               | MD5, SHA1, SHA256                |
| [Go](../go_proxy/_index.md)                            | MD5, SHA1, SHA256                |
| [Ruby gems](../rubygems_registry/_index.md)            | MD5, SHA1, SHA256 (gemspec만) |
