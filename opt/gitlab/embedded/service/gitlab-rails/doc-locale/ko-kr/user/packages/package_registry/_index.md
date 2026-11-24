---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 패키지 레지스트리
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [이동됨](https://gitlab.com/gitlab-org/gitlab/-/issues/221259) \- GitLab Premium에서 GitLab Free로 13.3에서 이동

{{< /history >}}

GitLab 패키지 레지스트리를 사용하면 다양한 [지원되는 패키지 관리자](supported_functionality.md)에 대해 GitLab을 비공개 또는 공개 레지스트리로 사용할 수 있습니다. 패키지를 게시하고 공유할 수 있으며, 이는 다운스트림 프로젝트에서 종속성으로 사용될 수 있습니다.

## 패키지 워크플로 {#package-workflows}

GitLab 패키지 레지스트리를 사용하여 자신만의 사용자 지정 패키지 워크플로를 구축하는 방법을 알아봅시다:

- [프로젝트를 패키지 레지스트리로 사용](../workflows/project_registry.md)하여 모든 패키지를 하나의 프로젝트로 게시합니다.

- 하나의 [모노레포 프로젝트](../workflows/working_with_monorepos.md)에서 여러 개의 다른 패키지를 게시합니다.

## 패키지 보기 {#view-packages}

프로젝트 또는 그룹의 패키지를 볼 수 있습니다:

1. 프로젝트 또는 그룹으로 이동합니다.
1. **배포** > **패키지 레지스트리**로 이동합니다.

이 페이지에서 패키지를 검색, 정렬 및 필터링할 수 있습니다. 브라우저에서 URL을 복사하여 붙여넣으면 검색 결과를 공유할 수 있습니다.

패키지 관리자를 구성하거나 특정 패키지를 설치하기 위한 유용한 코드 스니펫을 찾을 수 있습니다.

그룹에서 패키지를 볼 때:

- 그룹 및 해당 프로젝트에 게시된 모든 패키지가 표시됩니다.
- 액세스할 수 있는 프로젝트만 표시됩니다.
- 프로젝트가 비공개이거나 프로젝트의 멤버가 아닌 경우, 해당 프로젝트의 패키지는 표시되지 않습니다.

패키지를 생성하고 업로드하는 방법을 알아보려면 [패키지 유형](supported_functionality.md)에 대한 지침을 따르세요.

## GitLab CI/CD 사용 {#use-gitlab-cicd}

[GitLab CI/CD](../../../ci/_index.md)를 사용하여 패키지 레지스트리에 패키지를 빌드하거나 가져올 수 있습니다.

### 패키지 빌드 {#to-build-packages}

`CI_JOB_TOKEN`를 사용하여 GitLab으로 인증할 수 있습니다.

시작하려면 사용 가능한 [CI/CD 템플릿](https://gitlab.com/gitlab-org/gitlab/-/tree/master/lib/gitlab/ci/templates)을 사용할 수 있습니다.

GitLab 패키지 레지스트리를 CI/CD와 함께 사용하는 방법에 대한 자세한 내용은 다음을 참고하세요:

- [Generic](../generic_packages/_index.md#publish-a-package)
- [Maven](../maven_repository/_index.md#create-maven-packages-with-gitlab-cicd)
- [npm](../npm_registry/_index.md#publish-a-package-with-a-cicd-pipeline)
- [NuGet](../nuget_repository/_index.md#with-a-cicd-pipeline)
- [PyPI](../pypi_repository/_index.md#authenticate-with-the-gitlab-package-registry)
- [Terraform](../terraform_module_registry/_index.md#authenticate-to-the-terraform-module-registry)

CI/CD를 사용하여 패키지를 빌드하면, 패키지 세부 정보를 볼 때 확장된 활동 정보가 표시됩니다:

![패키지 CI/CD 활동](img/package_activity_v12_10.png)

패키지를 게시한 파이프라인, 커밋 및 트리거한 사용자를 확인할 수 있습니다. 그러나 이력은 주어진 패키지의 5개 업데이트로 제한됩니다.

### 패키지 가져오기 {#to-import-packages}

다른 레지스트리에서 빌드한 패키지가 이미 있는 경우, [패키지 가져오기](https://gitlab.com/gitlab-org/ci-cd/package-stage/pkgs_importer)를 사용하여 GitLab 패키지 레지스트리로 가져올 수 있습니다.

지원되는 패키지 목록은 [다른 리포지토리에서 패키지 가져오기](supported_functionality.md#importing-packages-from-other-repositories)를 참고하세요.

## 스토리지 사용량 감소 {#reduce-storage-usage}

패키지 레지스트리의 스토리지 사용량을 줄이는 방법에 대한 정보는 [패키지 레지스트리 스토리지 사용량 감소](reduce_package_registry_storage.md)를 참고하세요.

## 패키지 레지스트리 끄기 {#turn-off-the-package-registry}

패키지 레지스트리는 자동으로 켜집니다.

GitLab Self-Managed 인스턴스에서는 관리자가 GitLab 사이드바에서 **패키지 및 레지스트리** 메뉴 항목을 제거할 수 있습니다. 자세한 내용은 [GitLab 패키지 레지스트리 관리](../../../administration/packages/_index.md)를 참고하세요.

프로젝트별로 패키지 레지스트리를 제거할 수도 있습니다:

1. 프로젝트에서 **설정** > **일반**으로 이동합니다.
1. **표시 여부, 프로젝트 기능, 권한** 섹션을 확장하고 **패키지** 기능을 비활성화합니다.
1. **변경 사항 저장**을 선택합니다.

**배포** > **패키지 레지스트리** 항목이 사이드바에서 제거됩니다.

## 패키지 레지스트리 표시 여부 권한 {#package-registry-visibility-permissions}

[프로젝트 권한](../../permissions.md)은 패키지를 다운로드, 푸시 또는 삭제할 수 있는 멤버 및 사용자를 결정합니다.

패키지 레지스트리의 표시 여부는 리포지토리와 무관하며 프로젝트의 설정에서 제어할 수 있습니다. 예를 들어, 공개 프로젝트가 있고 리포지토리 표시 여부를 **프로젝트 멤버만**으로 설정하면, 패키지 레지스트리는 공개 상태입니다. **패키지 레지스트리** 토글을 끄면 모든 패키지 레지스트리 작업이 꺼집니다.

| 프로젝트 가시성 | 작업                | 필요한 최소 [역할](../../permissions.md#roles)     |
|--------------------|-----------------------|---------------------------------------------------------|
| 공개             | 패키지 레지스트리 보기 | 해당 없음 인터넷의 누구나 이 작업을 수행할 수 있습니다.    |
| 공개             | 패키지 게시     | Developer                                               |
| 공개             | 패키지 가져오기        | 해당 없음 인터넷의 누구나 이 작업을 수행할 수 있습니다.    |
| 내부           | 패키지 레지스트리 보기 | Guest                                                   |
| 내부           | 패키지 게시     | Developer                                               |
| 내부           | 패키지 가져오기        | 게스트 (1)                                               |
| 비공개            | 패키지 레지스트리 보기 | Reporter                                                |
| 비공개            | 패키지 게시     | Developer                                               |
| 비공개            | 패키지 가져오기        | 보고자 (1)                                            |

### 누구나 패키지 레지스트리에서 가져올 수 있도록 허용 {#allow-anyone-to-pull-from-package-registry}

{{< history >}}

- [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/385994) \- GitLab 15.7에서 도입
- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/issues/468058) \- GitLab 17.4에서 NuGet 그룹 엔드포인트를 지원하도록 변경
- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/issues/468059) \- GitLab 17.5에서 Maven 그룹 엔드포인트를 지원하도록 변경
- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/issues/468062) \- GitLab 17.5에서 Terraform 모듈 네임스페이스 엔드포인트를 지원하도록 변경

{{< /history >}}

프로젝트 표시 여부에 관계없이 누구나 패키지 레지스트리에서 가져올 수 있도록 허용하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 비공개 또는 내부 프로젝트를 찾습니다.
1. **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한**을 확장합니다.
1. **누구나 패키지 레지스트리에서 가져올 수 있도록 허용** 토글을 켭니다.
1. **변경 사항 저장**을 선택합니다.

인터넷의 누구나 프로젝트의 패키지 레지스트리에 액세스할 수 있습니다.

#### 누구나 가져올 수 있도록 허용 비활성화 {#disable-allowing-anyone-to-pull}

사전 요구 사항:

- 관리자여야 합니다.

**누구나 패키지 레지스트리에서 가져올 수 있도록 허용** 토글을 전역으로 숨기려면:

- [애플리케이션 설정 업데이트](../../../api/settings.md#update-application-settings) `package_registry_allow_anyone_to_pull_option`를 `false`로 변경합니다.

**누구나 패키지 레지스트리에서 가져올 수 있도록 허용** 토글을 켠 프로젝트도 익명 다운로드가 꺼집니다.

누구나 패키지 레지스트리에서 가져올 수 있도록 허용할 때 몇 가지 알려진 문제가 있습니다:

- 프로젝트용 엔드포인트가 지원됩니다.
- 그룹용 NuGet 레지스트리 엔드포인트가 지원됩니다. 그러나 NuGet 클라이언트가 인증 자격 증명을 전송하는 방식 때문에 익명 다운로드는 허용되지 않습니다. 이 설정이 켜져 있어도 GitLab 사용자만 패키지 레지스트리에서 가져올 수 있습니다.
- 그룹용 Maven 레지스트리 엔드포인트가 지원됩니다.
- 네임스페이스용 Terraform 모듈 레지스트리 엔드포인트가 지원됩니다.
- 다른 그룹 및 인스턴스 엔드포인트는 완벽하게 지원되지 않습니다. 그룹 엔드포인트에 대한 지원은 [에픽 14234](https://gitlab.com/groups/gitlab-org/-/epics/14234)에서 제안됩니다.
- [Composer](../composer_repository/_index.md#install-a-composer-package)에서는 작동하지 않습니다. 왜냐하면 Composer는 그룹 엔드포인트만 있기 때문입니다.
- Conan에서는 작동하지만, [`conan search`](../conan_1_repository/_index.md#search-for-conan-packages-in-the-package-registry)를 사용하면 작동하지 않습니다.

## 감사 이벤트 {#audit-events}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- GitLab 17.10에서 `package_registry_audit_events`라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/329588)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.2에서 [정식 출시](https://gitlab.com/gitlab-org/gitlab/-/issues/554817)되었습니다. `package_registry_audit_events` 기능 플래그가 제거되었습니다.

{{< /history >}}

패키지가 게시되거나 삭제될 때 감사 이벤트를 생성합니다. 네임스페이스 소유자는 [GraphQL API](../../../api/graphql/reference/_index.md#packagesettings)를 통해 `audit_events_enabled` 설정을 켤 수 있습니다.

감사 이벤트를 볼 수 있습니다:

- 패키지의 프로젝트가 그룹에 있으면 [**그룹 감사 이벤트**](../../compliance/audit_events.md#group-audit-events) 페이지에서 확인합니다.
- 패키지의 프로젝트가 사용자 네임스페이스에 있으면 [**프로젝트 감사 이벤트**](../../compliance/audit_events.md#project-audit-events) 페이지에서 확인합니다.

## 기여 수락 {#accepting-contributions}

다음 표는 지원되지 않는 패키지 형식을 나열합니다. GitLab에 기여하여 이러한 형식에 대한 지원을 추가하는 것을 고려하세요.

<!-- vale gitlab_base.Spelling = NO -->

| 형식    | 상태                                                        |
| --------- | ------------------------------------------------------------- |
| Conda     | [\#36891](https://gitlab.com/gitlab-org/gitlab/-/issues/36891) |
| Conda      | [\#36892](https://gitlab.com/gitlab-org/gitlab/-/issues/36892) |
| CRAN       | [\#5932](https://gitlab.com/groups/gitlab-org/-/epics/5128)    |
| Swift     | [\#12233](https://gitlab.com/gitlab-org/gitlab/-/issues/12233) |

<!-- vale gitlab_base.Spelling = YES -->
