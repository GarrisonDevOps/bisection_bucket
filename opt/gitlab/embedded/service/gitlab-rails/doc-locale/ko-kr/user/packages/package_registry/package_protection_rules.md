---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
gitlab_dedicated: yes
title: 보호된 패키지
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- `packages_protected_packages`이라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 GitLab 16.5에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/416395)되었습니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../../../policy/development_stages_support.md)입니다.
- 보호 규칙 설정 **액세스 수준까지 푸시 보호**가 GitLab 17.1에서 **푸시를 위한 최소 액세스 수준**으로 [이름이 변경](https://gitlab.com/gitlab-org/gitlab/-/issues/416382)되었습니다.
- GitLab 17.6에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/472655)합니다. 기능 플래그 `packages_protected_packages`이 제거되었습니다.
- Conan 보호된 패키지가 GitLab 17.6에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/323975)되었으며, 기능 플래그 `packages_protected_packages_conan` [포함](../../../administration/feature_flags/_index.md)됩니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../../../policy/development_stages_support.md)입니다.
- Maven 보호된 패키지가 GitLab 17.9에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/323969)되었으며, 기능 플래그 `packages_protected_packages_maven` [포함](../../../administration/feature_flags/_index.md)됩니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../../../policy/development_stages_support.md)입니다.
- GitLab 17.10에서 `packages_protected_packages_delete`라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/516215)되었습니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../../../policy/development_stages_support.md)입니다.
- Maven 보호된 패키지가 GitLab 17.11에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/497082) 상태가 되었습니다. 기능 플래그 `packages_protected_packages_maven`이 제거되었습니다.
- Conan 보호된 패키지가 GitLab 17.11에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/497811) 상태가 되었습니다. 기능 플래그 `packages_protected_packages_conan`이 제거되었습니다.
- NuGet 보호된 패키지가 GitLab 18.0에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/323972)되었으며, 기능 플래그 `packages_protected_packages_nuget` [포함](../../../administration/feature_flags/_index.md)됩니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../../../policy/development_stages_support.md)입니다.
- 보호된 Helm 차트가 GitLab 18.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/323973)되었으며, 기능 플래그 `packages_protected_packages_helm` [포함](../../../administration/feature_flags/_index.md)됩니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../../../policy/development_stages_support.md)입니다.
- 일반 보호된 패키지가 GitLab 18.1에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/323973)되었으며, 기능 플래그 `packages_protected_packages_generic` [포함](../../../administration/feature_flags/_index.md)됩니다. 기본적으로 비활성화되었습니다. 이 기능은 [실험](../../../policy/development_stages_support.md)입니다.
- 일반 보호된 패키지가 GitLab 18.2에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/537971) 상태가 되었습니다. 기능 플래그 `packages_protected_packages_generic`이 제거되었습니다.
- NuGet 보호된 패키지가 GitLab 18.2에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/524145) 상태가 되었습니다. 기능 플래그 `packages_protected_packages_nuget`이 제거되었습니다.
- Helm 보호된 패키지가 GitLab 18.3에서 [일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/538375) 상태가 되었습니다. 기능 플래그 `packages_protected_packages_helm`이 제거되었습니다.

{{< /history >}}

기본적으로 Developer, Maintainer 또는 Owner 역할을 가진 모든 사용자는 패키지를 생성, 편집 및 삭제할 수 있습니다. 패키지 보호 규칙을 추가하여 패키지를 변경할 수 있는 사용자를 제한합니다.

GitLab은 npm, PyPI, Maven 및 Conan 패키지에 대한 패키지 보호를 지원하지만 [에픽 5574](https://gitlab.com/groups/gitlab-org/-/epics/5574)는 추가 기능 및 패키지 형식을 추가할 것을 제안합니다.

패키지가 보호되면 기본 동작은 패키지에 다음 제한 사항을 적용합니다:

| 작업                                 | 최소 역할 또는 토큰                                                                     |
|:---------------------------------------|:----------------------------------------------------------------------------------|
| 패키지 보호                      | Maintainer 또는 Owner 역할입니다.                                                     |
| 새 패키지 푸시                     | [**푸시를 위한 최소 액세스 수준**](#protect-a-package)에 설정된 역할 이상이 필요합니다. |
| 배포 토큰으로 새 패키지 푸시 | 유효한 배포 토큰이면 되며, 푸시된 패키지가 보호 규칙과 일치하지 않는 경우에만 가능합니다. 보호된 패키지는 배포 토큰으로 푸시할 수 없습니다. |
| 패키지 삭제                       | [**삭제를 위한 최소 액세스 수준**](#protect-a-package)에 설정된 역할 이상이 필요합니다. |

## 패키지 보호 {#protect-a-package}

사전 요구 사항:

- Maintainer 또는 Owner 역할이 있어야 합니다.

패키지를 보호하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **패키지 레지스트리**를 확장합니다.
1. **보호된 패키지** 아래에서 **보호 규칙 추가**를 선택합니다.
1. 필드를 완성합니다:
   - **이름 패턴**은 보호하려는 패키지 이름 패턴입니다. 패턴에는 와일드카드(`*`)가 포함될 수 있습니다.
   - **패키지 유형**은 보호할 패키지의 유형입니다.
   - **푸시를 위한 최소 액세스 수준**은 이름 패턴과 일치하는 패키지를 푸시하는 데 필요한 최소 역할입니다.
   - **삭제를 위한 최소 액세스 수준**은 이름 패턴과 일치하는 패키지를 삭제하는 데 필요한 최소 역할입니다.
1. **보호**를 선택합니다.

패키지 보호 규칙이 생성되고 설정에 표시됩니다.

### 여러 패키지 보호 {#protecting-multiple-packages}

와일드카드를 사용하여 동일한 패키지 보호 규칙으로 여러 패키지를 보호할 수 있습니다. 예를 들어, CI/CD 파이프라인 중에 빌드된 모든 임시 패키지를 보호할 수 있습니다.

다음 표에는 여러 패키지와 일치하는 패키지 보호 규칙의 예제가 포함되어 있습니다:

| 와일드카드가 있는 패키지 이름 패턴 | 일치하는 패키지                                                           |
|------------------------------------|-----------------------------------------------------------------------------|
| `@group/package-*`                 | `@group/package-prod`, `@group/package-prod-sha123456789`                   |
| `@group/*package`                  | `@group/package`, `@group/prod-package`, `@group/prod-sha123456789-package` |
| `@group/*package*`                 | `@group/package`, `@group/prod-sha123456789-package-v1`                     |

동일한 패키지에 여러 보호 규칙을 적용할 수 있습니다. 최소 하나의 보호 규칙이 패키지에 적용되면 패키지는 보호됩니다.

## 패키지 보호 규칙 삭제 및 패키지 보호 해제 {#delete-a-package-protection-rule-and-unprotect-a-package}

사전 요구 사항:

- Maintainer 또는 Owner 역할이 있어야 합니다.

패키지 보호를 해제하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **패키지 레지스트리**를 확장합니다.
1. **보호된 패키지** 아래에서 삭제하려는 보호 규칙 옆에 **삭제** ({{< icon name="remove" >}})를 선택합니다.
1. 확인 대화 상자에서 **삭제**를 선택합니다.

패키지 보호 규칙이 삭제되고 설정에 나타나지 않습니다.
