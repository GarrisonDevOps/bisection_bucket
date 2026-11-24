---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: Git 브랜치를 사용하여 새 기능을 개발합니다. 중요한 브랜치에 브랜치 보호를 추가하여 신뢰할 수 있는 사용자만 병합할 수 있도록 합니다.
title: 기본 브랜치
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

새 [프로젝트](../../_index.md)를 만들 때 GitLab은 리포지토리에서 기본 브랜치를 만듭니다. 기본 브랜치는 다른 브랜치와 공유하지 않는 특수 구성 옵션이 있습니다:

- 삭제할 수 없습니다.
- [강제 푸시로부터 초기에 보호됩니다](protected.md).
- 머지 리퀘스트가 [이슈 닫기 패턴](../../issues/managing_issues.md#closing-issues-automatically)을 사용하여 이슈를 닫으면 작업이 이 브랜치에 병합됩니다.

새 [프로젝트의](../../_index.md) 기본 브랜치 이름은 GitLab 관리자가 인스턴스 또는 그룹에 대해 변경한 구성에 따라 달라집니다. GitLab은 먼저 특정 사용자 정의를 확인한 다음 더 광범위한 수준에서 확인하며, 사용자 정의가 설정되지 않은 경우에만 GitLab 기본값을 사용합니다:

1. [프로젝트별](#change-the-default-branch-name-for-a-project) 사용자 정의 기본 브랜치 이름.
1. 프로젝트의 직접 하위 그룹에 지정된 [사용자 정의 그룹 기본 브랜치 이름](#change-the-default-branch-name-for-new-projects-in-a-group).
1. 프로젝트의 최상위 그룹에 지정된 사용자 정의 그룹 기본 브랜치 이름.
1. [인스턴스](#change-the-default-branch-name-for-new-projects-in-an-instance)에 대해 설정된 사용자 정의 기본 브랜치 이름.
1. 사용자 정의 기본 브랜치 이름이 어떤 수준에서도 설정되지 않으면 GitLab은 `main`로 기본 설정됩니다.

GitLab UI에서 어떤 수준에서든 기본값을 변경할 수 있습니다. GitLab은 또한 리포지토리 복사본을 업데이트하기 위해 필요한 [Git 명령](#update-the-default-branch-name-in-your-repository)을 제공합니다.

## 프로젝트의 기본 브랜치 이름 변경 {#change-the-default-branch-name-for-a-project}

사전 요구 사항:

- 당신은 프로젝트에 대한 Maintainer 또는 Owner 역할을 가집니다.

개별 [프로젝트](../../_index.md)의 기본 브랜치를 업데이트하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **브랜치 기본값**을 확장합니다. **기본 브랜치**에서 새 기본 브랜치를 선택합니다.
1. 선택 사항. 머지 리퀘스트가 [닫기 패턴을 사용](../../issues/managing_issues.md#closing-issues-automatically)할 때 이슈를 닫으려면 **기본 브랜치에서 참조된 이슈 자동 닫기** 확인란을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

[프로젝트 API](../../../../api/projects.md)의 `default_branch` 속성을 사용할 수도 있습니다. API로 프로젝트를 만들고 `initialize_with_readme`를 `true`로 설정할 때 `default_branch` 매개 변수를 다음 중 하나로 지정할 수 있습니다:

- 브랜치 이름. 예를 들어, `main`입니다.
- 완전히 정규화된 참조. 예를 들어, `refs/heads/main`입니다.

완전히 정규화된 참조를 제공하면 API는 `refs/heads/` 접두사를 제거합니다.

## 인스턴스의 새 프로젝트에 대한 기본 브랜치 이름 변경 {#change-the-default-branch-name-for-new-projects-in-an-instance}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Self-Managed의 [관리자](../../../permissions.md)는 해당 인스턴스에서 호스팅되는 프로젝트의 초기 브랜치를 사용자 정의할 수 있습니다. 개별 그룹 및 하위 그룹은 프로젝트의 인스턴스 기본값을 재정의할 수 있습니다.

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **기본 브랜치**를 확장합니다.
1. **초기 기본 브랜치 이름**에서 새 기본 브랜치를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

설정을 변경한 후 이 인스턴스에서 만든 프로젝트는 그룹 또는 하위 그룹 구성이 재정의하지 않는 한 사용자 정의 브랜치 이름을 사용합니다.

## 그룹의 새 프로젝트에 대한 기본 브랜치 이름 변경 {#change-the-default-branch-name-for-new-projects-in-a-group}

사전 요구 사항:

- 그룹 및 하위 그룹에 대해 소유자 역할이 있어야 합니다.

그룹의 새 프로젝트에 대한 기본 브랜치 이름을 변경하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **기본 브랜치**를 확장합니다.
1. **초기 기본 브랜치 이름**에서 새 기본 브랜치를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

설정을 변경한 후 이 그룹에서 만든 프로젝트는 하위 그룹 구성이 재정의하지 않는 한 사용자 정의 브랜치 이름을 사용합니다.

## 초기 기본 브랜치 보호 {#protect-initial-default-branches}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab 관리자 및 그룹 소유자는 [브랜치 보호](protected.md)를 정의하여 인스턴스 또는 개별 그룹의 모든 리포지토리의 기본 브랜치에 다음 옵션 중 하나로 적용할 수 있습니다:

- **완전히 보호됨** \- 기본값입니다. 개발자는 새 커밋을 푸시할 수 없지만 유지보수자는 푸시할 수 있습니다. 아무도 강제 푸시를 할 수 없습니다.
- **초기 푸시 후 완전히 보호됨** \- 개발자는 리포지토리에 초기 커밋을 푸시할 수 있지만 그 이후에는 푸시할 수 없습니다. 유지보수자는 항상 푸시할 수 있습니다. 아무도 강제 푸시를 할 수 없습니다.
- **push로부터 보호됨** \- 개발자는 새 커밋을 푸시할 수 없지만 브랜치에 대한 머지 리퀘스트를 수락할 수 있습니다. 유지보수자는 브랜치에 푸시할 수 있습니다.
- **부분적으로 보호됨** \- 개발자 및 유지보수자 모두 새 커밋을 푸시할 수 있지만 강제 푸시는 할 수 없습니다.
- **보호되지 않음** \- 개발자 및 유지보수자 모두 새 커밋을 푸시하고 강제 푸시할 수 있습니다.

> [!warning]
> **완전히 보호됨**을 선택하지 않으면 악의적인 개발자가 민감한 데이터를 도용하려고 시도할 수 있습니다. 예를 들어 악의적인 `.gitlab-ci.yml` 파일을 보호된 브랜치에 커밋하고 나중에 파이프라인이 해당 브랜치에 대해 실행되면 그룹 CI/CD 변수가 유출될 수 있습니다.

### 인스턴스의 모든 프로젝트 {#for-all-projects-in-an-instance}

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

이 설정은 각 리포지토리의 기본 브랜치에만 적용됩니다. 다른 브랜치를 보호하려면 다음 중 하나를 수행해야 합니다:

- [리포지토리의 브랜치 보호](protected.md)를 구성합니다.
- [그룹의 브랜치 보호](../../../group/manage.md#change-the-default-branch-protection-of-a-group)를 구성합니다.

GitLab Self-Managed 인스턴스의 관리자는 해당 인스턴스에서 호스팅되는 프로젝트의 초기 기본 브랜치 보호를 사용자 정의할 수 있습니다. 개별 그룹 및 하위 그룹은 프로젝트의 인스턴스 기본 설정을 재정의할 수 있습니다.

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **기본 브랜치**를 확장합니다.
1. [**초기 기본 브랜치 보호**](#protect-initial-default-branches)를 선택합니다.
1. 그룹 소유자가 인스턴스의 기본 브랜치 보호를 재정의할 수 있도록 하려면 [**그룹당 기본 브랜치 보호를 관리하도록 소유자 허용**](#prevent-overrides-of-default-branch-protection)을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

#### 기본 브랜치 보호의 재정의 방지 {#prevent-overrides-of-default-branch-protection}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹 소유자는 전체 인스턴스에 대해 설정된 기본 브랜치에 대한 보호를 그룹 기준으로 재정의할 수 있습니다. [GitLab Premium 또는 Ultimate](https://about.gitlab.com/pricing/)에서 GitLab 관리자는 그룹 소유자에 대한 이 권한을 비활성화하여 인스턴스에 대해 설정된 보호 규칙을 적용할 수 있습니다:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **기본 브랜치** 섹션을 확장합니다.
1. **그룹당 기본 브랜치 보호를 관리하도록 소유자 허용** 확인란을 선택 해제합니다.
1. **변경 사항 저장**을 선택합니다.

> [!note]
> GitLab 관리자는 여전히 그룹의 기본 브랜치 보호를 업데이트할 수 있습니다.

### 그룹의 모든 프로젝트 {#for-all-projects-in-a-group}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹 소유자는 전체 인스턴스에 대해 설정된 기본 브랜치에 대한 보호를 그룹 기준으로 재정의할 수 있습니다. [GitLab Premium 또는 Ultimate](https://about.gitlab.com/pricing/)에서 GitLab 관리자는 [초기 기본 브랜치의 보호를 적용](#prevent-overrides-of-default-branch-protection)할 수 있으며, 이는 그룹 소유자의 설정을 잠급니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **기본 브랜치**를 확장합니다.
1. [**초기 기본 브랜치 보호**](#protect-initial-default-branches)를 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## 리포지토리에서 기본 브랜치 이름 업데이트 {#update-the-default-branch-name-in-your-repository}

> [!warning]
> 기본 브랜치의 이름을 변경하면 테스트, CI/CD 구성, 서비스, 도우미 유틸리티 및 리포지토리에서 사용하는 모든 통합이 중단될 수 있습니다. 이 브랜치 이름을 변경하기 전에 프로젝트 소유자 및 유지보수자에게 문의하세요. 이 변경의 범위가 관련 코드 및 스크립트에서 이전 브랜치 이름에 대한 참조를 포함한다는 것을 이해하는지 확인하세요.

기존 리포지토리의 기본 브랜치 이름을 변경할 때 새 브랜치를 만들지 마세요. 기본 브랜치의 이름을 변경하여 히스토리를 유지합니다. 이 예제는 Git 리포지토리의 (`example`) 기본 브랜치를 이름을 바꿉니다:

1. 로컬 명령줄에서 `example` 리포지토리로 이동하고 기본 브랜치에 있는지 확인합니다:

   ```plaintext
   cd example
   git checkout master
   ```

1. 기존 기본 브랜치를 새 이름(`main`)으로 이름을 바꿉니다. 인수 `-m`는 모든 커밋 히스토리를 새 브랜치로 이전합니다:

   ```plaintext
   git branch -m master main
   ```

1. 새로 만든 `main` 브랜치를 업스트림으로 푸시하고 로컬 브랜치를 같은 이름의 원격 브랜치를 추적하도록 설정합니다:

   ```plaintext
   git push -u origin main
   ```

1. 이전 기본 브랜치를 제거하려는 경우 `HEAD`를 새 기본 브랜치인 `main`를 가리키도록 업데이트합니다:

   ```plaintext
   git symbolic-ref refs/remotes/origin/HEAD refs/remotes/origin/main
   ```

1. 최소한 유지보수자 역할로 GitLab에 로그인하고 [이 프로젝트의 기본 브랜치 변경](#change-the-default-branch-name-for-a-project) 지침을 따릅니다. `main`을 새 기본 브랜치로 선택합니다.
1. 새 `main` 브랜치를 [보호된 브랜치 문서](protected.md)에 설명된 대로 보호합니다.
1. 선택 사항. 이전 기본 브랜치를 삭제하려는 경우:
   1. 아무것도 가리키지 않는지 확인합니다.
   1. 원격 브랜치를 삭제합니다:

      ```plaintext
      git push origin --delete master
      ```

      새 기본 브랜치가 예상대로 작동하는지 확인한 후 나중에 브랜치를 삭제할 수 있습니다.

1. 프로젝트 기여자들에게 이 변경을 알리세요. 왜냐하면 그들도 몇 가지 단계를 거쳐야 하기 때문입니다:

   - 기여자는 새 기본 브랜치를 리포지토리의 로컬 복사본으로 가져와야 합니다.
   - 이전 기본 브랜치를 대상으로 하는 미결 머지 리퀘스트가 있는 기여자는 머지 리퀘스트를 수동으로 `main`을 사용하도록 다시 지정해야 합니다.
1. 리포지토리에서 코드의 이전 브랜치 이름에 대한 모든 참조를 업데이트합니다.
1. 도우미 유틸리티 및 통합과 같이 리포지토리 외부에 있는 관련 코드 및 스크립트의 이전 브랜치 이름에 대한 참조를 업데이트합니다.

## 기본 브랜치 이름 변경 리다이렉트 {#default-branch-rename-redirect}

프로젝트의 특정 파일 또는 디렉토리에 대한 URL은 프로젝트의 기본 브랜치 이름을 포함하며 설명서 또는 브라우저 책갈피에서 자주 찾을 수 있습니다. [리포지토리에서 기본 브랜치 이름을 업데이트](#update-the-default-branch-name-in-your-repository)할 때 이러한 URL은 변경되며 업데이트해야 합니다.

전환 기간을 완화하기 위해 프로젝트의 기본 브랜치가 변경될 때마다 GitLab은 이전 기본 브랜치의 이름을 기록합니다. 해당 브랜치가 삭제되면 파일 또는 디렉토리를 보려는 시도는 "not found" 페이지를 표시하는 대신 현재 기본 브랜치로 리다이렉트됩니다.

## 관련 항목 {#related-topics}

- [wiki의 기본 브랜치 구성](../../wiki/_index.md)
- [기본 브랜치 이름 변경에 대한 논의](https://lore.kernel.org/git/pull.656.v4.git.1593009996.gitgitgadget@gmail.com/)는 Git 메일링 리스트에서
- [2021년 3월 블로그 게시물: 새로운 Git 기본 브랜치 이름](https://about.gitlab.com/blog/new-git-default-branch-name/)

## 문제 해결 {#troubleshooting}

### 기본 브랜치를 변경할 수 없음: 현재 브랜치로 재설정 {#unable-to-change-default-branch-resets-to-current-branch}

이 문제를 [이슈 20474](https://gitlab.com/gitlab-org/gitlab/-/issues/20474)에서 추적 중입니다. 이 문제는 `HEAD` 이름의 브랜치가 리포지토리에 있을 때 자주 발생합니다. 문제를 해결하려면:

1. 로컬 리포지토리에서 새 임시 브랜치를 만들고 푸시합니다:

   ```shell
   git checkout -b tmp_default && git push -u origin tmp_default
   ```

1. GitLab에서 [기본 브랜치 변경](#change-the-default-branch-name-for-a-project)을 진행하여 해당 임시 브랜치로 이동합니다.
1. 로컬 리포지토리에서 `HEAD` 브랜치를 삭제합니다:

   ```shell
   git push -d origin HEAD
   ```

1. GitLab에서 [기본 브랜치를 변경](#change-the-default-branch-name-for-a-project)하여 사용하려는 브랜치로 이동합니다.

### 기본 브랜치에 대한 GraphQL 쿼리 {#query-graphql-for-default-branches}

[GraphQL 쿼리](../../../../api/graphql/_index.md)를 사용하여 그룹의 모든 프로젝트에 대한 기본 브랜치를 검색할 수 있습니다.

단일 페이지의 결과에서 모든 프로젝트를 반환하려면 `GROUPNAME`을 그룹의 전체 경로로 바꾸세요. GitLab은 첫 페이지의 결과를 반환합니다. `hasNextPage`가 `true`이면 `after: null`의 `null`을 `endCursor`의 값으로 바꾸어 다음 페이지를 요청할 수 있습니다:

```graphql
{
 group(fullPath: "GROUPNAME") {
   projects(after: null) {
     pageInfo {
       hasNextPage
       endCursor
     }
     nodes {
       name
       repository {
         rootRef
       }
     }
   }
 }
}
```

### 새 하위 그룹은 더 높은 수준의 하위 그룹에서 기본 브랜치 이름을 상속하지 않음 {#new-subgroups-do-not-inherit-default-branch-name-from-a-higher-level-subgroup}

다른 하위 그룹을 포함하는 하위 그룹에서 기본 브랜치를 구성할 때 이는 프로젝트를 포함하고 기본 브랜치가 상속되지 않습니다.

이 문제를 [이슈 327208](https://gitlab.com/gitlab-org/gitlab/-/issues/327208)에서 추적 중입니다.
