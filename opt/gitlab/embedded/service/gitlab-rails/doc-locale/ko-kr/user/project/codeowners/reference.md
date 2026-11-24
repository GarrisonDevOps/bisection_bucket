---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "파일 경로 패턴, 소유자, 주석, 섹션 및 규칙 평가 방법에 대해 알아봅니다."
title: 파일의 구문
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

`CODEOWNERS` 파일은 소유권 규칙을 정의하는 구문을 사용합니다. 파일의 각 줄은 규칙을 나타내며, 파일 경로 패턴과 하나 이상의 소유자를 지정합니다. 주요 요소는 다음과 같습니다:

- 파일 경로: 특정 파일, 디렉터리 또는 와일드카드입니다.
- 코드 소유자: 사용자, 그룹 또는 역할에 대한 언급을 사용합니다.
- 주석: `#`로 시작하는 줄은 무시됩니다. 인라인 주석은 지원되지 않습니다. 주석에 나열된 모든 코드 소유자가 파싱됩니다.
- 섹션: `[Section name]`을 사용하여 정의된 선택적 규칙 그룹입니다.

> [!note]
> 섹션에서 항목이 중복되면 [마지막 항목이 사용됩니다](advanced.md#define-code-owners-for-specific-files-or-directories). 파일에서 나중에 정의된 규칙이 이전 규칙보다 우선합니다.

몇 가지 예는 다음과 같습니다:

```plaintext
# Specify a default Code Owner for all files with a wildcard:
* @default-owner

# Specify multiple Code Owners to a specific file:
README.md @doc-team @tech-lead

# Specify a Code Owner to all files with a specific extension:
*.rb @ruby-owner

# Specify Code Owners with usernames or email addresses:
LICENSE @legal janedoe@gitlab.com

# Use group names to match groups and nested groups:
README @group @group/with-nested/subgroup

# Specify a Code Owner to a directory and all its contents:
/docs/ @all-docs
/docs/* @root-docs
/docs/**/*.md @markdown-docs  # Match specific file types in any subdirectory
/db/**/index.md @index-docs   # Match a specific file name in any subdirectory

# Use a section to group related rules:
[Documentation]
ee/docs    @docs
docs       @docs

# Assign a role as a Code Owner:
/config/ @@maintainer
```

## 섹션 {#sections}

`CODEOWNERS` 파일에서 섹션은 별도로 분석되고 항상 적용되는 명명된 영역입니다. 섹션을 정의할 때까지 GitLab은 전체 `CODEOWNERS` 파일을 단일 섹션으로 취급합니다. 더 많은 섹션을 추가하면 GitLab이 파일을 평가하는 방식이 변경됩니다:

- GitLab은 첫 번째 섹션 헤더 전에 정의된 규칙을 포함하여 [섹션이 없는 항목](advanced.md#regular-entries-and-sections)을 다른 명명되지 않은 섹션인 것처럼 취급합니다.
- 각 섹션은 자신의 규칙을 별도로 적용합니다.
- 파일 경로가 섹션의 여러 항목과 일치하면 해당 섹션의 마지막 일치 항목만 사용됩니다.
- 파일 경로가 여러 섹션의 항목과 일치하면 각 섹션의 마지막 일치 항목이 사용됩니다.

예를 들어 `CODEOWNERS` 파일에서 `README` 파일의 코드 소유자를 정의하는 섹션이 있으면:

```plaintext
* @admin

[README Owners]
README.md @user1 @user2
internal/README.md @user4

[README other owners]
README.md @user3
```

- 루트 디렉터리의 `README.md`에 대한 코드 소유자는:
  - 명명되지 않은 섹션의 `@admin`입니다.
  - `@user1` 및 `@user2` - `[README Owners]`에서.
  - `@user3` - `[README other owners]`에서.
- `internal/README.md`의 코드 소유자는:
  - 명명되지 않은 섹션의 `@admin`입니다.
  - `@user4` - `[README Owners]`에서. 이 섹션의 `README.md` 및 `internal/README.md` 항목이 파일과 일치하지만, 섹션의 마지막 일치 항목만 사용됩니다.
  - `@user3` - `[README other owners]`에서.

`CODEOWNERS` 파일에 섹션을 추가하려면 섹션 이름을 대괄호로 입력한 다음 파일 또는 디렉터리, 사용자, 그룹 또는 하위 그룹을 입력하세요:

```plaintext
[README Owners]
README.md @user1 @user2
internal/README.md @user2
```

머지 리퀘스트 위젯의 각 코드 소유자는 레이블 아래에 나열됩니다. 다음 이미지는 `Default`, `Frontend` 및 `Technical Writing` 섹션을 보여줍니다:

![섹션별로 그룹화된 코드 소유자를 표시하는 머지 리퀘스트 위젯입니다.](img/sectional_code_owners_v17_4.png)

더 많은 섹션 구성 옵션은 다음을 참조하세요:

- [기본 코드 소유자 및 선택적 섹션](advanced.md#default-code-owners-and-optional-sections)
- [일반 항목 및 섹션](advanced.md#regular-entries-and-sections)
- [이름이 중복된 섹션](advanced.md#sections-with-duplicate-names)

### 섹션 제목 및 이름 {#section-headings-and-names}

섹션 제목에는 이름이 있어야 합니다. 섹션 이름은 대소문자를 구분하지 않으며, [이름이 중복된 섹션](advanced.md#sections-with-duplicate-names)은 병합됩니다. 보호된 브랜치의 경우 다음을 수행할 수 있습니다:

- 승인 필요(기본값).
- 선택 사항(`^`이 접두사로 지정됨).
- 특정 승인 수가 필요합니다. 자세한 내용은 [그룹 상속 및 적격성](advanced.md#group-inheritance-and-eligibility) 및 [선택 사항으로 표시된 승인](troubleshooting.md#approvals-shown-as-optional)을 참조하세요.
- 기본 소유자 포함

예:

```plaintext
# Required section
[Section name]

# Optional section
^[Section name]

# Section requiring 5 approvals
[Section name][5]

# Section with @username as default owner
[Section name] @username

# Section with @group and @subgroup as default owners and requiring 2 approvals
[Section name][2] @group @subgroup
```

### 섹션의 기본 코드 소유자 설정 {#set-default-code-owner-for-a-section}

섹션 내의 여러 파일 경로가 동일한 소유권을 공유하는 경우 섹션의 기본 코드 소유자를 정의합니다. 해당 섹션의 모든 경로는 이 기본값을 상속하며, 특정 줄에서 섹션 기본값을 재정의하지 않는 한 그렇습니다.

기본 소유자는 파일 경로에 대해 특정 소유자가 지정되지 않은 경우에 적용됩니다. 파일 경로 옆에 정의된 특정 소유자는 기본 소유자를 재정의합니다.

예를 들어:

```plaintext
[Documentation] @docs-team
docs/
README.md

[Database] @database-team @agarcia
model/db/
config/db/database-setup.md @docs-team
```

이 예에서:

- `@docs-team`은 `Documentation` 섹션의 모든 항목을 소유합니다.
- `@database-team` 및 `@agarcia`은 `Database` 섹션의 모든 항목을 소유하며, `config/db/database-setup.md`을 제외하고, 이는 `@docs-team`에 할당되도록 재정의됩니다.

이는 [일반 항목 및 섹션을 함께 사용할](advanced.md#regular-entries-and-sections) 때의 동작과 비교하세요. 이 경우 섹션의 항목은 섹션이 없는 항목을 재정의하지 않습니다.

### 선택적 섹션 {#optional-sections}

코드 소유자 파일에서 선택적 섹션을 지정할 수 있습니다. 선택적 섹션을 사용하면 코드베이스의 다양한 부분에 대해 책임자를 지정할 수 있지만 승인을 요구하지 않습니다. 이 방식은 자주 업데이트되지만 엄격한 검토가 필요하지 않은 프로젝트 부분에 대해 더 완화된 정책을 제공합니다.

전체 섹션을 선택 사항으로 취급하려면 섹션 이름 앞에 캐럿 `^` 문자를 붙입니다.

이 예에서 `[Go]` 섹션은 선택 사항입니다:

```plaintext
[Documentation]
*.md @root

[Ruby]
*.rb @root

^[Go]
*.go @root
```

선택적 코드 소유자 섹션이 머지 리퀘스트의 설명 아래에 표시됩니다:

![선택적 코드 소유자 섹션을 표시하는 머지 리퀘스트 위젯입니다.](img/optional_code_owners_sections_v17_4.png)

섹션이 파일에서 중복되고 하나는 선택 사항으로 표시되고 다른 하나는 그렇지 않으면 섹션이 필요합니다.

`CODEOWNERS` 파일의 선택적 섹션은 머지 리퀘스트를 사용하여 변경 사항을 제출할 때만 선택 사항으로 취급됩니다. 보호된 브랜치에 직접 변경 사항을 제출하면, 섹션이 선택 사항으로 표시되어 있더라도 코드 소유자의 승인이 여전히 필요합니다.

## 적격 코드 소유자 {#eligible-code-owners}

적격성 규칙은 유효한 코드 소유자가 될 수 있는 사람을 결정합니다. `CODEOWNERS` 파일의 참조 방법(사용자명, 그룹 또는 역할)에 따라 특정 규칙이 적용됩니다.

### 사용자 적격성 {#user-eligibility}

코드 소유자로 적격이 되려면 사용자명으로 참조되는 사용자(`@username`)는 프로젝트에 대해 승인을 받아야 합니다. 다음 규칙이 적용됩니다:

- 프로젝트 및 그룹 가시성 설정은 적격성에 영향을 주지 않습니다.
- [그룹에서 차단된](../../group/moderate_users.md) 사용자는 코드 소유자가 될 수 없습니다.
- 적격인 사용자는 다음과 같습니다:
  - Developer, Maintainer 또는 Owner 역할을 가진 프로젝트에 대한 직접 멤버십.
  - 프로젝트 그룹의 멤버십(직접 또는 상속).
  - 프로젝트 그룹의 상위 항목 중 하나에 멤버십.
  - 프로젝트에 초대된 그룹의 직접 또는 상속된 멤버십.
  - 프로젝트 그룹에 초대된 그룹의 직접 멤버십(상속되지 않음).
  - 프로젝트 그룹의 상위 항목에 초대된 그룹의 직접 멤버십(상속되지 않음).

### 그룹 적격성 {#group-eligibility}

그룹 이름(`@group_name`) 또는 중첩된 그룹 이름(`@nested/group/names`)으로 그룹을 참조할 때 다음 규칙이 적용됩니다:

- 그룹 가시성 설정은 적격성에 영향을 주지 않습니다.
- 참조된 그룹의 직접 멤버만 적격입니다. 상속된 멤버는 포함되지 않습니다.
- 적격인 그룹은 다음과 같습니다:
  - 프로젝트의 그룹.
  - 프로젝트 그룹의 상위 항목.
  - Developer, Maintainer 또는 Owner 역할을 가진 프로젝트에 직접 초대된 그룹.
  - 프로젝트 그룹 또는 해당 상위 항목과 공유되는 그룹. 공유 그룹은 상위 그룹에서 Developer, Maintainer 또는 Owner 역할을 가져야 합니다. 자세한 내용은 [상위 그룹과 공유되는 그룹](advanced.md#groups-shared-with-parent-groups)을 참조하세요.

### 역할 적격성 {#role-eligibility}

역할을 참조할 때(`@@role`) 다음 규칙이 적용됩니다:

- Developer, Maintainer 및 Owner 역할만 코드 소유자로 사용할 수 있습니다.
- 지정된 역할을 가진 직접 프로젝트 멤버만 적격입니다.
- 역할은 더 높은 역할을 포함하지 않습니다. 예를 들어 `@@developer`을 지정하면 Maintainer 또는 Owner 역할을 가진 사용자는 포함되지 않습니다.

복잡한 그룹 상속 및 적격성에 대한 자세한 내용은 [그룹 상속 및 적격성](advanced.md#group-inheritance-and-eligibility)을 참조하세요.

## 역할을 코드 소유자로 추가 {#add-a-role-as-a-code-owner}

{{< history >}}

- [GitLab 17.7에 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/282438) [기능 플래그](../../../administration/feature_flags/_index.md) `codeowner_role_approvers` 포함.
- [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/497504) GitLab 17.8에서.
- [GitLab 17.9에서 일반 공개](https://gitlab.com/gitlab-org/gitlab/-/issues/512623) 기능 플래그 `codeowner_role_approvers` 제거됨.

{{< /history >}}

직접 프로젝트 멤버를 코드 소유자로 역할을 추가하거나 설정할 수 있습니다:

- `@@` 접두사를 사용하여 역할을 설정합니다.
- Developer, Maintainer 및 Owner 역할만 사용할 수 있습니다.
- 역할은 더 높은 역할을 포함하지 않습니다. 예를 들어 `@@developer`을 지정하면 Maintainer 또는 Owner 역할을 가진 사용자는 포함되지 않습니다.
- 지정된 역할을 가진 직접 프로젝트 멤버만 적격 코드 소유자입니다.
- 복수 역할을 지정할 수 있습니다. 예를 들어 `@@developers`이 허용됩니다.

다음 예는 Developer 또는 Maintainer 역할을 가진 모든 직접 프로젝트 멤버를 `file.md`의 코드 소유자로 설정합니다:

1. `CODEOWNERS` 파일을 엽니다.
1. 다음 패턴을 사용하여 줄을 추가합니다:

   ```plaintext
   file.md @@developer @@maintainer
   ```

1. 파일을 저장합니다.
1. 변경 사항을 커밋하고 병합합니다.

## 그룹을 코드 소유자로 추가 {#add-a-group-as-a-code-owner}

그룹 또는 하위 그룹의 직접 멤버를 코드 소유자로 설정할 수 있습니다. 그룹 멤버십에 대한 자세한 내용은 [멤버십 유형](../members/_index.md#membership-types)을 참조하세요.

사전 요구 사항:

- 그룹은 [프로젝트에 초대되어야](../members/sharing_projects_groups.md#invite-a-group-to-a-project) 합니다.

그룹 또는 하위 그룹의 직접 멤버를 코드 소유자로 설정하려면:

1. `CODEOWNERS` 파일을 엽니다.
1. 다음 패턴 중 하나를 따르는 텍스트를 입력합니다:

   ```plaintext
   # All direct group members as Code Owners for a file
   file.md @group-x

   # All direct subgroup members as Code Owners for a file
   file.md @group-x/subgroup-y

   # All direct group and direct subgroup members as Code Owners for a file
   file.md @group-x @group-x/subgroup-y
   ```

1. 파일을 저장합니다.
1. 변경 사항을 커밋하고 병합합니다.

### 예제 구성 {#example-configuration}

```plaintext
[Maintainers]
* @gitlab-org/maintainers/group-name
```

이 예에서:

- `group-name` 그룹이 `[Maintainers]` 섹션 아래에 나열되어 있습니다.
- `group-name`에는 다음의 직접 멤버가 포함되어 있습니다:

  ![코드 소유자 상태에 적격인 사용자를 보여 주는 그룹 멤버 목록입니다.](img/direct_group_members_v17_9.png)

- 머지 리퀘스트 승인 위젯에서 동일한 직접 멤버는 `Maintainers`로 나열됩니다:

  ![유지관리자로 그룹 멤버를 나열하는 머지 리퀘스트 승인 위젯입니다.](img/merge_request_maintainers_v17_9.png)

> [!note]
> [전역 SAML 그룹 멤버십 잠금](../../group/saml_sso/group_sync.md#global-saml-group-memberships-lock)이 활성화되면 그룹 또는 하위 그룹을 코드 소유자로 설정할 수 없습니다. 자세한 내용은 [전역 SAML 그룹 멤버십 잠금과 호환되지 않음](troubleshooting.md#incompatibility-with-global-group-memberships-locks)을 참조하세요.

문제가 발생하면 [가능한 승인자로 표시되지 않은 사용자](troubleshooting.md#user-not-shown-as-possible-approver)를 참조하세요.

## 경로 일치 {#path-matching}

경로는 절대, 상대, 디렉터리, 와일드카드 또는 globstar일 수 있으며 리포지토리 루트와 비교하여 일치합니다.

### 절대 경로 {#absolute-paths}

`/`로 시작하는 경로는 리포지토리 루트에서 일치합니다:

```plaintext
# Matches only README.md in the root.
/README.md

# Matches only README.md inside the /docs directory.
/docs/README.md
```

### 상대 경로 {#relative-paths}

앞에 `/`가 없는 경로는 [globstar 경로](#globstar-paths)로 취급됩니다:

```plaintext
# Matches /README.md, /internal/README.md, /app/lib/README.md
README.md @username

# Matches /internal/README.md, /docs/internal/README.md, /docs/api/internal/README.md
internal/README.md
```

> [!note]
> globstar 경로를 사용할 때는 의도하지 않은 일치를 주의하세요. 예를 들어 앞에 `/`가 없는 `README.md`는 리포지토리의 모든 디렉터리 또는 하위 디렉터리의 모든 `README.md` 파일과 일치합니다.

### 디렉터리 경로 {#directory-paths}

경로 끝에 `/`을 붙여서 디렉터리 및 하위 디렉터리의 모든 파일과 일치시킵니다:

```plaintext
# Matches all files in /docs/ and its subdirectories
/docs/
```

### 와일드카드 경로 {#wildcard-paths}

`*`을 사용하여 여러 문자와 일치시킵니다:

```plaintext
# Any markdown files in the docs directory
/docs/*.md @username

# /docs/index file of any filetype
# For example: /docs/index.md, /docs/index.html, /docs/index.xml
/docs/index.* @username

# Any file in the docs directory with 'spec' in the name.
# For example: /docs/qa_specs.rb, /docs/spec_helpers.rb, /docs/runtime.spec
/docs/*spec* @username

# README.md files one level deep within the docs directory
# For example: /docs/api/README.md
/docs/*/README.md @username
```

### Globstar 경로 {#globstar-paths}

`**`을 사용하여 여러 디렉터리 수준의 파일 또는 패턴과 일치시킵니다:

```plaintext
# For example: /docs/index.md, /docs/api/index.md, and /docs/api/graphql/index.md.
/docs/**/index.md
```

디렉터리의 모든 파일과 일치시키려면 [디렉터리 경로](#directory-paths)를 후행 슬래시(`/`)와 함께 사용합니다.

### 제외 패턴 {#exclusion-patterns}

{{< history >}}

- GitLab 17.10에서 `codeowners_file_exclusions`라는 [기능 플래그](../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/180162)되었습니다.
- GitLab 17.10에서 [GitLab.com에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/issues/517075)되었습니다.
- GitLab 17.11에서 [일반 공급](https://gitlab.com/gitlab-org/gitlab/-/issues/517309)입니다. 기능 플래그 `codeowners_file_exclusions`이 제거되었습니다.

{{< /history >}}

파일 또는 경로 앞에 `!`을 붙여서 코드 소유자 승인이 필요하지 않도록 제외합니다. 제외 사항은 해당 섹션에 적용됩니다. 다음 예에서:

- `pom.xml` 제외 사항은 기본 섹션에 적용됩니다.
- `/config/**/*.rb` 제외 사항은 Ruby 섹션의 Ruby 파일에만 영향을 줍니다.

```plaintext
# All files require approval from @username
* @username

# Except pom.xml which needs no approval
!pom.xml

[Ruby]
# All ruby files require approval from @ruby-team
*.rb @ruby-team

# Except Ruby files in the config directory
!/config/**/*.rb
```

다음 지침은 제외 패턴이 어떻게 동작하는지 설명합니다:

- 제외 사항은 섹션에서 순서대로 평가됩니다. 예를 들어:

  ```plaintext
  * @default-owner
  !*.rb                      # Excludes all Ruby files.
  /special/*.rb @ruby-owner  # This won't take effect as *.rb is already excluded.
  ```

- 패턴이 제외되면 같은 섹션에서 다시 포함할 수 없습니다:

  ```plaintext
  [Ruby]
  *.rb @ruby-team           # All Ruby files need Ruby team approval.
  !/config/**/*.rb          # Ruby files in config don't need Ruby team approval.
  /config/routes.rb @ops    # This won't take effect as config Ruby files are excluded.
  ```

- 제외 패턴과 일치하는 파일은 해당 섹션에서 코드 소유자 승인이 필요하지 않습니다. 다른 소유자에 대해 다른 제외가 필요하면 여러 섹션을 사용하세요:

  ```plaintext
  [Ruby]
  *.rb @ruby-team
  !/config/**/*.rb        # Config Ruby files don't need Ruby team approval.

  [Config]
  /config/ @ops-team      # Config files still require ops-team approval.
  ```

- 자동으로 업데이트되는 파일의 제외를 사용하세요:

  ```plaintext
  * @default-owner

  # Files updated by automation don't need approval.
  !package-lock.json
  !yarn.lock
  !**/generated/          # Any files in generated directories.
  !.gitlab-ci.yml
  ```

## 항목 소유자 {#entry-owners}

항목에는 하나 이상의 소유자가 있어야 합니다. 이들은 그룹, 하위 그룹 및 사용자일 수 있습니다.

```plaintext
/path/to/entry.rb @group
/path/to/entry.rb @group/subgroup
/path/to/entry.rb @user
/path/to/entry.rb @group @group/subgroup @user
```

그룹을 코드 소유자로 추가하는 방법에 대한 자세한 내용은 [그룹을 코드 소유자로 추가](#add-a-group-as-a-code-owner)를 참조하세요.

## 관련 항목 {#related-topics}

- [코드 소유자](_index.md)
- [고급 `CODEOWNERS` 구성](advanced.md)
- [머지 리퀘스트 승인](../merge_requests/approvals/_index.md)
- [보호된 브랜치](../repository/branches/protected.md)
- [코드 소유자 문제 해결](troubleshooting.md)
