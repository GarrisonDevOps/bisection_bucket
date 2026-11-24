---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 푸시 규칙을 사용하여 리포지토리에서 허용하는 Git 커밋의 내용과 형식을 제어합니다. 커밋 메시지에 대한 표준을 설정하고 비밀번호나 자격 증명이 실수로 추가되는 것을 차단합니다.
title: 푸시 규칙
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

푸시 규칙은 사용자 친화적인 인터페이스에서 활성화할 수 있는 [`pre-receive` Git 후킹](https://git-scm.com/book/en/v2/Customizing-Git-Git-Hooks#:~:text=pre%2Dreceive,with%20the%20push.)입니다. 푸시 규칙을 사용하면 리포지토리에 푸시할 수 있는 내용과 없는 내용을 더 효과적으로 제어할 수 있습니다. GitLab은 [보호된 브랜치](branches/protected.md)를 제공하지만 더 구체적인 규칙이 필요할 수 있습니다. 예를 들어:

- 커밋의 내용을 평가합니다.
- 커밋 메시지가 예상 형식과 일치하는지 확인합니다.
- [브랜치 이름 규칙](branches/_index.md#name-your-branch)을 적용합니다.
- 파일의 세부 정보를 평가합니다.
- Git 태그 제거를 방지합니다.
- 서명된 커밋이 필요합니다.

GitLab은 푸시 규칙의 정규식에 [RE2 구문](https://github.com/google/re2/wiki/Syntax)을 사용합니다. [regex101 정규식 테스터](https://regex101.com/)에서 테스트할 수 있습니다. 각 정규식은 511자로 제한됩니다.

RE2는 `/pattern/flags` 형식을 지원하지 않습니다. 플래그를 설정하려면 표현식의 시작에 추가합니다. 예를 들어 대소문자를 구분하지 않는 패턴 일치를 위해 `(?i)pattern`를 사용합니다.

사용자 정의 푸시 규칙의 경우 [서버 후킹](../../../administration/server_hooks.md)을 사용합니다.

> [!note]
> 푸시 규칙은 포크 동기화 중에 무시됩니다. 업스트림 프로젝트에서 [포크를 업데이트](forking_workflow.md#update-your-fork)할 때 변경 사항은 포크의 푸시 규칙에 대한 유효성 검사 없이 직접 적용됩니다.

푸시 규칙은 상속된 설정이 아닌 템플릿으로 작동합니다:

- 전역 푸시 규칙은 새 프로젝트에 대한 템플릿 역할을 합니다. 전역 푸시 규칙을 만들면 해당 시점 이후에 만든 모든 프로젝트에 복사됩니다.
- 프로젝트 푸시 규칙은 독립적인 복사본입니다. 프로젝트가 생성된 후 전역 또는 그룹 규칙을 변경할 때 푸시 규칙이 자동으로 업데이트되지 않습니다.
- 프로젝트 푸시 규칙을 삭제하면 프로젝트에서 모든 푸시 규칙 제어가 제거됩니다. 프로젝트는 전역 또는 그룹 규칙을 사용하도록 되돌아가지 않습니다.

업데이트된 전역 푸시 규칙을 기존 프로젝트에 적용하려면 각 프로젝트에 대해 개별적으로 [전역 푸시 규칙을 재정의](#override-global-push-rules-per-project)해야 합니다.

> [!note]
> 프로젝트에서 푸시 규칙을 삭제하면 프로젝트에 푸시 규칙이 전혀 없습니다. 프로젝트는 그룹 또는 인스턴스에서 규칙을 자동으로 상속하지 않습니다. 푸시 규칙을 복원하려면 프로젝트에 대해 다시 구성해야 합니다.

## 전역 푸시 규칙 활성화 {#enable-global-push-rules}

모든 새 프로젝트에 대한 템플릿 역할을 하는 푸시 규칙을 만들 수 있습니다. 개별 프로젝트 또는 [그룹](#group-push-rules)에서 이러한 규칙을 재정의할 수 있습니다.

전역 푸시 규칙을 구성할 때:

- 전역 푸시 규칙을 구성한 후 생성하는 모든 프로젝트는 이 구성의 복사본을 상속합니다.
- 기존 프로젝트는 영향을 받지 않습니다. 이러한 프로젝트를 수동으로 업데이트하려면 [프로젝트별 전역 푸시 규칙 재정의](#override-global-push-rules-per-project)를 참조하세요.
- 전역 푸시 규칙에 대한 변경 사항은 이미 푸시 규칙이 구성된 프로젝트를 업데이트하지 않습니다.

사전 요구 사항:

- 관리자여야 합니다.

전역 푸시 규칙을 만들려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **푸시 규칙**을 선택합니다.
1. **푸시 규칙**을 확장합니다.
1. 원하는 규칙을 설정합니다.
1. **푸시 규칙 저장**을 선택합니다.

## 그룹 푸시 규칙 {#group-push-rules}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

그룹 푸시 규칙을 사용하면 그룹 유지 관리자가 특정 그룹에서 새로 생성된 프로젝트에 대한 푸시 규칙을 설정할 수 있습니다.

그룹에 대한 푸시 규칙을 구성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **사전 정의된 푸시 규칙** 섹션을 확장합니다.
1. 원하는 설정을 선택합니다.
1. **푸시 규칙 저장**을 선택합니다.

새 프로젝트는 다음에서 푸시 규칙을 상속합니다:

- 푸시 규칙이 정의된 가장 가까운 상위 그룹입니다.
- 상위 그룹에 푸시 규칙이 정의되지 않은 경우 전체 인스턴스에 대해 설정된 푸시 규칙입니다.

프로젝트만 푸시 규칙을 상속합니다. 하위 그룹은 상위 그룹에서 푸시 규칙을 상속하지 않습니다. 새 프로젝트에 적용되는 푸시 규칙을 확인하려면 하위 그룹에서 프로젝트를 만들고 프로젝트의 푸시 규칙을 확인합니다.

## 프로젝트별 전역 푸시 규칙 재정의 {#override-global-push-rules-per-project}

프로젝트 푸시 규칙은 전역 푸시 규칙과 독립적입니다. 프로젝트에 대한 푸시 규칙을 설정하면 해당 규칙이 해당 프로젝트에 대해 이전에 구성된 규칙을 대체합니다.

프로젝트에 대한 푸시 규칙을 설정하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **푸시 규칙**을 확장합니다.
1. 원하는 규칙을 설정합니다.
1. **푸시 규칙 저장**을 선택합니다.

프로젝트가 새 전역 푸시 규칙과 일치하려면 프로젝트의 푸시 규칙을 전역 설정과 일치하도록 구성해야 합니다. 프로젝트는 전역 푸시 규칙의 변경 사항을 자동으로 상속하지 않습니다.

## 사용자 확인 {#verify-users}

이러한 규칙을 사용하여 커밋을 만드는 사용자를 확인합니다.

> [!note]
> 이러한 푸시 규칙은 커밋에만 적용되며 [태그](tags/_index.md)에는 적용되지 않습니다.

- **인증되지 않은 사용자 거부**: 커미터 이메일은 사용자의 [확인된 이메일 주소](../../profile/_index.md#add-emails-to-your-user-profile) 또는 [개인 커밋 이메일 주소](../../profile/_index.md#use-an-automatically-generated-private-commit-email) 중 하나와 일치해야 합니다.
- **일치하지 않는 사용자명 거부**: 커밋 작성자 이름은 작성자와 커미터 이메일이 동일한 커밋에 대해 사용자의 GitLab 계정 이름과 일치해야 합니다. 이러한 이메일이 다를 때 체크가 건너뛰어지며, 이는 체리 픽 또는 다른 기여자로부터의 커밋 리베이싱과 같은 워크플로우 중에 발생합니다.

  이 규칙은 사용자의 Git 설정에서 잘못된 구성을 포착하여 커밋 위생을 유지하는 데 도움이 되지만 사칭을 방지하지는 않습니다. 암호화된 식별 확인을 위해 [**서명되지 않은 커밋 거부**](#require-signed-commits)를 대신 사용합니다.
- **커밋 작성자가 GitLab 사용자인지 확인**: 커밋 작성자와 커미터 이메일 주소 모두 GitLab 사용자의 [확인된 이메일 주소](../../profile/_index.md#add-emails-to-your-user-profile)와 일치해야 합니다.
- **작성자의 이메일 커밋**: 작성자와 커미터 이메일 주소 모두 정규식과 일치해야 합니다. 이메일 주소를 허용하려면 비워 둡니다.

[프로젝트용 봇 사용자](../settings/project_access_tokens.md#bot-users-for-projects) 또는 [그룹용 봇 사용자](../../group/settings/group_access_tokens.md#bot-users-for-groups)를 사용할 때 생성된 이메일 접미사를 추가해야 봇 토큰이 커밋하고 변경 사항을 푸시할 수 있습니다.

### GitLab에서 서명한 커밋 {#commits-signed-by-gitlab}

{{< history >}}

- GitLab 19.3에서 미러된 커밋을 포함하도록 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/587254)되었습니다.

{{< /history >}}

[GitLab에서 서명한](signed_commits/web_commits.md) 커밋의 커미터로는 `noreply@example.com`와 같은 인스턴스 이메일 주소가 있습니다. 이 주소는 GitLab 사용자에게 속하지 않습니다. 다음 규칙은 커밋이 프로젝트에 도달하는 방식에 관계없이 이러한 커밋에 대한 커미터 이메일 주소를 확인하지 않습니다:

- **인증되지 않은 사용자 거부**
- **커밋 작성자가 GitLab 사용자인지 확인**
- **작성자의 이메일 커밋**

GitLab은 작성자 이메일 주소를 대신 확인합니다. 예외는 **인증되지 않은 사용자 거부**이며, GitLab은 [리포지토리 미러링](mirror/_index.md)과 같은 Git 푸시로 도착하는 커밋에 대해 이를 건너뜁니다.

## 커밋 메시지 유효성 검사 {#validate-commit-messages}

커밋 메시지에 이러한 규칙을 사용합니다:

- **커밋 메시지에 표현식 필요**: 메시지는 표현식과 일치해야 합니다. 커밋 메시지를 허용하려면 비워 둡니다. `(?-m)`를 사용하여 비활성화할 수 있는 다중 라인 모드를 사용합니다. 몇 가지 유효성 검사 예제:

  - `JIRA\-\d+`은 모든 커밋이 Jira 이슈를 참조해야 합니다. 예를 들어 `Refactored css. Fixes JIRA-123`.
  - `[[:^punct:]]\b$`은 최종 문자가 구두점인 경우 커밋을 거부합니다. 단어 경계 문자(`\b`)는 Git이 커밋 메시지 끝에 줄바꿈 문자(`\n`)를 추가하기 때문에 거짓 부정을 방지합니다.

  GitLab UI에서 만든 커밋 메시지는 `\r\n`을 줄바꿈 문자로 설정합니다. 정규식에서 `\n` 대신 `(\r\n?|\n)`를 사용하여 올바르게 일치합니다.

  예를 들어 다음 다중 행 커밋 설명이 주어진 경우:

  ```plaintext
  JIRA:
  Description
  ```

  이 정규식으로 유효성을 검사할 수 있습니다: `JIRA:(\r\n?|\n)\w+`.

- **커밋 메시지에서 표현식 거부**: 커밋 메시지는 표현식과 일치하지 않아야 합니다. 커밋 메시지를 허용하려면 비워 둡니다. `(?-m)`를 사용하여 비활성화할 수 있는 다중 라인 모드를 사용합니다.

## 브랜치 이름 유효성 검사 {#validate-branch-names}

브랜치 이름을 유효성 검사하려면 **브랜치 이름**에 대한 정규식을 입력합니다. 모든 브랜치 이름을 허용하려면 비워 둡니다. 사용자의 [기본 브랜치](branches/default.md)는 항상 허용됩니다. 보안 목적상 특정 브랜치 이름 형식은 기본적으로 제한됩니다. Git 커밋 해시와 유사한 40개의 16진수 문자가 있는 이름은 금지됩니다.

몇 가지 유효성 검사 예제:

- 브랜치는 `JIRA-`로 시작해야 합니다.

  ```plaintext
  ^JIRA-
  ```

- 브랜치는 `-JIRA`로 끝나야 합니다.

  ```plaintext
  -JIRA$
  ```

- 브랜치는 `feature/`로 시작해야 하며, 대문자와 소문자의 모든 조합이 가능합니다.

  ```plaintext
  (?i)^feature/
  ```

- 브랜치는 `4`자에서 `15`자 사이여야 하며 소문자, 숫자 및 대시만 허용됩니다.

  ```plaintext
  ^[a-z0-9\\-]{4,15}$
  ```

## 의도하지 않은 결과 방지 {#prevent-unintended-consequences}

의도하지 않은 결과를 방지하려면 이러한 규칙을 사용합니다.

- **서명되지 않은 커밋 거부**: 커밋은 [서명되어야 합니다](signed_commits/_index.md). 이 규칙은 [Web IDE에서 생성된](#reject-unsigned-commits-and-the-web-ide) 일부 정당한 커밋을 차단할 수 있으며 [GitLab에서 생성된 서명되지 않은 커밋이 커밋 기록에 표시되도록](#require-signed-commits) 허용합니다.
- **`git push`를 사용하여 Git 태그를 제거하는 것을 사용자에게 허용하지 않음**: 사용자는 `git push`를 사용하여 Git 태그를 제거할 수 없습니다.

## 파일 유효성 검사 {#validate-files}

커밋에 포함된 파일을 유효성 검사하려면 이러한 규칙을 사용합니다.

- **비밀 파일 푸시 방지**: 파일에 [비밀](#prevent-pushing-secrets-to-the-repository)이 포함되면 안 됩니다.
- **금지된 파일 이름**: 리포지토리에 없는 파일은 정규식과 일치하지 않아야 합니다. 모든 파일 이름을 허용하려면 비워 둡니다. [일반적인 예제](#prohibit-files-by-name)를 참조하세요.
- **최대 파일 크기**: 추가되거나 업데이트된 파일은 이 파일 크기(MB)를 초과하지 않아야 합니다. 모든 크기의 파일을 허용하려면 `0`로 설정합니다. Git LFS에서 추적하는 파일은 제외됩니다.

### 리포지토리에 비밀 푸시 방지 {#prevent-pushing-secrets-to-the-repository}

자격 증명 파일 및 SSH 개인 키와 같은 비밀을 버전 제어 시스템에 커밋하지 마세요. GitLab에서는 사전 정의된 파일 이름 패턴 목록을 사용하여 일치하는 파일이 리포지토리에 푸시되는 것을 방지할 수 있습니다. 일치하는 파일을 포함하는 머지 리퀘스트가 차단됩니다. 이 푸시 규칙은 이미 리포지토리에 커밋된 파일을 제한하지 않습니다. 이 규칙을 사용하도록 기존 프로젝트의 구성을 업데이트해야 합니다. [프로젝트별 전역 푸시 규칙 재정의](#override-global-push-rules-per-project)에서 설명한 프로세스를 사용합니다.

이 규칙에 의해 차단된 파일은 아래에 나열되어 있습니다. 전체 기준 목록은 [`files_denylist.yml`](https://gitlab.com/gitlab-org/gitlab/-/blob/master/ee/lib/gitlab/checks/files_denylist.yml)를 참조하세요.

- AWS CLI 자격 증명 blob:
  - `.aws/credentials`
  - `aws/credentials`
  - `homefolder/aws/credentials`
- 비공개 RSA SSH 키:
  - `/ssh/id_rsa`
  - `/.ssh/personal_rsa`
  - `/config/server_rsa`
  - `id_rsa`
  - `.id_rsa`
- 비공개 DSA SSH 키:
  - `/ssh/id_dsa`
  - `/.ssh/personal_dsa`
  - `/config/server_dsa`
  - `id_dsa`
  - `.id_dsa`
- 비공개 ED25519 SSH 키:
  - `/ssh/id_ed25519`
  - `/.ssh/personal_ed25519`
  - `/config/server_ed25519`
  - `id_ed25519`
  - `.id_ed25519`
- 비공개 ECDSA SSH 키:
  - `/ssh/id_ecdsa`
  - `/.ssh/personal_ecdsa`
  - `/config/server_ecdsa`
  - `id_ecdsa`
  - `.id_ecdsa`
- 비공개 ECDSA_SK SSH 키:
  - `/ssh/id_ecdsa_sk`
  - `/.ssh/personal_ecdsa_sk`
  - `/config/server_ecdsa_sk`
  - `id_ecdsa_sk`
  - `.id_ecdsa_sk`
- 비공개 ED25519_SK SSH 키:
  - `/ssh/id_ed25519_sk`
  - `/.ssh/personal_ed25519_sk`
  - `/config/server_ed25519_sk`
  - `id_ed25519_sk`
  - `.id_ed25519_sk`
- 다음 접미사로 끝나는 모든 파일:
  - `*.pem`
  - `*.key`
  - `*.history`
  - `*_history`

### 파일 이름별 파일 금지 {#prohibit-files-by-name}

Git에서 파일 이름은 파일의 이름과 파일 이름 앞의 모든 디렉터리를 포함합니다. `git push`할 때 푸시의 각 파일 이름이 **금지된 파일 이름**의 정규식과 비교됩니다.

> [!note]
> 이 기능은 [RE2 구문](https://github.com/google/re2/wiki/Syntax)을 사용하며 긍정 또는 부정 선행 어설션을 지원하지 않습니다.

정규식은 다음을 수행할 수 있습니다:

- 리포지토리의 모든 위치에서 파일 이름과 일치합니다.
- 특정 위치에서 파일 이름과 일치합니다.
- 부분 파일 이름과 일치합니다.
- 확장자별로 특정 파일 유형을 제외합니다.
- 여러 패턴을 결합하여 여러 패턴을 제외합니다.

### 정규식 예제 {#regular-expression-examples}

이 예제는 일반적인 정규식 문자열 경계 패턴을 사용합니다:

- `^`: 문자열의 시작과 일치합니다.
- `$`: 문자열의 끝과 일치합니다.
- `\.`: 리터럴 마침표 문자와 일치합니다. 백슬래시는 마침표를 이스케이프 처리합니다.
- `\/`: 리터럴 슬래시와 일치합니다. 백슬래시는 슬래시를 이스케이프 처리합니다.

#### 특정 파일 유형 방지 {#prevent-specific-file-types}

- 리포지토리의 모든 위치에 `.exe` 파일 푸시를 방지하려면:

  ```plaintext
  \.exe$
  ```

#### 특정 파일 방지 {#prevent-specific-files}

- 특정 구성 파일을 푸시하는 것을 방지하려면:

  - 리포지토리 루트에서:

    ```plaintext
    ^config\.yml$
    ```

  - 특정 디렉터리에서:

    ```plaintext
    ^directory-name\/config\.yml$
    ```

- 어느 위치든 이 예제는 `install.exe`이라는 이름의 파일을 푸시하는 것을 방지합니다:

  ```plaintext
  (^|\/)install\.exe$
  ```

#### 패턴 결합 {#combine-patterns}

여러 패턴을 하나의 표현식으로 결합할 수 있습니다. 이 예제는 이전의 모든 표현식을 결합합니다:

```plaintext
(\.exe|^config\.yml|^directory-name\/config\.yml|(^|\/)install\.exe)$
```

## 서명된 커밋 필요 {#require-signed-commits}

[서명된 커밋](signed_commits/_index.md)은 Git 커밋의 진정성과 무결성을 확인하는 데 사용되는 디지털 서명입니다. 외부 기여자를 위해 서명된 커밋을 강제하고 GitLab에서 생성된 커밋은 서명되지 않은 상태로 유지하도록 **서명되지 않은 커밋 거부** 푸시 규칙을 사용합니다.

**서명되지 않은 커밋 거부** 푸시 규칙을 활성화할 때:

- GitLab 외부에서 푸시된 커밋(`git push`이 포함)은 유효한 암호화 서명을 포함해야 합니다. 서명되지 않은 커밋은 거부됩니다.
- GitLab UI 또는 API를 통해 생성된 커밋은 서명 없이도 허용됩니다. 이러한 커밋은 Web IDE, 머지 리퀘스트 작업 및 API 작업에서 올 수 있습니다.

> [!warning]
> GitLab에서 생성된 커밋이 이 규칙에서 제외되기 때문에 규칙이 활성화되어 있어도 서명되지 않은 커밋이 커밋 기록에 표시될 수 있습니다. 이 규칙은 외부 Git 클라이언트에서 푸시된 커밋만 확인합니다.
>
> 자세한 내용은 [이슈 5361](https://gitlab.com/gitlab-org/gitaly/-/issues/5361)을 참조하세요.

서명은 지원되는 서명 방법으로 생성해야 합니다:

- GPG
- SSH
- X.509

잘못되었거나 손상된 서명이 있는 커밋은 거부됩니다.

### 규칙 활성화 {#enable-the-rule}

**서명되지 않은 커밋 거부** 푸시 규칙을 활성화하려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **푸시 규칙**을 확장합니다.
1. **서명되지 않은 커밋 거부**를 선택합니다.
1. **푸시 규칙 저장**을 선택합니다.

### 서명되지 않은 커밋 거부 및 Web IDE {#reject-unsigned-commits-and-the-web-ide}

프로젝트에 **서명되지 않은 커밋 거부** 푸시 규칙이 있으면 사용자는 기본적으로 GitLab Web IDE를 통해 커밋을 만들 수 없습니다.

이 푸시 규칙이 있는 프로젝트의 Web IDE를 통해 커밋을 허용하려면 GitLab 관리자가 기능 플래그 `reject_unsigned_commits_by_gitlab`을 비활성화해야 합니다:

```ruby
Feature.disable(:reject_unsigned_commits_by_gitlab)
```

이 기능 플래그를 비활성화하면 Web IDE에서 생성된 커밋이 서명 없이 허용됩니다. 자세한 내용은 [기능 활성화 또는 비활성화](../../../administration/feature_flags/_index.md#enable-or-disable-the-feature)를 참조하세요.

## DCO 인증되지 않은 커밋 거부 {#reject-commits-that-arent-dco-certified}

[개발자 인증서 원본](https://developercertificate.org/)(DCO)으로 서명된 커밋은 기여자가 해당 커밋에 기여한 코드를 작성했거나 제출할 권리가 있음을 인증합니다. 프로젝트의 모든 커밋이 DCO를 준수하도록 요구할 수 있습니다. 이 푸시 규칙은 모든 커밋 메시지에 `Signed-off-by:` 트레일러가 필요하며 이를 없는 모든 커밋을 거부합니다.

## 관련 항목 {#related-topics}

- [리포지토리 보호](protect.md)
- [Git 서버 후킹](../../../administration/server_hooks.md)(이전에는 서버 후킹이라고 함)을 사용하여 복잡한 사용자 정의 푸시 규칙을 만듭니다
- [서명된 커밋](signed_commits/_index.md)
- [보호된 브랜치](branches/protected.md)
- [시크릿 검색](../../application_security/secret_detection/_index.md)

## 문제 해결 {#troubleshooting}

### 모든 프로젝트에 대한 푸시 규칙 일괄 업데이트 {#bulk-update-push-rules-for-all-projects}

모든 프로젝트에 대해 푸시 규칙을 동일하게 업데이트하려면 [Rails 콘솔](../../../administration/operations/rails_console.md#starting-a-rails-console-session)을 사용하거나 [푸시 규칙 API 끝점](../../../api/project_push_rules.md)을 사용하여 각 프로젝트를 업데이트하는 스크립트를 작성합니다.

예를 들어 **커밋 작성자가 GitLab 사용자인지 확인** 및 **`git push`를 사용하여 Git 태그를 제거하는 것을 사용자에게 허용하지 않음** 체크박스를 활성화하고 Rails 콘솔을 통해 특정 이메일 도메인의 커밋만 허용하는 필터를 만들려면:

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 올바른 조건에서 실행되지 않으면 손상을 일으킬 수 있습니다. 항상 먼저 테스트 환경에서 명령을 실행하고 복원할 준비가 된 백업 인스턴스를 준비합니다.

``` ruby
Project.find_each do |p|
  pr = p.push_rule || PushRule.new(project: p)
  # Check whether the commit author is a GitLab user
  pr.member_check = true
  # Do not allow users to remove Git tags with `git push`
  pr.deny_delete_tag = true
  # Commit author's email
  pr.author_email_regex = '@domain\.com$'
  pr.save!
end
```
