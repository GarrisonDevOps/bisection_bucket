---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "코드 소유자를 사용하여 코드베이스의 전문가를 정의하고, 파일 유형 또는 위치에 따라 검토 요구사항을 설정합니다."
title: 코드 소유자
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

코드 소유자 기능을 사용하여 프로젝트 코드베이스의 특정 부분에 대한 전문 지식을 가진 사람을 정의합니다.

리포지토리의 파일 및 디렉터리 소유자를 정의하여:

- 변경 사항을 승인하도록 소유자가 필요합니다. 보호된 브랜치와 코드 소유자를 결합하여 전문가가 보호된 브랜치로 병합되기 전에 머지 리퀘스트를 승인하도록 요구합니다. 자세한 내용은 [코드 소유자 및 보호된 브랜치](#code-owners-and-protected-branches)를 참조하세요.
- 소유자를 식별합니다. 코드 소유자 이름은 자신이 소유하는 파일 및 디렉터리에 표시됩니다:

  ![가장 최근 변경 사항의 설명 아래에 나열된 코드 소유자를 보여주는 파일 보기입니다.](img/codeowners_in_UI_v15_10.png)

## 코드 소유자 및 승인 규칙 {#code-owners-and-approval-rules}

코드 소유자를 머지 리퀘스트 [승인 규칙](../merge_requests/approvals/rules.md)(선택사항 또는 필수)과 결합하여 유연한 승인 워크플로우를 구축합니다:

- 코드 소유자를 사용하여 품질을 보장합니다. 리포지토리의 특정 경로에 대한 도메인 전문성을 가진 사용자를 정의합니다.
- 승인 규칙을 사용하여 리포지토리의 특정 파일 경로에 해당하지 않는 전문 분야를 정의합니다. 승인 규칙은 머지 리퀘스트 작성자가 프론트엔드 개발자 또는 보안 팀과 같은 올바른 검토자 집합으로 안내하는 데 도움이 됩니다.

예를 들어:

| 형식 | 이름 | 범위  | 댓글    |
|------|------|--------|------------|
| 승인 규칙            | UX                   | 모든 파일     | 사용자 경험(UX) 팀 멤버가 프로젝트에서 이루어진 모든 변경 사항의 사용자 경험을 검토합니다. |
| 승인 규칙            | 보안             | 모든 파일     | 보안 팀 멤버가 모든 변경 사항에서 취약점을 검토합니다. |
| 코드 소유자 승인 규칙 | 프론트엔드: 코드 스타일 | `*.css` 파일 | 프론트엔드 엔지니어가 CSS 파일 변경 사항을 프로젝트 스타일 표준 준수를 위해 검토합니다. |
| 코드 소유자 승인 규칙 | 백엔드: 코드 검토 | `*.rb` 파일  | 백엔드 엔지니어가 Ruby 파일의 로직과 코드 스타일을 검토합니다. |

<div class="video-fallback">
  비디오 소개: <a href="https://www.youtube.com/watch?v=RoyBySTUSB0">코드 소유자</a>입니다.
</div>
<figure class="video-container">
  <iframe src="https://www.youtube-nocookie.com/embed/RoyBySTUSB0" frameborder="0" allowfullscreen> </iframe>
</figure>

승인자 또는 코드 소유자로 머지 리퀘스트를 승인할 수 있는 사용자에 대한 정보는 [멤버십 유형별 승인자](../merge_requests/approvals/rules.md#approver-by-membership-type)를 참조하세요.

## 코드 소유자 및 보호된 브랜치 {#code-owners-and-protected-branches}

머지 리퀘스트 변경 사항이 [`CODEOWNERS` 파일](#codeowners-file)에 지정된 코드 소유자에 의해 검토 및 승인되도록 하려면, 머지 리퀘스트의 대상 브랜치가 [보호](../repository/branches/protected.md)되어야 하고 [코드 소유자 승인](../repository/branches/protected.md#require-code-owner-approval)이 활성화되어야 합니다.

보호된 브랜치에서 코드 소유자 승인을 활성화할 때 다음 기능을 사용할 수 있습니다:

- [코드 소유자로부터 승인 요구](../repository/branches/protected.md#require-code-owner-approval)합니다.
- [코드 소유자로부터 여러 승인 요구](advanced.md#require-multiple-approvals-from-code-owners)합니다.
- [코드 소유자로부터 선택적 승인](reference.md#optional-sections)입니다.

### 실제 예 {#practical-example}

프로젝트에 `config/` 디렉터리에 민감하고 중요한 정보가 포함되어 있습니다. 다음과 같이 수행할 수 있습니다.

1. 디렉터리의 소유권을 할당합니다. 이를 위해 `CODEOWNERS` 파일을 설정합니다.
1. 기본 브랜치에 대한 보호된 브랜치를 만듭니다. 예를 들어, `main`입니다.
1. 보호된 브랜치에서 **코드 소유자의 필수 승인**을 활성화합니다.
1. 선택 사항. `CODEOWNERS` 파일을 편집하여 여러 승인에 대한 규칙을 추가합니다.

이 구성을 사용하면 `config/` 디렉터리의 파일을 변경하고 `main` 브랜치를 대상으로 하는 머지 리퀘스트가 병합되기 전에 지정된 코드 소유자로부터 승인을 받아야 합니다.

### 코드 소유자가 없는 파일 {#files-without-a-code-owner}

GitLab은 머지 리퀘스트에서 변경된 파일을 대상 브랜치의 `CODEOWNERS` 파일과 비교합니다. `CODEOWNERS` 규칙과 일치하지 않는 파일은 코드 소유자 승인이 필요하지 않습니다. 여기에는 새 파일과 머지 리퀘스트가 열려 있는 동안 대상 브랜치에서 이동되거나 이름이 바뀐 파일이 포함됩니다.

모든 파일에 대해 승인을 요구하려면 파일 맨 위에 `*` 항목으로 기본 소유자를 추가합니다.

나중에 더 구체적인 항목을 추가하면 마지막 일치하는 항목이 사용되므로 `*` 항목이 재정의됩니다.

자세한 내용은 [`CODEOWNERS` 구문](reference.md) 및 [고급 `CODEOWNERS` 구성](advanced.md)을 참조하세요.

### 보호된 브랜치에 푸시 및 병합이 허용됨 {#allowed-to-push-and-merge-to-a-protected-branch}

**푸시와 머지가 허용됨** 권한이 있는 사용자는 자신의 변경 사항에 대한 머지 리퀘스트를 생성하거나 변경 사항을 브랜치에 직접 푸시할 수 있습니다. 사용자가 머지 리퀘스트 프로세스를 건너뛰면 보호된 브랜치 기능 및 머지 리퀘스트에 내장된 코드 소유자 승인도 건너뜁니다.

이 권한은 자동화([내부 사용자](../../../administration/internal_users.md))와 관련된 계정 및 릴리스 도구에 자주 부여됩니다.

**푸시가 허용됨** 권한이 없는 사용자의 모든 변경 사항은 머지 리퀘스트를 통해 라우팅되어야 합니다.

## 파일 또는 디렉터리의 코드 소유자 보기 {#view-code-owners-of-a-file-or-directory}

파일 또는 디렉터리의 코드 소유자를 보려면:

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **코드** > **리포지토리**를 선택합니다.
1. 코드 소유자를 보려는 파일 또는 디렉터리로 이동합니다.
1. 선택 사항. 브랜치 또는 태그를 선택합니다.

GitLab은 페이지 맨 위에 코드 소유자를 표시합니다.

## 코드 소유자 설정 {#set-up-code-owners}

사전 요구 사항:

- 기본 브랜치에 푸시하거나 머지 리퀘스트를 생성할 수 있는 권한이 있어야 합니다.

1. `CODEOWNERS` 파일을 [원하는 위치](#codeowners-file)에 만듭니다.
1. [`CODEOWNERS` 구문](reference.md)을 따라 파일에 일부 규칙을 정의합니다. 몇 가지 제안:
   - [**모든 대상 사용자**](../merge_requests/approvals/rules.md#code-owners-as-approvers) 승인 규칙을 구성합니다.
   - 보호된 브랜치에서 [코드 소유자 승인 요구](../repository/branches/protected.md#require-code-owner-approval)합니다.
1. 변경 사항을 커밋하고 GitLab에 푸시합니다.

## `CODEOWNERS` 파일 {#codeowners-file}

`CODEOWNERS` 파일은 GitLab 프로젝트의 코드에 대해 책임이 있는 사람을 정의합니다. 목적은 다음과 같습니다:

- 특정 파일 및 디렉터리에 대한 코드 소유자를 정의합니다.
- 보호된 브랜치에 대한 승인 요구사항을 적용합니다.
- 프로젝트의 코드 소유권을 전달합니다.

이 파일은 누가 변경 사항을 검토 및 승인해야 하는지를 결정하고 올바른 전문가가 코드 변경에 관여하도록 보장합니다.

각 리포지토리는 단일 `CODEOWNERS` 파일을 사용합니다. GitLab은 리포지토리에서 이 위치들을 이 순서대로 확인합니다. 찾은 첫 번째 `CODEOWNERS` 파일이 사용되고 다른 모든 파일은 무시됩니다:

1. 루트 디렉터리에서: `./CODEOWNERS`입니다.
1. `docs` 디렉터리에서: `./docs/CODEOWNERS`입니다.
1. `.gitlab` 디렉터리에서: `./.gitlab/CODEOWNERS`입니다.

자세한 내용은 [`CODEOWNERS` 구문](reference.md) 및 [고급 `CODEOWNERS` 구성](advanced.md)을 참조하세요.

## 관련 항목 {#related-topics}

- [`CODEOWNERS` 구문](reference.md)
- [고급 `CODEOWNERS` 구성](advanced.md)
- [코드 소유자 문제 해결](troubleshooting.md)
- [리포지토리 보호](../repository/protect.md)
- [보호된 브랜치](../repository/branches/protected.md)
