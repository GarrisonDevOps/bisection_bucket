---
stage: AI Coding
group: Code Review
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 병합 요청 제목 유효성 검사를 사용하여 명명 규칙을 적용하고 제목이 구성된 정규식 패턴과 일치하지 않을 때 병합을 차단합니다.
title: 병합 요청 제목 유효성 검사
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- [GitLab 17.11에서 도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/25689) [기능 플래그](../../../administration/feature_flags/_index.md) `merge_request_title_regex`로 명명됨. 기본적으로 비활성화되었습니다.
- [GitLab.com 및 GitLab Self-Managed에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/508022) GitLab 18.10에서.
- GitLab 18.10에서 [일반 공개되었습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/508022). 기능 플래그 `merge_request_title_regex`이 제거되었습니다.
- [초안 접두사를 무시하도록 변경됨](https://gitlab.com/gitlab-org/gitlab/-/issues/624452) GitLab 19.5에서.

{{< /history >}}

병합 요청 제목에 [RE2](https://github.com/google/re2/wiki/Syntax) 정규식 패턴을 적용하여 명명 규칙을 적용할 수 있습니다. 프로젝트에 대한 제목 패턴을 구성하면 패턴과 일치하지 않는 제목의 병합 요청이 병합되지 않습니다.

제목 유효성 검사를 사용하여:

- 제목에 Jira 또는 이슈 추적 시스템 티켓 참조가 필요합니다.
- [일반적인 커밋](https://www.conventionalcommits.org/) 형식을 적용합니다.
- 릴리스 관리 또는 거버넌스 워크플로우에 대한 제목 접두사를 표준화합니다.

## 병합 요청 제목 유효성 검사 구성 {#configure-merge-request-title-validation}

프로젝트의 모든 병합 요청 제목이 병합되기 전에 일치해야 하는 정규식 패턴을 구성합니다.

사전 요구 사항:

- 프로젝트에 대한 유지 관리자 또는 소유자 역할.

제목 유효성 검사를 구성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정 > 병합 요청**을 선택합니다.
1. **제목 패턴** 텍스트 상자에 정규식 패턴을 입력합니다.
1. **제목 예제** 텍스트 상자에 예상 형식에 대한 설명을 입력합니다. 병합 요청 작성자가 사용할 내용을 알 수 있도록 유효한 예제를 포함합니다.
1. **변경 사항 저장**을 선택합니다.

![프로젝트의 제목 유효성 검사 설정 필드입니다.](img/title_validation_settings_v18_10.png)

**제목 패턴**을 설정하면 **제목 예제**도 필수입니다. **제목 예제**는 사용자의 병합 요청 제목이 패턴과 일치하지 않을 때 사용자에게 표시됩니다.

제목 유효성 검사를 제거하려면 **제목 패턴** 및 **제목 예제** 텍스트 상자를 모두 지운 다음 **변경사항 저장**을 선택합니다.

API를 사용하여 제목 유효성 검사를 구성하려면 [프로젝트 API 사용](../../../api/projects.md)을 할 수도 있습니다.

## 정규식 구문 {#regex-syntax}

제목 유효성 검사는 [RE2 구문](https://github.com/google/re2/wiki/Syntax)을 사용하며 PCRE는 사용하지 않습니다. RE2는 역참조 또는 선행/후행 어설션을 지원하지 않습니다.

패턴 및 설명 필드는 각각 최대 255자의 길이를 가집니다.

정규식 패턴은 병합 요청 제목에서 초안 접두사(`[Draft]`, `Draft:`, 및 `(Draft)`)를 고려할 필요가 없습니다. 제목 유효성 검사는 패턴 일치 전에 자동으로 이를 제거합니다.

### 예제 패턴 {#example-patterns}

다음은 정규식 패턴 예제입니다:

- Jira 티켓 참조(유효한 제목 예제: `PROJ-123 Fix login bug`):

  ```plaintext
  ^[A-Z]+-\d+ .+
  ```

- 일반적인 커밋(유효한 제목 예제: `feat(auth): add SSO support`):

  ```plaintext
  ^(feat|fix|docs|chore|refactor|test|style)(\(.+\))?: .+
  ```

- 사용자 정의 접두사(유효한 제목 예제: `BUGFIX: resolve timeout error`):

  ```plaintext
  ^(FEATURE|BUGFIX|HOTFIX): .+
  ```

- 괄호로 묶인 범주(유효한 제목 예제: `[Feature] Add dark mode`):

  ```plaintext
  ^\[.+\] .+
  ```

## 유효성 검사 적용 {#validation-enforcement}

제목 유효성 검사 패턴이 구성되었을 때:

- 패턴과 일치하지 않는 제목의 병합 요청은 병합될 수 없습니다.
- 제목 확인은 승인, 파이프라인 상태 및 스레드 해결과 같은 다른 확인과 함께 병합 확인으로 나타납니다.
- [자동 병합](auto_merge.md)이 활성화되면 병합 요청은 병합하기 전에 제목이 패턴과 일치할 때까지 기다립니다.
- 유효성 검사는 병합 시 현재 제목에 적용됩니다. 작성자는 병합하기 전 언제든지 제목을 업데이트할 수 있습니다.

![제목 유효성 검사 확인으로 차단된 병합 요청입니다.](img/title_validation_failed_v18_10.png)

## 문제 해결 {#troubleshooting}

### 제목 유효성 검사로 인해 병합 요청을 병합할 수 없음 {#merge-request-cannot-be-merged-due-to-title-validation}

병합 요청이 제목 유효성 검사로 차단된 경우:

1. 병합 요청의 병합 확인 섹션에서 제목 유효성 검사 실패를 확인합니다.
1. 병합 요청 제목을 **설정** > **병합 요청** > **제목 패턴**에 구성된 패턴과 일치하도록 업데이트합니다.
1. 오류 메시지에 표시된 **제목 예제**를 예상 형식에 대한 참조로 사용합니다.

### 정규식 패턴이 예상대로 일치하지 않음 {#regex-pattern-does-not-match-as-expected}

제목 유효성 검사는 [RE2 구문](https://github.com/google/re2/wiki/Syntax)을 사용하며 많은 온라인 정규식 테스터에서 사용되는 PCRE 구문과는 다릅니다. 패턴을 확인하려면:

- RE2 호환 정규식 테스터를 사용합니다.
- 역참조 또는 선행 어설션과 같은 지원되지 않는 기능을 사용하지 않고 있는지 확인합니다.
- 특수 문자가 올바르게 이스케이프되었는지 확인합니다.

## 관련 항목 {#related-topics}

- [자동 병합](auto_merge.md)
- [프로젝트 API - `merge_request_title_regex`](../../../api/projects.md)
- [병합 상태 API](../../../api/merge_requests.md#merge-status)
