---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab UI에서 서명한 커밋
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

{{< history >}}

- 서명한 GitLab UI 커밋에 대해 **검증됨** 배지를 표시하는 기능이 GitLab 16.3에서 [도입되었으며](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/124218) [기능 플래그](../../../../administration/feature_flags/_index.md)(`gitaly_gpg_signing`)로 제공됩니다. 기본적으로 비활성화되었습니다.
- `rotated_signing_keys` 옵션에 지정된 여러 키를 사용하여 서명을 검증하는 기능이 GitLab 16.3에서 [도입되었습니다.](https://gitlab.com/gitlab-org/gitaly/-/merge_requests/6163)
- `gitaly_gpg_signing` 기능 플래그이 GitLab 17.0에서 GitLab Self-Managed 및 GitLab Dedicated에서 [기본적으로 활성화되었습니다.](https://gitlab.com/gitlab-org/gitaly/-/merge_requests/6876)

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요. 이 기능은 테스트 가능하지만 프로덕션 사용은 준비되지 않았습니다.

GitLab 사용자 인터페이스를 사용하여 커밋을 생성할 때 커밋이 직접 푸시되지 않습니다. 대신 커밋이 사용자를 대신하여 생성됩니다.

이러한 커밋에 서명하기 위해 GitLab은 인스턴스에 대해 구성된 글로벌 키를 사용합니다. GitLab이 개인 키에 액세스할 수 없기 때문에 생성된 커밋은 계정과 연결된 키를 사용하여 서명할 수 없습니다.

> [!note]
> GitLab에서 검증한 서명으로 서명된 커밋은 [리포지토리 미러링](../mirror/_index.md) 작업에서도 나타날 수 있습니다. 두 경우 모두 Gitaly는 인스턴스의 구성된 서명 키를 사용하여 커밋에 암호 서명합니다.

예를 들어 사용자 A가 사용자 B가 작성한 [제안](../../merge_requests/reviews/suggestions.md)을 적용하면 커밋에는 다음이 포함됩니다:

```plaintext
Author: User A <a@example.com>
Committer: GitLab <noreply@gitlab.com>

Co-authored-by: User B <b@example.com>
```

## 사전 요구 사항 {#prerequisites}

GitLab UI 커밋에 커밋 서명을 사용하려면 먼저 [구성](../../../../administration/gitaly/configure_gitaly.md#configure-commit-signing-for-gitlab-ui-commits)해야 합니다.

## 그룹 또는 프로젝트에서 웹 기반 커밋 서명 활성화 {#turn-on-web-based-commit-signing-for-a-group-or-project}

{{< details >}}

제공 서비스: GitLab.com

{{< /details >}}

{{< history >}}

- GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/200425)되었으며 `configure_web_based_commit_signing` 이름의 [기능 플래그가 포함](../../../../administration/feature_flags/_index.md)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.9에서 [GitLab.com에서 활성화되었습니다.](https://gitlab.com/gitlab-org/gitlab/-/issues/542975)
- GitLab 18.10에서 [일반 공급됩니다.](https://gitlab.com/gitlab-org/gitlab/-/issues/542975) 기능 플래그 `configure_web_based_commit_signing`이 제거되었습니다.

{{< /history >}}

그룹의 모든 프로젝트 또는 개별 프로젝트에 대해 웹 기반 커밋 서명을 활성화할 수 있습니다.

웹 기반 커밋 서명이 활성화되면 GitLab UI(웹 편집기, Web IDE 및 병합 요청)를 통해 생성된 모든 커밋이 인스턴스의 구성된 서명 키로 자동 서명됩니다.

### 그룹의 경우 {#for-a-group}

사전 요구 사항:

- 그룹의 소유자 역할이 있어야 합니다.

그룹의 모든 프로젝트에 대해 웹 기반 커밋 서명을 활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **일반**을 펼칩니다.
1. **웹 기반 커밋에 서명** 확인란을 선택합니다.

그룹의 프로젝트는 이 설정을 상속합니다.

### 프로젝트의 경우 {#for-a-project}

사전 요구 사항:

- 프로젝트의 관리자 또는 소유자 역할이 필요합니다.

> [!note]
> 프로젝트는 이미 웹 기반 커밋 서명이 활성화된 그룹에 속할 수 없습니다. 그룹 설정이 활성화되면 프로젝트 확인란을 사용할 수 없습니다.

프로젝트에 대해 웹 기반 커밋 서명을 활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **일반**을 펼칩니다.
1. **웹 기반 커밋에 서명** 확인란을 선택합니다.

## 커밋의 커미터 필드 {#committer-field-of-the-commits}

Git에서 커밋은 작성자와 커미터 모두를 포함합니다. 웹 커밋의 경우 `Committer` 필드를 구성할 수 있습니다. 이 필드를 업데이트하려면 [GitLab UI 커밋 서명 구성](../../../../administration/gitaly/configure_gitaly.md#configure-commit-signing-for-gitlab-ui-commits)을 참조하세요.

GitLab은 `Committer` 필드가 커밋을 생성하는 사용자로 설정되는 것에 의존하는 여러 보안 기능을 제공합니다. 예를 들어:

- [푸시 규칙](../push_rules.md): (`Reject unverified users` 또는 `Commit author's email`).
- [병합 요청 승인 방지](../../merge_requests/approvals/settings.md#prevent-approvals-by-users-who-add-commits).

인스턴스에서 서명한 커밋의 경우 `Committer` 필드에는 인스턴스 이메일 주소가 포함되므로 `Commit author's email` 푸시 규칙은 대신 `Author` 필드를 확인합니다. `Reject unverified users` 푸시 규칙은 GitLab UI에서 생성된 커밋에 대해 `Author` 필드를 확인합니다. 예를 들어 [푸시 미러](../mirror/push.md)에서 오는 것과 같이 일반 Git 푸시로 도착하는 서명된 커밋의 경우 GitLab은 해당 규칙을 건너뜁니다.

## REST API를 사용하여 생성된 커밋 {#commits-created-using-rest-api}

[REST API를 사용하여 생성된 커밋](../../../../api/commits.md#create-a-commit)도 웹 기반 커밋으로 간주됩니다. REST API 엔드포인트를 사용하면 커밋의 `author_name` 및 `author_email` 필드를 설정할 수 있으므로 다른 사용자를 대신하여 커밋을 생성할 수 있습니다.

커밋 서명이 활성화되면 API 요청을 보내는 사용자와 다른 `author_name` 및 `author_email`가 있는 REST API를 사용하여 생성된 커밋이 거부됩니다.

## 문제 해결 {#troubleshooting}

### 웹 커밋이 리베이스 후 서명되지 않음 {#web-commits-become-unsigned-after-rebase}

브랜치의 이전에 서명된 커밋은 다음의 경우 서명되지 않습니다:

- 커밋 서명이 GitLab UI에서 생성된 커밋에 대해 구성됩니다.
- 병합 요청이 GitLab UI에서 리베이스됩니다.

이는 이전 커밋이 수정되고 대상 브랜치 위에 추가되기 때문에 발생합니다. GitLab이 이러한 커밋에 서명할 수 없습니다.

이 문제를 해결하려면 로컬에서 브랜치를 리베이스한 다음 변경 사항을 GitLab에 푸시하세요.
