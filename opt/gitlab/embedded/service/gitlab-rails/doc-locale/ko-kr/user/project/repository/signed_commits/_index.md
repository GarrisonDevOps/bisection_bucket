---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab 커밋에 암호학적으로 서명해야 하는 이유와 서명된 커밋을 검증하는 방법.
title: 서명된 커밋
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

커밋에 디지털 서명을 추가하면 커밋이 가짜 사용자가 아닌 사용자로부터 시작되었다는 추가적인 보증을 제공합니다. 디지털 서명은 진정성을 검증하기 위해 사용되는 암호학적 출력입니다.

서명된 커밋과 검증된 커밋의 차이를 이해하는 것이 중요합니다:

- 서명된 커밋은 커밋의 무결성과 진정성을 증명하는 암호학적 서명이 첨부되어 있습니다. 서명은 개인 키를 사용하여 생성됩니다.
- 검증된 커밋은 GitLab이 사용자의 GitLab 프로필에 저장된 공개 키에 대해 검증할 수 있는 서명을 가지고 있습니다.

GitLab이 공개 키로 커미터의 신원을 확인할 수 있으면 커밋은 GitLab UI에서 **검증됨**으로 표시됩니다.

> [!note]
> 커미터와 작성자 필드는 Git에서 서로 다릅니다. 작성자는 커밋을 작성하고 커미터는 이를 적용합니다. 커밋 서명은 커미터의 신원만 검증합니다.

GitLab은 커밋과 태그의 서명을 검증합니다. 다음 서명 방법이 지원됩니다:

- [SSH 키](ssh.md)
- [GPG 키](gpg.md)
- [X.509 인증서](x509.md)

## 커밋 검증 {#verify-commits}

병합 요청 또는 전체 프로젝트의 커밋을 검토하고 서명되었는지 확인하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 커밋을 검토하려면:
   - 프로젝트의 경우 **코드** > **커밋**을 선택합니다.
   - 병합 요청의 경우:
     1. 왼쪽 사이드바에서 **코드** > **병합 요청**을 선택한 후 병합 요청을 선택합니다.
     1. **커밋**을 선택합니다.
1. 검토할 커밋을 식별합니다. 서명의 검증 상태에 따라 서명된 커밋은 **검증됨** 또는 **미인증** 배지를 표시합니다.

   ![검증된 배지와 검증되지 않은 배지가 있는 커밋 목록입니다.](img/project_signed_and_unsigned_commits_v17_4.png)

   서명되지 않은 커밋은 배지를 표시하지 않습니다.

1. 커밋의 서명 세부 정보를 표시하려면 **검증됨** 또는 **미인증**을 선택하여 지문 또는 키 ID를 확인합니다:

   ![커밋의 검증된 서명 세부 정보입니다.](img/project_signed_commit_verified_signature_v17_4.png)

   ![커밋의 검증되지 않은 서명 세부 정보입니다.](img/project_signed_commit_unverified_signature_v17_4.png)

[커밋 API 사용](../../../../api/commits.md#retrieve-commit-signature)하여 커밋의 서명을 확인할 수도 있습니다.

### GitLab 서명 커밋 검증 {#verify-gitlab-signed-commits}

GitLab은 웹 UI를 통해 만들어진 커밋과 같이 자신이 생성한 커밋에 인스턴스에 구성된 키로 서명합니다. 이러한 커밋을 로컬에서 검증하려면 [웹 커밋 API](../../../../api/web_commits.md#retrieve-public-signing-key)를 사용하여 커밋 서명을 위한 GitLab 공개 키를 획득합니다.

서명은 커밋이 다른 프로젝트로 복사될 때 커밋과 함께 유지되며, 예를 들어 [리포지토리 미러링](../mirror/_index.md)을 통해 유지됩니다. 대상 프로젝트에서 GitLab은 인스턴스가 커밋에 서명한 키로 구성된 경우에만 **검증됨** 배지를 표시합니다.

### 검증되지 않은 커미터 이메일에 대한 경고 배지 {#warning-badge-for-unverified-committer-email}

{{< history >}}

- GitLab 17.5에서 `check_for_mailmapped_commit_emails`라는 [기능 플래그](../../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/425042)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.9에서 [GitLab.com에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/481441).
- GitLab 19.1에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/481441)합니다. 기능 플래그 `check_for_mailmapped_commit_emails`이 제거되었습니다.

{{< /history >}}

검증된 서명된 커밋의 커미터 이메일이 더 이상 서명 사용자에게 검증되지 않으면 GitLab은 경고 기호가 있는 주황색 검증 배지({{< icon name="warning" >}} **검증됨**)를 표시합니다.

이는 커미터 이메일이 사용자의 검증된 이메일에서 제거되었을 때 발생할 수 있습니다.

녹색 **검증됨** 배지를 복원하려면 커미터 이메일 주소를 GitLab 프로필에 추가하고 검증합니다.

## 푸시 규칙으로 서명된 커밋 적용 {#enforce-signed-commits-with-push-rules}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

푸시 규칙을 사용하여 프로젝트 전체에서 서명된 커밋을 요구할 수 있습니다. **서명되지 않은 커밋 거부** 푸시 규칙은 서명되지 않은 커밋이 리포지토리로 푸시되는 것을 방지하여 조직이 코드 무결성을 유지하고 규정 준수 요구 사항을 충족하도록 돕습니다.

이 규칙의 작동 방식 및 제한 사항에 대한 자세한 내용은 [서명된 커밋 요구](../push_rules.md#require-signed-commits)를 참조하세요.

## 문제 해결 {#troubleshooting}

### 서명된 커밋의 검증 문제 해결 {#fix-verification-problems-with-signed-commits}

GPG 키 또는 X.509 인증서로 서명된 커밋의 검증 프로세스는 여러 이유로 실패할 수 있습니다:

| 값                       | 설명 | 가능한 해결 방법 |
|-----------------------------|-------------|----------------|
| `UNVERIFIED`                | 커밋 서명이 유효하지 않습니다. | 유효한 서명으로 커밋에 서명합니다. |
| `SAME_USER_DIFFERENT_EMAIL` | 커밋에 서명하는 데 사용된 GPG 키는 커미터 이메일을 포함하지 않지만 커미터의 다른 유효한 이메일을 포함합니다. | GPG 키와 일치하는 이메일 주소를 사용하도록 커밋을 수정하거나 [이메일 주소를 포함하도록](https://security.stackexchange.com/a/261468) GPG 키를 업데이트합니다. |
| `OTHER_USER`                | 서명과 GPG 키는 유효하지만 키는 커미터와 다른 사용자에게 속합니다. | 커밋을 수정하여 올바른 이메일 주소를 사용하거나 사용자와 연결된 GPG 키를 사용하도록 커밋을 수정합니다. |
| `UNVERIFIED_KEY`            | GPG 서명과 연결된 키에는 커미터와 연결된 검증된 이메일 주소가 없습니다. | GitLab 프로필에 이메일을 추가하고 검증하거나 [이메일 주소를 포함하도록 GPG 키를 업데이트](https://security.stackexchange.com/a/261468)하거나 다른 커미터 이메일 주소를 사용하도록 커밋을 수정합니다. |
| `UNKNOWN_KEY`               | 이 커밋의 GPG 서명과 연결된 GPG 키는 GitLab에 알려지지 않았습니다. | [GPG 키 추가](gpg.md#add-a-gpg-key-to-your-account)를 GitLab 프로필에 추가합니다. |
| `MULTIPLE_SIGNATURES`       | 커밋에 대해 여러 GPG 또는 X.509 서명이 발견되었습니다. | 커밋을 수정하여 하나의 GPG 또는 X.509 서명만 사용합니다. |
