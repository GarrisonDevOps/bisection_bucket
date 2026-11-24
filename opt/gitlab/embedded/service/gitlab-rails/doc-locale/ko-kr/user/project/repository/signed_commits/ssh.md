---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab 리포지토리에서 SSH 키로 커밋 및 태그에 서명합니다.
title: SSH 키로 커밋 및 태그에 서명
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

SSH 키로 커밋 또는 태그에 서명하면 GitLab은 GitLab 계정과 연결된 SSH 공개 키를 사용하여 암호화 방식으로 서명을 확인합니다. 성공하면 GitLab이 커밋 또는 태그에 **검증됨** 레이블을 표시합니다.

GitLab에서 커밋을 검증된 것으로 간주하려면:

- 커밋에 서명하는 데 사용한 SSH 키를 [사용 유형](../../../ssh.md#add-an-ssh-key-to-your-gitlab-account)이 **인증 및 서명** 또는 **서명**인 GitLab 계정에 추가해야 합니다.
- Git 구성의 커밋터 이메일 주소가 GitLab 계정과 연결된 [검증된 이메일 주소](../../../profile/_index.md#change-your-primary-email)와 일치해야 합니다.

서명이 유효하지만 커밋터 이메일이 계정의 검증된 이메일과 일치하지 않으면 커밋이 **미인증**으로 표시됩니다.

`git+ssh` 인증 및 커밋 서명에 동일한 SSH 키를 사용할 수 있습니다. 단, 사용 유형이 **인증 및 서명**이어야 합니다. 이는 [GitLab 계정에 SSH 키 추가](../../../ssh.md#add-an-ssh-key-to-your-gitlab-account) 페이지에서 확인할 수 있습니다.

GitLab 계정과 연결된 SSH 키 관리에 대한 자세한 내용은 [SSH 키를 사용하여 GitLab과 통신](../../../ssh.md)을 참조하세요.

## SSH 키로 커밋 및 태그에 서명하도록 Git 구성 {#configure-git-to-sign-commits-and-tags-with-your-ssh-key}

[SSH 키를 생성](../../../ssh.md#generate-an-ssh-key-pair)하고 [GitLab 계정에 추가](../../../ssh.md#add-an-ssh-key-to-your-gitlab-account)한 후 Git이 키를 사용하도록 구성합니다.

사전 요구 사항:

- Git 2.34.0 이상.
- OpenSSH 8.1 이상.

  > [!note]
  > OpenSSH 8.7의 서명 기능이 손상되었습니다. OpenSSH 8.7을 사용 중이면 OpenSSH 8.8로 업그레이드하세요.

- **사용 유형**이 `Authentication & Signing` 또는 `Signing`인 SSH 키. 다음 SSH 키 유형이 지원됩니다:
  - ED25519
  - ED25519_SK
  - RSA
  - ECDSA
  - ECDSA_SK

Git이 키를 사용하도록 구성하려면:

1. Git이 커밋 서명을 위해 SSH를 사용하도록 구성합니다:

   ```shell
   git config --global gpg.format ssh
   ```

1. 서명 키로 사용할 공개 SSH 키를 지정하고 파일명(`~/.ssh/examplekey.pub`)을 키의 위치로 변경합니다. 파일명은 키를 생성한 방식에 따라 다를 수 있습니다:

   ```shell
   git config --global user.signingkey ~/.ssh/examplekey.pub
   ```

## SSH 키로 커밋에 서명 {#sign-commits-with-your-ssh-key}

사전 요구 사항:

- [SSH 키를 생성](../../../ssh.md#generate-an-ssh-key-pair)했습니다.
- GitLab 계정에 [키를 추가](../../../ssh.md#add-an-ssh-key-to-your-gitlab-account)했습니다.
- SSH 키로 [Git이 커밋에 서명하도록 구성](#configure-git-to-sign-commits-and-tags-with-your-ssh-key)했습니다.
- Git `user.email`이(가) GitLab 계정과 연결된 [검증된 이메일 주소](../../../profile/_index.md#change-your-primary-email)와 일치합니다.

커밋에 서명하려면:

1. 커밋에 서명할 때 `-S` 플래그를 사용합니다:

   ```shell
   git commit -S -m "My commit msg"
   ```

1. 선택 사항. 매번 커밋할 때 `-S` 플래그를 입력하지 않으려면 Git이 자동으로 커밋에 서명하도록 지시합니다:

   ```shell
   git config --global commit.gpgsign true
   ```

1. SSH 키가 보호되면 Git이 암호를 입력하라는 메시지를 표시합니다.
1. GitLab으로 푸시합니다.
1. 커밋이 [검증되었는지](#verify-commits) 확인합니다. 서명 확인은 `allowed_signers` 파일을 사용하여 이메일 및 SSH 키를 연결합니다. 이 파일 구성에 대한 도움말은 [로컬 커밋 검증](#verify-commits-locally)을 참조하세요.

## 태그에 서명 및 검증 {#sign-and-verify-tags}

{{< history >}}

- GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/384473)되었으며 `render_ssh_signed_tags_verification_status` 이름의 [기능 플래그가 포함](../../../../administration/feature_flags/_index.md)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 18.11에서 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에 사용으로 설정](https://gitlab.com/gitlab-org/gitlab/-/issues/561452)되었습니다.
- GitLab 19.1에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/596049)합니다. 기능 플래그 `render_ssh_signed_tags_verification_status`이 제거되었습니다.

{{< /history >}}

SSH 키로 [커밋 및 태그에 서명하도록 Git을 구성](#configure-git-to-sign-commits-and-tags-with-your-ssh-key)한 후 태그에 서명할 수 있습니다:

1. Git 태그를 생성할 때 `-s` 플래그를 추가합니다:

   ```shell
   git tag -s v1.1.1 -m "My signed tag"
   ```

1. GitLab으로 푸시하고 다음 명령으로 태그가 서명되었는지 확인합니다:

   ```shell
   git tag --verify v1.1.1
   ```

1. 선택 사항. `-s` 플래그 없이 자동으로 태그에 서명하려면 다음을 실행합니다:

   ```shell
   git config --global tag.gpgsign true
   ```

## 커밋 검증 {#verify-commits}

모든 서명된 커밋을 [GitLab UI에서](_index.md#verify-commits) 검증할 수 있습니다. SSH 키로 서명된 커밋은 로컬에서도 검증할 수 있습니다.

### 로컬 커밋 검증 {#verify-commits-locally}

로컬로 커밋을 검증하려면 Git이 SSH 공개 키와 사용자를 연결하도록 [허용된 서명자 파일](https://man7.org/linux/man-pages/man1/ssh-keygen.1.html#ALLOWED_SIGNERS)을 생성합니다. 이 예제에서는 `~/.ssh/allowed_signers`를 사용하지만 다른 경로를 지정할 수 있습니다. 다음 단계에서 동일한 경로를 사용합니다.

1. SSH 디렉터리를 만듭니다:

   ```shell
   mkdir -p ~/.ssh
   ```

1. 허용된 서명자 파일을 만듭니다.

   ```shell
   touch ~/.ssh/allowed_signers
   ```

1. Git이 파일을 사용하도록 구성합니다:

   ```shell
   git config gpg.ssh.allowedSignersFile "$HOME/.ssh/allowed_signers"
   ```

1. 허용된 서명자 파일에 항목을 추가합니다. `<MY_KEY>`을(를) 키의 이름으로 바꿉니다. 1단계에서 다른 경로를 선택했으면 `~/.ssh/allowed_signers`를 해당 경로로 바꿉니다:

   ```shell
   # Declaring the `git` namespace helps prevent cross-protocol attacks.
   echo "$(git config --get user.email) namespaces=\"git\" $(cat ~/.ssh/<MY_KEY>.pub)" >> ~/.ssh/allowed_signers
   ```

   결과 항목에는 이메일 주소, 키 유형 및 키 내용이 포함됩니다:

   ```plaintext
   example@gitlab.com namespaces="git" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAmaTS47vRmsKyLyK1jlIFJn/i8wdGQ3J49LYyIYJ2hv
   ```

1. 검증하려는 각 추가 사용자에 대해 이 단계를 반복합니다. 다른 기여자와 협업하는 경우 이 파일을 Git 리포지토리에 체크인하는 것을 고려하세요.

1. `git log --show-signature`을(를) 사용하여 커밋의 서명 상태를 봅니다:

   ```shell
   $ git log --show-signature

   commit e2406b6cd8ebe146835ceab67ff4a5a116e09154 (HEAD -> main, origin/main, origin/HEAD)
   Good "git" signature for johndoe@example.com with ED25519 key SHA256:Ar44iySGgxic+U6Dph4Z9Rp+KDaix5SFGFawovZLAcc
   Author: John Doe <johndoe@example.com>
   Date:   Tue Nov 29 06:54:15 2022 -0600

       SSH signed commit
   ```

## 제거된 SSH 키가 있는 서명된 커밋 {#signed-commits-with-removed-ssh-keys}

커밋에 서명하는 데 사용한 SSH 키를 취소하거나 삭제할 수 있습니다. 자세한 내용은 [SSH 키 제거](../../../ssh.md#remove-an-ssh-key)를 참조하세요.

SSH 키를 제거하면 해당 키로 서명된 모든 커밋에 영향을 미칠 수 있습니다:

- SSH 키를 취소하면 이전 커밋이 **미인증**으로 표시됩니다. 새 SSH 키를 추가할 때까지 모든 새 커밋도 **미인증**으로 표시됩니다.
- SSH 키를 삭제하면 이전 커밋에는 영향을 미치지 않습니다. 새 SSH 키를 추가할 때까지 모든 새 커밋이 **미인증**으로 표시됩니다.

## 관련 항목 {#related-topics}

- [X.509 인증서로 커밋 및 태그에 서명](x509.md)
- [GPG를 사용하여 커밋에 서명](gpg.md)
- [커밋 API](../../../../api/commits.md)
