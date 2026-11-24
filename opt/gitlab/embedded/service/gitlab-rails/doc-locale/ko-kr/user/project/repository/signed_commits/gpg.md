---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab 리포지토리에서 GPG(GNU Privacy Guard) 키로 커밋 및 태그에 서명합니다.
title: GPG로 커밋 및 태그에 서명
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab 리포지토리에서 [GPG(GNU Privacy Guard)](https://gnupg.org/) 키로 커밋에 서명할 수 있습니다.

> [!note]
> GitLab은 모든 OpenPGP, PGP 및 GPG 관련 자료 및 구현을 나타내기 위해 GPG라는 용어를 사용합니다.

GitLab이 커밋을 검증된 것으로 간주하려면:

- 커밋자는 GPG 공개/개인 키 쌍을 가지고 있어야 합니다.
- 커밋자의 공개 키는 GitLab 계정에 업로드되어야 합니다.
- GPG 공개 키의 이메일 주소 중 하나는 GitLab에서 커밋자가 사용하는 검증된 이메일 주소와 일치해야 합니다. GitLab은 해지된 사용자 ID의 이메일 주소를 무시합니다. 이 주소를 비공개로 유지하려면 GitLab이 프로필에 제공하는 자동으로 생성된 [비공개 커밋 이메일 주소](../../../profile/_index.md#use-an-automatically-generated-private-commit-email)를 사용하세요.
- 커밋자의 이메일 주소는 GPG 키의 검증된 이메일 주소와 일치해야 합니다.

GitLab은 자체 키링을 사용하여 GPG 서명을 검증합니다. 공개 키 서버에 액세스하지 않습니다.

GPG에 대한 자세한 내용은 [관련 항목 목록](#related-topics)을 참조하세요.

## 사용자의 공개 GPG 키 보기 {#view-a-users-public-gpg-key}

사용자의 공개 GPG 키를 보려면 다음 중 하나를 수행할 수 있습니다:

- `https://gitlab.example.com/<USERNAME>.gpg`로 이동합니다. GitLab은 사용자가 하나를 구성한 경우 GPG 키를 표시하고, 구성된 GPG 키가 없는 사용자의 경우 빈 페이지를 표시합니다.
- 사용자의 프로필(예: `https://gitlab.example.com/<USERNAME>`)로 이동합니다. 사용자 프로필의 오른쪽 위 모서리에서 **공개 GPG 키 보기**({{< icon name="key" >}})를 선택합니다. 이 버튼은 사용자가 키를 구성한 경우에만 표시됩니다.

## 커밋 서명 구성 {#configure-commit-signing}

커밋에 서명하려면 로컬 컴퓨터와 GitLab 계정을 모두 구성해야 합니다:

1. [GPG 키 생성](#create-a-gpg-key).
1. [계정에 GPG 키 추가](#add-a-gpg-key-to-your-account).
1. [Git과 GPG 키 연결](#associate-your-gpg-key-with-git).
1. [Git 커밋에 서명](#sign-your-git-commits).

### GPG 키 생성 {#create-a-gpg-key}

아직 GPG 키가 없으면 하나를 생성합니다:

1. 운영 체제용 [GPG 설치](https://www.gnupg.org/download/). 운영 체제에 `gpg2`가 설치되어 있으면 이 페이지의 명령에서 `gpg`를 `gpg2`로 바꿉니다.
1. GPG 버전에 적합한 명령을 실행하려면 `gpg`:

   ```shell
   # Use this command for the default version of GPG, including
   # Gpg4win on Windows, and most macOS versions:
   gpg --gen-key

   # Use this command for versions of GPG later than 2.1.17:
   gpg --full-gen-key
   ```

1. 키가 사용해야 할 알고리즘을 선택하거나 <kbd>Enter</kbd> 키를 눌러 기본 옵션인 `RSA and RSA`을(를) 선택합니다.
1. 비트 단위의 키 길이를 선택합니다. GitLab은 4096비트 키를 권장합니다.
1. 키의 유효 기간을 지정합니다. 이 값은 주관적이며 기본값은 만료 없음입니다.
1. 답을 확인하려면 `y`을(를) 입력합니다.
1. 이름을 입력하세요.
1. 이메일 주소를 입력하세요. GitLab 계정에서 [검증된 이메일 주소](../../../profile/_index.md#change-the-email-displayed-on-your-commits)와 일치해야 합니다.
1. 선택 사항. 이름 뒤의 괄호에 표시할 설명을 입력합니다.
1. GPG는 지금까지 입력한 정보를 표시합니다. 정보를 편집하거나 <kbd>O</kbd> 키(`Okay`)를 눌러 계속합니다.
1. 강력한 비밀번호를 입력한 다음 확인을 위해 다시 입력합니다.
1. 비공개 GPG 키를 나열하려면 이 명령을 실행하고 `<EMAIL>`을(를) 키를 생성할 때 사용한 이메일 주소로 바꿉니다:

   ```shell
   gpg --list-secret-keys --keyid-format LONG <EMAIL>
   ```

1. 출력에서 `sec` 줄을 식별하고 GPG 키 ID를 복사합니다. `/` 문자 뒤에 시작합니다. 이 예에서 키 ID는 `30F2B65B9246B6CA`입니다:

   ```plaintext
   sec   rsa4096/30F2B65B9246B6CA 2017-08-18 [SC]
         D5E4F29F3275DC0CDA8FFC8730F2B65B9246B6CA
   uid                   [ultimate] Mr. Robot <your_email>
   ssb   rsa4096/B7ABC0813E4028C0 2017-08-18 [E]
   ```

1. 연결된 공개 키를 표시하려면 이 명령을 실행하고 `<ID>`을(를) 이전 단계의 GPG 키 ID로 바꿉니다:

   ```shell
   gpg --armor --export <ID>
   ```

1. `BEGIN PGP PUBLIC KEY BLOCK` 및 `END PGP PUBLIC KEY BLOCK` 줄을 포함하여 공개 키를 복사합니다. 다음 단계에서 이 키가 필요합니다.

### 계정에 GPG 키 추가 {#add-a-gpg-key-to-your-account}

GPG 키를 사용자 설정에 추가하려면:

1. GitLab에 로그인합니다.
1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **GPG 키**를 선택합니다.
1. **새 키 추가**를 선택하세요.
1. **키**에 공개 키를 붙여넣습니다.
1. 계정에 키를 추가하려면 **키 추가**를 선택합니다.

GitLab은 키의 지문, 이메일 주소 및 생성 날짜를 표시합니다. GPG 키에서 사용자 ID를 해지하면 GitLab은 이메일 주소를 표시하지 않습니다. 해당 주소를 커밋자 이메일로 사용하는 커밋은 검증되지 않은 것으로 표시됩니다.

키를 추가한 후에는 편집할 수 없습니다. 대신 문제가 있는 키를 제거하고 다시 추가합니다.

### Git과 GPG 키 연결 {#associate-your-gpg-key-with-git}

[GPG 키를 생성](#create-a-gpg-key)하고 [계정에 추가](#add-a-gpg-key-to-your-account)한 후 Git이 이 키를 사용하도록 구성해야 합니다:

1. 이 명령을 실행하여 방금 생성한 비공개 GPG 키를 나열하고 `<EMAIL>`을(를) 키의 이메일 주소로 바꿉니다:

   ```shell
   gpg --list-secret-keys --keyid-format LONG <EMAIL>
   ```

1. `sec`로 시작하는 GPG 비공개 키 ID를 복사합니다. 이 예에서 비공개 키 ID는 `30F2B65B9246B6CA`입니다:

   ```plaintext
   sec   rsa4096/30F2B65B9246B6CA 2017-08-18 [SC]
         D5E4F29F3275DC0CDA8FFC8730F2B65B9246B6CA
   uid                   [ultimate] Mr. Robot <your_email>
   ssb   rsa4096/B7ABC0813E4028C0 2017-08-18 [E]
   ```

1. 이 명령을 실행하여 키로 커밋에 서명하도록 Git을 구성하고 `<KEY ID>`을(를) GPG 키 ID로 바꿉니다:

   ```shell
   git config --global user.signingkey <KEY ID>
   ```

### Git 커밋에 서명 {#sign-your-git-commits}

[계정에 공개 키를 추가](#add-a-gpg-key-to-your-account)한 후 개별 커밋에 수동으로 서명하거나 Git을 구성하여 기본적으로 서명된 커밋을 사용할 수 있습니다:

- 개별 Git 커밋에 수동으로 서명:
  1. 서명하려는 모든 커밋에 `-S` 플래그를 추가합니다:

     ```shell
     git commit -S -m "My commit message"
     ```

  1. 요청하면 GPG 키의 암호를 입력합니다.
  1. GitLab으로 푸시하고 커밋이 [검증되었는지 확인](_index.md#verify-commits)합니다.
- 이 명령을 실행하여 모든 Git 커밋에 기본적으로 서명합니다:

  ```shell
  git config --global commit.gpgsign true
  ```

#### 서명 키를 조건부로 설정 {#set-signing-key-conditionally}

업무 및 개인용 등 별도의 목적으로 서명 키를 유지하는 경우, `IncludeIf` 문을 `.gitconfig` 파일에서 사용하여 커밋에 서명하는 데 사용할 키를 설정합니다.

사전 요구 사항:

- Git 버전 2.13 이상이 필요합니다.

1. 주 `~/.gitconfig` 파일과 같은 디렉터리에서 `.gitconfig-gitlab`와 같은 두 번째 파일을 만듭니다.
1. 주 `~/.gitconfig` 파일에서 비 GitLab 프로젝트에서 작업하기 위한 Git 설정을 추가합니다.
1. 주 `~/.gitconfig` 파일의 끝에 이 정보를 추가합니다:

   ```ini
   # The contents of this file are included only for GitLab.com URLs
   [includeIf "hasconfig:remote.*.url:https://gitlab.com/**"]

   # Edit this line to point to your alternative configuration file
   path = ~/.gitconfig-gitlab
   ```

1. 대체 `.gitconfig-gitlab` 파일에서 GitLab 리포지토리에 커밋할 때 사용할 구성 재정의를 추가합니다. 주 `~/.gitconfig` 파일의 모든 설정이 유지되며 명시적으로 재정의하지 않는 한 유지됩니다. 이 예에서:

   ```ini
   # Alternative ~/.gitconfig-gitlab file
   # These values are used for repositories matching the string 'gitlab.com',
   # and override their corresponding values in ~/.gitconfig

   [user]
   email = you@example.com
   signingkey = <KEY ID>

   [commit]
   gpgsign = true
   ```

## 태그에 서명 및 확인 {#sign-and-verify-tags}

{{< history >}}

- GitLab 18.3에서 [기능 플래그를](../../../../administration/feature_flags/_index.md) 포함하여 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/19260) `render_gpg_signed_tags_verification_status`. 기본적으로 비활성화되었습니다.
- GitLab 19.0에서 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화됨](https://gitlab.com/gitlab-org/gitlab/-/issues/560619).
- GitLab 19.1에서 [일반적으로 사용 가능](https://gitlab.com/gitlab-org/gitlab/-/issues/599765)합니다. 기능 플래그 `render_gpg_signed_tags_verification_status`이 제거되었습니다.

{{< /history >}}

[Git과 GPG 키를 연결](#associate-your-gpg-key-with-git)한 후 태그에 서명할 수 있습니다:

1. Git 태그를 만들 때 `-s` 플래그를 추가합니다:

   ```shell
   git tag -s v1.1.1 -m "My signed tag"
   ```

1. GitLab으로 태그를 푸시합니다.
1. 서명을 로컬에서 확인하려면 다음을 실행합니다:

   ```shell
   git tag --verify v1.1.1
   ```

1. 선택 사항. 모든 태그에 자동으로 서명하려면 다음을 실행합니다:

   ```shell
   git config --global tag.gpgsign true
   ```

## GPG 키 해지 {#revoke-a-gpg-key}

GPG 키가 손상되면 해지합니다. 키를 해지하면 향후 커밋과 과거 커밋이 모두 변경됩니다:

- 이 키로 서명된 과거 커밋은 검증되지 않은 것으로 표시됩니다.
- 이 키로 서명된 향후 커밋은 검증되지 않은 것으로 표시됩니다.

GitLab에서 키를 해지하는 것은 GnuPG를 사용하여 키의 사용자 ID 중 하나를 해지하는 것과 다릅니다. 사용자 ID를 해지하면 해당 사용자 ID의 이메일 주소를 커밋자 이메일로 사용하는 커밋만 검증되지 않은 것으로 표시됩니다.

GPG 키를 해지하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **GPG 키**를 선택합니다.
1. 해지하려는 GPG 키 옆에서 **해지**를 선택합니다.

## GPG 키 제거 {#remove-a-gpg-key}

GitLab 계정에서 GPG 키를 제거할 때:

- 이 키로 서명된 이전 커밋은 검증된 상태로 유지됩니다.
- 이 키를 사용하려고 시도하는 향후 커밋(이미 생성되었지만 아직 푸시되지 않은 커밋 포함)은 검증되지 않습니다.

계정에서 GPG 키를 제거하려면:

1. 오른쪽 위 모서리에서 아바타를 선택합니다.
1. **프로필 편집**을 선택합니다.
1. 왼쪽 사이드바에서 **액세스** > **GPG 키**를 선택합니다.
1. 삭제하려는 GPG 키 옆에서 **삭제**({{< icon name="remove" >}})를 선택합니다.

향후 및 과거 커밋을 모두 검증 취소해야 하는 경우 대신 [관련 GPG 키를 해지](#revoke-a-gpg-key)하세요.

## 관련 항목 {#related-topics}

- [웹 UI에서 만든 커밋에 대한 커밋 서명 구성](../../../../administration/gitaly/configure_gitaly.md#configure-commit-signing-for-gitlab-ui-commits)
- GPG 리소스:
  - [Git 도구 - 작업에 서명](https://git-scm.com/book/en/v2/Git-Tools-Signing-Your-Work)
  - [OpenPGP 키 관리](https://riseup.net/en/security/message-security/openpgp/gpg-keys)
  - [OpenPGP 모범 사례](https://riseup.net/en/security/message-security/openpgp/best-practices)
  - [하위 키를 사용하여 새로운 GPG 키 만들기](https://www.void.gr/kargig/blog/2013/12/02/creating-a-new-gpg-key-with-subkeys/)(고급)
  - [인스턴스에서 GPG 키 보기](../../../../administration/credentials_inventory.md#view-the-credentials-inventory)
  - [Beyond Identity 통합](../../integrations/beyond_identity.md)

## 문제 해결 {#troubleshooting}

### 사용할 수 없는 비공개 키 {#secret-key-not-available}

`secret key not available` 또는 `gpg: signing failed: secret key not available` 오류를 받으면 `gpg` 대신 `gpg2`를 사용하십시오:

```shell
git config --global gpg.program gpg2
```

GPG 키가 비밀번호로 보호되어 있고 비밀번호 입력 프롬프트가 나타나지 않으면 `export GPG_TTY=$(tty)`을(를) 셸의 `rc` 파일(일반적으로 `~/.bashrc` 또는 `~/.zshrc`)에 추가합니다

### GPG가 데이터에 서명하지 못함 {#gpg-fails-to-sign-data}

GPG 키가 비밀번호로 보호되어 있고 다음 오류 중 하나를 받으면:

```plaintext
error: gpg failed to sign the data
fatal: failed to write commit object
gpg: signing failed: Inappropriate ioctl for device
```

비밀번호 입력 프롬프트가 나타나지 않으면:

1. 셸의 구성 파일(일반적으로 `~/.bashrc` 또는 `~/.zshrc`)을 텍스트 편집기에서 엽니다.
1. 파일에 다음 줄을 추가합니다:

   ```shell
   export GPG_TTY=$(tty)
   ```

1. 파일을 저장하고 텍스트 편집기를 종료합니다.
1. 변경 사항을 적용합니다. 다음 중 하나를 선택합니다:

   - 터미널을 다시 시작합니다.
   - `source ~/.bashrc` 또는 `source ~/.zshrc`를 실행합니다.

> [!note]
> 정확한 단계는 운영 체제 및 셸 구성에 따라 다를 수 있습니다.
