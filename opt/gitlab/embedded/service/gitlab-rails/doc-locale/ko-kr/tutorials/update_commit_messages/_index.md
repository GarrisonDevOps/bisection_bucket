---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: '자습서: Git 커밋 메시지 업데이트'
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

브랜치에 몇 개의 커밋을 수행한 후 하나 이상의 커밋 메시지를 업데이트해야 한다는 것을 깨닫게 되는 경우가 있습니다. 오타를 발견했거나 프로젝트의 [커밋 메시지 지침](../../topics/git/commit.md#write-a-good-commit-message)과 완전히 맞지 않다고 자동화 도구에서 경고했을 수도 있습니다.

명령줄 인터페이스(CLI)를 사용해 본 경험이 별로 없다면 메시지를 업데이트하기가 까다로울 수 있습니다. 하지만 걱정하지 마세요. GitLab UI에서만 작업해 본 경우에도 이 단계를 따라 CLI를 사용할 수 있습니다.

이 자습서는 커밋 메시지를 다시 작성하는 방법을 설명합니다. GitLab UI에서만 작업하는 경우 처음부터 시작하세요. 이미 리포지토리를 로컬에 복제한 경우 브랜치를 가져오고 확인하는 단계로 건너뛸 수 있습니다.

## 시작하기 전에 {#before-you-begin}

다음이 필요합니다:

- 업데이트하려는 커밋이 포함된 Git 브랜치가 있는 GitLab 프로젝트.
- 로컬 머신에 [설치된](../../topics/git/how_to_install_git/_index.md) Git.
- 로컬 머신의 명령줄 인터페이스(CLI)에 대한 액세스. macOS에서는 Terminal을 사용할 수 있습니다. Windows에서는 PowerShell을 사용할 수 있습니다. Linux 사용자는 자신의 시스템 CLI에 이미 익숙할 것입니다.
- 시스템의 기본 편집기에 대한 숙련도. 이 자습서는 편집기가 Vim이라고 가정하지만 모든 텍스트 편집기가 작동합니다. Vim을 사용해 본 경험이 없으면 [Vim 시작하기](https://opensource.com/article/19/3/getting-started-vim)의 단계 1과 2에서 이 자습서의 뒷부분에서 사용되는 모든 명령을 설명합니다.
- 커밋 메시지를 덮어쓸 수 있는 권한. 같은 브랜치에서 여러 사람과 함께 작업하는 경우 먼저 커밋을 업데이트해도 괜찮은지 확인하세요. 일부 조직은 커밋 재작성 금지 규칙이 있을 수 있습니다. 이는 파괴적인 변경으로 간주되기 때문입니다.

마지막 단계에서 커밋 메시지를 덮어쓰려면 GitLab으로 인증해야 합니다. GitLab 계정이 기본 사용자 이름 및 암호 인증을 사용하는 경우 CLI에서 인증하려면 [2단계 인증(2FA)](../../user/profile/account/two_factor_authentication.md)을 비활성화해야 합니다. 또는 [SSH 키를 사용하여 GitLab으로 인증](../../user/ssh.md)할 수 있습니다.

## 리포지토리를 로컬 머신에 복제 {#clone-your-repository-to-your-local-machine}

시작하려면 머신에서 리포지토리의 로컬 복사본을 만듭니다.

{{< guide >}}

1. 리포지토리 URL을 복사합니다.

   GitLab의 프로젝트 개요 페이지 오른쪽 위에서 **코드**를 선택합니다. 드롭다운 목록에서 다음 옆의 {{< icon name="copy-to-clipboard" >}}을 선택하여 리포지토리의 URL을 복사합니다:

   - GitLab 계정이 기본 사용자 이름 및 암호 인증을 사용하는 경우 **HTTPS로 복제**.
   - SSH를 사용하여 GitLab으로 인증하는 경우 **SSH로 clone**.

1. 리포지토리를 복제합니다.

   로컬 머신의 CLI(Terminal, PowerShell 등)로 전환하고 리포지토리를 복제할 디렉터리로 이동합니다. 예를 들어, `/users/my-username/my-projects/`입니다. `git clone`를 실행하고 이전에 복사한 URL을 붙여넣습니다:

   ```shell
   git clone https://gitlab.com/my-username/my-awesome-project.git
   ```

   이렇게 하면 리포지토리가 `my-awesome-project/`라는 새 디렉터리로 복제됩니다.

{{< /guide >}}

이제 리포지토리가 컴퓨터에 있고 Git CLI 명령을 사용할 준비가 되었습니다.

## 브랜치를 가져오고 확인 {#fetch-and-check-out-your-branch}

다음으로 업데이트하려는 커밋이 포함된 브랜치로 전환합니다.

{{< guide >}}

1. 프로젝트 디렉터리로 변경합니다.

   이전 단계와 같은 CLI 위치에 있다고 가정하고 `cd`을 사용하여 프로젝트 디렉터리로 변경합니다:

   ```shell
   cd my-awesome-project
   ```

1. 필요한 경우 브랜치를 가져옵니다.

   방금 리포지토리를 복제한 경우 브랜치가 이미 컴퓨터에 있어야 합니다. 하지만 이전에 리포지토리를 복제했고 이 단계로 건너뛴 경우 브랜치를 가져와야 할 수도 있습니다:

   ```shell
   git fetch origin my-branch-name
   ```

1. 브랜치를 확인합니다.

   이제 브랜치가 로컬 시스템에 있으므로 다음으로 전환합니다:

   ```shell
   git checkout my-branch-name
   ```

1. 올바른 브랜치에 있는지 확인합니다.

   `git log`을 실행하고 가장 최근 커밋이 GitLab의 브랜치에 있는 커밋과 일치하는지 확인합니다. 로그를 종료하려면 `q`을 사용합니다.

{{< /guide >}}

## 커밋 메시지 업데이트 {#update-the-commit-messages}

이제 대화형 리베이스를 사용하여 커밋 메시지를 다시 작성할 준비가 되었습니다.

{{< guide >}}

1. 업데이트할 커밋 수를 결정합니다.

   GitLab에서 커밋 기록에서 얼마나 뒤로 가야 하는지 확인합니다:

   - 이미 브랜치에 대해 열린 머지 리퀘스트가 있으면 **커밋** 탭을 확인하고 커밋의 총 개수를 사용할 수 있습니다.
   - 브랜치에서만 작업하는 경우:
     1. **코드** > **커밋**으로 이동합니다.
     1. 왼쪽 위의 드롭다운 목록을 선택하고 브랜치를 찾습니다.
     1. 업데이트하려는 가장 오래된 커밋을 찾아 그 커밋이 얼마나 뒤에 있는지 셉니다. 예를 들어 두 번째와 네 번째 커밋을 업데이트하려면 개수는 4입니다.

1. 대화형 리베이스를 시작합니다.

   CLI에서 이전 단계의 커밋 개수를 `HEAD~`의 끝에 추가하여 리베이스 프로세스를 시작합니다:

   ```shell
   git rebase -i HEAD~4
   ```

   이 예에서 Git은 브랜치의 4개의 가장 최근 커밋을 선택하여 업데이트합니다.
1. 다시 작성할 커밋을 표시합니다.

   Git은 텍스트 편집기를 시작하고 선택한 커밋을 나열합니다. 예를 들어 다음과 같이 표시됩니다:

   ```shell
   pick a0cea50 Fix broken link
   pick bb84712 Update milestone-plan.md
   pick ce11fad Add list of maintainers
   pick d211d03 update template.md

   # Rebase 1f5ec88..d211d03 onto 1f5ec88 (4 commands)
   #
   # Commands:
   # p, pick <commit> = use commit
   # r, reword <commit> = use commit, but edit the commit message
   # e, edit <commit> = use commit, but stop for amending
   # s, squash <commit> = use commit, but meld into previous commit
   # f, fixup [-C | -c] <commit> = like "squash" but keep only the previous
   #                    commit's log message, unless -C is used, in which case
   # [and so on...]
   ```

   `pick` 명령은 Git에게 커밋을 변경 없이 사용하도록 알려줍니다. 업데이트하려는 커밋의 명령을 `pick`에서 `reword`으로 변경합니다. `i`을 입력하여 `INSERT` 모드로 들어간 후 텍스트 편집을 시작합니다.

   예를 들어 이전 샘플의 두 번째와 네 번째 커밋의 텍스트를 업데이트하려면 다음과 같이 편집합니다:

   ```shell
   pick a0cea50 Fix broken link
   reword bb84712 Update milestone-plan.md
   pick ce11fad Add list of maintainers
   reword d211d03 update template.md
   ```

1. 변경 사항을 저장합니다.

   <kbd>Esc</kbd>를 눌러 `INSERT` 모드를 종료한 후 `:wq`을 입력하고 <kbd>Enter</kbd>를 눌러 저장하고 종료합니다.
1. 각 커밋 메시지를 업데이트합니다.

   Git은 이제 각 커밋을 한 번에 하나씩 진행합니다. `pick`이 있는 모든 커밋이 변경되지 않은 상태로 브랜치에 다시 추가됩니다. Git이 `reword`이 있는 커밋에 도달하면 중지하고 텍스트 편집기를 다시 엽니다.

   필요에 따라 커밋 메시지를 업데이트합니다:

   - 한 줄의 커밋 메시지의 경우 텍스트를 업데이트합니다. 예를 들어:

   ```plaintext
   Update the monthly milestone plan
   ```

   - 제목과 본문이 있는 커밋 메시지의 경우 빈 줄로 구분합니다. 예를 들어:

   ```plaintext
   Update the monthly milestone plan

   Make the milestone plan clearer by listing the responsibilities
   of each maintainer.
   ```

   저장하고 종료한 후 Git은 커밋 메시지를 업데이트하고 다음 커밋을 순서대로 처리합니다. 완료되면 `Successfully rebased and update refs/heads/my-branch-name` 메시지가 표시되어야 합니다.

1. 업데이트를 확인합니다.

   커밋 메시지가 업데이트되었는지 확인하려면 `git log`을 실행하고 아래로 스크롤하여 커밋 메시지를 봅니다.

{{< /guide >}}

## 변경 사항을 GitLab에 푸시 {#push-the-changes-to-gitlab}

마지막으로 업데이트된 커밋을 GitLab으로 다시 푸시합니다.

{{< guide >}}

1. 변경 사항을 강제 푸시합니다.

   CLI에서 변경 사항을 GitLab으로 다시 푸시합니다. `-f` "강제 푸시" 옵션을 사용해야 합니다. 커밋이 업데이트되었고 강제 푸시는 GitLab의 기존 커밋을 덮어쓰기 때문입니다:

   ```shell
   git push -f origin
   ```

   GitLab에서 커밋 메시지를 덮어쓰기 전에 터미널에서 사용자 이름과 암호를 입력하라는 메시지가 표시될 수 있습니다.
1. GitLab에서 변경 사항을 확인합니다.

   GitLab의 프로젝트에서 커밋이 업데이트되었는지 확인합니다:

   - 이미 브랜치에 대해 열린 머지 리퀘스트가 있으면 **커밋** 탭을 확인합니다.
   - 브랜치에서만 작업하는 경우:
     1. **코드** > **커밋**으로 이동합니다.
     1. 왼쪽 위의 드롭다운 목록을 선택하고 브랜치를 찾습니다.
     1. 목록의 관련 커밋이 이제 업데이트되었는지 확인합니다.

{{< /guide >}}

축하합니다. 커밋 메시지를 성공적으로 업데이트하고 GitLab으로 푸시했습니다!
