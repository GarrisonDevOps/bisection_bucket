---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: '자습서: Git 리모트 URL 업데이트'
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

다음과 같은 경우 Git 리모트 URL을 업데이트합니다:

- 다른 Git 리포지토리 호스트에서 기존 프로젝트를 가져왔습니다.
- 조직이 프로젝트를 새로운 도메인 이름을 가진 새로운 GitLab 인스턴스로 이동했습니다.
- 프로젝트가 동일한 GitLab 인스턴스의 새 경로로 이름이 변경되었습니다.

> [!note]
> 이전 리모트에서 기존 로컬 작업 복사본이 없으면 이 자습서가 필요하지 않습니다. 대신 새 GitLab URL에서 프로젝트를 복제할 수 있습니다.

이 자습서에서는 로컬 리포지토리의 리모트 URL을 다음과 같이 업데이트하는 방법을 설명합니다:

- 미완성된 로컬 변경 사항을 손실하지 않습니다.
- 아직 GitLab에 게시되지 않은 변경 사항을 손실하지 않습니다.
- 새 URL에서 리포지토리의 새로운 복제된 작업 복사본을 만들지 않습니다.

이 자습서에서는 `git-remote` 명령을 사용하여 [리모트 및 추적된 리포지토리를 관리합니다](https://git-scm.com/docs/git-remote).

Git 리모트 URL을 업데이트하려면:

- [기존 및 새로운 URL 결정](#determine-existing-and-new-urls)
- [Git 리모트 URL 업데이트](#update-git-remote-urls)
- [(선택 사항) 원래 리모트 URL 유지](#optional-keep-original-remote-urls)

## 시작하기 전에 {#before-you-begin}

다음이 필요합니다:

- Git 리포지토리와 새 GitLab URL을 가진 GitLab 프로젝트입니다.
- 새 GitLab URL로 마이그레이션할 프로젝트의 복제된 로컬 작업 복사본입니다.
- 로컬 머신에 [설치된](../../topics/git/how_to_install_git/_index.md) Git.
- 로컬 머신의 명령줄 인터페이스(CLI)에 대한 액세스. macOS에서는 Terminal을 사용할 수 있습니다. Windows에서는 PowerShell을 사용할 수 있습니다. Linux 사용자는 자신의 시스템 CLI에 이미 익숙할 것입니다.
- GitLab 인증 자격 증명:
  - Git 리모트 URL을 업데이트하려면 GitLab으로 인증해야 합니다. GitLab 계정이 기본 사용자 이름 및 암호 인증을 사용하는 경우 CLI에서 인증하려면 [2단계 인증(2FA)](../../user/profile/account/two_factor_authentication.md)을 비활성화해야 합니다. 또는 [SSH 키를 사용하여 GitLab으로 인증](../../user/ssh.md)할 수 있습니다.

## 기존 및 새로운 URL 결정 {#determine-existing-and-new-urls}

Git 리모트 URL을 업데이트하려면 리포지토리의 기존 및 새로운 URL을 확인합니다:

1. 터미널 또는 명령 프롬프트를 엽니다.
1. 로컬 리포지토리 작업 복사본으로 이동합니다. 디렉터리를 변경하려면 `cd`을(를) 사용하세요:

   ```shell
   cd <repository-name>
   ```

1. 각 리포지토리에는 `origin`이라는 기본 리모트가 있습니다. 리모트 리포지토리의 현재 리모트 _fetch_ 및 _push_ URL을 보려면 다음을 실행합니다:

   ```shell
   git remote -v
   ```

1. 반환된 URL을 복사하고 기록해 둡니다. 일반적으로 동일합니다.
1. 새 URL 가져오기:
   1. GitLab으로 이동합니다.
   1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
   1. 왼쪽 사이드바에서 **코드** > **리포지토리**를 선택하여 프로젝트의 **리포지토리** 페이지로 이동합니다
   1. 오른쪽 위 모서리에서 **코드**를 선택합니다
   1. `git`을(를) 사용한 인증 및 복제 방법에 따라 HTTPS 또는 SSH URL을 복사합니다. 확실하지 않으면 이전 단계의 `origin` URL과 동일한 방법을 사용합니다.
   1. 복사된 URL을 기록해 둡니다.

## Git 리모트 URL 업데이트 {#update-git-remote-urls}

Git 리모트 URL을 업데이트하려면:

1. 터미널 또는 명령 프롬프트를 엽니다.
1. 로컬 리포지토리 작업 복사본으로 이동합니다. 디렉터리를 변경하려면 `cd`을(를) 사용하세요:

   ```shell
   cd <repository-name>
   ```

1. 리모트 URL을 업데이트하여 `<new_url>`을(를) 복사한 새 리포지토리 URL로 바꿉니다:

   ```shell
   git remote set-url origin <new_url>
   ```

1. 리모트 URL 업데이트가 성공했는지 확인합니다. 다음 명령은 fetch 및 push 작업 모두에 대한 새 URL을 표시하고, 로컬 브랜치를 나열하며, GitLab으로 추적 중임을 확인합니다:

   ```shell
   git remote show origin
   ```

   - 업데이트가 실패한 경우 이전 단계로 돌아가서 올바른 `<new_url>`이(가) 있는지 확인하고 다시 시도합니다.

여러 리포지토리의 리모트 URL을 업데이트하려면:

1. `git remote set-url` 명령을 사용합니다. `origin`을(를) 업데이트할 리모트의 이름으로 바꿉니다. 예를 들어:

   ```shell
   git remote set-url <remote_name> <new_url>
   ```

1. 각 리모트 URL 업데이트를 확인합니다:

   ```shell
   git remote show <remote_name>
   ```

리모트 URL을 업데이트한 후 평소대로 Git 명령을 계속 사용할 수 있습니다. 다음 `git fetch`, `git pull`, 또는 `git push`은 GitLab의 새 URL을 사용합니다.

축하합니다. 리포지토리의 리모트 URL을 성공적으로 업데이트했습니다.

## (선택 사항) 원래 리모트 URL 유지 {#optional-keep-original-remote-urls}

프로젝트에 둘 이상의 리모트 위치가 있을 수 있습니다. 예를 들어 GitHub에서 호스팅되는 프로젝트에서 포크된 리포지토리가 있지만 GitHub에 풀 요청하기 전에 GitLab에서 포크를 작업하려고 합니다.

원래 리모트 URL을 유지하면서 업데이트하고 새 리모트 URL과 기존 리모트 URL을 모두 유지하려면 기존 리모트를 수정하지 않고 새 리모트를 추가할 수 있습니다.

이 방법을 사용하면 원래 리포지토리에 대한 액세스를 유지하면서 새 URL로 점진적으로 전환할 수 있습니다.

새 리모트 URL을 추가하려면:

1. 터미널 또는 명령 프롬프트를 엽니다.
1. 로컬 리포지토리 작업 복사본으로 이동합니다.
1. 새 리모트 URL을 추가합니다. `<new_remote_name>`을(를) 새 리모트의 이름(예: `new-origin`)으로 바꾸고 `<new_url>`을(를) 새 리포지토리 URL로 바꿉니다:

   ```shell
   git remote add <new_remote_name> <new_url>
   ```

1. 새 리모트가 추가되었는지 확인합니다:

   ```shell
   git remote -v
   ```

이제 원래 리모트와 새 리모트를 모두 사용할 수 있습니다. 예를 들어:

- 원래 리모트로 푸시하려면: `git push origin main`
- 새 리모트로 푸시하려면: `git push <new_remote_name> main`
