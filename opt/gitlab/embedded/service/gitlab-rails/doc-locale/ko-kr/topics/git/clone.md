---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: SSH 또는 HTTPS와 같은 다양한 프로토콜과 여러 IDE를 사용하여 GitLab 서버에서 Git 리포지토리를 clone하는 방법을 알아봅니다.
title: Git 리포지토리를 로컬 컴퓨터에 clone하기
---

Git 리포지토리를 로컬 컴퓨터에 clone할 수 있습니다. 이 작업은 리포지토리의 사본을 만들고 컴퓨터와 GitLab 서버 간의 변경 사항을 동기화하는 연결을 설정합니다. 이 연결을 위해서는 자격 증명을 추가해야 합니다. [SSH로 clone](#clone-with-ssh)하거나 [HTTPS로 clone](#clone-with-https)할 수 있습니다. SSH는 권장되는 인증 방법입니다.

리포지토리 clone:

- 모든 프로젝트 파일, 히스토리 및 메타데이터를 로컬 머신에 다운로드합니다.
- 최신 버전의 파일이 포함된 작업 디렉터리를 만듭니다.
- 향후 변경 사항을 동기화하도록 원격 추적을 설정합니다.
- 완전한 코드베이스에 대한 오프라인 액세스를 제공합니다.
- 프로젝트에 코드를 기여하기 위한 기초를 설정합니다.

## SSH로 clone {#clone-with-ssh}

한 번만 인증하려는 경우 SSH로 clone합니다.

1. [SSH 설명서](../../user/ssh.md)의 지침에 따라 GitLab으로 인증합니다.
1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 clone하려는 프로젝트를 찾습니다.
1. 프로젝트의 개요 페이지의 우측 상단 모서리에서 **코드**를 선택한 다음 **SSH로 clone**의 URL을 복사합니다.
1. 터미널을 열고 파일을 clone할 디렉터리로 이동합니다. Git은 리포지토리 이름으로 폴더를 자동 생성하고 파일을 그 위치에 다운로드합니다.
1. 다음 명령을 실행합니다:

   ```shell
   git clone <copied URL>
   ```

1. 파일을 보려면 새 디렉터리로 이동합니다:

   ```shell
   cd <new directory>
   ```

## HTTPS로 clone {#clone-with-https}

컴퓨터와 GitLab 간의 각 작업을 수행할 때마다 인증하려는 경우 HTTPS로 clone합니다. [OAuth 자격 증명 도우미](../../user/profile/account/two_factor_authentication.md#oauth-credential-helpers)는 수동 인증이 필요한 횟수를 줄일 수 있으므로 HTTPS를 원활한 환경으로 만듭니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 clone하려는 프로젝트를 찾습니다.
1. 프로젝트의 개요 페이지의 우측 상단 모서리에서 **코드**를 선택한 다음 **HTTPS로 clone**의 URL을 복사합니다.
1. 터미널을 열고 파일을 clone할 디렉터리로 이동합니다.
1. 다음 명령을 실행합니다. Git은 리포지토리 이름으로 폴더를 자동 생성하고 파일을 그 위치에 다운로드합니다.

   ```shell
   git clone <copied URL>
   ```

1. 요청을 인증합니다.

   > [!note]
   > 2단계 인증(2FA)을 활성화한 경우 사용자 이름 및 비밀번호 인증을 사용할 수 없습니다. 대신:
   >
   > - [토큰 사용](#clone-using-a-token)(`read_repository` 또는 `write_repository` 권한 포함)
   > - [OAuth 자격 증명 도우미](../../user/profile/account/two_factor_authentication.md#oauth-credential-helpers) 설치

1. 파일을 보려면 새 디렉터리로 이동합니다:

   ```shell
   cd <new directory>
   ```

> [!note]
> Windows에서 비밀번호를 잘못 입력한 후 `Access denied` 메시지가 표시되면 네임스페이스(사용자 이름 또는 그룹)를 경로에 추가합니다: `git clone https://namespace@gitlab.com/gitlab-org/gitlab.git`

### 토큰을 사용하여 clone {#clone-using-a-token}

다음의 경우 HTTPS를 사용하여 토큰으로 clone합니다:

- 2FA를 사용하려고 합니다.
- 하나 이상의 리포지토리로 범위가 지정된 해지 가능한 자격 증명 세트를 원합니다.

HTTPS를 통해 clone할 때 인증하는 데 이러한 토큰을 사용할 수 있습니다:

- [개인 액세스 토큰](../../user/profile/personal_access_tokens.md)
- [배포 토큰](../../user/project/deploy_tokens/_index.md)
- [프로젝트 액세스 토큰](../../user/project/settings/project_access_tokens.md)
- [그룹 액세스 토큰](../../user/group/settings/group_access_tokens.md)

예를 들어:

```shell
git clone https://<username>:<token>@gitlab.example.com/tanuki/awesome_project.git
```

## Apple Xcode에서 clone하고 열기 {#clone-and-open-in-apple-xcode}

`.xcodeproj` 또는 `.xcworkspace` 디렉터리가 포함된 프로젝트는 macOS의 Xcode로 clone할 수 있습니다.

1. GitLab UI에서 프로젝트의 개요 페이지로 이동합니다.
1. 우측 상단 모서리에서 **코드**를 선택합니다.
1. **Xcode**를 선택합니다.

프로젝트가 컴퓨터로 clone되고 Xcode를 열라는 메시지가 표시됩니다.

## Visual Studio Code에서 clone하고 열기 {#clone-and-open-in-visual-studio-code}

모든 프로젝트는 GitLab 사용자 인터페이스에서 Visual Studio Code로 clone할 수 있지만 Visual Studio Code에서 clone하기 위해 [GitLab for VS Code 확장](../../editor_extensions/visual_studio_code/_index.md)을 설치할 수도 있습니다.

전제 조건:

- [Visual Studio Code](https://code.visualstudio.com/)는 로컬 머신에 설치되어야 합니다. VS Code Insiders 및 VSCodium과 같은 다른 버전의 VS Code는 지원되지 않습니다.
- [IDE 프로토콜에 대한 브라우저 구성](#configure-browsers-for-ide-protocols)
- GitLab 인터페이스에서:
  1. 프로젝트의 개요 페이지로 이동합니다.
  1. 우측 상단 모서리에서 **코드**를 선택합니다.
  1. **IDE에서 열기** 아래에서 **Visual Studio Code (SSH)** 또는 **Visual Studio Code(HTTPS)**를 선택합니다.
  1. 프로젝트를 clone할 폴더를 선택합니다.

     Visual Studio Code가 프로젝트를 clone한 후 폴더를 엽니다.
- Visual Studio Code에서 [확장](../../editor_extensions/visual_studio_code/_index.md)이 설치된 상태에서 확장의 [`Git: Clone` 명령](../../editor_extensions/visual_studio_code/remote_urls.md#clone-a-git-project)을 사용합니다.

## IntelliJ IDEA에서 clone하고 열기 {#clone-and-open-in-intellij-idea}

모든 프로젝트는 GitLab 사용자 인터페이스에서 [IntelliJ IDEA](https://www.jetbrains.com/idea/)로 clone할 수 있습니다.

전제 조건:

- [IntelliJ IDEA](https://www.jetbrains.com/idea/)는 로컬 머신에 설치되어야 합니다.
- [IDE 프로토콜에 대한 브라우저 구성](#configure-browsers-for-ide-protocols)

다음과 같이 설정합니다.

1. 프로젝트의 개요 페이지로 이동합니다.
1. 우측 상단 모서리에서 **코드**를 선택합니다.
1. **IDE에서 열기** 아래에서 **IntelliJ IDEA(SSH)** 또는 **IntelliJ IDEA(HTTPS)**를 선택합니다.

## IDE 프로토콜에 대한 브라우저 구성 {#configure-browsers-for-ide-protocols}

**IDE에서 열기** 기능이 작동하는지 확인하려면 `vscode://` 또는 `jetbrains://`과 같은 사용자 지정 응용 프로그램 프로토콜을 처리하도록 브라우저를 구성해야 합니다.

### Firefox {#firefox}

필요한 응용 프로그램이 시스템에 설치되어 있으면 Firefox는 사용자 지정 프로토콜을 자동으로 처리합니다. 처음으로 사용자 지정 프로토콜 링크를 선택하면 대화 상자가 열리고 응용 프로그램을 열지 확인합니다. **링크 열기**를 선택하여 Firefox가 응용 프로그램을 열 수 있도록 합니다.

다시 메시지를 표시하지 않으려면 확인란을 선택하여 선택 사항을 기억합니다.

프롬프트 대화 상자가 열리지 않으면 Firefox를 수동으로 구성해야 합니다:

1. Firefox를 엽니다.
1. 우측 상단에서 **응용 프로그램 메뉴 열기**({{< icon name="hamburger" >}})를 선택합니다.
1. **응용 프로그램** 섹션을 검색하거나 이동합니다.
1. 목록에서 원하는 응용 프로그램을 찾아 선택합니다. 예를 들어 `vscode` 또는 `jetbrains`입니다.
1. 드롭다운 목록에서 Visual Studio Code 또는 IntelliJ IDEA를 선택하거나 **다른 항목 사용...**을 선택하여 실행 파일을 찾습니다.

선호하는 IDE가 나열되지 않으면 해당 링크를 처음 선택할 때 응용 프로그램을 선택하라는 메시지가 표시됩니다.

### Chrome {#chrome}

필요한 응용 프로그램이 시스템에 설치되어 있으면 Chrome은 사용자 지정 프로토콜을 자동으로 처리합니다. Chrome에서 처음으로 사용자 지정 프로토콜 링크를 선택하면 대화 상자가 열리고 응용 프로그램을 열지 확인합니다. **열기**를 선택하여 Chrome이 응용 프로그램을 열 수 있도록 합니다.

다시 메시지를 표시하지 않으려면 확인란을 선택하여 선택 사항을 기억합니다.

## clone 크기 줄이기 {#reduce-clone-size}

Git 리포지토리가 커지면 다음으로 인해 작업하기 번거로워질 수 있습니다:

- 다운로드해야 할 많은 양의 히스토리
- 필요한 많은 양의 디스크 공간

[부분 clone](https://git-scm.com/docs/partial-clone)은 리포지토리의 완전한 사본이 없어도 Git이 작동할 수 있게 하는 성능 최적화입니다. 이 작업의 목표는 Git이 매우 큰 리포지토리를 더 잘 처리할 수 있도록 하는 것입니다.

Git 2.22.0 이상이 필요합니다.

### 파일 크기로 필터링 {#filter-by-file-size}

큰 바이너리 파일을 Git에 저장하는 것은 일반적으로 권장되지 않습니다. 추가된 모든 큰 파일은 이후에 clone하거나 변경 사항을 가져오는 모든 사용자가 다운로드하기 때문입니다. 이러한 다운로드는 특히 느리거나 불안정한 인터넷 연결에서 작업할 때 느리고 문제가 될 수 있습니다.

파일 크기 필터를 사용한 부분 clone은 clone 및 가져오기에서 문제가 되는 큰 파일을 제외하여 이 문제를 해결합니다. Git이 누락된 파일을 발견하면 필요할 때 다운로드합니다.

리포지토리를 clone할 때 `--filter=blob:limit=<size>` 인수를 사용합니다. 예를 들어 1메가바이트보다 큰 파일을 제외하고 리포지토리를 clone하려면:

```shell
git clone --filter=blob:limit=1m git@gitlab.com:gitlab-com/www-gitlab-com.git
```

다음과 같은 출력이 생성됩니다:

```shell
Cloning into 'www-gitlab-com'...
remote: Enumerating objects: 832467, done.
remote: Counting objects: 100% (832467/832467), done.
remote: Compressing objects: 100% (207226/207226), done.
remote: Total 832467 (delta 585563), reused 826624 (delta 580099), pack-reused 0
Receiving objects: 100% (832467/832467), 2.34 GiB | 5.05 MiB/s, done.
Resolving deltas: 100% (585563/585563), done.
remote: Enumerating objects: 146, done.
remote: Counting objects: 100% (146/146), done.
remote: Compressing objects: 100% (138/138), done.
remote: Total 146 (delta 8), reused 144 (delta 8), pack-reused 0
Receiving objects: 100% (146/146), 471.45 MiB | 4.60 MiB/s, done.
Resolving deltas: 100% (8/8), done.
Updating files: 100% (13008/13008), done.
Filtering content: 100% (3/3), 131.24 MiB | 4.65 MiB/s, done.
```

출력이 더 길어지는 이유는 Git이 다음을 수행하기 때문입니다:

1. 1메가바이트보다 큰 파일을 제외하고 리포지토리를 clone합니다.
1. 기본 브랜치를 확인하는 데 필요한 누락된 대용량 파일을 다운로드합니다.

브랜치를 변경하면 Git이 더 많은 누락된 파일을 다운로드할 수 있습니다.

### 개체 유형으로 필터링 {#filter-by-object-type}

수백만 개의 파일과 긴 히스토리가 있는 리포지토리의 경우 모든 파일을 제외하고 [`git sparse-checkout`](https://git-scm.com/docs/git-sparse-checkout)을 사용하여 작업 사본의 크기를 줄일 수 있습니다.

```shell
# Clone the repo excluding all files
$ git clone --filter=blob:none --sparse git@gitlab.com:gitlab-com/www-gitlab-com.git
Cloning into 'www-gitlab-com'...
remote: Enumerating objects: 678296, done.
remote: Counting objects: 100% (678296/678296), done.
remote: Compressing objects: 100% (165915/165915), done.
remote: Total 678296 (delta 472342), reused 673292 (delta 467476), pack-reused 0
Receiving objects: 100% (678296/678296), 81.06 MiB | 5.74 MiB/s, done.
Resolving deltas: 100% (472342/472342), done.
remote: Enumerating objects: 28, done.
remote: Counting objects: 100% (28/28), done.
remote: Compressing objects: 100% (25/25), done.
remote: Total 28 (delta 0), reused 12 (delta 0), pack-reused 0
Receiving objects: 100% (28/28), 140.29 KiB | 341.00 KiB/s, done.
Updating files: 100% (28/28), done.

$ cd www-gitlab-com

$ git sparse-checkout set data --cone
remote: Enumerating objects: 301, done.
remote: Counting objects: 100% (301/301), done.
remote: Compressing objects: 100% (292/292), done.
remote: Total 301 (delta 16), reused 102 (delta 9), pack-reused 0
Receiving objects: 100% (301/301), 1.15 MiB | 608.00 KiB/s, done.
Resolving deltas: 100% (16/16), done.
Updating files: 100% (302/302), done.
```

자세한 내용은 [`sparse-checkout`](https://git-scm.com/docs/git-sparse-checkout)에 대한 Git 설명서를 참조하세요.

### 파일 경로로 필터링 {#filter-by-file-path}

부분 clone과 sparse checkout 간의 더 깊은 통합은 `--filter=sparse:oid=<blob-ish>` 필터 사양을 통해 가능합니다. 이 필터링 모드는 `.gitignore` 파일과 유사한 형식을 사용하여 clone 및 가져오기 시 포함할 파일을 지정합니다.

> [!warning]
> 부분 clone에 `sparse` 필터를 사용하는 것은 여전히 실험 단계입니다. clone 및 가져오기 시 리소스 활용이 느릴 수 있고 [Gitaly](../../administration/gitaly/_index.md) 리소스 활용을 크게 증가시킬 수 있습니다. [모든 blob을 필터링하고 sparse-checkout을 사용](#filter-by-object-type)하세요. [`git-sparse-checkout`](https://git-scm.com/docs/git-sparse-checkout)은 이 유형의 부분 clone 사용을 단순화하고 그 제한을 극복합니다.

자세한 내용은 [`rev-list-options`](https://git-scm.com/docs/git-rev-list#Documentation/git-rev-list.txt---filterltfilter-specgt)에 대한 Git 설명서를 참조하세요.

1. 필터 사양을 만듭니다. 예를 들어 각각 루트의 다른 하위 디렉터리에 있는 많은 응용 프로그램이 있는 단일 리포지토리를 생각해 봅시다. `shiny-app/.filterspec` 파일을 만듭니다:

   ```plaintext
   # Only the paths listed in the file will be downloaded when performing a
   # partial clone using `--filter=sparse:oid=shiny-app/.gitfilterspec`

   # Explicitly include filterspec needed to configure sparse checkout with
   # git config --local core.sparsecheckout true
   # git show master:snazzy-app/.gitfilterspec >> .git/info/sparse-checkout
   shiny-app/.gitfilterspec

   # Shiny App
   shiny-app/

   # Dependencies
   shimmery-app/
   shared-component-a/
   shared-component-b/
   ```

1. 경로별로 clone 및 필터링합니다. clone 명령으로 `--filter=sparse:oid`을(를) 사용하는 것은 sparse checkout과 완전히 통합되지 않았습니다.

   ```shell
   # Clone the filtered set of objects using the filterspec stored on the
   # server. WARNING: this step may be very slow!
   git clone --sparse --filter=sparse:oid=master:shiny-app/.gitfilterspec <url>

   # Optional: Check for missing objects that have not been fetched
   git rev-list --all --quiet --objects --missing=print | wc -l
   ```

   > [!warning]
   > `bash`, Zsh 등과의 Git 통합 및 Git 상태 정보를 자동으로 표시하는 편집기는 종종 전체 리포지토리를 가져오는 `git fetch`을(를) 실행합니다. 이러한 통합을 비활성화하거나 재구성해야 할 수 있습니다.

### 부분 clone 필터링 제거 {#remove-partial-clone-filtering}

부분 clone 필터링이 있는 Git 리포지토리는 필터링을 제거할 수 있습니다. 필터링을 제거하려면:

1. 필터에서 제외된 모든 항목을 가져와서 리포지토리가 완전한지 확인합니다. `git sparse-checkout`이 사용된 경우 `git sparse-checkout disable`을(를) 사용하여 비활성화합니다. [`disable` 설명서](https://git-scm.com/docs/git-sparse-checkout#Documentation/git-sparse-checkout.txt-emdisableem)를 참조하여 자세히 알아봅니다.

   그런 다음 정기적인 `fetch`을(를) 수행하여 리포지토리가 완전한지 확인합니다. 가져올 누락된 개체가 있는지 확인한 후 가져오고, 특히 `git sparse-checkout`을(를) 사용하지 않을 때 다음 명령을 사용할 수 있습니다:

   ```shell
   # Show missing objects
   git rev-list --objects --all --missing=print | grep -e '^\?'

   # Show missing objects without a '?' character before them (needs GNU grep)
   git rev-list --objects --all --missing=print | grep -oP '^\?\K\w+'

   # Fetch missing objects
   git fetch origin $(git rev-list --objects --all --missing=print | grep -oP '^\?\K\w+')

   # Show number of missing objects
   git rev-list --objects --all --missing=print | grep -e '^\?' | wc -l
   ```

1. 모든 항목을 다시 압축합니다. 예를 들어 `git repack -a -d`을(를) 사용하여 수행할 수 있습니다. 이렇게 하면 `.git/objects/pack/` 내에만 세 개의 파일이 남아야 합니다:
   - `pack-<SHA1>.pack` 파일
   - 해당하는 `pack-<SHA1>.idx` 파일
   - `pack-<SHA1>.promisor` 파일

1. `.promisor` 파일을 삭제합니다. 이전 단계에서 빈 상태여야 하는 `pack-<SHA1>.promisor` 파일 하나만 남아야 하므로 삭제해야 합니다.
1. 부분 clone 구성을 제거합니다. 부분 clone 관련 구성 변수는 Git 구성 파일에서 제거해야 합니다. 일반적으로 다음 구성만 제거해야 합니다:
   - `remote.origin.promisor`.
   - `remote.origin.partialclonefilter`.
