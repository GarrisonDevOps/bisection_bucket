---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: Git 리포지토리의 콘텐츠를 다른 리포지토리로 푸시하거나 풀하기 위해 리포지토리 미러링을 사용합니다.
title: 리포지토리 미러링
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

리포지토리를 외부 소스로 그리고 외부 소스에서 미러링할 수 있습니다. 어느 리포지토리를 소스로 사용할지 선택할 수 있습니다. 브랜치, 태그 및 커밋이 자동으로 동기화됩니다.

여러 미러링 방법이 있습니다:

- [푸시](push.md): 리포지토리를 GitLab에서 다른 위치로 미러링합니다.
- [풀](pull.md): 리포지토리를 다른 위치에서 미러링합니다. Premium 및 Ultimate 티어에서 사용 가능합니다.
- [양방향](bidirectional.md) 미러링도 사용할 수 있지만 충돌을 일으킬 수 있습니다.

다음의 경우 리포지토리를 미러링합니다:

- 프로젝트의 정식 버전이 GitLab으로 마이그레이션되었습니다. 이전 위치에서 프로젝트 사본을 계속 제공하려면 GitLab 리포지토리를 [푸시 미러](push.md)로 구성합니다. GitLab 리포지토리에서 수행한 변경 사항이 이전 위치로 복사됩니다.
- GitLab 인스턴스는 비공개이지만 일부 프로젝트를 오픈 소스로 제공하고 싶습니다.
- GitLab으로 마이그레이션했지만 프로젝트의 정식 버전이 다른 곳에 있습니다. GitLab 리포지토리를 다른 프로젝트의 [풀 미러](pull.md)로 구성합니다. GitLab 리포지토리가 프로젝트의 커밋, 태그 및 브랜치 사본을 풀합니다. 이들은 GitLab에서 사용할 수 있게 됩니다.

다음은 지원되지 않습니다:

- SCP 스타일 URL. SCP 스타일 URL을 구현하는 작업이 진행 중입니다. 자세한 정보 및 진행 상황을 추적하려면 [이슈 18993](https://gitlab.com/gitlab-org/gitlab/-/issues/18993)을 참조하세요.
- [dumb HTTP protocol](https://git-scm.com/book/en/v2/Git-on-the-Server-The-Protocols#_dumb_http)을 통한 리포지토리 미러링.
- 다른 객체 형식을 사용하는 리포지토리 간 미러링. 예를 들어 SHA-1과 [SHA-256](../../_index.md#create-a-project-that-uses-sha-256-hashing) 리포지토리 간.

## 리포지토리 미러 만들기 {#create-a-repository-mirror}

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.
- 미러가 `ssh://`에 연결되는 경우 호스트 키가 서버에서 감지 가능하거나 키의 로컬 사본이 있어야 합니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **리포지토리 미러링**을 확장합니다.
1. **신규 추가**를 선택합니다.
1. **Git 리포지토리 URL**을 입력합니다. 리포지토리는 `http://`, `https://`, `ssh://` 또는 `git://`을(를) 통해 접근 가능해야 합니다.
1. **미러 방향**을 선택합니다. 자세한 정보는 [풀 미러링](pull.md) 및 [푸시 미러링](push.md)을 참조하세요.
1. `ssh://` URL을 입력한 경우 다음 중 하나를 선택합니다:
   - **호스트 키 발견**: GitLab이 서버에서 호스트 키를 가져오고 지문을 표시합니다.
   - **호스트 키를 수동으로 입력**하고 호스트 키를 **SSH 호스트 키**에 입력합니다.

   리포지토리를 미러링할 때 GitLab은 연결하기 전에 저장된 호스트 키 중 적어도 하나가 일치하는지 확인합니다. 이 확인은 미러를 악의적인 코드 주입으로부터 보호하거나 암호가 도용되는 것을 방지합니다.

   - SSH 인증으로 리포지토리 미러를 만들려면 [SSH 인증으로 미러 만들기](#example-create-mirror-with-ssh-authentication) 예제를 참조하세요.

1. **인증 방법**을 선택합니다. 자세한 정보는 [미러에 대한 인증 방법](#authentication-methods-for-mirrors)을 참조하세요.
1. SSH 호스트 키로 인증하는 경우 [호스트 키 확인](#verify-a-host-key)을 수행하여 올바른지 확인합니다.
1. 다양한(divergent) 참조에 대한 강제 푸시를 방지하려면 **다양한(divergent) 참조 유지**를 선택합니다. 자세한 정보는 [다양한(divergent) 참조 유지](push.md#keep-divergent-refs)를 참조하세요.
1. 선택 사항. 미러링된 브랜치의 개수를 제한하려면 **보호된 브랜치만 미러링**을 선택하거나 **특정 브랜치를 미러링**에 정규식을 입력합니다.
1. **리포지토리 미러링**을 선택합니다.

### 예: SSH 인증으로 미러 만들기 {#example-create-mirror-with-ssh-authentication}

`SSH public key`을(를) 인증 방법으로 선택하면 GitLab이 GitLab 리포지토리에 대한 공개키를 생성합니다. 이 키를 non-GitLab 서버에 제공해야 합니다. 자세한 정보는 [SSH 공개 키 얻기](#get-your-ssh-public-key)를 참조하세요.

SSH 인증으로 리포지토리를 미러링하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **리포지토리 미러링**을 확장합니다.
1. **신규 추가**를 선택합니다.
1. **Git 리포지토리 URL**을 입력합니다. `ssh://gitlab.com/gitlab-org/gitlab.git` 형식으로 URL을 입력합니다.

   > [!note]
   > SSH URL은 SCP 스타일 URL(`git@host:path/to/repo.git`) 대신 `ssh://host/path/to/repo.git` 형식을 사용해야 합니다. 콜론(`:`)을 슬래시(`/`)로 바꾸고 `ssh://` 접두사를 추가합니다.

1. **미러 방향**을 선택합니다. 자세한 정보는 [풀 미러링](pull.md) 및 [푸시 미러링](push.md)을 참조하세요.
1. **호스트 키 발견** 또는 **호스트 키를 수동으로 입력**을 선택합니다.
1. **인증 방법** 필드에서 **SSH 공개키**를 선택합니다.
1. **사용자명** 필드에 `git`을(를) 추가합니다.
1. 선택 사항. **브랜치 미러링** 설정을 구성합니다.
1. **리포지토리 미러링**을 선택합니다.
1. SSH 공개 키를 복사하고 non-GitLab 서버에 제공합니다.

### 보호된 브랜치만 미러링 {#mirror-only-protected-branches}

미러링 프로젝트의 [보호된 브랜치](../branches/protected.md)만 미러링하도록 선택할 수 있으며, 원격 리포지토리에서 또는 원격 리포지토리로 미러링할 수 있습니다. [풀 미러링](pull.md)의 경우, 미러링 프로젝트의 보호되지 않은 브랜치는 미러링되지 않으며 다양해질 수 있습니다.

이 옵션을 사용하려면 리포지토리 미러를 만들 때 **보호된 브랜치만 미러링**을 선택합니다.

### 특정 브랜치를 미러링 {#mirror-specific-branches}

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[RE2 정규 표현식](https://github.com/google/re2/wiki/Syntax)과 일치하는 이름의 브랜치만 미러링하려면 **특정 브랜치를 미러링** 필드에 정규 표현식을 입력합니다. 정규 표현식과 일치하지 않는 이름의 브랜치는 미러링되지 않습니다.

## 미러 업데이트 {#update-a-mirror}

미러 리포지토리를 업데이트하면 모든 새 브랜치, 태그 및 커밋이 프로젝트의 활동 피드에 표시됩니다. GitLab의 리포지토리 미러는 자동으로 업데이트됩니다. 수동으로 업데이트를 트리거할 수도 있습니다:

- GitLab.com에서는 최대 5분에 한 번입니다.
- GitLab Self-Managed 인스턴스의 관리자가 설정한 [풀 미러링 간격 제한](../../../../administration/instance_limits.md#pull-mirroring-interval)에 따릅니다.

> [!note]
> [GitLab Silent Mode](../../../../administration/silent_mode/_index.md)는 푸시 및 풀 업데이트를 모두 비활성화합니다.

### 업데이트 강제 실행 {#force-an-update}

미러는 자동으로 업데이트되도록 예약되어 있지만 다음의 경우를 제외하고 즉시 업데이트를 강제할 수 있습니다:

- 미러가 이미 업데이트되고 있습니다.
- 풀 미러링에 대한 [간격(초 단위)](../../../../administration/instance_limits.md#pull-mirroring-interval) 제한이 마지막 업데이트 이후 경과하지 않았습니다.

사전 요구 사항:

- 프로젝트에 대해 유지 관리자 또는 소유자 역할이 있어야 합니다.

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **리포지토리 미러링**을 확장합니다.
1. **미러링된 리포지토리**로 스크롤하여 업데이트할 미러를 식별합니다.
1. **지금 업데이트**({{< icon name="retry" >}})를 선택합니다.

## 미러에 대한 인증 방법 {#authentication-methods-for-mirrors}

미러를 만들 때 미러의 인증 방법을 구성해야 합니다. GitLab은 다음 인증 방법을 지원합니다:

- [SSH 인증](#ssh-authentication).
- 사용자명 및 비밀번호.

[프로젝트 액세스 토큰](../../settings/project_access_tokens.md) 또는 [그룹 액세스 토큰](../../../group/settings/group_access_tokens.md)의 경우 비어 있지 않은 값을 사용자명으로 사용하고 토큰을 비밀번호로 사용합니다.

### SSH 인증 {#ssh-authentication}

SSH 인증은 상호입니다:

- 리포지토리에 액세스할 수 있는 권한이 있음을 서버에 증명해야 합니다.
- 서버도 자신이 누구인지 증명해야 합니다.

SSH 인증의 경우 자격 증명을 비밀번호 또는 공개 키로 제공합니다. 다른 리포지토리가 있는 서버가 호스트 키로 자격 증명을 제공합니다. 이 호스트 키의 [지문을 확인](#verify-a-host-key)해야 합니다.

SSH를 통해 미러링하는 경우(`ssh://` URL 사용) 다음을 사용하여 인증할 수 있습니다:

- HTTPS를 통해 사용하는 것처럼 비밀번호 기반 인증입니다.
- 공개 키 인증. 이 방법은 특히 다른 리포지토리가 [배포 키](../../deploy_keys/_index.md)를 지원할 때 비밀번호 인증보다 더 안전합니다.

### SSH 공개 키 얻기 {#get-your-ssh-public-key}

리포지토리를 미러링하고 **SSH 공개키**를 인증 방법으로 선택하면 GitLab이 공개 키를 생성합니다. non-GitLab 서버는 이 키를 GitLab 리포지토리와의 신뢰를 설정하는 데 필요로 합니다. SSH 공개 키를 복사하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **리포지토리 미러링**을 확장합니다.
1. **미러링된 리포지토리**로 스크롤합니다.
1. 올바른 리포지토리를 식별하고 **SSH 공개 키 복사**({{< icon name="copy-to-clipboard" >}})를 선택합니다.
1. 공개 SSH 키를 다른 리포지토리의 구성에 추가합니다:
   - 다른 리포지토리가 GitLab에서 호스팅되는 경우 공개 SSH 키를 [배포 키](../../deploy_keys/_index.md)로 추가합니다.
   - 다른 리포지토리가 다른 곳에서 호스팅되는 경우 사용자의 `authorized_keys` 파일에 키를 추가합니다. 전체 공개 SSH 키를 파일에 자신의 라인으로 붙여넣고 저장합니다.

언제든지 키를 변경해야 하는 경우 미러를 제거했다가 다시 추가하여 새 키를 생성할 수 있습니다. 미러가 계속 실행되도록 다른 리포지토리를 새 키로 업데이트합니다.

> [!note]
> 생성된 키는 GitLab 데이터베이스에 저장되며 파일 시스템에는 저장되지 않습니다. 따라서 미러에 대한 SSH 공개 키 인증은 pre-receive 훅에서 사용할 수 없습니다.

### 호스트 키 확인 {#verify-a-host-key}

호스트 키를 사용할 때는 항상 지문이 예상과 일치하는지 확인하세요. GitLab.com 및 기타 코드 호스팅 사이트는 확인할 수 있도록 지문을 게시합니다:

- [AWS CodeCommit](https://docs.aws.amazon.com/codecommit/latest/userguide/regions.html#regions-fingerprints)
- [Bitbucket](https://support.atlassian.com/bitbucket-cloud/docs/configure-ssh-and-two-step-verification/)
- [Codeberg](https://docs.codeberg.org/security/ssh-fingerprint/)
- [GitHub](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints)
- [GitLab.com](../../../gitlab_com/_index.md#ssh-host-keys-fingerprints)
- [Launchpad](https://documentation.ubuntu.com/launchpad/user/reference/ssh-fingerprints/)
- [Savannah](https://savannah.gnu.org/maintenance/SshAccess/)
- [SourceForge](https://sourceforge.net/p/forge/documentation/SSH%20Key%20Fingerprints/)

다른 공급자들은 다양합니다. 다음 명령어를 사용하여 안전하게 키 지문을 수집할 수 있습니다:

- GitLab Self-Managed를 실행합니다.
- 다른 리포지토리의 서버에 액세스할 수 있습니다.

```shell
$ cat /etc/ssh/ssh_host*pub | ssh-keygen -E md5 -l -f -
256 MD5:f4:28:9f:23:99:15:21:1b:bf:ed:1f:8e:a0:76:b2:9d root@example.com (ECDSA)
256 MD5:e6:eb:45:8a:3c:59:35:5f:e9:5b:80:12:be:7e:22:73 root@example.com (ED25519)
2048 MD5:3f:72:be:3d:62:03:5c:62:83:e8:6e:14:34:3a:85:1d root@example.com (RSA)
```

SSH의 더 오래된 버전은 명령어에서 `-E md5`을(를) 제거하도록 요구할 수 있습니다.

## 관련 항목 {#related-topics}

- 리포지토리 미러링에 대한 [문제 해결](troubleshooting.md).
- [풀 미러링 간격](../../../../administration/instance_limits.md#pull-mirroring-interval) 구성
- [프로젝트에 대한 미러 비활성화](../../../../administration/settings/visibility_and_access_controls.md#enable-project-mirroring)
- [비밀 파일 및 미러링](../../../../administration/backup_restore/troubleshooting_backup_gitlab.md#when-the-secrets-file-is-lost)
