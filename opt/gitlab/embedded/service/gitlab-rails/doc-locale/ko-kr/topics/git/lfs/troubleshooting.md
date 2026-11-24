---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Git LFS 문제 해결
---

Git LFS를 사용할 때 다음과 같은 문제가 발생할 수 있습니다.

- Git LFS 원본 v1 API는 지원되지 않습니다.
- Git LFS 요청은 HTTPS 자격 증명을 사용하므로 Git [자격 증명 저장소](https://git-scm.com/book/en/v2/Git-Tools-Credential-Storage)를 사용해야 합니다.
- [그룹 위키](../../../user/project/wiki/group.md)는 Git LFS를 지원하지 않습니다.

## 오류: 리포지토리 또는 개체를 찾을 수 없음 {#error-repository-or-object-not-found}

이 오류는 몇 가지 이유로 발생할 수 있습니다:

- 특정 LFS 개체에 액세스할 수 있는 권한이 없습니다. 프로젝트에 푸시하거나 프로젝트에서 가져올 수 있는 권한이 있는지 확인합니다.
- 프로젝트가 LFS 개체에 액세스할 수 없습니다. 푸시(또는 가져오기)하려는 LFS 개체를 더 이상 프로젝트에서 사용할 수 없습니다. 대부분의 경우 개체가 서버에서 제거되었습니다.
- 로컬 Git 리포지토리가 Git LFS API의 더 이상 사용되지 않는 버전을 사용하고 있습니다. Git LFS의 로컬 복사본을 업데이트하고 다시 시도합니다.

## `<url>`에 대한 잘못된 상태 : 501 {#invalid-status-for-url--501}

Git LFS는 오류를 로그 파일에 기록합니다. 이 로그 파일을 보려면:

1. 터미널 창에서 프로젝트의 디렉터리로 이동합니다.
1. 최근 로그 파일을 확인하려면 다음 명령을 실행합니다:

   ```shell
   git lfs logs last
   ```

다음 문제로 인해 `501` 오류가 발생할 수 있습니다:

- Git LFS가 프로젝트 설정에서 활성화되지 않았습니다. 프로젝트 설정을 확인하고 Git LFS를 활성화합니다.
- GitLab 서버에서 Git LFS 지원이 활성화되지 않았습니다. GitLab 관리자에게 서버에서 Git LFS가 활성화되지 않은 이유를 확인합니다. Git LFS 지원을 활성화하는 방법에 대한 지침은 [LFS 관리 설명서](../../../administration/lfs/_index.md)를 참조합니다.
- Git LFS 클라이언트 버전이 GitLab 서버에서 지원되지 않습니다. 다음을 수행해야 합니다:
  1. `git lfs version`로 Git LFS 버전을 확인합니다.
  1. `git lfs -l`로 프로젝트의 Git 구성을 확인하여 더 이상 사용되지 않는 API의 흔적을 찾습니다. 구성이 `batch = false`를 설정하면 해당 줄을 제거한 후 Git LFS 클라이언트를 업데이트합니다. GitLab은 버전 1.0.1 이상만 지원합니다.

## 개체를 푸시할 때 항상 자격 증명이 필요합니다 {#credentials-are-always-required-when-pushing-an-object}

Git LFS는 모든 푸시에서 모든 개체에 대해 HTTP 기본 인증으로 사용자를 인증하므로 사용자 HTTPS 자격 증명이 필요합니다. 기본적으로 Git은 사용하는 각 리포지토리의 자격 증명을 기억하는 것을 지원합니다. 자세한 내용은 [공식 Git 설명서](https://git-scm.com/docs/gitcredentials)를 참조합니다.

예를 들어, Git이 개체를 푸시할 것으로 예상되는 기간 동안 비밀번호를 기억하도록 지시할 수 있습니다. 이 예제는 자격 증명을 1시간(3600초) 동안 기억하며 1시간 후에 다시 인증해야 합니다:

```shell
git config --global credential.helper 'cache --timeout=3600'
```

자격 증명을 저장하고 암호화하려면 다음을 참조합니다:

- macOS: `osxkeychain`을 사용합니다.
- Windows: `wincred`을 사용하거나 Microsoft [Git Credential Manager for Windows](https://github.com/Microsoft/Git-Credential-Manager-for-Windows/releases)를 사용합니다.

사용자 자격 증명 저장에 대해 자세히 알아보려면 [Git 자격 증명 저장소 설명서](https://git-scm.com/book/en/v2/Git-Tools-Credential-Storage)를 참조합니다.

## 푸시 시 LFS 개체가 누락되었습니다 {#lfs-objects-are-missing-on-push}

GitLab은 LFS 포인터를 감지하기 위해 푸시 시 파일을 확인합니다. LFS 포인터를 감지하면 GitLab은 이러한 파일이 이미 LFS에 있는지 확인하려고 합니다. Git LFS에 별도의 서버를 사용 중이고 이 문제가 발생하면:

1. Git LFS를 로컬에 설치했는지 확인합니다.
1. `git lfs push --all`로 수동 푸시를 고려합니다.

Git LFS 파일을 GitLab 외부에 저장하는 경우 프로젝트에서 [Git LFS를 비활성화](_index.md#enable-or-disable-git-lfs-for-a-project)할 수 있습니다.

## LFS 개체를 외부에서 호스팅 {#hosting-lfs-objects-externally}

사용자 지정 LFS URL을 설정하여 LFS 개체를 외부에서 호스팅할 수 있습니다:

```shell
git config -f .lfsconfig lfs.url https://example.com/<project>.git/info/lfs
```

Nexus Repository 같은 어플라이언스에 LFS 데이터를 저장하는 경우 이렇게 할 수 있습니다. 외부 LFS 저장소를 사용하면 GitLab은 LFS 개체를 확인할 수 없습니다. GitLab LFS 지원이 활성화되어 있으면 푸시가 실패합니다.

푸시 실패를 중지하려면 [프로젝트 설정](_index.md#enable-or-disable-git-lfs-for-a-project)에서 Git LFS 지원을 비활성화할 수 있습니다. 그러나 이 방법은 GitLab LFS 기능도 비활성화하기 때문에 바람직하지 않을 수 있습니다:

- LFS 개체를 확인합니다.
- LFS용 GitLab UI 통합.

## LFS 개체를 푸시할 때 I/O 시간 초과 {#io-timeout-when-pushing-lfs-objects}

네트워크 상태가 불안정하면 Git LFS 클라이언트가 파일을 업로드하려고 할 때 시간 초과될 수 있습니다. 다음과 같은 오류가 표시될 수 있습니다:

```shell
LFS: Put "http://example.com/root/project.git/gitlab-lfs/objects/<OBJECT-ID>/15":
read tcp your-instance-ip:54544->your-instance-ip:443: i/o timeout
error: failed to push some refs to 'ssh://example.com:2222/root/project.git'
```

이 문제를 해결하려면 클라이언트 활동 시간 초과를 더 높은 값으로 설정합니다. 예를 들어 시간 초과를 60초로 설정하려면:

```shell
git config lfs.activitytimeout 60
```

## 포인터여야 했지만 포인터가 아닌 `n` 파일을 발견했습니다 {#encountered-n-files-that-should-have-been-pointers-but-werent}

이 오류는 리포지토리가 Git LFS를 사용하여 파일을 추적해야 하지만 그렇지 않음을 나타냅니다.

문제를 해결하려면 영향을 받는 파일을 마이그레이션하고 리포지토리에 푸시합니다:

1. 파일을 LFS로 마이그레이션합니다:

   ```shell
   git lfs migrate import --yes --no-rewrite "<your-file>"
   ```

1. 리포지토리에 다시 푸시합니다:

   ```shell
   git push
   ```

1. 선택사항. `.git` 폴더를 정리합니다:

   ```shell
   git reflog expire --expire-unreachable=now --all
   git gc --prune=now
   ```

## LFS 개체가 자동으로 체크아웃되지 않음 {#lfs-objects-not-checked-out-automatically}

Git LFS 개체가 자동으로 체크아웃되지 않는 문제가 발생할 수 있습니다. 이 경우 파일이 존재하지만 실제 콘텐츠 대신 포인터 참조를 포함합니다. 이러한 파일을 열면 예상된 파일 콘텐츠 대신 다음과 같은 LFS 포인터가 표시될 수 있습니다:

```plaintext
version https://git-lfs.github.com/spec/v1
oid sha256:d276d250bc645e27a1b0ab82f7baeb01f7148df7e4816c4b333de12d580caa29
size 2323563
```

이 문제는 파일명이 `.gitattributes` 파일의 규칙과 일치하지 않을 때 발생합니다. LFS 파일은 `.gitattributes`의 규칙과 일치할 때만 자동으로 체크아웃됩니다.

`git-lfs` v3.6.0에서 이 동작이 변경되었으며 [LFS 파일이 일치하는 방식이 최적화되었습니다](https://github.com/git-lfs/git-lfs/pull/5699).

GitLab Runner v17.7.0은 기본 도우미 이미지를 업그레이드하여 `git-lfs` v3.6.0을 사용합니다.

대소문자 민감도가 다른 여러 운영 체제에서 일관된 동작을 위해 `.gitattributes` 파일을 조정하여 다양한 대문자 패턴과 일치시킵니다.

예를 들어 `image.jpg`과 `wombat.JPG`라는 LFS 파일이 있는 경우 `.gitattributes` 파일에서 대소문자를 구분하지 않는 정규식을 사용합니다:

```plaintext
*.[jJ][pP][gG] filter=lfs diff=lfs merge=lfs -text
*.[jJ][pP][eE][gG] filter=lfs diff=lfs merge=lfs -text
```

대부분의 Linux 배포판과 같은 대소문자를 구분하는 파일 시스템에서만 작업하는 경우 더 간단한 패턴을 사용할 수 있습니다. 예를 들어:

```plaintext
*.jpg filter=lfs diff=lfs merge=lfs -text
*.jpeg filter=lfs diff=lfs merge=lfs -text
```

## 경고:  가능한 LFS 구성 문제 {#warning-possible-lfs-configuration-issue}

GitLab UI에서 다음 경고가 표시될 수 있습니다:

```plaintext
Possible LFS configuration issue. This project contains LFS objects but there is no .gitattributes file.
You can ignore this message if you recently added a .gitattributes file.
```

이 경고는 Git LFS가 활성화되고 LFS 개체를 포함하지만 프로젝트의 루트 디렉터리에서 `.gitattributes` 파일이 감지되지 않을 때 발생합니다. Git은 `.gitattributes` 파일을 하위 디렉터리에 배치하는 것을 지원하지만 GitLab은 루트 디렉터리에서만 이 파일을 확인합니다.

해결 방법은 루트 디렉터리에 빈 `.gitattributes` 파일을 만드는 것입니다:

{{< tabs >}}

{{< tab title="Git 사용" >}}

1. 리포지토리를 복제합니다:

   ```shell
   git clone <repository>
   cd repository
   ```

1. 빈 `.gitattributes` 파일을 만듭니다:

   ```shell
   touch .gitattributes
   git add .gitattributes
   git commit -m "Add empty .gitattributes file to root directory"
   git push
   ```

{{< /tab >}}

{{< tab title="UI에서" >}}

1. 상단 바에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 더하기 아이콘(**+**)을 선택하고 **새 파일**을 선택합니다.
1. **파일명** 필드에 `.gitattributes`을 입력합니다.
1. **변경 사항 커밋**을 선택합니다.
1. **커밋 메시지** 필드에 커밋 메시지를 입력합니다.
1. **변경 사항 커밋**을 선택합니다.

{{< /tab >}}

{{< /tabs >}}
