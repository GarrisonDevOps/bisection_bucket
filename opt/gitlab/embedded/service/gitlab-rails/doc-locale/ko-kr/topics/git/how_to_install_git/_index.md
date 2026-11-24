---
stage: Create
group: Source Code
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 로컬 머신에 Git을 설치하는 방법입니다.
title: Git 설치
---

GitLab 프로젝트에 기여하려면 로컬 머신에 Git 클라이언트를 다운로드, 설치 및 구성해야 합니다. GitLab은 SSH 프로토콜을 사용하여 Git과 안전하게 통신합니다. SSH를 사용하면 매번 사용자 이름과 암호를 입력하지 않고도 GitLab 원격 서버에 인증할 수 있습니다.

Git을 설치하고 구성한 후 [SSH 키 쌍 생성 및 추가](../../../user/ssh.md#generate-an-ssh-key-pair)를 GitLab 계정에 수행합니다.

## Git 설치 및 업데이트 {#install-and-update-git}

{{< tabs >}}

{{< tab title="macOS" >}}

macOS에서 제공하는 Git 버전이 있지만, 최신 버전의 Git을 설치해야 합니다. Git을 설치하는 일반적인 방법은 [Homebrew](https://brew.sh/index.html)를 사용하는 것입니다.

Homebrew를 사용하여 macOS에 최신 버전의 Git을 설치하려면:

1. 이전에 Homebrew를 설치한 적이 없다면 [Homebrew 설치 지침](https://brew.sh/index.html)을 따르세요.
1. 터미널에서 `brew install git`을 실행하여 Git을 설치합니다.
1. 로컬 머신에서 Git이 작동하는지 확인합니다:

   ```shell
   git --version
   ```

다음 명령을 주기적으로 실행하여 Git을 최신 상태로 유지합니다:

```shell
brew update && brew upgrade git
```

{{< /tab >}}

{{< tab title="Ubuntu Linux" >}}

Ubuntu에서 제공하는 Git 버전이 있지만, 최신 버전의 Git을 설치해야 합니다. 최신 버전은 PPA(개인 패키지 아카이브)를 사용하여 사용할 수 있습니다.

PPA를 사용하여 Ubuntu Linux에 최신 버전의 Git을 설치하려면:

1. 터미널에서 필요한 PPA를 구성하고, Ubuntu 패키지 목록을 업데이트한 후 `git`을 설치합니다:

   ```shell
   sudo apt-add-repository ppa:git-core/ppa
   sudo apt-get update
   sudo apt-get install git
   ```

1. 로컬 머신에서 Git이 작동하는지 확인합니다:

   ```shell
   git --version
   ```

다음 명령을 주기적으로 실행하여 Git을 최신 상태로 유지합니다:

```shell
sudo apt-get update && sudo apt-get install git
```

{{< /tab >}}

{{< tab title="기타 운영 체제" >}}

다른 운영 체제에서 Git을 다운로드 및 설치하는 방법에 대한 정보는 [공식 Git 웹 사이트](https://git-scm.com/downloads/)를 참조하세요.

{{< /tab >}}

{{< /tabs >}}

## Git 구성 {#configure-git}

로컬 머신에서 Git을 사용하려면 자신을 작업의 작성자로 식별하기 위해 자격 증명을 입력해야 합니다.

Git 연동을 로컬 또는 전역으로 구성할 수 있습니다:

- 로컬: 현재 프로젝트에만 사용합니다.
- 전역: 모든 현재 및 향후 프로젝트에 사용합니다.

{{< tabs >}}

{{< tab title="로컬 설정" >}}

현재 프로젝트에만 사용할 Git 연동을 로컬로 구성합니다.

전체 이름과 이메일 주소는 GitLab에서 사용하는 것과 일치해야 합니다.

1. 터미널에 전체 이름을 입력합니다. 예를 들어:

   ```shell
   git config --local user.name "Alex Smith"
   ```

1. 이메일 주소를 입력합니다. 예를 들어:

   ```shell
   git config --local user.email "your_email_address@example.com"
   ```

1. 구성을 확인하려면 다음을 실행합니다:

   ```shell
   git config --local --list
   ```

{{< /tab >}}

{{< tab title="전역 설정" >}}

머신의 모든 현재 및 향후 프로젝트에 사용할 Git 연동을 전역으로 구성합니다.

전체 이름과 이메일 주소는 GitLab에서 사용하는 것과 일치해야 합니다.

1. 터미널에 전체 이름을 입력합니다. 예를 들어:

   ```shell
   git config --global user.name "Sidney Jones"
   ```

1. 이메일 주소를 입력합니다. 예를 들어:

   ```shell
   git config --global user.email "your_email_address@example.com"
   ```

1. 구성을 확인하려면 다음을 실행합니다:

   ```shell
   git config --global --list
   ```

{{< /tab >}}

{{< /tabs >}}

### Git 구성 설정 확인 {#check-git-configuration-settings}

구성된 Git 설정을 확인하려면 다음을 실행합니다:

```shell
git config user.name && git config user.email
```

## 관련 항목 {#related-topics}

- [Git 구성 설명서](https://git-scm.com/book/en/v2/Customizing-Git-Git-Configuration)
- [SSH 키를 사용하여 GitLab과 통신](../../../user/ssh.md)
