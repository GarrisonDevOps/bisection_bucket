---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Linux 패키지 CE 인스턴스를 EE로 변환
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

기존 Linux 패키지 인스턴스를 Community Edition(CE)에서 Enterprise Edition(EE)으로 변환할 수 있습니다. 인스턴스를 변환하려면 CE 인스턴스 위에 EE Linux 패키지를 설치합니다.

CE에서 EE로 동일한 버전을 사용할 필요는 없습니다. 예를 들어 CE 18.0에서 EE 18.1로 업그레이드하면 작동해야 합니다. 다만 동일한 버전으로 업그레이드(예: CE 18.1에서 EE 18.1)하는 것이 좋습니다.

> [!warning]
> CE에서 EE로 변환한 후 나중에 EE로 돌아갈 계획이 있다면 CE로 되돌리지 마세요. CE로 되돌리면 [데이터베이스 문제](package_troubleshooting.md#500-error-when-accessing-project-repository-settings)가 발생할 수 있으며 지원 개입이 필요할 수 있습니다.

## CE에서 EE로 변환 {#convert-from-ce-to-ee}

Linux 패키지 CE 인스턴스를 EE로 변환하려면:

1. [GitLab 백업](../../administration/backup_restore/backup_gitlab.md)을 만듭니다.
1. 설치된 GitLab 버전을 찾으세요:

   {{< tabs >}}

   {{< tab title="Debian/Ubuntu" >}}

   ```shell
   sudo apt-cache policy gitlab-ce | grep Installed
   ```

   반환된 버전을 적어 두세요.

   {{< /tab >}}

   {{< tab title="CentOS/RHEL" >}}

   ```shell
   sudo rpm -q gitlab-ce
   ```

   반환된 버전을 적어 두세요.

   {{< /tab >}}

   {{< /tabs >}}

1. `gitlab-ee` [Apt 또는 Yum 리포지토리](https://packages.gitlab.com/ui/browse/gitlab/gitlab-ee)를 추가합니다. 이 명령들은 OS 버전을 찾아 리포지토리를 자동으로 설정합니다.

   {{< tabs >}}

   {{< tab title="Debian/Ubuntu" >}}

   ```shell
   curl --silent "https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.deb.sh" | sudo bash
   ```

   {{< /tab >}}

   {{< tab title="CentOS/RHEL" >}}

   ```shell
   curl --silent "https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.rpm.sh" | sudo bash
   ```

   {{< /tab >}}

   {{< /tabs >}}

   `dpkg` 또는 `rpm` 대신 `apt-get` 또는 `yum`를 사용하려면 [다운로드한 패키지로 업그레이드](../package/_index.md#upgrade-with-a-downloaded-package)를 참조하세요.

1. `gitlab-ee` Linux 패키지를 설치합니다. 설치하면 GitLab에서 `gitlab-ce` 패키지를 자동으로 제거합니다.

   {{< tabs >}}

   {{< tab title="Debian/Ubuntu" >}}

   ```shell
   ## Make sure the repositories are up-to-date
   sudo apt-get update

   ## Install the package using the version you wrote down from step 1
   sudo apt-get install gitlab-ee=18.1.0-ee.0

   ## Reconfigure GitLab
   sudo gitlab-ctl reconfigure
   ```

   {{< /tab >}}

   {{< tab title="CentOS/RHEL" >}}

   ```shell
   ## Install the package using the version you wrote down from step 1
   sudo yum install gitlab-ee-18.1.0-ee.0.el9.x86_64

   ## Reconfigure GitLab
   sudo gitlab-ctl reconfigure
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. [라이선스 추가](../../administration/license.md)하여 Enterprise Edition을 활성화합니다.
1. GitLab이 예상대로 작동하는지 확인한 후 이전 Community Edition 리포지토리를 제거할 수 있습니다:

   {{< tabs >}}

   {{< tab title="Debian/Ubuntu" >}}

   ```shell
   sudo rm /etc/apt/sources.list.d/gitlab_gitlab-ce.list
   ```

   {{< /tab >}}

   {{< tab title="CentOS/RHEL" >}}

   ```shell
   sudo rm /etc/yum.repos.d/gitlab_gitlab-ce.repo
   ```

   {{< /tab >}}

   {{< /tabs >}}

1. 선택사항. [Elasticsearch 통합 설정](../../integration/advanced_search/elasticsearch.md)하여 [고급 검색](../../user/search/advanced_search.md)을 활성화합니다.

완료되었습니다! 이제 GitLab Enterprise Edition을 사용할 수 있습니다! 최신 버전으로 업그레이드하려면 [Linux 패키지 인스턴스 업그레이드](_index.md)를 참조하세요.

## CE로 되돌리기 {#revert-back-to-ce}

EE 인스턴스를 CE로 되돌리는 방법에 대한 정보는 [EE에서 CE로 되돌리는 방법](revert.md)을 참조하세요.
