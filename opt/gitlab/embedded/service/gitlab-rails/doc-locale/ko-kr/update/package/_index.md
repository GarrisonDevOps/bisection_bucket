---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: Linux 패키지 인스턴스 업그레이드
description: 단일 노드 Linux 패키지 기반 인스턴스를 업그레이드합니다.
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

Linux 패키지 인스턴스를 업그레이드하기 위한 지침은 단일 노드인지 다중 노드 GitLab 인스턴스인지에 따라 달라집니다. 다중 노드 Linux 패키지 GitLab 인스턴스를 업그레이드하려면 다음을 참조하세요:

- [다운타임을 포함한 다중 노드 인스턴스 업그레이드](../with_downtime.md).
- [다운타임 없이 다중 노드 인스턴스 업그레이드](../zero_downtime.md).

단일 노드 Linux 패키지 GitLab 인스턴스를 업그레이드하려면 이 페이지의 정보를 따르세요.

> [!note]
> 제품 설명서를 호스팅하는 경우 [최신 버전으로 업그레이드](../../administration/docs_self_host.md#upgrade-the-product-documentation-to-a-later-version)할 수도 있습니다.

## 전제 조건 {#prerequisites}

단일 노드 Linux 패키지 GitLab 인스턴스를 업그레이드하기 전에:

- [필수 정보를 읽고 필수 단계를 수행](../plan_your_upgrade.md)해야 합니다.
- 필요한 경우 [지원되는 운영 체제](../../install/package/_index.md)로 업그레이드합니다.
- 운영 체제를 업그레이드할 때 `glibc` 버전이 변경되면 손상된 인덱스를 피하기 위해 [PostgreSQL의 운영 체제 업그레이드](../../administration/postgresql/upgrading_os.md)를 따라야 합니다.
- PostgreSQL, Redis, Gitaly가 실행 중인지 확인합니다.

새로운 GitLab 버전을 설치하기 전에 GitLab 데이터베이스가 백업됩니다. `/etc/gitlab/skip-auto-backup`에 빈 파일을 만들어 이 자동 데이터베이스 백업을 건너뛸 수 있습니다:

```shell
sudo touch /etc/gitlab/skip-auto-backup
```

그럼에도 불구하고 자신의 [백업](../../administration/backup_restore/_index.md)을 최신으로 유지해야 합니다.

## 단일 노드 Linux 패키지 인스턴스 업그레이드 {#upgrade-a-single-node-linux-package-instance}

단일 노드 Linux 패키지 인스턴스를 업그레이드하려면:

1. 업그레이드 중에 [유지보수 모드 활성화](../../administration/maintenance_mode/_index.md)를 고려하세요.
1. [실행 중인 CI/CD 파이프라인 및 작업](../plan_your_upgrade.md#pause-cicd-pipelines-and-jobs)을 일시 중지합니다.
1. [GitLab Runner 업그레이드](https://docs.gitlab.com/runner/install/)를 대상 GitLab 버전과 동일한 버전으로 업그레이드합니다.
1. [Linux 패키지를 사용하여 GitLab 업그레이드](#upgrade-with-the-linux-package)합니다.

업그레이드 후:

1. [실행 중인 CI/CD 파이프라인 및 작업](../plan_your_upgrade.md#pause-cicd-pipelines-and-jobs)을 다시 시작합니다.
1. 활성화된 경우 [유지보수 모드 비활성화](../../administration/maintenance_mode/_index.md#disable-maintenance-mode)합니다.
1. [업그레이드 상태 확인](../plan_your_upgrade.md#run-upgrade-health-checks)을 실행합니다.

## Linux 패키지로 업그레이드 {#upgrade-with-the-linux-package}

단일 노드에서 실행되는 GitLab를 업그레이드하거나 다중 노드 GitLab 인스턴스의 일부인 노드를 업그레이드하려면 다음 중 하나로 업그레이드합니다:

- [공식 리포지토리 사용](#upgrade-with-the-official-repositories-recommended).
- [다운로드한 패키지 사용](#upgrade-with-a-downloaded-package).

### 공식 리포지토리로 업그레이드(권장) {#upgrade-with-the-official-repositories-recommended}

모든 GitLab 패키지는 GitLab [패키지 서버](https://packages.gitlab.com/ui/browse/gitlab)에 게시됩니다.

| 리포지토리                                                                                       | 설명 |
|:-------------------------------------------------------------------------------------------------|:------------|
| [`gitlab/gitlab-ce`](https://packages.gitlab.com/ui/browse/gitlab/gitlab-ce)                     | 커뮤니티 에디션 기능만 포함하는 간소화된 패키지입니다. |
| [`gitlab/gitlab-ee`](https://packages.gitlab.com/ui/browse/gitlab/gitlab-ee)                     | 커뮤니티 에디션 및 엔터프라이즈 에디션의 모든 기능을 포함하는 전체 GitLab 패키지입니다. |
| [`gitlab/nightly-builds`](https://packages.gitlab.com/ui/browse/gitlab/nightly-builds)           | 야간 빌드. |
| [`gitlab/nightly-fips-builds`](https://packages.gitlab.com/ui/browse/gitlab/nightly-fips-builds) | 야간 FIPS 준수 빌드. |
| [`gitlab/gitlab-fips`](https://packages.gitlab.com/ui/browse/gitlab/gitlab-fips)                 | FIPS 준수 빌드. |

기본적으로 Linux 배포 패키지 관리자는 패키지의 최신 사용 가능 버전을 설치합니다. [업그레이드 경로](../upgrade_paths.md)에 여러 단계가 필요한 경우 GitLab의 최신 주 버전으로 직접 업그레이드할 수 없습니다. 업그레이드 경로에 여러 버전이 포함되어 있으면 각 업그레이드마다 특정 GitLab 패키지 버전을 지정해야 합니다.

업그레이드 경로에 중간 단계가 없으면 최신 버전으로 직접 업그레이드할 수 있습니다.

{{< tabs >}}

{{< tab title="Ubuntu/Debian" >}}

```shell
# GitLab Enterprise Edition (specific version)
sudo apt update && sudo apt install gitlab-ee=<version>-ee.0

# GitLab Community Edition (specific version)
sudo apt update && sudo apt install gitlab-ce=<version>-ce.0

# GitLab Enterprise Edition (latest version)
sudo apt update && sudo apt install gitlab-ee

# GitLab Community Edition (latest version)
sudo apt update && sudo apt install gitlab-ce
```

{{< /tab >}}

{{< tab title="Amazon Linux 2" >}}

```shell
# GitLab Enterprise Edition (specific version)
sudo yum install gitlab-ee-<version>-ee.0.amazon2

# GitLab Community Edition (specific version)
sudo yum install gitlab-ce-<version>-ce.0.amazon2

# GitLab Enterprise Edition (latest version)
sudo yum install gitlab-ee

# GitLab Community Edition (latest version)
sudo yum install gitlab-ce
```

{{< /tab >}}

{{< tab title="RHEL/Oracle Linux/AlmaLinux 8/9" >}}

```shell
# GitLab Enterprise Edition (specific version)
sudo dnf install gitlab-ee-<version>-ee.0.el9

# GitLab Enterprise Edition (specific version)
sudo dnf install gitlab-ee-<version>-ee.0.el8

# GitLab Community Edition (specific version)
sudo dnf install gitlab-ce-<version>-ce.0.el9

# GitLab Community Edition (specific version)
sudo dnf install gitlab-ce-<version>-ce.0.el8

# GitLab Enterprise Edition (latest version)
sudo dnf upgrade gitlab-ee

# GitLab Community Edition (latest version)
sudo dnf upgrade gitlab-ce
```

{{< /tab >}}

{{< tab title="Amazon Linux 2023" >}}

```shell
# GitLab Enterprise Edition (specific version)
sudo dnf install gitlab-ee-<version>-ee.0.amazon2023

# GitLab Community Edition (specific version)
sudo dnf install gitlab-ce-<version>-ce.0.amazon2023

# GitLab Enterprise Edition (latest version)
sudo dnf upgrade gitlab-ee

# GitLab Community Edition (latest version)
sudo dnf upgrade gitlab-ce
```

{{< /tab >}}

{{< tab title="OpenSUSE Leap 15.5" >}}

```shell
# GitLab Enterprise Edition (specific version)
sudo zypper install gitlab-ee=<version>-ee.sles15

# GitLab Community Edition (specific version)
sudo zypper install gitlab-ce=<version>-ce.sles15

# GitLab Enterprise Edition (latest version)
sudo zypper install gitlab-ee

# GitLab Community Edition (latest version)
sudo zypper install gitlab-ce
```

{{< /tab >}}

{{< tab title="SUSE Enterprise Server 12.2/12.5" >}}

```shell
# GitLab Enterprise Edition (specific version)
sudo zypper install gitlab-ee=<version>-ee.0.sles12

# GitLab Community Edition (specific version)
sudo zypper install gitlab-ce=<version>-ce.0.sles12

# GitLab Enterprise Edition (latest version)
sudo zypper install gitlab-ee

# GitLab Community Edition (latest version)
sudo zypper install gitlab-ce
```

{{< /tab >}}

{{< /tabs >}}

### 공식 리포지토리에서 패키지 미리 다운로드 {#pre-download-a-package-from-the-official-repository}

업그레이드 중 설치 시간을 단축하거나 패키지에 액세스할 수 있는지 테스트하려면 공식 리포지토리에서 다운로드한 후 나중에 설치할 수 있습니다:

{{< tabs >}}

{{< tab title="Ubuntu/Debian" >}}

```shell
# GitLab Enterprise Edition
sudo apt-get install --download-only gitlab-ee=<version>-ee.0
sudo apt-get install /var/cache/apt/archives/gitlab-ee_<version>-ee.0_amd64.deb

# GitLab Community Edition
sudo apt-get install --download-only gitlab-ce=<version>-ce.0
sudo apt-get install /var/cache/apt/archives/gitlab-ce_<version>-ce.0_amd64.deb
```

{{< /tab >}}

{{< tab title="Amazon Linux 2" >}}

```shell
# GitLab Enterprise Edition
sudo yumdownloader gitlab-ee-<version>-ee.0.amazon2
sudo yum install ./gitlab-ee-<version>-ee.0.amazon2.x86_64.rpm

# GitLab Community Edition
sudo yumdownloader gitlab-ce-<version>-ce.0.amazon2
sudo yum install ./gitlab-ce-<version>-ce.0.amazon2.x86_64.rpm
```

{{< /tab >}}

{{< tab title="RHEL/Oracle Linux/AlmaLinux 8/9" >}}

```shell
# GitLab Enterprise Edition (el9)
sudo dnf download gitlab-ee-<version>-ee.0.el9
sudo dnf install ./gitlab-ee-<version>-ee.0.el9.x86_64.rpm

# GitLab Enterprise Edition (el8)
sudo dnf download gitlab-ee-<version>-ee.0.el8
sudo dnf install ./gitlab-ee-<version>-ee.0.el8.x86_64.rpm

# GitLab Community Edition (el9)
sudo dnf download gitlab-ce-<version>-ce.0.el9
sudo dnf install ./gitlab-ce-<version>-ce.0.el9.x86_64.rpm

# GitLab Community Edition (el8)
sudo dnf download gitlab-ce-<version>-ce.0.el8
sudo dnf install ./gitlab-ce-<version>-ce.0.el8.x86_64.rpm
```

{{< /tab >}}

{{< tab title="Amazon Linux 2023" >}}

```shell
# GitLab Enterprise Edition
sudo dnf download gitlab-ee-<version>-ee.0.amazon2023
sudo dnf install ./gitlab-ee-<version>-ee.0.amazon2023.x86_64.rpm

# GitLab Community Edition
sudo dnf download gitlab-ce-<version>-ce.0.amazon2023
sudo dnf install ./gitlab-ce-<version>-ce.0.amazon2023.x86_64.rpm
```

{{< /tab >}}

{{< tab title="OpenSUSE Leap 15.5" >}}

```shell
# GitLab Enterprise Edition
sudo zypper install --download-only gitlab-ee-<version>-ee.0.sles15.x86_64
sudo zypper install /var/cache/zypp/packages/gitlab_gitlab-ee/Packages/g/gitlab-ee-<version>-ee.sles15.x86_64.rpm

# GitLab Community Edition
sudo zypper install --download-only gitlab-ce-<version>-ce.0.sles15.x86_64
sudo zypper install /var/cache/zypp/packages/gitlab_gitlab-ce/Packages/g/gitlab-ce-<version>-ce.sles15.x86_64.rpm
```

{{< /tab >}}

{{< tab title="SUSE Enterprise Server 12.2/12.5" >}}

```shell
# GitLab Enterprise Edition
sudo zypper install --download-only gitlab-ee-<version>-ee.0.sles12.x86_64
sudo zypper install /var/cache/zypp/packages/gitlab_gitlab-ee/Packages/g/gitlab-ee-<version>-ee.0.sles12.x86_64.rpm

# GitLab Community Edition
sudo zypper install --download-only gitlab-ce-<version>-ce.0.sles12.x86_64
sudo zypper install /var/cache/zypp/packages/gitlab_gitlab-ce/Packages/g/gitlab-ce-<version>-ce.0.sles12.x86_64.rpm
```

{{< /tab >}}

{{< /tabs >}}

### 다운로드한 패키지로 업그레이드 {#upgrade-with-a-downloaded-package}

공식 리포지토리를 사용하지 않으려면 패키지를 다운로드하여 수동으로 설치할 수 있습니다. 이 방법은 GitLab을 처음 설치하거나 업그레이드하는 데 사용할 수 있습니다.

GitLab을 다운로드하고 설치하거나 업그레이드하려면:

1. 패키지의 [공식 리포지토리](#upgrade-with-the-official-repositories-recommended)로 이동합니다.
1. 설치하려는 버전을 검색하여 목록을 필터링합니다. 예를 들어, `18.4.1`입니다. 단일 버전에 여러 패키지가 있을 수 있으며, 각각 지원되는 배포판과 아키텍처용입니다. 일부 파일은 둘 이상의 배포판과 관련이 있으므로 파일 이름 옆에 배포판을 나타내는 레이블이 있습니다.
1. 설치하려는 패키지 버전을 찾아 목록에서 파일 이름을 선택합니다.
1. 오른쪽 위 모서리에서 **다운로드**를 선택합니다.
1. 패키지가 다운로드된 후 다음 명령 중 하나를 사용하여 설치하고 `<package_name>`을(를) 다운로드한 패키지 이름으로 바꿉니다:

   {{< tabs >}}

   {{< tab title="Ubuntu/Debian" >}}

   ```shell
   dpkg -i <package_name>
   ```

   {{< /tab >}}

   {{< tab title="Amazon Linux 2" >}}

   ```shell
   rpm -Uvh <package_name>
   ```

   {{< /tab >}}

   {{< tab title="RHEL/Oracle Linux/AlmaLinux 8/9 및 Amazon Linux 2023" >}}

   ```shell
   dnf install <package_name>
   ```

   {{< /tab >}}

   {{< tab title="SUSE 및 OpenSUSE" >}}

   ```shell
   zypper install <package_name>
   ```

   {{< /tab >}}

   {{< /tabs >}}
