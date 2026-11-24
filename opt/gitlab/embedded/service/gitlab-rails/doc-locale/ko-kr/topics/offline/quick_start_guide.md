---
stage: GitLab Delivery
group: Operate
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "오프라인 환경에서 GitLab Self-Managed 인스턴스를 설치, 구성 및 사용합니다."
title: 오프라인 GitLab Self-Managed 인스턴스 설치
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

GitLab Self-Managed 인스턴스를 완전히 오프라인으로 설치, 구성 및 사용할 수 있도록 도와주는 단계별 가이드입니다.

## 설치 {#installation}

> [!note]
> 이 가이드는 서버가 Ubuntu 20.04를 사용하고 [Linux 패키지 설치 방법](../../install/package/_index.md)으로 GitLab Enterprise Edition을 실행하고 있다고 가정합니다. 다른 서버의 지침은 다를 수 있습니다. 이 가이드는 서버 호스트가 `my-host.internal`으로 확인된다고 가정하며, 이를 서버의 FQDN으로 바꾸고 필요한 패키지 파일을 다운로드할 수 있는 인터넷 접근 권한이 있는 다른 서버에 액세스할 수 있다고 가정합니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 이 프로세스의 비디오 시연을 보려면 [오프라인 GitLab 설치: 다운로드 및 설치](https://www.youtube.com/watch?v=TJaq4ua2Prw)를 참조하세요.

### GitLab 패키지 다운로드 {#download-the-gitlab-package}

인터넷에 액세스할 수 있는 동일한 운영 체제 유형의 서버를 사용하여 [GitLab 패키지를 다운로드](../../update/package/_index.md#upgrade-with-a-downloaded-package)하고 관련 종속성을 다운로드해야 합니다.

오프라인 환경에 로컬 네트워크 액세스 권한이 없으면 USB 드라이브와 같은 물리적 미디어를 통해 관련 패키지를 수동으로 전송해야 합니다.

Ubuntu에서는 인터넷 액세스가 있는 서버에서 다음 명령을 사용하여 수행할 수 있습니다:

```shell
# Download the bash script to prepare the repository
curl --silent "https://packages.gitlab.com/install/repositories/gitlab/gitlab-ee/script.deb.sh" | sudo bash

# Download the gitlab-ee package and dependencies to /var/cache/apt/archives
sudo apt-get install --download-only gitlab-ee

# Copy the contents of the apt download folder to a mounted media device
sudo cp /var/cache/apt/archives/*.deb /path/to/mount
```

### GitLab 패키지 설치 {#install-the-gitlab-package}

전제 조건:

- 오프라인 환경에 GitLab 패키지를 설치하기 전에 먼저 필요한 모든 종속성을 설치했는지 확인하세요.

Ubuntu를 사용하는 경우 `.deb` 패키지를 복사한 후 `dpkg`로 설치할 수 있습니다. 아직 GitLab 패키지를 설치하지 마세요.

```shell
# Go to the physical media device
sudo cd /path/to/mount

# Install the dependency packages
sudo dpkg -i <package_name>.deb
```

[운영 체제에 맞는 관련 명령을 사용하여 패키지를 설치](../../update/package/_index.md#upgrade-with-a-downloaded-package)하되 `EXTERNAL_URL` 설치 단계에서 `http` URL을 지정해야 합니다. 설치 후 SSL을 수동으로 구성할 수 있습니다.

서버의 IP 주소에 바인딩하는 것보다 IP 확인을 위해 도메인을 설정해야 합니다. 도메인은 인증서의 CN(일반 이름)에 대한 안정적인 대상을 제공하고 장기 확인을 단순화합니다.

다음은 Ubuntu의 예로, `EXTERNAL_URL`을 HTTP로 지정하고 GitLab 패키지를 설치합니다:

```shell
sudo EXTERNAL_URL="http://my-host.internal" dpkg -i <gitlab_package_name>.deb
```

## SSL 활성화 {#enabling-ssl}

새로운 인스턴스에서 SSL을 활성화하려면 다음 단계를 따르세요. 이 단계는 [NGINX 구성에서 SSL을 수동으로 구성](https://docs.gitlab.com/omnibus/settings/ssl/#configure-https-manually)하는 단계를 반영합니다:

1. `/etc/gitlab/gitlab.rb`에 다음 변경 사항을 적용합니다:

   ```ruby
   # Update external_url from "http" to "https"
   external_url "https://my-host.internal"

   # Set Let's Encrypt to false
   letsencrypt['enable'] = false
   ```

1. 자체 서명된 인증서를 생성하기 위한 적절한 권한으로 다음 디렉토리를 만듭니다:

   ```shell
   sudo mkdir -p /etc/gitlab/ssl
   sudo chmod 755 /etc/gitlab/ssl
   sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/gitlab/ssl/my-host.internal.key -out /etc/gitlab/ssl/my-host.internal.crt
   ```

1. 변경 사항을 적용하려면 인스턴스를 다시 구성합니다:

   ```shell
   sudo gitlab-ctl reconfigure
   ```

## GitLab 컨테이너 레지스트리 활성화 {#enabling-the-gitlab-container-registry}

컨테이너 레지스트리를 활성화하려면 다음 단계를 따르세요. 이 단계는 [기존 도메인 아래에서 컨테이너 레지스트리 구성](../../administration/packages/container_registry.md#configure-container-registry-under-an-existing-gitlab-domain)하는 단계를 반영합니다:

1. `/etc/gitlab/gitlab.rb`에 다음 변경 사항을 적용합니다:

   ```ruby
   # Change external_registry_url to match external_url, but append the port 4567
   external_url "https://gitlab.example.com"
   registry_external_url "https://gitlab.example.com:4567"
   ```

1. 변경 사항을 적용하려면 인스턴스를 다시 구성합니다:

   ```shell
   sudo gitlab-ctl reconfigure
   ```

## Docker 데몬이 레지스트리 및 GitLab Runner를 신뢰하도록 허용 {#allow-the-docker-daemon-to-trust-the-registry-and-gitlab-runner}

[레지스트리에서 신뢰된 인증서를 사용하기 위한 단계를 따르](../../administration/packages/container_registry.md#configure-self-signed-certificates)고 Docker 데몬에 인증서를 제공합니다:

```shell
sudo mkdir -p /etc/docker/certs.d/my-host.internal:5000

sudo cp /etc/gitlab/ssl/my-host.internal.crt /etc/docker/certs.d/my-host.internal:5000/ca.crt
```

[러너에서 신뢰된 인증서를 사용하기 위한 단계를 따르](https://docs.gitlab.com/runner/install/docker/#installing-trusted-ssl-server-certificates)고 GitLab Runner(다음에 설치할)에 인증서를 제공합니다:

```shell
sudo mkdir -p /etc/gitlab-runner/certs

sudo cp /etc/gitlab/ssl/my-host.internal.crt /etc/gitlab-runner/certs/ca.crt
```

## GitLab Runner 활성화 {#enabling-gitlab-runner}

[GitLab Runner를 Docker 서비스로 설치하기 위한 단계와 유사한 프로세스를 따르](https://docs.gitlab.com/runner/install/docker/#install-the-docker-image-and-start-the-container)며, 먼저 러너를 등록해야 합니다:

```shell
$ sudo docker run --rm -it -v /etc/gitlab-runner:/etc/gitlab-runner gitlab/gitlab-runner register
Updating CA certificates...
Runtime platform                                    arch=amd64 os=linux pid=7 revision=1b659122 version=12.8.0
Running in system-mode.

Enter the GitLab instance URL (for example, https://gitlab.com/):
https://my-host.internal
Enter the registration token:
XXXXXXXXXXX
Enter a description for the runner:
[eb18856e13c0]:
Enter tags for the runner (comma-separated):
Enter optional maintenance note for the runner:

Registering runner... succeeded                     runner=FSMwkvLZ
Please enter the executor: custom, docker, virtualbox, kubernetes, docker+machine, docker-ssh+machine, docker-ssh, parallels, shell, ssh:
docker
Please enter the default Docker image (for example, ruby:2.6):
ruby:2.6
Runner registered successfully. Feel free to start it, but if it's running already the config should be automatically reloaded!
```

다음으로 러너에 추가 구성을 추가해야 합니다.

`/etc/gitlab-runner/config.toml`에 다음 변경 사항을 적용합니다:

- Docker 소켓을 볼륨 `volumes = ["/var/run/docker.sock:/var/run/docker.sock", "/cache"]`에 추가합니다
- `pull_policy = "if-not-present"`을 실행기 구성에 추가합니다

이제 러너를 시작할 수 있습니다:

```shell
sudo docker run -d --restart always --name gitlab-runner -v /etc/gitlab-runner:/etc/gitlab-runner -v /var/run/docker.sock:/var/run/docker.sock gitlab/gitlab-runner:latest
90646b6587127906a4ee3f2e51454c6e1f10f26fc7a0b03d9928d8d0d5897b64
```

### 호스트 OS에 대한 레지스트리 인증 {#authenticating-the-registry-against-the-host-os}

[Docker 레지스트리 인증 설명서](https://distribution.github.io/distribution/about/insecure/#docker-still-complains-about-the-certificate-when-using-authentication)에서 언급한 대로 Docker의 특정 버전은 OS 레벨에서 인증서 체인을 신뢰해야 합니다.

Ubuntu의 경우 `update-ca-certificates`을 사용해야 합니다:

```shell
sudo cp /etc/docker/certs.d/my-host.internal\:5000/ca.crt /usr/local/share/ca-certificates/my-host.internal.crt

sudo update-ca-certificates
```

모든 것이 잘 진행되면 다음과 같이 표시됩니다:

```plaintext
1 added, 0 removed; done.
Running hooks in /etc/ca-certificates/update.d...
done.
```

### 버전 확인 및 서비스 핑 비활성화 {#disable-version-check-and-service-ping}

버전 확인 및 서비스 핑은 GitLab 사용자 환경을 개선하고 사용자가 최신 GitLab 인스턴스를 사용하도록 합니다. 이 두 서비스는 오프라인 환경에서 끌 수 있으므로 GitLab 서비스에 연결을 시도하지 않고 실패하지 않습니다.

자세한 정보는 [서비스 핑 활성화 또는 비활성화](../../administration/settings/usage_statistics.md#enable-or-disable-service-ping)를 참조하세요.

### 러너 버전 관리 비활성화 {#disable-runner-version-management}

러너 버전 관리는 GitLab에서 최신 러너 버전을 검색하여 [사용자 환경에서 어떤 러너가 최신 상태가 아닌지 확인](../../ci/runners/runners_scope.md#determine-which-runners-need-to-be-upgraded)합니다. 오프라인 환경에서는 [러너 버전 관리를 비활성화](../../administration/settings/continuous_integration.md#control-runner-version-management)해야 합니다.

### NTP 구성 {#configure-ntp}

Gitaly Cluster(Praefect)는 `pool.ntp.org`이 액세스 가능하다고 가정합니다. `pool.ntp.org`에 액세스할 수 없으면 Gitaly 및 Praefect 서버에서 [시간 서버 설정을 사용자 지정](../../administration/gitaly/praefect/configure.md#customize-time-server-setting)하여 액세스 가능한 NTP 서버를 사용할 수 있습니다.

오프라인 인스턴스에서 [GitLab Geo 확인 Rake 작업](../../administration/geo/replication/troubleshooting/common.md#can-geo-detect-the-current-site-correctly)은 `pool.ntp.org`을 사용하기 때문에 항상 실패합니다. 이 오류는 무시할 수 있지만 [해결 방법을 읽어볼 수](../../administration/geo/replication/troubleshooting/common.md#message-machine-clock-is-synchronized--exception) 있습니다.

## 패키지 메타데이터 데이터베이스 활성화 {#enabling-the-package-metadata-database}

[지속적 취약성 스캔](../../user/application_security/continuous_vulnerability_scanning/_index.md) 및 [CycloneDX 파일의 라이선스 스캔](../../user/compliance/license_scanning_of_cyclonedx_files/_index.md)은 패키지 메타데이터 데이터베이스를 읽습니다. 오프라인 인스턴스는 이를 다운로드할 수 없으므로 인터넷 액세스가 있는 머신에서 다운로드한 후 인스턴스에 복사합니다.

- 데이터베이스에 포함된 내용과 GitLab 버전이 읽는 데이터 형식 버전을 보려면 [패키지 메타데이터 데이터베이스](../../user/application_security/detect/package-metadata-database.md)를 참조하세요.
- 다운로드 및 복사 절차는 [오프라인 인스턴스용 패키지 메타데이터 데이터베이스](package-metadata-database.md)를 참조하세요.
