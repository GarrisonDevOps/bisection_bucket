---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
title: 패키지 레지스트리의 Debian 패키지
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab Self-Managed
- 상태:  실험적 기능

{{< /details >}}

{{< history >}}

- [기능 플래그 뒤에 배포됨](../../../administration/feature_flags/list.md), 기본적으로 비활성화됨.

{{< /history >}}

> [!warning]
> GitLab의 Debian 패키지 레지스트리는 개발 중이며 프로덕션 사용할 준비가 되어 있지 않습니다. 이 [에픽](https://gitlab.com/groups/gitlab-org/-/work_items/6057)은 프로덕션 준비를 위한 남은 작업과 일정을 설명합니다. [Debian 패키지는 실험](../package_registry/supported_functionality.md)이며 알려진 보안 취약점이 있습니다.

프로젝트의 패키지 레지스트리에 Debian 패키지를 게시합니다. 그런 다음 필요할 때마다 패키지를 종속성으로 사용하기 위해 설치합니다.

프로젝트 및 그룹 패키지가 지원됩니다.

Debian 패키지 관리자 클라이언트가 사용하는 특정 API 끝점의 설명서는 [Debian API 설명서](../../../api/packages/debian.md)를 참조하세요.

사전 요구 사항:

- `dpkg-deb` 바이너리는 GitLab 인스턴스에 설치되어야 합니다. 이 바이너리는 일반적으로 [`dpkg` 패키지](https://wiki.debian.org/Teams/Dpkg/Downstream)에서 제공되며 Debian 및 파생 버전에 기본적으로 설치됩니다.
- 권장하는 방식입니다. `dpkg-deb` 1.22.21 이상을 사용하세요. `dpkg-deb` 1.22.20 이하에서는 바이너리가 쓰기 불가능한 디렉터리를 포함하는 아카이브에서 임시 파일을 삭제할 수 없습니다. 이러한 파일은 디스크 공간을 소비하며 서비스 거부 공격을 유발할 수 있습니다.
- ZStandard 압축 알고리즘 지원에는 Debian 12 Bookworm의 `dpkg >= 1.21.18` 또는 Ubuntu 18.04 Bionic Beaver의 `dpkg >= 1.19.0.5ubuntu2`가 필요합니다.

## Debian API 활성화 {#enable-the-debian-api}

Debian 리포지토리 지원은 아직 진행 중인 작업입니다. 기본적으로 비활성화된 기능 플래그 뒤에 있습니다. [GitLab Rails 콘솔에 액세스할 수 있는 GitLab 관리자](../../../administration/feature_flags/_index.md)는 활성화를 선택할 수 있습니다.

> [!warning]
> [개발 중인 기능을 활성화할 때의 안정성 및 보안 위험](../../../administration/feature_flags/_index.md#risks-when-enabling-features-still-in-development)을 이해하세요.

활성화하려면:

```ruby
Feature.enable(:debian_packages)
```

비활성화하려면:

```ruby
Feature.disable(:debian_packages)
```

## Debian 그룹 API 활성화 {#enable-the-debian-group-api}

Debian 그룹 리포지토리는 기본적으로 비활성화된 두 번째 기능 플래그 뒤에 있습니다.

> [!warning]
> [개발 중인 기능을 활성화할 때의 안정성 및 보안 위험](../../../administration/feature_flags/_index.md#risks-when-enabling-features-still-in-development)을 이해하세요.

활성화하려면:

```ruby
Feature.enable(:debian_group_packages)
```

비활성화하려면:

```ruby
Feature.disable(:debian_group_packages)
```

## Debian 패키지 빌드 {#build-a-debian-package}

Debian 패키지 생성은 [Debian Wiki](https://wiki.debian.org/Packaging)에 문서화되어 있습니다.

## Debian 끝점에 인증 {#authenticate-to-the-debian-endpoints}

인증 방법은 [분포 API](#authenticate-to-the-debian-distributions-apis)와 [패키지 리포지토리](#authenticate-to-the-debian-package-repositories) 간에 다릅니다.

### Debian 분포 API에 인증 {#authenticate-to-the-debian-distributions-apis}

분포를 만들기, 읽기, 업데이트 또는 삭제하려면 다음 중 하나가 필요합니다:

- [개인 액세스 토큰](../../profile/personal_access_tokens.md), `--header "PRIVATE-TOKEN: <personal_access_token>"` 사용
- [배포 토큰](../../project/deploy_tokens/_index.md) `--header "Deploy-Token: <deploy_token>"` 사용
- [CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md) `--header "Job-Token: <job_token>"` 사용

### Debian 패키지 리포지토리에 인증 {#authenticate-to-the-debian-package-repositories}

패키지를 게시하거나 개인 패키지를 설치하려면 기본 인증을 사용해야 하며 다음 중 하나가 필요합니다:

- [개인 액세스 토큰](../../profile/personal_access_tokens.md), `<username>:<personal_access_token>` 사용
- [배포 토큰](../../project/deploy_tokens/_index.md) `<deploy_token_name>:<deploy_token>` 사용
- [CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md) `gitlab-ci-token:<job_token>` 사용

## 배포 생성 {#create-a-distribution}

프로젝트 수준에서 Debian 패키지는 Debian 분포로 게시됩니다. 그룹 수준에서 Debian 패키지는 다음 조건이 충족되는 그룹의 프로젝트에서 집계됩니다:

- 프로젝트 표시 여부가 `public`으로 설정됩니다.
- 그룹의 Debian `codename`이 프로젝트의 Debian `codename`과 일치합니다.

개인 액세스 토큰을 사용하여 프로젝트 수준의 배포를 생성하려면:

```shell
curl --fail-with-body --request POST --header "PRIVATE-TOKEN: <personal_access_token>" \
  "https://gitlab.example.com/api/v4/projects/<project_id>/debian_distributions?codename=<codename>"
```

`codename=sid`이(가) 포함된 응답 예시:

```json
{
  "id": 1,
  "codename": "sid",
  "suite": null,
  "origin": null,
  "label": null,
  "version": null,
  "description": null,
  "valid_time_duration_seconds": null,
  "components": [
    "main"
  ],
  "architectures": [
    "all",
    "amd64"
  ]
}
```

Debian 배포 API에 대한 자세한 정보:

- [Debian 프로젝트 배포 API](../../../api/packages/debian_project_distributions.md)
- [Debian 그룹 배포 API](../../../api/packages/debian_group_distributions.md)

## 패키지 게시 {#publish-a-package}

빌드된 후 여러 파일이 생성됩니다:

- `.deb` 파일: 바이너리 패키지
- `.udeb` 파일: Debian-Installer에 사용되는 경량 .deb 파일(필요한 경우)
- `.ddeb` 파일: Ubuntu 디버그 .deb 파일(필요한 경우)
- `.tar.{gz,bz2,xz,...}` 파일: 소스 파일
- `.dsc` 파일: 소스 메타데이터 및 소스 파일 목록(해시 포함)
- `.buildinfo` 파일: 재현 가능한 빌드에 사용됨(선택 사항)
- `.changes` 파일: 업로드 메타데이터 및 업로드된 파일 목록(위 모두)

이러한 파일을 업로드하려면 `dput-ng >= 1.32`(Debian bullseye)를 사용할 수 있습니다. `<username>`와 `<password>`은 [Debian 패키지 리포지토리](#authenticate-to-the-debian-package-repositories)에서와 같이 정의됩니다:

```shell
cat <<EOF > dput.cf
[gitlab]
method = https
fqdn = <username>:<password>@gitlab.example.com
incoming = /api/v4/projects/<project_id>/packages/debian
EOF

dput --config=dput.cf --unchecked --no-upload-log gitlab <your_package>.changes
```

## 명시적 배포 및 구성 요소를 사용하여 패키지 업로드 {#upload-a-package-with-explicit-distribution-and-component}

`.changes` 파일에 액세스할 수 없는 경우 배포 `codename` 및 대상 `component`을(를) 매개 변수로 전달하여 `.deb`을(를) 직접 업로드할 수 있습니다(사용자의 [자격 증명](#authenticate-to-the-debian-package-repositories) 포함). 예를 들어 개인 액세스 토큰을 사용하여 배포 `sid`의 구성 요소 `main`에 업로드하려면:

```shell
curl --fail-with-body --request PUT --user "<username>:<personal_access_token>" \
  "https://gitlab.example.com/api/v4/projects/<project_id>/packages/debian/your.deb?distribution=sid&component=main" \
  --upload-file  /path/to/your.deb
```

## 패키지 설치 {#install-a-package}

패키지를 설치하려면:

1. 리포지토리 구성:

   개인 프로젝트를 사용하는 경우 apt 구성에 [자격 증명](#authenticate-to-the-debian-package-repositories)을 추가합니다:

   ```shell
   echo 'machine gitlab.example.com login <username> password <password>' \
     | sudo tee /etc/apt/auth.conf.d/gitlab_project.conf
   ```

   [자격 증명](#authenticate-to-the-debian-distributions-apis)을 사용하여 배포 키를 다운로드하세요:

   ```shell
   sudo mkdir -p /etc/apt/keyrings
   sudo curl --fail --silent --show-error --header "PRIVATE-TOKEN: <your_access_token>" \
        --output /etc/apt/keyrings/<codename>-archive-keyring.asc \
        --url "https://gitlab.example.com/api/v4/projects/<project_id>/debian_distributions/<codename>/key.asc"
   ```

   프로젝트를 소스로 추가:

   ```shell
   echo 'deb [ signed-by=/etc/apt/keyrings/<codename>-archive-keyring.asc ] https://gitlab.example.com/api/v4/projects/<project_id>/packages/debian <codename> <component1> <component2>' |
       sudo tee /etc/apt/sources.list.d/gitlab_project.list
   sudo apt-get update
   ```

1. 패키지 설치:

   ```shell
   sudo apt-get -y install -t <codename> <package-name>
   ```

## 소스 패키지 다운로드 {#download-a-source-package}

소스 패키지를 다운로드하려면:

1. 리포지토리 구성:

   개인 프로젝트를 사용하는 경우 apt 구성에 [자격 증명](#authenticate-to-the-debian-package-repositories)을 추가합니다:

   ```shell
   echo 'machine gitlab.example.com login <username> password <password>' \
     | sudo tee /etc/apt/auth.conf.d/gitlab_project.conf
   ```

   [자격 증명](#authenticate-to-the-debian-distributions-apis)을 사용하여 배포 키를 다운로드하세요:

   ```shell
   sudo mkdir -p /etc/apt/keyrings
   sudo curl --fail --silent --show-error --header "PRIVATE-TOKEN: <your_access_token>" \
        --output /etc/apt/keyrings/<codename>-archive-keyring.asc \
        --url "https://gitlab.example.com/api/v4/projects/<project_id>/debian_distributions/<codename>/key.asc"
   ```

   프로젝트를 소스로 추가:

   ```shell
   echo 'deb-src [ signed-by=/etc/apt/keyrings/<codename>-archive-keyring.asc ] https://gitlab.example.com/api/v4/projects/<project_id>/packages/debian <codename> <component1> <component2>' |
       sudo tee /etc/apt/sources.list.d/gitlab_project-sources.list
   sudo apt-get update
   ```

1. 소스 패키지를 다운로드하세요:

   ```shell
   sudo apt-get source -t <codename> <package-name>
   ```

## Debian 패키지 삭제 {#delete-a-debian-package}

사전 요구 사항:

- Maintainer 또는 Owner 역할이 있어야 합니다.

패키지를 삭제하기 전에 [관련 보안 위험](../package_registry/supported_functionality.md#deleting-packages)을 이해해야 합니다.

패키지를 삭제하려면 다음 중 하나를 수행할 수 있습니다:

- [UI 사용](../package_registry/reduce_package_registry_storage.md#delete-a-package)하세요.
- [API 사용](../../../api/packages.md#delete-a-project-package)하세요.
