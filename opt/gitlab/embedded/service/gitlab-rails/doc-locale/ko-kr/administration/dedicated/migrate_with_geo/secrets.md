---
stage: GitLab Dedicated
group: Environment Automation
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab Self-Managed 인스턴스에서 마이그레이션 암호를 수집하고 업로드합니다.
title: Geo 마이그레이션 암호 수집
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab Dedicated

{{< /details >}}

> [!note]
> GitLab Dedicated for Government는 지속적인 Geo 복제 또는 Geo 기반 장애 조치를 지원하지 않습니다. 신규 테넌트 온보딩을 위한 Geo 마이그레이션은 지원되지만 VPN 연결이 필요합니다. 이를 설정하려면 GitLab Dedicated for Government 온보딩 팀에 문의하세요.

Geo 마이그레이션을 위해서는 GitLab Self-Managed 주요 인스턴스의 시크릿이 필요하므로 GitLab Dedicated가 마이그레이션 후 데이터를 복호화할 수 있습니다. 이 시크릿에는 데이터베이스 암호화 키, CI/CD 변수 및 기타 민감한 구성 세부 정보가 포함됩니다.

SSH 호스트 키는 선택 사항이지만 강력히 권장됩니다. 이를 유지하면 마이그레이션 후 사용자가 SSH를 통해 `git clone` 또는 `git pull`를 실행할 때 SSH 호스트 키 검증 실패를 방지할 수 있습니다. 고유한 도메인을 사용하려는 경우 특히 중요합니다.

수집 스크립트는 [age](https://github.com/FiloSottile/age)(파일 암호화 도구)를 사용하여 Switchboard에 업로드하기 전에 시크릿을 안전하게 암호화합니다.

## 마이그레이션 시크릿 수집 및 업로드 {#collect-and-upload-migration-secrets}

[GitLab Dedicated 인스턴스를 생성할 때](../create_instance/_index.md#create-your-instance) Geo 마이그레이션 시크릿을 수집하고 업로드합니다.

전제 조건:

- GitLab Self-Managed 주요 인스턴스에 대한 관리자 액세스
- Python 3.x
- Switchboard의 **Geo migration secrets** 페이지에서 `age` 공개 키
- GitLab 클러스터에 대한 액세스 권한이 있는 `kubectl` (Kubernetes 설치 전용)

마이그레이션 시크릿을 수집하고 업로드하려면:

1. [Switchboard](https://console.gitlab-dedicated.com/)에 로그인하세요.
1. **Geo migration secrets** 페이지에서 설치 유형에 맞는 수집 스크립트를 다운로드하세요.
1. 선택 사항. 오프라인 환경의 경우, 수집 스크립트를 실행하기 전에 `age` 바이너리를 수집 스크립트에 포함하세요. 자세한 내용은 [오프라인 환경](#offline-environments)을 참조하세요.
1. 설치 유형에 맞는 수집 스크립트를 실행하고 `<age_public_key>`을(를) 페이지에 표시된 키로 바꾸세요:

   - Linux 패키지 설치의 경우 Rails 노드에서 다음 명령을 실행하세요:

     ```shell
     python3 collect_secrets_linux_package.py <age_public_key>
     ```

     `/etc/gitlab/gitlab-secrets.json`, `/var/opt/gitlab/gitlab-rails/etc/database.yml` 및 `/etc/ssh/`에 대한 읽기 액세스가 필요합니다.

   - Kubernetes 설치의 경우 `kubectl` 액세스 권한이 있는 워크스테이션에서 다음 명령을 실행하세요:

     ```shell
     python3 collect_secrets_k8s.py <age_public_key>
     ```

     기본값을 무시하려면 추가 플래그를 전달할 수 있습니다. 자세한 정보는 [Kubernetes collection script flags](#kubernetes-collection-script-flags)를 참조하세요.

1. 선택 사항. SSH 호스트 키만 수집하려면 명령에 `--hostkeys-only` 플래그를 추가하세요.

   스크립트는 다음을 생성합니다:

   - `migration_secrets.json.age`: GitLab 시크릿 (필수)
   - `ssh_host_keys.json.age`: SSH 호스트 키 (선택 사항이지만 권장)

1. `migration_secrets.json.age` 파일을 업로드하세요.
1. 선택 사항. `ssh_host_keys.json.age` 파일을 업로드하세요.
1. 검증이 완료될 때까지 기다리세요. 검증은 파일당 약 10-20초가 소요됩니다.
1. 표시된 파일 이름과 지문이 업로드한 파일과 일치하는지 확인하세요.

> [!note]
> 검증은 파일이 올바르게 암호화되어 있고 예상되는 구조를 포함하는지 확인합니다. 파일의 내용을 복호화하거나 노출하지 않습니다.

시크릿을 업로드한 후 나머지 단계를 완료하여 테넌트를 생성하세요.

### Kubernetes 수집 스크립트 플래그 {#kubernetes-collection-script-flags}

`collect_secrets_k8s.py`와 함께 이러한 선택적 플래그를 사용하여 기본값을 무시합니다:

| 플래그                     | 기본값         | 설명 |
|--------------------------|-----------------|-------------|
| `--namespace NAME`       | 현재 컨텍스트 | Kubernetes 네임스페이스. |
| `--release NAME`         | `gitlab`        | Helm 릴리스 이름 접두사. |
| `--rails-secret NAME`    | 없음            | Rails 시크릿 이름. |
| `--registry-secret NAME` | 없음            | 레지스트리 시크릿 이름. |
| `--postgres-secret NAME` | 없음            | Postgres 비밀번호 시크릿 이름. |
| `--hostkeys-secret NAME` | 없음            | SSH 호스트 키 시크릿 이름. |

### 오프라인 환경 {#offline-environments}

GitLab Self-Managed 인스턴스에 인터넷 액세스 권한이 없으면 스크립트를 실행하기 전에 수집 스크립트에 `age` 바이너리를 포함하세요.

오프라인 환경에 대해 수집 스크립트를 설정하려면:

1. 인터넷 액세스 권한이 있는 컴퓨터에서 `download_age_binaries.py` 및 `embed_age_binary.py`를 [Geo secrets collection](https://gitlab.com/gitlab-com/gl-infra/gitlab-dedicated/customer-tools/geo-secrets-collection) 프로젝트에서 다운로드하고 Switchboard에서 다운로드한 수집 스크립트와 동일한 디렉터리에 넣으세요.
1. `age` 바이너리를 다운로드하고 인코딩합니다:

   ```shell
   python3 download_age_binaries.py > age_binaries.txt
   ```

   스크립트는 Linux AMD64 및 ARM64용 base64 인코딩된 `age` 바이너리를 표준 출력으로 출력하므로 출력을 `age_binaries.txt`로 리디렉션해야 합니다.

1. 수집 스크립트에 바이너리를 포함하세요:

   ```shell
   python3 embed_age_binary.py
   ```

   스크립트는 현재 디렉터리에서 `age_binaries.txt`을(를) 읽고 `collect_secrets_linux_package.py` 및 `collect_secrets_k8s.py`을(를) 포함된 바이너리가 포함된 버전으로 덮어씁니다.

1. 업데이트된 수집 스크립트를 오프라인 환경으로 전송하세요.
1. [마이그레이션 시크릿 수집 및 업로드](#collect-and-upload-migration-secrets)에 설명된 대로 GitLab Self-Managed 인스턴스에서 스크립트를 실행하세요.

업데이트된 스크립트는 독립적이며 포함된 `age` 바이너리를 자동으로 추출하고 사용합니다.

## 문제 해결 {#troubleshooting}

Geo 마이그레이션으로 작업할 때 다음과 같은 문제가 발생할 수 있습니다.

### 오류: 수집 스크립트를 실행할 때 `Permission denied` {#error-permission-denied-when-running-the-collection-script}

수집 스크립트가 GitLab 구성 파일에 액세스하려고 할 때 권한 오류가 발생할 수 있습니다.

스크립트가 필요한 파일을 읽을 수 있는 충분한 권한 없이 실행될 때 이 문제가 발생합니다.

이 이슈를 해결하려면:

1. Linux 패키지 설치의 경우 `root` 사용자로 스크립트를 실행하거나 `sudo`를 사용하세요.
1. Kubernetes 설치의 경우 `kubectl` 컨텍스트에 GitLab 네임스페이스에 대한 액세스 권한이 있는지 확인하세요.
1. 필요한 파일이 예상 경로에 있는지 확인하세요.

### 수집 스크립트가 GitLab 설치를 찾을 수 없음 {#collection-script-cannot-find-gitlab-installation}

스크립트가 GitLab 설치 또는 구성 파일을 찾을 수 없다는 오류가 발생할 수 있습니다.

이 문제는 다음과 같은 시나리오에서 발생합니다:

- 스크립트가 GitLab이 설치되지 않은 컴퓨터에서 실행됩니다.
- GitLab이 비표준 위치에 설치되어 있습니다.
- 필요한 구성 파일이 없거나 이동되었습니다.

일반적인 오류 메시지는 다음과 같습니다:

- Linux 패키지: `Error: database.yml not found: /var/opt/gitlab/gitlab-rails/etc/database.yml` 다음 `✗ Failed to collect GitLab secrets`
- Kubernetes: `Error: Could not retrieve gitlab-rails-secrets`

이 이슈를 해결하려면:

1. 스크립트가 올바른 컴퓨터(Linux 패키지 설치의 경우 Rails 노드)에서 실행되는지 확인하세요.
1. GitLab이 올바르게 설치되고 구성되어 있는지 확인하세요.
1. GitLab이 비표준 위치에 설치된 경우 구성 파일 경로가 설치와 일치하는지 확인하세요.
1. 필요한 파일이 없거나 손상된 경우 마이그레이션을 진행하기 전에 Professional Services에 연락하여 설치의 상태 확인을 수행하세요.
