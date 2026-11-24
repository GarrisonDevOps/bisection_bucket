---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 패키지 레지스트리의 PyPI 패키지
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

PyPI(Python Package Index)는 Python의 공식 타사 소프트웨어 리포지토리입니다. GitLab PyPI 패키지 레지스트리를 사용하여 GitLab 프로젝트, 그룹 및 조직에서 Python 패키지를 게시하고 공유합니다. 이 통합을 통해 코드와 함께 Python 종속성을 관리할 수 있으며, GitLab 내에서 Python 개발을 위한 원활한 워크플로우를 제공합니다.

패키지 레지스트리는 다음과 함께 작동합니다:

- [pip](https://pypi.org/project/pip/)
- [twine](https://pypi.org/project/twine/)

`pip`과 `twine` 클라이언트가 사용하는 특정 API 엔드포인트에 대한 설명서는 [PyPI API 설명서](../../../api/packages/pypi.md)를 참조하세요.

[PyPI 패키지를 빌드하는 방법](../workflows/build_packages.md#pypi)을 알아보세요.

## 패키지 요청 전달 보안 공지 {#package-request-forwarding-security-notice}

GitLab PyPI 패키지 레지스트리를 사용할 때, GitLab 레지스트리에서 찾을 수 없는 패키지 요청은 자동으로 `pypi.org`으로 전달됩니다. 이 동작으로 인해 `pypi.org`에서 패키지가 다운로드될 수 있으며, `--index-url` 플래그를 사용하는 경우에도 마찬가지입니다.

개인 패키지를 사용할 때 최대 보안을 위해:

- 그룹 설정에서 패키지 전달을 해제합니다.
- 패키지를 설치할 때 [`--index-url`과 `--no-index`](#security-implications) 플래그를 모두 사용합니다.

사전 요구 사항:

- 그룹의 소유자 역할이 있어야 합니다.

패키지 요청 전달을 해제하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **패키지 전달**에서 **PyPI 패키지 요청 전달** 확인란을 선택 해제합니다.

**운영자** 영역에서 패키지 전달을 해제하는 방법에 대한 자세한 내용은 [패키지 전달 제어](../../../administration/settings/continuous_integration.md#control-package-forwarding)를 참조하세요.

## GitLab 패키지 레지스트리로 인증 {#authenticate-with-the-gitlab-package-registry}

GitLab 패키지 레지스트리와 상호 작용하기 전에 인증해야 합니다.

다음으로 인증할 수 있습니다:

- 범위가 `api`로 설정된 [PAT](../../profile/personal_access_tokens.md).
- 범위가 `read_package_registry`, `write_package_registry` 또는 둘 다로 설정된 [배포 토큰](../../project/deploy_tokens/_index.md).
- [CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md).

여기에 설명된 방법 이외의 인증 방법을 사용하지 마세요. 문서화되지 않은 인증 방법은 향후 제거될 수 있습니다.

GitLab 토큰으로 인증하려면:

- `TWINE_USERNAME`과 `TWINE_PASSWORD` 환경 변수를 업데이트합니다.

예를 들어:

{{< tabs >}}

{{< tab title="개인 액세스 토큰 사용" >}}

```yaml
run:
  image: python:latest
  variables:
    TWINE_USERNAME: <personal_access_token_name>
    TWINE_PASSWORD: <personal_access_token>
  script:
    - pip install build twine
    - python -m build
    - python -m twine upload --repository-url ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/pypi dist/*
```

{{< /tab >}}

{{< tab title="배포 토큰 사용" >}}

```yaml
run:
  image: python:latest
  variables:
    TWINE_USERNAME: <deploy_token_username>
    TWINE_PASSWORD: <deploy_token>
  script:
    - pip install build twine
    - python -m build
    - python -m twine upload --repository-url ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/pypi dist/*
```

{{< /tab >}}

{{< tab title="CI/CD 작업 토큰 사용" >}}

```yaml
run:
  image: python:latest
  variables:
    TWINE_USERNAME: gitlab-ci-token
    TWINE_PASSWORD: $CI_JOB_TOKEN
  script:
    - pip install build twine
    - python -m build
    - python -m twine upload --repository-url ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/pypi dist/*
```

{{< /tab >}}

{{< /tabs >}}

### 그룹에 대해 인증 {#authenticate-for-a-group}

그룹의 패키지 레지스트리로 인증하려면:

- 패키지 레지스트리로 인증하되, 프로젝트 URL 대신 그룹 URL을 사용합니다:

```shell
https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/pypi
```

## PyPI 패키지 게시 {#publish-a-pypi-package}

twine을 사용하여 패키지를 게시할 수 있습니다.

사전 요구 사항:

- [패키지 레지스트리로 인증](#authenticate-with-the-gitlab-package-registry)해야 합니다.
- [버전 문자열이 유효](#use-valid-version-strings)해야 합니다.
- 패키지:
  - 5GB 이하입니다.
  - 4000자 이하의 `description`이(가) 있습니다. 더 긴 `description` 문자열은 잘립니다.
  - 패키지 레지스트리에 아직 게시되지 않았습니다. 같은 버전의 패키지를 게시하려고 하면 `400 Bad Request`이(가) 반환됩니다.

PyPI 패키지는 프로젝트 ID를 사용하여 게시됩니다. 프로젝트가 그룹에 있으면, 프로젝트 레지스트리에 게시된 PyPI 패키지도 그룹 레지스트리에서 사용할 수 있습니다. 자세한 내용은 [그룹에서 설치](#install-from-a-group)를 참조하세요.

패키지를 게시하려면:

1. 리포지토리 소스를 정의하고, `~/.pypirc` 파일을 편집하고 다음을 추가합니다:

   ```ini
   [distutils]
   index-servers =
       gitlab

   [gitlab]
   repository = https://gitlab.example.com/api/v4/projects/<project_id>/packages/pypi
   ```

1. twine을 사용하여 패키지를 업로드합니다:

   ```shell
   python3 -m twine upload --repository gitlab dist/*
   ```

   패키지가 성공적으로 게시되면 이와 같은 메시지가 표시됩니다:

   ```plaintext
   Uploading distributions to https://gitlab.example.com/api/v4/projects/<project_id>/packages/pypi
   Uploading mypypipackage-0.0.1-py3-none-any.whl
   100%|███████████████████████████████████████████████████████████████████████████████████████████| 4.58k/4.58k [00:00<00:00, 10.9kB/s]
   Uploading mypypipackage-0.0.1.tar.gz
   100%|███████████████████████████████████████████████████████████████████████████████████████████| 4.24k/4.24k [00:00<00:00, 11.0kB/s]
   ```

패키지는 패키지 레지스트리에 게시되며, **패키지 및 레지스트리** 페이지에 표시됩니다.

### 인라인 인증으로 게시 {#publish-with-inline-authentication}

리포지토리 소스를 정의하기 위해 `.pypirc` 파일을 사용하지 않은 경우, 인라인 인증으로 리포지토리에 게시할 수 있습니다:

```shell
TWINE_PASSWORD=<personal_access_token, deploy_token, or $CI_JOB_TOKEN> \
TWINE_USERNAME=<username, deploy_token_username, or gitlab-ci-token> \
python3 -m twine upload --repository-url https://gitlab.example.com/api/v4/projects/<project_id>/packages/pypi dist/*
```

### 같은 이름과 버전의 패키지 게시 {#publishing-packages-with-the-same-name-and-version}

같은 이름과 버전의 패키지가 이미 있으면 패키지를 게시할 수 없습니다. 먼저 [기존 패키지를 삭제](../package_registry/reduce_package_registry_storage.md#delete-a-package)해야 합니다. 같은 패키지를 두 번 이상 게시하려고 하면 `400 Bad Request` 오류가 발생합니다.

## PyPI 패키지 설치 {#install-a-pypi-package}

기본적으로, PyPI 패키지가 GitLab 패키지 레지스트리에서 찾을 수 없으면 요청은 [pypi.org](https://pypi.org/)로 전달됩니다. 요청 전달을 방지하는 방법에 대한 자세한 내용은 [패키지 요청 전달 및 보안 공지](#package-request-forwarding-security-notice)를 참조하세요.

이 동작:

- 모든 GitLab 인스턴스에 대해 기본적으로 활성화됩니다.
- 그룹의 **패키지 및 레지스트리** 설정에서 구성할 수 있습니다.
- `--index-url` 플래그를 사용하는 경우에도 적용됩니다.

관리자는 [지속적 통합 설정](../../../administration/settings/continuous_integration.md#control-package-forwarding)에서 이 동작을 전역적으로 비활성화할 수 있습니다. 그룹 소유자는 그룹 설정의 **패키지 및 레지스트리** 섹션에서 특정 그룹에 대해 이 동작을 비활성화할 수 있습니다.

> [!note]
> `--index-url` 옵션을 사용할 때 기본 포트인 경우 포트를 지정하지 마세요. `http` URL은 포트 80으로 기본 설정되고, `https` URL은 포트 443으로 기본 설정됩니다.

### 프로젝트에서 설치 {#install-from-a-project}

패키지의 최신 버전을 설치하려면 다음 명령을 사용합니다:

```shell
pip install --index-url https://<personal_access_token_name>:<personal_access_token>@gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple --no-deps <package_name>
```

- `<package_name>`은(는) 패키지 이름입니다.
- `<personal_access_token_name>`은(는) `read_api` 범위를 가진 개인 액세스 토큰 이름입니다.
- `<personal_access_token>`은(는) `read_api` 범위를 가진 개인 액세스 토큰입니다.
- `<project_id>`은(는) 프로젝트의 [URL 인코딩](../../../api/rest/_index.md#namespaced-paths) 경로(예: `group%2Fproject`) 또는 프로젝트의 ID(예: `42`)입니다.

이 명령에서 `--extra-index-url` 대신 `--index-url`을(를) 사용할 수 있습니다. 가이드를 따르고 `MyPyPiPackage` 패키지를 설치하려면 다음을 실행할 수 있습니다:

```shell
pip install mypypipackage --no-deps --index-url https://<personal_access_token_name>:<personal_access_token>@gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
```

이 메시지는 패키지가 성공적으로 설치되었음을 나타냅니다:

```plaintext
Looking in indexes: https://<personal_access_token_name>:****@gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
Collecting mypypipackage
  Downloading https://gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/files/d53334205552a355fee8ca35a164512ef7334f33d309e60240d57073ee4386e6/mypypipackage-0.0.1-py3-none-any.whl (1.6 kB)
Installing collected packages: mypypipackage
Successfully installed mypypipackage-0.0.1
```

### 그룹에서 설치 {#install-from-a-group}

그룹에서 패키지의 최신 버전을 설치하려면 다음 명령을 사용합니다:

```shell
pip install --index-url https://<personal_access_token_name>:<personal_access_token>@gitlab.example.com/api/v4/groups/<group_id>/-/packages/pypi/simple --no-deps <package_name>
```

이 명령에서:

- `<package_name>`은(는) 패키지 이름입니다.
- `<personal_access_token_name>`은(는) `read_api` 범위를 가진 개인 액세스 토큰 이름입니다.
- `<personal_access_token>`은(는) `read_api` 범위를 가진 개인 액세스 토큰입니다.
- `<group_id>`은(는) 그룹 ID입니다.

이 명령에서 `--extra-index-url` 대신 `--index-url`을(를) 사용할 수 있습니다. 가이드를 따르고 `MyPyPiPackage` 패키지를 설치하려면 다음을 실행할 수 있습니다:

```shell
pip install mypypipackage --no-deps --index-url https://<personal_access_token_name>:<personal_access_token>@gitlab.example.com/api/v4/groups/<group_id>/-/packages/pypi/simple
```

### 패키지 이름 {#package-names}

GitLab은 [Python 정규화 이름(PEP-503)](https://www.python.org/dev/peps/pep-0503/#normalized-names)을(를) 사용하는 패키지를 찾습니다. `-`, `_`, `.` 문자는 모두 같게 처리되며, 반복되는 문자는 제거됩니다.

`pip install` 요청 `my.package`은(는) `my-package`, `my_package`, `my....package`과 같은 세 문자 중 일치하는 패키지를 찾습니다.

### 보안 영향 {#security-implications}

PyPI 패키지를 설치할 때 `--extra-index-url`과 `--index-url`을(를) 사용하는 보안 영향은 상당하며 상세히 이해할 가치가 있습니다:

- `--index-url`: 이 옵션은 기본 PyPI 인덱스 URL을 지정된 URL로 바꿉니다. 기본적으로 켜진 GitLab 패키지 전달 설정은 패키지 레지스트리에서 찾을 수 없는 패키지를 PyPI에서 다운로드할 수 있습니다. 패키지가 GitLab에서만 설치되도록 하려면 다음 중 하나를 수행합니다:
  - 그룹 설정에서 패키지 전달을 비활성화합니다.
  - `--index-url`과 `--no-index` 플래그를 함께 사용합니다.
- `--extra-index-url`: 이 옵션은 기본 PyPI 인덱스와 함께 검색할 추가 인덱스를 추가합니다. 이는 덜 안전하고 종속성 혼동 공격에 더 취약하며, 기본 PyPI와 추가 인덱스에서 패키지를 확인하기 때문입니다.

개인 패키지를 사용할 때 다음 모범 사례를 고려하세요:

- 그룹의 패키지 전달 설정을 확인합니다.
- 개인 패키지를 설치할 때 `--no-index`과 `--index-url` 플래그를 함께 사용합니다.
- `pip debug`을(를) 사용하여 패키지 소스를 정기적으로 감시합니다.

## PyPI 패키지 삭제 {#delete-a-pypi-package}

사전 요구 사항:

- 유지 관리자 또는 소유자 역할이 있어야 합니다.

패키지를 삭제하기 전에 [관련 보안 위험](../package_registry/supported_functionality.md#deleting-packages)을(를) 이해했는지 확인하세요.

패키지를 삭제하려면 다음 중 하나를 수행할 수 있습니다:

- [UI 사용](../package_registry/reduce_package_registry_storage.md#delete-a-package).
- [API 사용](../../../api/packages.md#delete-a-project-package).

## CI/CD 파이프라인에서 개인 PyPI 패키지 설치 {#install-a-private-pypi-package-in-a-cicd-pipeline}

[CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md)을(를) 사용하여 CI/CD 파이프라인에서 개인 PyPI 패키지를 설치할 수 있습니다. 작업 토큰은 자동으로 인증되며 같은 최상위 그룹 내 다른 프로젝트의 패키지에도 액세스할 수 있습니다.

사전 요구 사항:

- 패키지가 다른 프로젝트에 있으면, 해당 프로젝트는 프로젝트의 작업 토큰을 허용해야 합니다. 자세한 내용은 [작업 토큰 액세스 제어](../../../ci/jobs/ci_job_token.md#control-job-token-access-to-your-project)를 참조하세요.
- CI/CD 작업 토큰으로 인증할 때 사용자 이름은 `gitlab-ci-token`이어야 합니다.

### 인라인 자격 증명 사용 {#use-inline-credentials}

`CI_JOB_TOKEN`을(를) `pip install` 명령에 직접 전달합니다:

{{< tabs >}}

{{< tab title="프로젝트에서" >}}

```yaml
install:
  image: python:latest
  script:
    - pip install <package_name> --index-url https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
```

{{< /tab >}}

{{< tab title="그룹에서" >}}

그룹의 모든 프로젝트의 패키지를 포함하는 그룹 인덱스에서 설치하려면:

```yaml
install:
  image: python:latest
  script:
    - pip install <package_name> --index-url https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.example.com/api/v4/groups/<group_id>/-/packages/pypi/simple
```

{{< /tab >}}

{{< /tabs >}}

### CI/CD에서 `.netrc` 파일 사용 {#use-a-netrc-file-for-cicd}

`.netrc`은(는) `requirements.txt`을(를) 자격 증명 없이 유지하므로 같은 파일이 로컬 및 CI/CD 파이프라인에서 모두 작동합니다. pip은 `.netrc` 파일을 자동으로 읽어 주어진 호스트 이름의 자격 증명을 찾습니다. 자세한 내용은 [.netrc 지원](https://pip.pypa.io/en/stable/topics/authentication/#netrc-support)을(를) 참조하세요.

`.gitlab-ci.yml`에서 `.netrc` 파일을 `before_script`에서 생성합니다:

```yaml
install:
  image: python:latest
  before_script:
    - |
      echo "machine gitlab.example.com
      login gitlab-ci-token
      password ${CI_JOB_TOKEN}" > ~/.netrc
  script:
    - pip install -r requirements.txt
```

`requirements.txt`은(는) 자격 증명 없이 GitLab 레지스트리를 참조합니다:

```plaintext
--extra-index-url https://gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
package-name==1.0.0
```

로컬 개발의 경우, `~/.netrc` 파일을 [개인 액세스 토큰](../../profile/personal_access_tokens.md)으로 생성하고 `api` 범위를 가집니다:

```plaintext
machine gitlab.example.com
login <personal_access_token_name>
password <personal_access_token>
```

> [!note]
> `.netrc` 파일은 호스트 이름당 한 집합의 자격 증명을 구성합니다. 여러 GitLab 인스턴스의 패키지로 인증해야 하는 경우 각 호스트 이름에 대해 별도의 `machine` 항목을 추가합니다.

### Docker 빌드 중에 개인 패키지 설치 {#install-private-packages-during-a-docker-build}

개인 PyPI 패키지를 필요로 하는 Docker 이미지를 빌드할 때, `CI_JOB_TOKEN`을(를) 빌드 인수로 전달합니다:

```yaml
build:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker build --build-arg CI_JOB_TOKEN=$CI_JOB_TOKEN -t my-image .
```

`Dockerfile`에서 토큰을 사용하여 레지스트리로 인증합니다:

```dockerfile
ARG CI_JOB_TOKEN
RUN pip install <package_name> --index-url https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
```

> [!note]
> 빌드 인수는 이미지 히스토리에 표시될 수 있습니다. 프로덕션 이미지의 경우 [다단계 빌드](https://docs.docker.com/build/building/multi-stage/)를 사용하여 최종 이미지 레이어에 토큰이 없도록 합니다.

## `requirements.txt` 사용 {#using-requirementstxt}

pip이 공개 레지스트리에 액세스하도록 하려면 `--extra-index-url` 매개변수와 레지스트리의 URL을 `requirements.txt` 파일에 추가합니다.

```plaintext
--extra-index-url https://gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
package-name==1.0.0
```

개인 레지스트리인 경우 몇 가지 방법으로 인증할 수 있습니다. 예를 들어:

- `requirements.txt` 파일을 [개인 액세스 토큰](../../profile/personal_access_tokens.md)과 함께 사용:

  ```plaintext
  --extra-index-url https://<personal_access_token_name>:<personal_access_token>@gitlab.example.com/api/v4/projects/<project_id>/packages/pypi/simple
  package-name==1.0.0
  ```

- `~/.netrc` 파일을 [개인 액세스 토큰](../../profile/personal_access_tokens.md)과 함께 사용:

  ```plaintext
  machine gitlab.example.com
  login <personal_access_token_name>
  password <personal_access_token>
  ```

## PyPI 패키지 버전 관리 {#versioning-pypi-packages}

적절한 버전 관리는 PyPI 패키지를 효과적으로 관리하는 데 중요합니다. 패키지가 올바르게 버전화되도록 이 모범 사례를 따릅니다.

### 시멘틱 버전 관리(SemVer) 사용 {#use-semantic-versioning-semver}

패키지에 시멘틱 버전 관리를 채택합니다. 버전 번호는 `MAJOR.MINOR.PATCH` 형식이어야 합니다:

- `MAJOR` 버전을 호환되지 않는 API 변경에 대해 증가시킵니다.
- `MINOR` 버전을 이전 버전과 호환되는 새로운 기능에 대해 증가시킵니다.
- `PATCH` 버전을 이전 버전과 호환되는 버그 수정에 대해 증가시킵니다.

예를 들어: 1.0.0, 1.1.0, 1.1.1.

새 프로젝트의 경우 버전 0.1.0으로 시작합니다. 이는 API가 아직 안정적이지 않은 초기 개발 단계를 나타냅니다.

### 유효한 버전 문자열 사용 {#use-valid-version-strings}

버전 문자열이 PyPI 표준에 따라 유효한지 확인합니다. GitLab은 버전 문자열을 검증하기 위해 특정 정규식을 사용합니다:

```ruby
\A(?:
    v?
    (?:([0-9]+)!)?                                                 (?# epoch)
    ([0-9]+(?:\.[0-9]+)*)                                          (?# release segment)
    ([-_\.]?((a|b|c|rc|alpha|beta|pre|preview))[-_\.]?([0-9]+)?)?  (?# pre-release)
    ((?:-([0-9]+))|(?:[-_\.]?(post|rev|r)[-_\.]?([0-9]+)?))?       (?# post release)
    ([-_\.]?(dev)[-_\.]?([0-9]+)?)?                                (?# dev release)
    (?:\+([a-z0-9]+(?:[-_\.][a-z0-9]+)*))?                         (?# local version)
)\z}xi
```

이 [정규식 편집기](https://rubular.com/r/FKM6d07ouoDaFV)를 사용하여 정규식을 실험하고 버전 문자열을 시도할 수 있습니다.

정규식에 대한 자세한 내용은 [Python 설명서](https://www.python.org/dev/peps/pep-0440/#appendix-b-parsing-version-strings-with-regular-expressions)를 참조하세요.

## 지원되는 CLI 명령 {#supported-cli-commands}

GitLab PyPI 리포지토리는 다음 CLI 명령을 지원합니다:

- `twine upload`: 레지스트리에 패키지를 업로드합니다.
- `pip install`: 레지스트리에서 PyPI 패키지를 설치합니다.

## 문제 해결 {#troubleshooting}

성능을 향상하기 위해 pip 명령은 패키지와 관련된 파일을 캐시합니다. Pip은 자동으로 데이터를 제거하지 않습니다. 캐시는 새 패키지가 설치될수록 증가합니다. 문제가 발생하면 이 명령으로 캐시를 지웁니다:

```shell
pip cache purge
```

### 여러 `index-url` 또는 `extra-index-url` 매개변수 {#multiple-index-url-or-extra-index-url-parameters}

여러 `index-url` 및 `extra-index-url` 매개변수를 정의할 수 있습니다.

같은 도메인 이름(예: `gitlab.example.com`)을(를) 다른 인증 토큰으로 여러 번 사용하면 `pip`이(가) 패키지를 찾지 못할 수 있습니다. 이 문제는 `pip`이(가) 명령 실행 중에 [토큰을 등록하고 저장](https://github.com/pypa/pip/pull/10904#issuecomment-1126690115)하는 방식 때문입니다.

이 문제를 해결하려면 [그룹 배포 토큰](../../project/deploy_tokens/_index.md)을(를) `read_package_registry` 범위로 사용할 수 있으며, `index-url` 및 `extra-index-url` 값으로 대상이 되는 모든 프로젝트 또는 그룹에 대한 공통 부모 그룹에서 사용합니다.

### 예기치 않은 패키지 소스 {#unexpected-package-sources}

GitLab 레지스트리만 사용하려는 경우 PyPI에서 패키지가 설치되고 있으면:

- 그룹의 패키지 전달 설정을 확인합니다.
- `--no-index`과 `--index-url` 플래그를 함께 사용하여 PyPI 대체를 방지합니다.
- `pip debug`을(를) 사용하여 패키지 소스를 정기적으로 감시합니다.
