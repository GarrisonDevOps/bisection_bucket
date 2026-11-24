---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: '튜토리얼: GitLab CI/CD로 Python 패키지 빌드 및 서명'
---

이 튜토리얼은 Python 패키지를 위한 보안 파이프라인을 구현하는 방법을 보여줍니다. 파이프라인에는 GitLab CI/CD 및 [Sigstore Cosign](https://docs.sigstore.dev/)을 사용하여 Python 패키지에 암호화 방식으로 서명하고 검증하는 스테이지가 포함되어 있습니다.

마지막에는 다음을 학습하게 됩니다:

- GitLab CI/CD를 사용하여 Python 패키지를 빌드하고 서명합니다.
- 일반 패키지 레지스트리를 사용하여 패키지 서명을 저장하고 관리합니다.
- 최종 사용자로서 패키지 서명을 검증합니다.

## 패키지 서명의 이점은 무엇입니까? {#what-are-the-benefits-of-package-signing}

패키지 서명은 몇 가지 중요한 보안 이점을 제공합니다:

- 신뢰성: 사용자는 패키지가 신뢰할 수 있는 출처에서 나온 것임을 확인할 수 있습니다.
- 데이터 무결성: 패키지가 배포 중에 변조되면 감지됩니다.
- 부인 방지: 패키지의 출처를 암호화 방식으로 증명할 수 있습니다.
- 공급망 보안: 패키지 서명은 공급망 공격 및 손상된 리포지토리로부터 보호합니다.

## 시작하기 전에 {#before-you-begin}

이 튜토리얼을 완료하려면 다음이 필요합니다:

- GitLab 계정 및 테스트 프로젝트
- Python 패키징, GitLab CI/CD 및 패키지 레지스트리 개념에 대한 기본 이해

## 단계 {#steps}

수행하려는 작업의 개요는 다음과 같습니다:

1. [Python 프로젝트 설정](#set-up-a-python-project)
1. [기본 구성 추가](#add-base-configuration)
1. [빌드 스테이지 구성](#configure-the-build-stage)
1. [서명 스테이지 구성](#configure-the-sign-stage)
1. [검증 스테이지 구성](#configure-the-verify-stage)
1. [게시 스테이지 구성](#configure-the-publish-stage)
1. [게시 서명 스테이지 구성](#configure-the-publish-signatures-stage)
1. [소비자 검증 스테이지 구성](#configure-the-consumer-verification-stage)
1. [사용자로서 패키지 검증](#verify-packages-as-a-user)

### Python 프로젝트 설정 {#set-up-a-python-project}

먼저 테스트 프로젝트를 만듭니다. 프로젝트 루트에 `pyproject.toml` 파일을 추가합니다:

```toml
[build-system]
requires = ["setuptools>=45", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "<my_package>"  # Will be dynamically replaced by CI/CD pipeline
version = "<1.0.0>"    # Will be dynamically replaced by CI/CD pipeline
description = "<Your package description>"
readme = "README.md"
requires-python = ">=3.7"
authors = [
    {name = "<Your Name>", email = "<your.email@example.com>"},
]

[project.urls]
"Homepage" = "<https://gitlab.com/my_package>"  # Will be replaced with actual project URL
```

`Your Name` 및 `your.email@example.com`를 개인 정보로 바꿔야 합니다.

다음 단계에서 CI/CD 파이프라인 빌드를 완료하면 파이프라인이 자동으로:

- `my_package`을 프로젝트 이름의 정규화된 버전으로 바꿉니다.
- `version`을 파이프라인 버전과 일치하도록 변경합니다.
- `Homepage` URL을 GitLab 프로젝트 URL과 일치하도록 변경합니다.

#### 기본 구성 추가 {#add-base-configuration}

프로젝트 루트에서 `.gitlab-ci.yml` 파일을 추가합니다. 다음 구성을 추가합니다:

```yaml
variables:
  # Base Python version for all jobs
  PYTHON_VERSION: '3.10'
  # Package names and versions
  PACKAGE_NAME: ${CI_PROJECT_NAME}
  PACKAGE_VERSION: "1.0.0"  # Use semantic versioning
  # Sigstore service URLs
  FULCIO_URL: 'https://fulcio.sigstore.dev'
  REKOR_URL: 'https://rekor.sigstore.dev'
  # Identity for Sigstore verification
  CERTIFICATE_IDENTITY: 'https://gitlab.com/${CI_PROJECT_PATH}//.gitlab-ci.yml@refs/heads/${CI_DEFAULT_BRANCH}'
  CERTIFICATE_OIDC_ISSUER: 'https://gitlab.com'
  # Pip cache directory for faster builds
  PIP_CACHE_DIR: "$CI_PROJECT_DIR/.pip-cache"
  # Auto-accept prompts from Cosign
  COSIGN_YES: "true"
  # Base URL for generic package registry
  GENERIC_PACKAGE_BASE_URL: "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/${PACKAGE_NAME}/${PACKAGE_VERSION}"

default:
  before_script:
    # Normalize package name once at the start of any job
    - export NORMALIZED_NAME=$(echo "${CI_PROJECT_NAME}" | tr '-' '_')

# Template for Python-based jobs
.python-job:
  image: python:${PYTHON_VERSION}
  before_script:
    # First normalize package name
    - export NORMALIZED_NAME=$(echo "${CI_PROJECT_NAME}" | tr '-' '_')
    # Then install Python dependencies
    - pip install --upgrade pip
    - pip install build twine setuptools wheel
  cache:
    paths:
      - ${PIP_CACHE_DIR}

# Template for Python + Cosign jobs
.python+cosign-job:
  extends: .python-job
  before_script:
    # First normalize package name
    - export NORMALIZED_NAME=$(echo "${CI_PROJECT_NAME}" | tr '-' '_')
    # Then install dependencies
    - apt-get update && apt-get install -y curl wget
    - wget -O cosign https://github.com/sigstore/cosign/releases/download/v2.2.3/cosign-linux-amd64
    - chmod +x cosign && mv cosign /usr/local/bin/
    - export COSIGN_EXPERIMENTAL=1
    - pip install --upgrade pip
    - pip install build twine setuptools wheel
stages:
  - build
  - sign
  - verify
  - publish
  - publish_signatures
  - consumer_verification
```

이 기본 구성:

- 파이프라인에 일관성을 위한 기본 이미지로 Python `3.10`을 사용하도록 지시합니다
- 기본 Python 작업을 위한 `.python-job` 및 서명 작업을 위한 `.python+cosign-job`라는 두 가지 재사용 가능한 템플릿을 설정합니다
- pip 캐싱을 구현하여 빌드 속도를 높입니다
- Python 호환성을 위해 하이픈을 언더스코어로 변환하여 패키지 이름을 정규화합니다
- 쉬운 관리를 위해 파이프라인 수준에서 모든 주요 변수를 정의합니다

### 빌드 스테이지 구성 {#configure-the-build-stage}

빌드 스테이지는 Python 배포 패키지를 빌드합니다.

`.gitlab-ci.yml` 파일에 다음 구성을 추가합니다:

```yaml
build:
  extends: .python-job
  stage: build
  script:
    # Initialize git repo with actual content
    - git init
    - git config --global init.defaultBranch main
    - git config --global user.email "ci@example.com"
    - git config --global user.name "CI"
    - git add .
    - git commit -m "Initial commit"

    # Update package name, version, and homepage URL in pyproject.toml
    - sed -i "s/name = \".*\"/name = \"${NORMALIZED_NAME}\"/" pyproject.toml
    - sed -i "s/version = \".*\"/version = \"${PACKAGE_VERSION}\"/" pyproject.toml
    - sed -i "s|\"Homepage\" = \".*\"|\"Homepage\" = \"https://gitlab.com/${CI_PROJECT_PATH}\"|" pyproject.toml

    # Debug: show updated file
    - echo "Updated pyproject.toml contents:"
    - cat pyproject.toml

    # Build package
    - python -m build
  artifacts:
    paths:
      - dist/
      - pyproject.toml
```

빌드 스테이지 구성:

- 빌드 컨텍스트를 위한 Git 리포지토리를 초기화합니다
- `pyproject.toml`에서 패키지 메타데이터를 동적으로 업데이트합니다
- 휠 (`.whl`) 및 소스 배포 (`.tar.gz`) 패키지를 모두 추가합니다
- 후속 스테이지를 위해 빌드 아티팩트를 보존합니다
- 문제 해결을 위한 디버그 출력을 제공합니다

### 서명 스테이지 구성 {#configure-the-sign-stage}

서명 스테이지는 Sigstore Cosign을 사용하여 패키지에 서명합니다.

`.gitlab-ci.yml` 파일에 다음 구성을 추가합니다:

```yaml
sign:
  extends: .python+cosign-job
  stage: sign
  id_tokens:
    SIGSTORE_ID_TOKEN:
      aud: sigstore
  script:
    - |
      for file in dist/*.whl dist/*.tar.gz; do
        if [ -f "$file" ]; then
          filename=$(basename "$file")

          cosign sign-blob --yes \
            --fulcio-url=${FULCIO_URL} \
            --rekor-url=${REKOR_URL} \
            --oidc-issuer $CI_SERVER_URL \
            --identity-token $SIGSTORE_ID_TOKEN \
            --output-signature "dist/${filename}.sig" \
            --output-certificate "dist/${filename}.crt" \
            "$file"

          # Debug: Verify files were created
          echo "Checking generated signature and certificate:"
          ls -l "dist/${filename}.sig" "dist/${filename}.crt"
        fi
      done
  artifacts:
    paths:
      - dist/
```

서명 스테이지 구성:

- 향상된 보안을 위해 Sigstore의 [키리스 서명](https://docs.sigstore.dev/cosign/signing/overview/)을 사용합니다
- 휠 및 소스 배포 패키지 모두에 서명합니다
- 별도의 서명 (`.sig`) 및 인증서 (`.crt`) 파일을 생성합니다
- 인증을 위해 OIDC 통합을 사용합니다
- 서명 생성을 위한 자세한 로깅을 포함합니다

### 검증 스테이지 구성 {#configure-the-verify-stage}

검증 스테이지는 서명을 로컬에서 검증합니다.

`.gitlab-ci.yml` 파일에 다음 구성을 추가합니다:

```yaml
verify:
  extends: .python+cosign-job
  stage: verify
  script:
    - |
      failed=0

      for file in dist/*.whl dist/*.tar.gz; do
        if [ -f "$file" ]; then
          filename=$(basename "$file")

          echo "Verifying file: $file"
          echo "Using signature: dist/${filename}.sig"
          echo "Using certificate: dist/${filename}.crt"

          if ! cosign verify-blob \
            --signature "dist/${filename}.sig" \
            --certificate "dist/${filename}.crt" \
            --certificate-identity "${CERTIFICATE_IDENTITY}" \
            --certificate-oidc-issuer "${CERTIFICATE_OIDC_ISSUER}" \
            "$file"; then
            echo "Verification failed for $filename"
            failed=1
          fi
        fi
      done

      if [ $failed -eq 1 ]; then
        exit 1
      fi
```

검증 스테이지 구성:

- 서명 후 즉시 서명을 검증합니다
- 휠 및 소스 배포 패키지를 모두 확인합니다
- 인증서 ID 및 OIDC 발급자를 검증합니다
- 검증이 실패하면 빠르게 실패합니다
- 자세한 검증 로그를 제공합니다

### 게시 스테이지 구성 {#configure-the-publish-stage}

게시 스테이지는 GitLab PyPI 패키지 레지스트리에 패키지를 업로드합니다.

`.gitlab-ci.yml` 파일에 다음 구성을 추가합니다:

```yaml
publish:
  extends: .python-job
  stage: publish
  script:
    - |
      # Configure PyPI settings for GitLab package registry
      cat << EOF > ~/.pypirc
      [distutils]
      index-servers = gitlab
      [gitlab]
      repository = ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/pypi
      username = gitlab-ci-token
      password = ${CI_JOB_TOKEN}
      EOF

      # Upload packages using twine
      TWINE_PASSWORD=${CI_JOB_TOKEN} TWINE_USERNAME=gitlab-ci-token \
        twine upload --repository-url ${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/pypi \
        dist/*.whl dist/*.tar.gz
```

게시 스테이지 구성:

- PyPI 레지스트리 인증을 구성합니다
- GitLab 기본 제공 패키지 레지스트리를 사용합니다
- 휠 및 소스 배포를 모두 게시합니다
- 보안 인증을 위해 작업 토큰을 사용합니다
- 재사용 가능한 `.pypirc` 구성을 생성합니다

### 게시 서명 스테이지 구성 {#configure-the-publish-signatures-stage}

게시 서명 스테이지는 GitLab 일반 패키지 레지스트리에 서명을 저장합니다.

`.gitlab-ci.yml` 파일에 다음 구성을 추가합니다:

```yaml
publish_signatures:
  extends: .python+cosign-job
  stage: publish_signatures
  script:
    - |
      for file in dist/*.whl dist/*.tar.gz; do
        if [ -f "$file" ]; then
          filename=$(basename "$file")

          ls -l "dist/${filename}.sig" "dist/${filename}.crt"

          echo "Publishing signatures for $filename"
          echo "Publishing to: ${GENERIC_PACKAGE_BASE_URL}/${filename}.sig"

          # Upload signature and certificate
          curl --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
               --fail \
               --upload-file "dist/${filename}.sig" \
               "${GENERIC_PACKAGE_BASE_URL}/${filename}.sig"

          curl --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
               --fail \
               --upload-file "dist/${filename}.crt" \
               "${GENERIC_PACKAGE_BASE_URL}/${filename}.crt"
        fi
      done
```

게시 서명 스테이지 구성:

- 서명을 일반 패키지 레지스트리에 저장합니다
- 서명-패키지 매핑을 유지합니다
- 아티팩트에 일관된 명명 규칙을 사용합니다
- 서명에 대한 크기 검증을 포함합니다
- 자세한 업로드 로그를 제공합니다

### 소비자 검증 스테이지 구성 {#configure-the-consumer-verification-stage}

소비자 검증 스테이지는 최종 사용자 패키지 검증을 시뮬레이션합니다.

`.gitlab-ci.yml` 파일에 다음 구성을 추가합니다:

```yaml
consumer_verification:
  extends: .python+cosign-job
  stage: consumer_verification
  script:
    - |
      # Initialize git repo for setuptools_scm
      git init
      git config --global init.defaultBranch main

      # Create directory for downloading packages
      mkdir -p pkg signatures

      # Download the specific wheel version
      pip download --index-url "https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.com/api/v4/projects/${CI_PROJECT_ID}/packages/pypi/simple" \
          "${NORMALIZED_NAME}==${PACKAGE_VERSION}" --no-deps -d ./pkg --verbose

      # Download the specific source distribution version
      pip download --no-binary :all: \
          --index-url "https://gitlab-ci-token:${CI_JOB_TOKEN}@gitlab.com/api/v4/projects/${CI_PROJECT_ID}/packages/pypi/simple" \
          "${NORMALIZED_NAME}==${PACKAGE_VERSION}" --no-deps -d ./pkg --verbose

      failed=0
      for file in pkg/*.whl pkg/*.tar.gz; do
        if [ -f "$file" ]; then
          filename=$(basename "$file")

          sig_url="${GENERIC_PACKAGE_BASE_URL}/${filename}.sig"
          cert_url="${GENERIC_PACKAGE_BASE_URL}/${filename}.crt"

          echo "Downloading signatures for $filename"
          echo "Signature URL: $sig_url"
          echo "Certificate URL: $cert_url"

          # Download signatures
          curl --fail --silent --show-error \
               --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
               --output "signatures/${filename}.sig" \
               "$sig_url"

          curl --fail --silent --show-error \
               --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
               --output "signatures/${filename}.crt" \
               "$cert_url"

          # Verify signature
          if ! cosign verify-blob \
            --signature "signatures/${filename}.sig" \
            --certificate "signatures/${filename}.crt" \
            --certificate-identity "${CERTIFICATE_IDENTITY}" \
            --certificate-oidc-issuer "${CERTIFICATE_OIDC_ISSUER}" \
            "$file"; then
            echo "Signature verification failed"
            failed=1
          fi
        fi
      done

      if [ $failed -eq 1 ]; then
        echo "Verification failed for one or more packages"
        exit 1
      fi
```

소비자 검증 스테이지 구성:

- 실제 패키지 설치를 시뮬레이션합니다
- 두 패키지 형식을 모두 다운로드하고 검증합니다
- 일관성을 위해 정확한 버전 매칭을 사용합니다
- 포괄적인 오류 처리를 구현합니다
- 완전한 검증 워크플로우를 테스트합니다

### 사용자로서 패키지 검증 {#verify-packages-as-a-user}

최종 사용자로서 다음 단계를 통해 패키지 서명을 검증할 수 있습니다:

1. Cosign 설치:

   ```shell
   wget -O cosign https://github.com/sigstore/cosign/releases/download/v2.2.3/cosign-linux-amd64
   chmod +x cosign && sudo mv cosign /usr/local/bin/
   ```

   Cosign은 전역 설치를 위해 특별한 권한이 필요합니다. 권한 문제를 우회하려면 `sudo`을 사용합니다.

1. 패키지 및 서명 다운로드:

   ```shell
   # You can find your PROJECT_ID in your GitLab project's home page under the project name

   # Download the specific version of the package
   pip download your-package-name==1.0.0 --no-deps

   # The FILENAME will be the output from the pip download command
   # For example: your-package-name-1.0.0.tar.gz or your-package-name-1.0.0-py3-none-any.whl

   # Download signatures from GitLab's generic package registry
   # Replace these values with your project's details:
   # GITLAB_URL: Your GitLab instance URL (for example, https://gitlab.com)
   # PROJECT_ID: Your project's ID number
   # PACKAGE_NAME: Your package name
   # VERSION: Package version (for example, 1.0.0)
   # FILENAME: The exact filename of your downloaded package

   curl --output "${FILENAME}.sig" \
     "${GITLAB_URL}/api/v4/projects/${PROJECT_ID}/packages/generic/${PACKAGE_NAME}/${VERSION}/${FILENAME}.sig"

   curl --output "${FILENAME}.crt" \
     "${GITLAB_URL}/api/v4/projects/${PROJECT_ID}/packages/generic/${PACKAGE_NAME}/${VERSION}/${FILENAME}.crt"
   ```

1. 서명 검증:

   ```shell
   # Replace CERTIFICATE_IDENTITY and CERTIFICATE_OIDC_ISSUER with the values from the project's pipeline
   export CERTIFICATE_IDENTITY="https://gitlab.com/your-group/your-project//.gitlab-ci.yml@refs/heads/main"
   export CERTIFICATE_OIDC_ISSUER="https://gitlab.com"

   # Verify wheel package
   FILENAME="your-package-name-1.0.0-py3-none-any.whl"
   COSIGN_EXPERIMENTAL=1 cosign verify-blob \
     --signature "${FILENAME}.sig" \
     --certificate "${FILENAME}.crt" \
     --certificate-identity "${CERTIFICATE_IDENTITY}" \
     --certificate-oidc-issuer "${CERTIFICATE_OIDC_ISSUER}" \
     "${FILENAME}"

   # Verify source distribution
   FILENAME="your-package-name-1.0.0.tar.gz"
   COSIGN_EXPERIMENTAL=1 cosign verify-blob \
     --signature "${FILENAME}.sig" \
     --certificate "${FILENAME}.crt" \
     --certificate-identity "${CERTIFICATE_IDENTITY}" \
     --certificate-oidc-issuer "${CERTIFICATE_OIDC_ISSUER}" \
     "${FILENAME}"
   ```

최종 사용자로서 패키지를 검증할 때:

- 패키지 다운로드가 검증하려는 정확한 버전과 일치하는지 확인합니다.
- 각 패키지 유형(휠 및 소스 배포)을 별도로 검증합니다.
- 인증서 ID가 패키지에 서명하는 데 사용된 것과 정확히 일치하는지 확인합니다.
- 모든 URL 구성 요소가 올바르게 설정되었는지 확인합니다. 예를 들어 `GITLAB_URL` 또는 `PROJECT_ID`입니다.
- 패키지 파일명이 레지스트리에 업로드된 것과 정확히 일치하는지 확인합니다.
- 키리스 검증을 위해 `COSIGN_EXPERIMENTAL=1` 기능 플래그를 사용합니다. 이 플래그는 필수입니다.
- 실패한 검증이 변조 또는 부정확한 인증서 및 서명 쌍을 나타낼 수 있음을 이해합니다.
- 프로젝트의 파이프라인에서 인증서 ID 및 발급자 값을 추적합니다.

## 문제 해결 {#troubleshooting}

이 튜토리얼을 완료할 때 다음 오류가 발생할 수 있습니다:

### 오류: `404 Not Found` {#error-404-not-found}

`404 Not Found` 오류 페이지가 발생하면:

- 모든 URL 구성 요소를 다시 확인합니다.
- 패키지 버전이 레지스트리에 존재하는지 확인합니다.
- 버전 및 플랫폼 태그를 포함하여 파일명이 정확히 일치하는지 확인합니다.

### 검증 실패 {#verification-failed}

서명 검증이 실패하면 다음을 확인합니다:

- `CERTIFICATE_IDENTITY`이 서명 파이프라인과 일치하는지 확인합니다.
- `CERTIFICATE_OIDC_ISSUER`이 올바른지 확인합니다.
- 서명 및 인증서 쌍이 패키지에 올바른지 확인합니다.

### 권한 거부 {#permission-denied}

권한 문제가 발생하면:

- 패키지 레지스트리에 접근 권한이 있는지 확인합니다.
- 레지스트리가 비공개인 경우 인증을 확인합니다.
- Cosign을 설치할 때 올바른 파일 권한을 사용합니다.

### 인증 문제 {#authentication-issues}

인증 문제가 발생하면:

- `CI_JOB_TOKEN` 권한을 확인합니다.
- 레지스트리 인증 구성을 확인합니다.
- 프로젝트의 접근 설정을 확인합니다.

### 패키지 구성 및 파이프라인 설정 확인 {#verify-package-configuration-and-pipeline-settings}

패키지 구성을 확인합니다. 다음을 확인합니다:

- 패키지 이름은 하이픈(`-`)이 아닌 언더스코어(`_`)를 사용합니다.
- 버전 문자열은 유효한 [PEP 440](https://peps.python.org/pep-0440/)을 사용합니다.
- `pyproject.toml` 파일의 형식이 올바른지 확인합니다.

파이프라인 설정을 확인합니다. 다음을 확인합니다:

- OIDC가 올바르게 구성되었습니다.
- 작업 종속성이 올바르게 설정됩니다.
- 필요한 권한이 준비되어 있습니다.
