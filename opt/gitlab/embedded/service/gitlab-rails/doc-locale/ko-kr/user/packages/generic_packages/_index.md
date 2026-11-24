---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab 일반 패키지 리포지토리
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

일반 패키지 리포지토리를 사용하여 프로젝트의 패키지 레지스트리에 릴리스 바이너리와 같은 일반 파일을 게시하고 관리합니다. 이 기능은 npm이나 Maven과 같은 특정 패키지 형식에 맞지 않는 아티팩트를 저장하고 배포하는 데 특히 유용합니다.

일반 패키지 리포지토리는 다음을 제공합니다:

- 모든 파일 유형을 패키지로 저장할 수 있는 위치입니다.
- 패키지의 버전 관리입니다.
- GitLab CI/CD와의 통합입니다.
- 자동화를 위한 API 액세스입니다.

## 패키지 레지스트리에 인증 {#authenticate-to-the-package-registry}

패키지 레지스트리와 상호 작용하려면 다음 방법 중 하나로 인증해야 합니다:

- [개인 액세스 토큰](../../profile/personal_access_tokens.md)이며 범위를 `api`로 설정합니다.
- [프로젝트 액세스 토큰](../../project/settings/project_access_tokens.md)이며 범위를 `api`로 설정하고 개발자, 유지 관리자 또는 소유자 역할이 있습니다.
- [CI/CD 작업 토큰](../../../ci/jobs/ci_job_token.md)입니다.
- [배포 토큰](../../project/deploy_tokens/_index.md)이며 범위를 `read_package_registry`, `write_package_registry` 또는 둘 다로 설정합니다.

여기에 설명된 방법 외의 인증 방법을 사용하지 마십시오. 문서화되지 않은 인증 방법은 나중에 제거될 수 있습니다.

패키지 레지스트리로 인증할 때 다음 모범 사례를 따르십시오:

- 개발자 역할과 연결된 권한에 액세스하려면 개인 액세스 토큰을 사용합니다.
- 자동화된 파이프라인에는 CI/CD 작업 토큰을 사용합니다.
- 외부 시스템 통합에는 배포 토큰을 사용합니다.
- 항상 HTTPS를 통해 인증 정보를 전송합니다.

### HTTP 기본 인증 {#http-basic-authentication}

표준 인증 방법을 지원하지 않는 도구를 사용하는 경우 HTTP 기본 인증을 사용할 수 있습니다:

```shell
curl --user "<username>:<token>" <other options> <GitLab API endpoint>
```

무시되지만 사용자 이름을 제공해야 합니다. 토큰은 개인 액세스 토큰, CI/CD 작업 토큰 또는 배포 토큰입니다.

## 패키지 게시 {#publish-a-package}

API를 사용하여 패키지를 게시할 수 있습니다.

### 단일 파일 게시 {#publish-a-single-file}

단일 파일을 게시하려면 다음 API 엔드포인트를 사용합니다:

```shell
PUT /projects/:id/packages/generic/:package_name/:package_version/:file_name
```

URL의 자리 표시자를 특정 값으로 바꾸십시오:

- `:id`: 프로젝트 ID 또는 URL 인코딩 경로
- `:package_name`: 패키지 이름
- `:package_version`: 패키지 버전
- `:file_name`: 업로드 중인 파일의 이름입니다. [유효한 패키지 파일 이름 형식](#valid-package-filename-format)을(를) 아래에서 확인하세요.

예를 들어:

{{< tabs >}}

{{< tab title="개인 액세스 토큰" >}}

HTTP 헤더 사용:

```shell
curl --location --header "PRIVATE-TOKEN: <personal_access_token>" \
     --upload-file path/to/file.txt \
     "https://gitlab.example.com/api/v4/projects/24/packages/generic/my_package/1.0.0/file.txt"
```

HTTP 기본 인증 사용:

```shell
curl --location --user "<username>:<personal_access_token>" \
     --upload-file path/to/file.txt \
     "https://gitlab.example.com/api/v4/projects/24/packages/generic/my_package/1.0.0/file.txt"
```

{{< /tab >}}

{{< tab title="프로젝트 액세스 토큰" >}}

HTTP 헤더 사용:

```shell
curl --location --header "PRIVATE-TOKEN: <project_access_token>" \
     --upload-file path/to/file.txt \
     "https://gitlab.example.com/api/v4/projects/24/packages/generic/my_package/1.0.0/file.txt"
```

HTTP 기본 인증 사용:

```shell
curl --location --user "<project_access_token_username>:project_access_token" \
     --upload-file path/to/file.txt \
     "https://gitlab.example.com/api/v4/projects/24/packages/generic/my_package/1.0.0/file.txt"
```

{{< /tab >}}

{{< tab title="배포 토큰" >}}

HTTP 헤더 사용:

```shell
curl --location --header "DEPLOY-TOKEN: <deploy_token>" \
     --upload-file path/to/file.txt \
     "https://gitlab.example.com/api/v4/projects/24/packages/generic/my_package/1.0.0/file.txt"
```

HTTP 기본 인증 사용:

```shell
curl --location --user "<deploy_token_username>:<deploy_token>" \
     --upload-file path/to/file.txt \
     "https://gitlab.example.com/api/v4/projects/24/packages/generic/my_package/1.0.0/file.txt"
```

`<deploy_token_username>`을(를) 배포 토큰의 사용자 이름으로 바꾸고 `<deploy_token>`을(를) 실제 배포 토큰으로 바꾸십시오.

{{< /tab >}}

{{< tab title="CI/CD 작업 토큰" >}}

이 예제는 `.gitlab-ci.yml` 파일을 위한 것입니다. GitLab CI/CD는 자동으로 `CI_JOB_TOKEN`를 제공합니다.

HTTP 헤더 사용:

```yaml
publish:
  stage: deploy
  script:
    - |
      curl --location --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
           --upload-file path/to/file.txt \
           "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/my_package/${CI_COMMIT_TAG}/file.txt"
```

HTTP 기본 인증 사용:

```yaml
publish:
  stage: deploy
  script:
    - |
      curl --location --user "gitlab-ci-token:${CI_JOB_TOKEN}" \
           --upload-file path/to/file.txt \
           "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/my_package/${CI_COMMIT_TAG}/file.txt"
```

{{< /tab >}}

{{< /tabs >}}

각 요청은 성공 또는 실패를 나타내는 응답을 반환합니다. 업로드가 성공하면 응답 상태는 `201 Created`입니다.

### 여러 파일 게시 {#publish-multiple-files}

여러 파일 또는 전체 디렉토리를 게시하려면 각 파일에 대해 하나의 API 호출을 해야 합니다.

리포지토리에 여러 파일을 게시할 때 다음 모범 사례를 따르십시오:

- 버전 관리: 패키지에 일관된 버전 관리 스키마를 사용합니다. 프로젝트 버전, 빌드 번호 또는 날짜를 기반으로 할 수 있습니다.
- 파일 구성: 패키지 내에서 파일을 구조화하는 방법을 고려하십시오. 포함된 모든 파일 및 해당 목적을 나열하는 매니페스트 파일을 포함할 수 있습니다.
- 자동화: 가능하면 CI/CD 파이프라인을 통해 게시 프로세스를 자동화합니다. 이렇게 하면 일관성이 보장되고 수동 오류가 줄어듭니다.
- 오류 처리: 스크립트에서 오류 확인을 구현합니다. 예를 들어 cURL의 HTTP 응답 코드를 확인하여 각 파일이 성공적으로 업로드되었는지 확인합니다.
- 로깅: 어떤 파일이 언제 누가 업로드했는지에 대한 로그를 유지합니다. 이는 문제 해결 및 감시에 중요할 수 있습니다.
- 압축: 큰 디렉토리의 경우 업로드하기 전에 내용을 단일 파일로 압축하는 것을 고려하십시오. 이렇게 하면 업로드 프로세스를 단순화하고 API 호출 수를 줄일 수 있습니다.
- 체크섬: SHA256 체크섬은 업로드된 파일에 대해 자동으로 계산되고 저장됩니다. 체크섬을 사용하여 다운로드한 파일의 무결성을 확인합니다.

예를 들어:

{{< tabs >}}

{{< tab title="Bash 스크립트 사용" >}}

파일을 반복하고 업로드하는 Bash 스크립트를 만듭니다:

```shell
#!/bin/bash

TOKEN="<access_token>"
PROJECT_ID="24"
PACKAGE_NAME="my_package"
PACKAGE_VERSION="1.0.0"
DIRECTORY_PATH="./files_to_upload"

for file in "$DIRECTORY_PATH"/*; do
    if [ -f "$file" ]; then
        filename=$(basename "$file")
        curl --location --header "PRIVATE-TOKEN: $TOKEN" \
             --upload-file "$file" \
             "https://gitlab.example.com/api/v4/projects/$PROJECT_ID/packages/generic/$PACKAGE_NAME/$PACKAGE_VERSION/$filename"
        echo "Uploaded: $filename"
    fi
done
```

{{< /tab >}}

{{< tab title="GitLab CI/CD 사용" >}}

CI/CD 파이프라인에서 자동화된 업로드의 경우 파일을 반복하고 업로드할 수 있습니다:

```yaml
upload_package:
  stage: publish
  script:
    - |
      for file in ./build/*; do
        if [ -f "$file" ]; then
          filename=$(basename "$file")
          curl --header "JOB-TOKEN: $CI_JOB_TOKEN" \
               --upload-file "$file" \
               "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/my_package/${CI_COMMIT_TAG}/$filename"
          echo "Uploaded: $filename"
        fi
      done
```

{{< /tab >}}

{{< /tabs >}}

### 디렉토리 구조 유지 {#maintain-directory-structure}

게시된 디렉토리의 구조를 유지하려면 파일 이름에 상대 경로를 포함합니다:

```shell
#!/bin/bash

TOKEN="<access_token>"
PROJECT_ID="24"
PACKAGE_NAME="my_package"
PACKAGE_VERSION="1.0.0"
DIRECTORY_PATH="./files_to_upload"

find "$DIRECTORY_PATH" -type f | while read -r file; do
    relative_path=${file#"$DIRECTORY_PATH/"}
    curl --location --header "PRIVATE-TOKEN: $TOKEN" \
         --upload-file "$file" \
         "https://gitlab.example.com/api/v4/projects/$PROJECT_ID/packages/generic/$PACKAGE_NAME/$PACKAGE_VERSION/$relative_path"
    echo "Uploaded: $relative_path"
done
```

## 패키지 다운로드 {#download-a-package}

API를 사용하여 패키지를 다운로드할 수 있습니다.

### 단일 파일 다운로드 {#download-a-single-file}

단일 패키지 파일을 다운로드하려면 다음 API 엔드포인트를 사용합니다:

```shell
GET /projects/:id/packages/generic/:package_name/:package_version/:file_name
```

URL의 자리 표시자를 특정 값으로 바꾸십시오:

- `:id`: 프로젝트 ID 또는 URL 인코딩 경로
- `:package_name`: 패키지 이름
- `:package_version`: 패키지 버전
- `:file_name`: 다운로드 중인 파일의 이름

예를 들어:

{{< tabs >}}

{{< tab title="개인 액세스 토큰" >}}

HTTP 헤더 사용:

```shell
curl --header "PRIVATE-TOKEN: <access_token>" \
     --location \
     "https://gitlab.example.com/api/v4/projects/1/packages/generic/my_package/0.0.1/file.txt" \
     --output file.txt
```

HTTP 기본 인증 사용:

```shell
curl --user "<username>:<access_token>" \
     --location \
     "https://gitlab.example.com/api/v4/projects/1/packages/generic/my_package/0.0.1/file.txt" \
     --output file.txt
```

{{< /tab >}}

{{< tab title="프로젝트 액세스 토큰" >}}

HTTP 헤더 사용:

```shell
curl --header "PRIVATE-TOKEN: <project_access_token>" \
     --location \
     "https://gitlab.example.com/api/v4/projects/1/packages/generic/my_package/0.0.1/file.txt" \
     --output file.txt
```

HTTP 기본 인증 사용:

```shell
curl --user "<project_access_token_username>:<project_access_token>" \
     --location \
     "https://gitlab.example.com/api/v4/projects/1/packages/generic/my_package/0.0.1/file.txt" \
     --output file.txt
```

{{< /tab >}}

{{< tab title="배포 토큰" >}}

HTTP 헤더 사용:

```shell
curl --header "DEPLOY-TOKEN: <deploy_token>" \
     --location \
     "https://gitlab.example.com/api/v4/projects/1/packages/generic/my_package/0.0.1/file.txt" \
     --output file.txt
```

HTTP 기본 인증 사용:

```shell
curl --user "<deploy_token_username>:<deploy_token>" \
     --location \
     "https://gitlab.example.com/api/v4/projects/1/packages/generic/my_package/0.0.1/file.txt" \
     --output file.txt
```

{{< /tab >}}

{{< tab title="CI/CD 작업 토큰" >}}

이 예제는 `.gitlab-ci.yml` 파일을 위한 것입니다. GitLab CI/CD는 자동으로 `CI_JOB_TOKEN`를 제공합니다.

HTTP 헤더 사용:

```yaml
download:
  stage: test
  script:
    - |
      curl --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
           --location \
           --output file.txt \
           "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/my_package/${CI_COMMIT_TAG}/file.txt"
```

HTTP 기본 인증 사용:

```yaml
download:
  stage: test
  script:
    - |
      curl --user "gitlab-ci-token:${CI_JOB_TOKEN}" \
           --location \
           --output file.txt \
           "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/my_package/${CI_COMMIT_TAG}/file.txt"
```

각 요청은 성공 또는 실패를 나타내는 응답을 반환합니다. 업로드가 성공하면 응답 상태는 `201 Created`입니다.

{{< /tab >}}

{{< /tabs >}}

### 여러 파일 다운로드 {#download-multiple-files}

여러 파일 또는 전체 디렉토리를 다운로드하려면 각 파일에 대해 하나의 API 호출을 하거나 추가 도구를 사용해야 합니다.

리포지토리에서 여러 파일을 다운로드할 때 다음 모범 사례를 따르십시오:

- 버전 관리: 일관성을 보장하려면 항상 다운로드할 패키지의 정확한 버전을 지정합니다.
- 디렉토리 구조: 다운로드할 때 패키지의 원본 디렉토리 구조를 유지하여 파일 구성을 보존합니다.
- 자동화: 패키지 다운로드를 CI/CD 파이프라인 또는 빌드 스크립트에 통합하여 자동화된 워크플로우를 실행합니다.
- 오류 처리: 모든 파일이 성공적으로 다운로드되도록 검사를 구현합니다. HTTP 상태 코드를 확인하거나 다운로드 후 파일 존재 여부를 확인할 수 있습니다.
- 캐싱: 자주 사용되는 패키지의 경우 캐싱 메커니즘을 구현하여 네트워크 사용량을 줄이고 빌드 시간을 개선하는 것을 고려하십시오.
- 병렬 다운로드: 많은 파일이 있는 대규모 패키지의 경우 병렬 다운로드를 구현하여 프로세스 속도를 높이는 것을 고려하십시오.
- 체크섬: SHA256 체크섬을 사용하여 다운로드한 파일의 무결성을 확인합니다. 체크섬은 검증을 위해 응답 헤더 및 API 응답에서 제공됩니다.
- 증분 다운로드: 자주 변경되는 대규모 패키지의 경우 마지막 다운로드 이후 변경된 파일만 다운로드하는 메커니즘을 구현하는 것을 고려하십시오.

예를 들어:

{{< tabs >}}

{{< tab title="Bash 스크립트 사용" >}}

여러 파일을 다운로드하는 bash 스크립트를 만듭니다:

```shell
#!/bin/bash

TOKEN="<access_token>"
PROJECT_ID="24"
PACKAGE_NAME="my_package"
PACKAGE_VERSION="1.0.0"
OUTPUT_DIR="./downloaded_files"

# Create output directory if it doesn't exist
mkdir -p "$OUTPUT_DIR"

# Array of files to download
files=("file1.txt" "file2.txt" "subdirectory/file3.txt")

for file in "${files[@]}"; do
    curl --location --header "PRIVATE-TOKEN: $TOKEN" \
         --output "$OUTPUT_DIR/$file" \
         --create-dirs \
         "https://gitlab.example.com/api/v4/projects/$PROJECT_ID/packages/generic/$PACKAGE_NAME/$PACKAGE_VERSION/$file"
    echo "Downloaded: $file"
done
```

{{< /tab >}}

{{< tab title="GitLab CI/CD 사용" >}}

CI/CD 파이프라인에서 자동화된 다운로드의 경우:

```yaml
download_package:
  stage: build
  script:
    - |
      FILES=("file1.txt" "file2.txt" "subdirectory/file3.txt")
      for file in "${FILES[@]}"; do
        curl --location --header "JOB-TOKEN: $CI_JOB_TOKEN" \
             --output "$file" \
             --create-dirs \
             "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/my_package/${CI_COMMIT_TAG}/$file"
        echo "Downloaded: $file"
      done
```

{{< /tab >}}

{{< /tabs >}}

### 전체 패키지 다운로드 {#download-an-entire-package}

패키지의 모든 파일을 다운로드하려면 다음을 수행해야 합니다:

1. 패키지 ID를 가져옵니다.
1. GitLab API를 사용하여 패키지 콘텐츠를 나열합니다.
1. 각 파일을 다운로드합니다.

패키지의 모든 파일을 다운로드하려면 다음 명령을 실행합니다:

```shell
TOKEN="<access_token>"
PROJECT_ID="24"
PACKAGE_NAME="my_package"
PACKAGE_VERSION="1.0.0"
GITLAB_URL="https://gitlab.example.com"
OUTPUT_DIR="./downloaded_package"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Step 1: Get the package ID
PACKAGE_ID=$(curl --location --header "PRIVATE-TOKEN: $TOKEN" \
     "$GITLAB_URL/api/v4/projects/$PROJECT_ID/packages?package_type=generic&package_name=$PACKAGE_NAME&package_version=$PACKAGE_VERSION" \
     | jq -r ".[] | select(.name==\"$PACKAGE_NAME\" and .version==\"$PACKAGE_VERSION\") | .id")

if [ -z "$PACKAGE_ID" ] || [ "$PACKAGE_ID" = "null" ]; then
    echo "Error: Package '$PACKAGE_NAME' version '$PACKAGE_VERSION' not found"
    exit 1
fi

echo "Found package ID: $PACKAGE_ID"

# Step 2: Get list of files in the package
files=$(curl --location --header "PRIVATE-TOKEN: $TOKEN" \
     "$GITLAB_URL/api/v4/projects/$PROJECT_ID/packages/$PACKAGE_ID/package_files" \
     | jq -r '.[].file_name')

if [ -z "$files" ]; then
    echo "Error: No files found in package"
    exit 1
fi

# Step 3: Download each file
for file in $files; do
    echo "Downloading: $file"
    curl --location --header "PRIVATE-TOKEN: $TOKEN" \
         --output "$OUTPUT_DIR/$file" \
         --create-dirs \
         "$GITLAB_URL/api/v4/projects/$PROJECT_ID/packages/generic/$PACKAGE_NAME/$PACKAGE_VERSION/$file"
    # Check if download was successful
    if [ $? -eq 0 ]; then
        echo "✓ Downloaded: $file"
    else
        echo "✗ Failed to download: $file"
    fi
done

echo "Package download complete"
```

## 패키지 삭제 {#delete-a-package}

패키지를 삭제하기 전에 [관련된 보안 위험](../package_registry/supported_functionality.md#deleting-packages)을(를) 이해했는지 확인하십시오.

패키지를 삭제하려면 다음을 수행할 수 있습니다:

- [UI 사용](../package_registry/reduce_package_registry_storage.md#delete-a-package)합니다.
- [API 사용](../../../api/packages.md#delete-a-project-package)합니다.

## 체크섬으로 파일 무결성 확인 {#verify-file-integrity-with-checksums}

SHA256 체크섬은 업로드된 모든 파일에 대해 자동으로 계산되고 저장됩니다. 이 체크섬을 사용하여 다운로드한 파일의 무결성을 확인할 수 있습니다.

체크섬을 확인하려면 다음을 수행할 수 있습니다:

- HTTP 응답 헤더에서 체크섬을 가져옵니다.
- API 응답에서 체크섬을 가져옵니다.
- CI/CD 파이프라인에 체크섬 검증을 통합합니다.

### 응답 헤더에서 체크섬 가져오기 {#get-checksums-from-response-headers}

파일을 다운로드할 때 `X-Checksum-SHA256` 응답 헤더에서 SHA256 체크섬을 가져올 수 있습니다.

사전 요구 사항:

응답 헤더에서 체크섬을 가져오려면 다음 중 하나를 수행해야 합니다:

- 오브젝트 스토리지를 비활성화하여 파일을 로컬로 저장합니다.
- 오브젝트 스토리지를 활성화하되 직접 다운로드를 비활성화합니다(파일은 GitLab Workhorse를 통해 제공됩니다). 오브젝트 스토리지 직접 다운로드가 활성화되면 파일이 오브젝트 스토리지 제공자로 리디렉션되고 `X-Checksum-SHA256`과 같은 사용자 정의 헤더를 리디렉션 응답에 포함할 수 없습니다.

```shell
# Download a file and get the checksum from the response header
curl --header "PRIVATE-TOKEN: <access_token>" \
     --location \
     --output file.txt \
     --dump-header headers.txt \
     --url "https://gitlab.example.com/api/v4/projects/1/packages/generic/my_package/0.0.1/file.txt"

# Extract the checksum from the response header
CHECKSUM=$(grep "X-Checksum-SHA256:" headers.txt | cut -d' ' -f2 | tr -d '\r')
echo "Expected checksum: $CHECKSUM"

# Verify the downloaded file
ACTUAL_CHECKSUM=$(sha256sum file.txt | cut -d' ' -f1)
if [ "$CHECKSUM" = "$ACTUAL_CHECKSUM" ]; then
    echo "✓ File integrity verified"
else
    echo "✗ File integrity check failed"
fi
```

### API 응답에서 체크섬 가져오기 {#get-checksums-from-api-responses}

API 호출에서 패키지 파일을 나열하여 체크섬을 가져옵니다:

```shell
# Get the package ID
PACKAGE_ID=$(curl --header "PRIVATE-TOKEN: <access_token>" \
     --url "https://gitlab.example.com/api/v4/projects/1/packages?package_type=generic&package_name=my_package&package_version=0.0.1" \
     | jq -r ".[] | select(.name==\"my_package\" and .version==\"0.0.1\") | .id")

# Get file information, including checksums
curl --header "PRIVATE-TOKEN: <access_token>" \
     --url "https://gitlab.example.com/api/v4/projects/1/packages/$PACKAGE_ID/package_files" \
     | jq '.[] | {file_name: .file_name, file_sha256: .file_sha256}'
```

### CI/CD 파이프라인에서 파일 무결성 확인 {#verify-file-integrity-in-cicd-pipelines}

CI/CD 파이프라인에 체크섬 검증을 통합할 수 있습니다.

사전 요구 사항:

CI/CD 파이프라인에서 체크섬을 확인하려면 다음 중 하나를 수행해야 합니다:

- 오브젝트 스토리지를 비활성화하여 파일을 로컬로 저장합니다.
- 오브젝트 스토리지를 활성화하되 직접 다운로드를 비활성화합니다(파일은 GitLab Workhorse를 통해 제공됩니다). 오브젝트 스토리지 직접 다운로드가 활성화되면 파일이 오브젝트 스토리지 제공자로 리디렉션되고 `X-Checksum-SHA256`과 같은 사용자 정의 헤더를 리디렉션 응답에 포함할 수 없습니다.

```yaml
verify_download:
  stage: test
  script:
    - |
      # Download file and get checksum from header
      curl --header "JOB-TOKEN: ${CI_JOB_TOKEN}" \
           --location \
           --output file.txt \
           --dump-header headers.txt \
           "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/my_package/${CI_COMMIT_TAG}/file.txt"

      # Extract checksum from response header
      EXPECTED_CHECKSUM=$(grep "X-Checksum-SHA256:" headers.txt | cut -d' ' -f2 | tr -d '\r')

      # Calculate actual checksum
      ACTUAL_CHECKSUM=$(sha256sum file.txt | cut -d' ' -f1)

      # Verify integrity
      if [ "$EXPECTED_CHECKSUM" = "$ACTUAL_CHECKSUM" ]; then
        echo "✓ File integrity verified"
      else
        echo "✗ File integrity check failed"
        exit 1
      fi
```

## 중복 패키지 이름 게시 비활성화 {#disable-publishing-duplicate-package-names}

{{< history >}}

- 필요한 역할이 [GitLab 15.0에서 개발자에서 유지 관리자로 변경](https://gitlab.com/gitlab-org/gitlab/-/issues/350682)되었습니다.
- 필요한 역할이 [GitLab 17.0에서 유지 관리자에서 소유자로 변경](https://gitlab.com/gitlab-org/gitlab/-/issues/370471)되었습니다.

{{< /history >}}

기본적으로 기존 패키지와 동일한 이름 및 버전으로 패키지를 게시하면 새 파일이 기존 패키지에 추가됩니다. 설정에서 중복 파일 이름 게시를 비활성화할 수 있습니다.

사전 요구 사항:

- 소유자 역할이 있어야 합니다.

중복 파일 이름 게시를 비활성화하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **중복 패키지** 테이블의 **일반** 행에서 **중복 허용** 토글을 끕니다.
1. 선택 사항. **예외** 텍스트 상자에 패키지를 허용하는 이름 및 버전과 일치하는 정규식을 입력합니다.

> [!note]
> **중복 허용**이(가) 켜져 있으면 **예외** 텍스트 상자에 중복되지 않아야 하는 패키지 이름 및 버전을 지정할 수 있습니다.

## 패키지 보존 정책 추가 {#add-a-package-retention-policy}

패키지 보존 정책을 구현하여 스토리지를 관리하고 관련 버전을 유지합니다.

다음을 수행합니다:

- GitLab 기본 제공 [정리 정책](../package_registry/reduce_package_registry_storage.md#cleanup-policy)을(를) 사용합니다.

API를 사용하여 사용자 정의 정리 스크립트를 구현할 수도 있습니다.

## 일반 패키지 샘플 프로젝트 {#generic-package-sample-project}

[파이프라인에서 CI/CD 변수 작성](https://gitlab.com/guided-explorations/cfg-data/write-ci-cd-variables-in-pipeline) 프로젝트에는 GitLab CI/CD에서 일반 패키지를 만들고, 업로드하고, 다운로드하는 데 사용할 수 있는 작동하는 예제가 포함되어 있습니다.

또한 일반 패키지에 대한 의미 있는 버전을 관리하는 방법을 보여줍니다. CI/CD 변수에 저장하고, 검색하고, 증가하고, 다운로드 테스트가 제대로 작동할 때 CI/CD 변수로 다시 작성합니다.

## 유효한 패키지 파일 이름 형식 {#valid-package-filename-format}

유효한 패키지 파일 이름에 포함될 수 있는 항목:

- 문자: A-Z, a-z
- 숫자: 0-9
- 특수 문자: . (점), _ (밑줄), - (하이픈), + (더하기), ~ (물결표), @ (골뱅이), / (슬래시)

패키지 파일 이름은 다음을 할 수 없습니다:

- 물결표(~) 또는 골뱅이(@)로 시작
- 물결표(~) 또는 골뱅이(@)로 끝남
- 공백 포함

## 문제 해결 {#troubleshooting}

### HTTP 403 오류 {#http-403-errors}

`HTTP 403 Forbidden` 오류가 발생할 수 있습니다. 이 오류는 다음 중 하나인 경우 발생합니다:

- 리소스에 대한 액세스 권한이 없습니다.
- 프로젝트에 대해 패키지 레지스트리가 활성화되지 않았습니다.

문제를 해결하려면 패키지 레지스트리가 활성화되어 있고 액세스할 수 있는 권한이 있는지 확인하십시오.

### S3에 대한 대용량 파일 업로드 시 내부 서버 오류 {#internal-server-error-on-large-file-uploads-to-s3}

S3 호환 오브젝트 스토리지는 [단일 PUT 요청의 크기를 5GB로 제한](https://docs.aws.amazon.com/AmazonS3/latest/userguide/upload-objects.html)합니다. `aws_signature_version`이(가) `2`로 설정된 경우 [오브젝트 스토리지 연결 설정](../../../administration/object_storage.md)에서 5GB 제한보다 큰 패키지 파일을 게시하려고 하면 `HTTP 500: Internal Server Error` 응답이 발생할 수 있습니다.

S3에 대용량 파일을 게시할 때 `HTTP 500: Internal Server Error` 응답을 받는 경우 `aws_signature_version`을(를) `4`로 설정합니다:

```ruby
# Consolidated Object Storage settings
gitlab_rails['object_store']['connection'] = {
  # Other connection settings
  'aws_signature_version' => '4'
}
# OR
# Storage-specific form settings
gitlab_rails['packages_object_store_connection'] = {
  # Other connection settings
  'aws_signature_version' => '4'
}
```
