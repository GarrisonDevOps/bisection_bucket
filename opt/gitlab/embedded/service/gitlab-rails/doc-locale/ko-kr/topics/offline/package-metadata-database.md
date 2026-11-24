---
stage: Application Security Testing
group: Composition Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 패키지 메타데이터 데이터베이스를 다운로드하여 오프라인 GitLab Self-Managed 인스턴스에 복사합니다.
title: 오프라인 인스턴스용 패키지 메타데이터 데이터베이스
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab Self-Managed

{{< /details >}}

[패키지 메타데이터 데이터베이스](../../user/application_security/detect/package-metadata-database.md)를 활성화하려면 [지속적 취약성 검사](../../user/application_security/continuous_vulnerability_scanning/_index.md) 및 [CycloneDX 파일의 라이선스 검사](../../user/compliance/license_scanning_of_cyclonedx_files/_index.md)를 활성화해야 합니다. 이 프로세스는 패키지 메타데이터 데이터베이스라고 통칭하는 라이선스 및/또는 자문 데이터의 사용이 필요하며, [EE 라이선스](https://storage.googleapis.com/prod-export-license-bucket-1a6c642fc4de57d4/LICENSE)에 따라 라이선스가 부여됩니다. 패키지 메타데이터 데이터베이스 사용과 관련하여 다음을 참고하세요:

- 패키지 메타데이터 데이터베이스의 전부 또는 일부를 언제든지 예고 없이 변경하거나 중단할 수 있으며, 이는 당사의 단독 재량입니다.
- 패키지 메타데이터 데이터베이스에는 제3자 웹사이트 또는 리소스에 대한 링크가 포함될 수 있습니다. 이러한 링크는 편의를 위해서만 제공되며, 해당 웹사이트 또는 리소스의 제3자 데이터, 콘텐츠, 제품 또는 서비스나 표시되는 링크에 대해 책임을 지지 않습니다.
- 패키지 메타데이터 데이터베이스는 제3자가 제공하는 정보를 기반으로 하며, GitLab은 제공되는 콘텐츠의 정확성 또는 완전성에 대해 책임을 지지 않습니다.

패키지 메타데이터 데이터베이스는 라이선스, 자문, 악성 자문 및 CVE 보강이라는 4개의 데이터 세트로 구성됩니다. 패키지 메타데이터는 v2 및 v3이라는 2가지 형식 버전으로 게시되며, 각 데이터 세트는 그 중 하나를 사용합니다. 두 형식 버전은 서로 다른 데이터를 보유하고 있으며 다른 방식으로 다운로드되므로, 각각 아래에 자체 절차가 있습니다. 각 데이터 세트와 GitLab 버전이 어떤 형식 버전을 사용하는지 알아보려면 [패키지 메타데이터 데이터베이스](../../user/application_security/detect/package-metadata-database.md)를 참고하세요.

v2 데이터는 다음의 공개 Google Cloud Provider (GCP) 버킷에 저장되며, GitLab이 유지 관리하고 소유합니다:

- 라이선스 검사: `prod-export-license-bucket-1a6c642fc4de57d4`
- 종속성 검사: `prod-export-advisory-bucket-1a6c642fc4de57d4`
- CVE 보강: `prod-export-cve-enrichment-bucket-1a6c642fc4de57d4`

v3 데이터는 공개 버킷이 없습니다. 인증된 GitLab 서비스에 의해 배포되므로, 다운로드하려면 라이선스 키가 필요합니다. [v3 패키지 메타데이터 데이터베이스 데이터 다운로드](#download-v3-package-metadata-database-data)를 참고하세요.

CVE 보강은 취약성에 표시되는 [EPSS 점수 및 KEV 상태](../../user/application_security/vulnerabilities/risk_assessment_data.md)를 포함합니다. 라이선스 및 자문 버킷만 동기화하는 인스턴스는 종속성 검사 및 라이선스 데이터를 보유하고 있으며, 위험 평가 데이터는 없습니다.

> [!note]
> 모든 데이터 세트에 대해 GitLab은 `vendor/package_metadata` 아래의 디렉터리를 읽으며, 이는 데이터 자체를 다운로드하는 것보다 우선합니다. 존재하는 디렉터리는 항상 우선하며, 온라인 동기화로의 폴백이 없습니다. 부실 데이터를 보유하는 디렉터리는 따라서 부실 데이터를 제공하며, 오류를 보고하지 않습니다. [악성 자문](#confirm-gitlab-detects-the-offline-directory)도 동일한 규칙을 따릅니다.

## 첫 로드 전 {#before-the-first-load}

아무것도 다운로드하기 전에 동기화할 패키지 레지스트리 유형을 결정합니다. [운영자 설정](../../administration/settings/security_and_compliance.md#choose-package-registry-metadata-to-sync)에서 활성화된 유형만 가져옵니다. 비활성화한 유형을 다운로드하면 시간과 디스크 공간이 소비되며, 어떤 것도 데이터베이스에 도달하지 않습니다.

동기화 작업의 제한은 인스턴스의 리소스가 아니라 가져오기 속도를 설정하므로, 더 큰 인스턴스가 더 빠르게 가져오지는 않습니다. 각 실행은 고정 기간 후 중지되고 다음 실행에서 체크포인트에서 재개됩니다. 모든 레지스트리 유형이 활성화된 상태에서 첫 로드는 오래 걸립니다. 시간을 단축하려면 활성화된 유형을 좁혀야 합니다.

## gsutil을 사용하여 v2 패키지 메타데이터 다운로드 {#download-v2-package-metadata-with-gsutil}

이 섹션은 v2 데이터를 다운로드하는 방법을 설명합니다.

1. [`gsutil`](https://docs.cloud.google.com/storage/docs/gsutil_install) 도구를 설치합니다.
1. GitLab Rails 디렉터리의 루트를 찾습니다.

   ```shell
   export GITLAB_RAILS_ROOT_DIR="$(gitlab-rails runner 'puts Rails.root.to_s')"
   echo $GITLAB_RAILS_ROOT_DIR
   ```

1. 동기화할 데이터의 유형을 설정합니다.

   ```shell
   # For License Scanning
   export PKG_METADATA_BUCKET=prod-export-license-bucket-1a6c642fc4de57d4
   export DATA_DIR="licenses"

   # For dependency scanning
   export PKG_METADATA_BUCKET=prod-export-advisory-bucket-1a6c642fc4de57d4
   export DATA_DIR="advisories"

   # For CVE enrichment
   export PKG_METADATA_BUCKET=prod-export-cve-enrichment-bucket-1a6c642fc4de57d4
   export DATA_DIR="cve_enrichment"
   ```

1. 패키지 메타데이터 내보내기를 다운로드합니다.

   ```shell
   # To download the package metadata exports, an outbound connection to Google Cloud Storage bucket must be allowed.
   mkdir -p "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/$DATA_DIR"
   gsutil -m rsync -r -d gs://$PKG_METADATA_BUCKET "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/$DATA_DIR"

   # Alternatively, if the GitLab instance is not allowed to connect to the Google Cloud Storage bucket, the package metadata
   # exports can be downloaded using a machine with the allowed access, and then copied to the root of the GitLab Rails directory.
   rsync rsync://example_username@gitlab.example.com/package_metadata/$DATA_DIR "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/$DATA_DIR"
   ```

1. GitLab 19.4 이전 버전의 CVE 보강의 경우, 다운로드한 파일을 한 디렉터리 수준 위로 이동합니다. GitLab 19.5 이상에서는 이 단계를 건너뜁니다. 자세한 내용은 [머지 리퀘스트 253401](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/253401)을 참고하세요.

   라이선스 및 자문 버킷은 `v2/` 아래의 각 패키지 레지스트리에 대해 하나의 디렉터리를 보유하고 있으며, GitLab은 그대로 복사본을 읽습니다. CVE 보강은 패키지 레지스트리가 없으며, 해당 버킷은 대신 해당 위치에 `cve_enrichment` 디렉터리 하나를 보유합니다. GitLab 19.4 이전 버전에서 GitLab은 `cve_enrichment/v2/<sequence>/<chunk>.ndjson`에서만 CVE 보강을 읽으며, 정확히 해당 깊이입니다. 그대로 복사하면 파일이 한 디렉터리 수준 너무 깊게 됩니다. GitLab은 아무것도 가져오지 않고 아무것도 로깅하지 않습니다.

   ```shell
   cd "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/cve_enrichment/v2"
   cp -a cve_enrichment/. . && rm -r cve_enrichment
   ```

   CVE 보강 내보내기를 다운로드할 때마다 이 단계를 반복합니다. `cp -a`은 이미 존재하는 시퀀스 디렉터리에 새 파일을 병합하며, `mv`는 중지됩니다.

## Google Cloud Storage REST API를 사용하여 v2 패키지 메타데이터 다운로드 {#download-v2-package-metadata-using-the-google-cloud-storage-rest-api}

이 섹션은 v2 패키지 메타데이터를 다운로드하는 다른 방법을 설명합니다.

패키지 메타데이터 내보내기는 Google Cloud Storage API를 사용하여 다운로드할 수도 있습니다. 콘텐츠는 <https://storage.googleapis.com/storage/v1/b/prod-export-license-bucket-1a6c642fc4de57d4/o> 및 <https://storage.googleapis.com/storage/v1/b/prod-export-advisory-bucket-1a6c642fc4de57d4/o>에서 사용할 수 있습니다. 다음은 [cURL](https://curl.se/) 및 [jq](https://stedolan.github.io/jq/)를 사용하여 이를 다운로드하는 방법의 예입니다.

```shell
#!/bin/bash

set -euo pipefail

DATA_TYPE=$1

GITLAB_RAILS_ROOT_DIR="$(gitlab-rails runner 'puts Rails.root.to_s')"

if [ "$DATA_TYPE" == "license" ]; then
  PKG_METADATA_DIR="$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses"
elif [ "$DATA_TYPE" == "advisory" ]; then
  PKG_METADATA_DIR="$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/advisories"
else
  echo "Usage: import_script.sh [license|advisory]"
  exit 1
fi

PKG_METADATA_BUCKET="prod-export-$DATA_TYPE-bucket-1a6c642fc4de57d4"
PKG_METADATA_DOWNLOADS_OUTPUT_FILE="/tmp/package_metadata_${DATA_TYPE}_object_links.tsv"

# Download the contents of the bucket
# The script downloads all the objects and creates files with a maximum 1000 objects per file in JSON format.

MAX_RESULTS=1000
TEMP_FILE="out.json"

curl --silent --show-error --request GET "https://storage.googleapis.com/storage/v1/b/$PKG_METADATA_BUCKET/o?maxResults=$MAX_RESULTS" >"$TEMP_FILE"
NEXT_PAGE_TOKEN="$(jq -r '.nextPageToken' $TEMP_FILE)"
jq -r '.items[] | [.name, .mediaLink] | @tsv' "$TEMP_FILE" >"$PKG_METADATA_DOWNLOADS_OUTPUT_FILE"

while [ "$NEXT_PAGE_TOKEN" != "null" ]; do
  curl --silent --show-error --request GET "https://storage.googleapis.com/storage/v1/b/$PKG_METADATA_BUCKET/o?maxResults=$MAX_RESULTS&pageToken=$NEXT_PAGE_TOKEN" >"$TEMP_FILE"
  NEXT_PAGE_TOKEN="$(jq -r '.nextPageToken' $TEMP_FILE)"
  jq -r '.items[] | [.name, .mediaLink] | @tsv' "$TEMP_FILE" >>"$PKG_METADATA_DOWNLOADS_OUTPUT_FILE"
  #use for API rate-limiting
  sleep 1
done

trap 'rm -f "$TEMP_FILE"' EXIT

echo "Fetched $DATA_TYPE export manifest"

# Parse the links and names for the bucket objects and output them into a tsv file

echo -e "Saving package metadata exports to $PKG_METADATA_DIR\n"

# Track how many objects will be downloaded
INDEX=1
TOTAL_OBJECT_COUNT="$(wc -l "$PKG_METADATA_DOWNLOADS_OUTPUT_FILE" | awk '{print $1}')"

# Download the objects
while IFS= read -r line; do
  FILE="$(echo -n "$line" | awk '{print $1}')"
  URL="$(echo -n "$line" | awk '{print $2}')"
  OUTPUT_PATH="$PKG_METADATA_DIR/$FILE"

  echo "Downloading $FILE"

  if [ ! -f "$OUTPUT_PATH" ]; then
    curl --progress-bar --create-dirs --output "$OUTPUT_PATH" --request "GET" "$URL"
  else
    echo "Existing file found"
  fi

  echo -e "$INDEX of $TOTAL_OBJECT_COUNT objects downloaded\n"

  INDEX=$((INDEX + 1))
done <"$PKG_METADATA_DOWNLOADS_OUTPUT_FILE"

echo "All objects saved to $PKG_METADATA_DIR"
```

## 일정에 따라 v2 패키지 메타데이터 다운로드 {#download-v2-package-metadata-on-a-schedule}

GitLab 인스턴스는 [정기적으로](https://gitlab.com/gitlab-org/gitlab/-/blob/63a187d47f6da353ba4514650bbbbeb99c356325/config/initializers/1_settings.rb#L840-842) `package_metadata` 디렉터리의 콘텐츠와 동기화됩니다. 로컬 복사본을 업스트림 변경 사항으로 자동 업데이트하려면, cron 작업을 추가하여 정기적으로 새 내보내기를 다운로드할 수 있습니다. 예를 들어, 다음 crontab을 추가하여 30분마다 실행되는 cron 작업을 설정할 수 있습니다.

라이선스 및 자문 작업은 `-y "^v3\/"`을 전달하여 `v3/` 폴더를 제외하므로, v2 형식 버전만 미러링합니다.

v2 라이선스 검사 (GitLab 19.3 이전):

```plaintext
*/30 * * * * gsutil -m rsync -r -d -y "^v3\/" gs://prod-export-license-bucket-1a6c642fc4de57d4 $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses
```

v2 종속성 검사:

```plaintext
*/30 * * * * gsutil -m rsync -r -d -y "^v3\/" gs://prod-export-advisory-bucket-1a6c642fc4de57d4 $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/advisories
```

GitLab 19.4 이전의 CVE 보강의 경우, `-d`을 생략하고 다운로드 절차의 이동 단계를 연결합니다:

```plaintext
*/30 * * * * gsutil -m rsync -r gs://prod-export-cve-enrichment-bucket-1a6c642fc4de57d4 $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/cve_enrichment && cd $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/cve_enrichment/v2 && cp -a cve_enrichment/. . && rm -r cve_enrichment
```

이동 단계 후 로컬 레이아웃은 더 이상 버킷과 일치하지 않으므로, `-d`은 이동된 파일을 삭제합니다. 이동은 또한 `gsutil rsync`이 비교하는 디렉터리를 제거하므로, `-d`이 있는지 여부에 관계없이 모든 실행은 전체 내보내기를 다시 다운로드합니다.

GitLab 19.5 이상에서는 이동 단계 없이 다운로드를 실행합니다. 이전 버전에서 업그레이드하는 경우, 기존 CVE 보강 라인을 다음으로 바꿉니다:

```plaintext
*/30 * * * * gsutil -m rsync -r -d gs://prod-export-cve-enrichment-bucket-1a6c642fc4de57d4 $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/cve_enrichment
```

> [!warning]
> `-d` 플래그는 라이선스 및 자문 예제와 GitLab 19.5 이상의 CVE 보강 예제에서 더 이상 버킷에 없는 로컬 파일을 삭제하므로, 진행 중인 가져오기를 폐기할 수 있습니다. GitLab은 각 데이터 유형 및 패키지 레지스트리에 대해 가져온 마지막 파일을 기록하고 그 후의 파일에서 재개됩니다. 정리가 해당 레코드가 가리키는 시퀀스 디렉터리를 제거하면, GitLab이 레코드를 찾을 수 없습니다. 그러면 처음부터 전체 데이터 유형을 다시 가져옵니다. 정리하기 전에, 각 데이터 유형의 기록된 시퀀스가 여전히 디스크에 있는지 확인합니다. 기록된 시퀀스를 읽으려면 [데이터 확인](#verify-data)을 참고하세요. 두 개 이상의 인스턴스가 읽는 디렉터리에서 기록한 것 중 가장 오래된 시퀀스 뒤에서만 정리합니다.
>
> 이 동작은 GitLab이 한 번에 하나의 파일씩 가져오는 라이선스, 자문 및 CVE 보강 내보내기에 적용됩니다. [악성 자문 절차](#download-gitlab-v3-malware-advisories)는 다릅니다. 모든 실행에서 완전한 스냅샷을 교체하며, `rsync --delete`이 필요합니다.

## v3 패키지 메타데이터 데이터베이스 데이터 다운로드 {#download-v3-package-metadata-database-data}

{{< details >}}

- 티어: Ultimate

{{< /details >}}

v3 라이선스 및 악성 자문은 공개 버킷에 없습니다. 이는 인증된 GitLab 서비스인 패키지 메타데이터 데이터베이스 배포 서비스 (PDS)에서 제공되므로, 오프라인 인스턴스가 직접 다운로드할 수 없습니다. 대신 인터넷 액세스가 있는 머신에서 다음 스크립트를 실행한 다음, 데이터를 오프라인 인스턴스로 복사합니다. 스크립트는 두 데이터 세트 모두에서 작동합니다. 첫 번째 인수로 데이터 세트 이름을 전달합니다.

각 패키지 레지스트리에 대해 스크립트는 디스크에 이미 있는 스냅샷 이후 게시된 델타를 다운로드하거나, 스냅샷이 없거나 레지스트리가 델타가 더 저렴한 옵션이 되기에 너무 뒤쳐져 있을 때 새 스냅샷을 다운로드합니다. 해당 레지스트리의 모든 아카이브를 다운로드한 후 각 레지스트리의 체크포인트를 마지막에 작성하므로, 부분 다운로드가 완전한 것으로 간주되지 않습니다. 라이선스 키를 3일 동안 유효한 토큰으로 교환합니다. 인터넷 액세스가 있는 머신은 라이선스 파일의 사본이 필요하지만 오프라인 인스턴스에 액세스할 필요는 없습니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.
- 오프라인 라이선스입니다. 레거시 라이선스 파일은 작동하지 않습니다: 토큰 요청이 `Invalid cloud license`로 실패하고 스크립트가 중지됩니다. **운영자** 영역 대시보드는 **라이선스 개요** 아래에 라이선스 유형을 표시합니다.
- 인터넷 액세스가 있는 머신에서 cURL, jq 1.6 이상 및 `customers.gitlab.com`, `pmdb-dist-svc.runway.gitlab.net` 및 `storage.googleapis.com`에 대한 아웃바운드 액세스. 배포 서비스는 `gitlab.net` 도메인에 있으므로, `gitlab.com`로 제한된 허용 목록이 이에 도달할 수 없습니다.
- 오프라인 인스턴스에서 rsync합니다.

오프라인 라이선스를 얻으려면 승인이 필요한 [클라우드 라이선싱의 옵트아웃 예외](https://about.gitlab.com/pricing/licensing-faq/cloud-licensing/#offline-cloud-licensing)를 받아야 합니다. 자세한 내용은 GitLab 영업 담당자에게 문의하세요. 이미 오프라인 라이선스가 있는 경우 [고객 포털](https://customers.gitlab.com)에서 파일을 다시 다운로드할 수 있습니다.

스크립트는 라이선스 파일이 보유한 텍스트의 긴 블록인 라이선스 키가 필요합니다. 파일에 작성하려면 오프라인 인스턴스에서 다음을 실행합니다:

```shell
sudo gitlab-rails runner 'puts License.current.data' > Gitlab.gitlab-license
```

활성화 코드는 라이선스 키가 아닙니다. 활성화 코드는 짧은 문자열이며, 토큰 요청이 거부합니다.

이 단계는 Linux 패키지 설치에 적용됩니다. Kubernetes 설치에서 데이터는 Sidekiq pod가 읽는 볼륨에 있어야 합니다. [Helm 차트가 설치된 인스턴스](#instances-installed-with-the-helm-chart)를 참고하세요.

> [!warning]
> Docker 설치에서 Rails 디렉터리는 마운트된 볼륨에 없습니다. 데이터를 복사하기 전에 `vendor/package_metadata`을 바인드 마운트하거나, 컨테이너를 업그레이드할 때 손실됩니다.

다음 스크립트를 `download_pmdb_data.sh`로 저장하고 `chmod +x download_pmdb_data.sh`로 실행 가능하게 만듭니다.

```shell
#!/bin/bash

set -euo pipefail

CDOT_URL="${CDOT_URL:-https://customers.gitlab.com}"
PDS_URL="${PDS_URL:-https://pmdb-dist-svc.runway.gitlab.net}"

# A registry far enough behind is cheaper to replace with a fresh snapshot than
# to catch up one delta at a time. Set to 0 to never download a delta.
MAX_DELTAS="${MAX_DELTAS:-100}"

if [ $# -lt 5 ]; then
  echo "Usage: download_pmdb_data.sh <license_file> <gitlab_version> <dataset> <output_dir> <registry>"
  echo "dataset is licenses or malware_advisories."
  echo "Pass the package registries to download separated by space, or 'all' for every supported registry."
  exit 1
fi

LICENSE_FILE=$1
GITLAB_VERSION=$2
DATASET=$3
OUTPUT_DIR=$4
shift 4
REQUESTED_REGISTRIES="$*"

# The two datasets differ only in their distribution service path and the name
# used in the closing message. Everything after this point is common to both.
case "$DATASET" in
licenses)
  DATASET_PATH="licenses"
  DATASET_LABEL="License data"
  ;;
malware_advisories)
  DATASET_PATH="malware/advisories"
  DATASET_LABEL="Advisories"
  ;;
*)
  echo "dataset must be licenses or malware_advisories"
  exit 1
  ;;
esac

if [ -z "$OUTPUT_DIR" ]; then
  echo "output_dir must not be empty"
  exit 1
fi

if [ ! -r "$LICENSE_FILE" ]; then
  echo "Cannot read $LICENSE_FILE"
  exit 1
fi

mkdir -p "$OUTPUT_DIR"

# Serialize runs against this output directory. Two concurrent runs would race
# on the same dataset directory: one can write checkpoint.json while the other
# has deleted and re-created the directory, leaving a partial shard set that
# GitLab imports as a complete snapshot. mkdir either creates the directory or
# fails, in one step, so it needs nothing beyond the shell.
LOCK_DIR="$OUTPUT_DIR/.download.lock"

if ! mkdir "$LOCK_DIR" 2>/dev/null; then
  echo "Another download is already running for $OUTPUT_DIR"
  echo "If no other run is active, remove $LOCK_DIR and try again."
  exit 1
fi

REQUEST_FILE="$(mktemp)"
RESPONSE_FILE="$(mktemp)"
SNAPSHOT_FILE="$(mktemp)"
SHARDS_FILE="$(mktemp)"
DELTAS_FILE="$(mktemp)"
HEADER_FILE="$(mktemp)"
trap 'rm -f "$REQUEST_FILE" "$RESPONSE_FILE" "$SNAPSHOT_FILE" "$SHARDS_FILE" "$DELTAS_FILE" "$HEADER_FILE"; rmdir "$LOCK_DIR" 2>/dev/null || true' EXIT
chmod 600 "$HEADER_FILE"

# Exchange the license key for a Cloud Connector token.
GRAPHQL_QUERY='query($licenseKey: String!, $gitlabVersion: String!) {
  cloudConnectorAccess(licenseKey: $licenseKey, gitlabVersion: $gitlabVersion) {
    serviceToken { token }
  }
}'

jq --null-input --arg query "$GRAPHQL_QUERY" --rawfile licenseKey "$LICENSE_FILE" \
  --arg gitlabVersion "$GITLAB_VERSION" \
  '{query: $query, variables: {licenseKey: $licenseKey, gitlabVersion: $gitlabVersion}}' >"$REQUEST_FILE"

HTTP_STATUS="$(curl --silent --show-error --request POST "$CDOT_URL/graphql" \
  --header 'Content-Type: application/json' --data @"$REQUEST_FILE" \
  --output "$RESPONSE_FILE" --write-out '%{http_code}')"

if [ "$HTTP_STATUS" != "200" ]; then
  echo "Token request to $CDOT_URL failed with HTTP $HTTP_STATUS"
  head -c 500 "$RESPONSE_FILE"
  exit 1
fi

TOKEN="$(jq --raw-output '.data.cloudConnectorAccess.serviceToken.token // empty' "$RESPONSE_FILE")"

if [ -z "$TOKEN" ]; then
  echo "$CDOT_URL refused to issue a token for $LICENSE_FILE"
  echo "It must hold the license key, the output of: gitlab-rails runner 'puts License.current.data'"
  echo "An activation code is not a license key, and a legacy license is not accepted."
  echo "The customer portal reported:"
  jq --raw-output '.errors[]?.message // "no reason given"' "$RESPONSE_FILE"
  exit 1
fi

# The distribution service requires X-Gitlab-Instance-Id to equal the token's
# subject claim and X-Gitlab-Realm to equal its realm claim. Both are in the
# payload, which is the second dot-separated segment of the token.
CLAIMS="$(printf '%s' "$TOKEN" |
  jq --raw-input 'split(".")[1] | gsub("-"; "+") | gsub("_"; "/") | @base64d | fromjson')"

INSTANCE_ID="$(jq --raw-output '.sub // empty' <<<"$CLAIMS")"
REALM="$(jq --raw-output '.gitlab_realm // empty' <<<"$CLAIMS")"

if [ -z "$INSTANCE_ID" ] || [ -z "$REALM" ]; then
  echo "The token is missing its subject or realm claim"
  exit 1
fi

# Pass the headers through a file so the token never appears in a process
# list. It is readable there by any local user for the download's duration.
{
  printf 'header = "Authorization: Bearer %s"\n' "$TOKEN"
  printf 'header = "X-Gitlab-Instance-Id: %s"\n' "$INSTANCE_ID"
  printf 'header = "X-Gitlab-Realm: %s"\n' "$REALM"
} >"$HEADER_FILE"

# Writes the response body to $2 and returns the HTTP status.
pds_request() {
  curl --silent --show-error --config "$HEADER_FILE" \
    --output "$2" --write-out '%{http_code}' "$1"
}

HTTP_STATUS="$(pds_request "$PDS_URL/v1/$DATASET_PATH/supported" "$RESPONSE_FILE")"

if [ "$HTTP_STATUS" != "200" ]; then
  echo "Request for the supported package registries failed with HTTP $HTTP_STATUS"
  head -c 500 "$RESPONSE_FILE"
  exit 1
fi

SUPPORTED="$(jq --raw-output '.registries[]' "$RESPONSE_FILE")"
SKIPPED=""

if [ -z "$SUPPORTED" ]; then
  echo "No package registries are available"
  exit 1
fi

echo "Available package registries: $(echo "$SUPPORTED" | tr '\n' ' ')"

# Disable filename expansion so a registry name is never treated as a glob.
set -f

if [ "$REQUESTED_REGISTRIES" = "all" ]; then
  REGISTRIES="$SUPPORTED"
else
  REGISTRIES="$REQUESTED_REGISTRIES"

  for REGISTRY in $REGISTRIES; do
    if ! grep --quiet --fixed-strings --line-regexp "$REGISTRY" <<<"$SUPPORTED"; then
      echo "$REGISTRY is not a supported package registry"
      exit 1
    fi
  done
fi

# Downloads the current snapshot into a registry's full_dataset directory, and
# removes any delta archives beside it: a snapshot supersedes every delta older
# than itself, and GitLab reads whatever is newer than its own checkpoint, so
# leaving them would re-apply changes the snapshot already contains.
download_snapshot() {
  REGISTRY=$1
  UNTIL=$2
  DATASET_DIR="$OUTPUT_DIR/v3/$REGISTRY/full_dataset"

  # Remove any previous snapshot. GitLab reads every archive in this directory,
  # so archives left over from an earlier snapshot would be imported alongside
  # the new ones, restoring data that changed since.
  rm -rf "$DATASET_DIR" "$OUTPUT_DIR/v3/$REGISTRY/deltas"
  mkdir -p "$DATASET_DIR"

  # Read the shards from the saved /all body. The delta loop reuses
  # $RESPONSE_FILE, so by the time a fallback lands here it no longer holds it.
  jq --raw-output '.shards[] | [.shard, (.signed_url // .url)] | @tsv' "$SNAPSHOT_FILE" >"$SHARDS_FILE"
  SHARD_COUNT="$(wc -l <"$SHARDS_FILE" | tr -d ' ')"

  while IFS=$'\t' read -r SHARD URL; do
    echo "Downloading $REGISTRY snapshot archive $SHARD"
    curl --fail --silent --show-error --location --output "$DATASET_DIR/$SHARD.tar.zst.part" "$URL"
    mv "$DATASET_DIR/$SHARD.tar.zst.part" "$DATASET_DIR/$SHARD.tar.zst"
  done <"$SHARDS_FILE"

  # Write the checkpoint last. GitLab ignores a directory that has no
  # checkpoint, so an interrupted download is never imported as a snapshot.
  jq --null-input --argjson until "$UNTIL" --argjson shards "$SHARD_COUNT" \
    '{until: $until, shards: $shards}' >"$DATASET_DIR/checkpoint.json"
}

for REGISTRY in $REGISTRIES; do
  HTTP_STATUS="$(pds_request "$PDS_URL/v1/$DATASET_PATH/all?purl_type=$REGISTRY" "$RESPONSE_FILE")"

  # A pending snapshot is the only skippable outcome. Every other 503 is
  # transient, and treating it as "no data" would delete a registry that the
  # instance already has.
  if [ "$HTTP_STATUS" = "503" ]; then
    # A 503 from in front of the service has no JSON body, so keep the reason
    # empty rather than letting jq abort the script.
    REASON="$(jq --raw-output '.reason // empty' "$RESPONSE_FILE" 2>/dev/null || true)"

    if [ "$REASON" = "snapshot_not_yet_published" ]; then
      echo "Skipping $REGISTRY, no snapshot is published yet"
      SKIPPED="$SKIPPED $REGISTRY"
      continue
    fi

    echo "Request for $REGISTRY failed with HTTP 503, try again later ($REASON)"
    exit 1
  fi

  if [ "$HTTP_STATUS" != "200" ]; then
    echo "Request for $REGISTRY failed with HTTP $HTTP_STATUS"
    head -c 500 "$RESPONSE_FILE"
    exit 1
  fi

  # Keep the /all body: the snapshot is the fallback for every branch below,
  # and the delta loop writes over $RESPONSE_FILE before one can be taken.
  cp "$RESPONSE_FILE" "$SNAPSHOT_FILE"

  UNTIL="$(jq --raw-output '.until // empty' "$SNAPSHOT_FILE")"

  if [ -z "$UNTIL" ]; then
    echo "The response for $REGISTRY has no snapshot timestamp"
    exit 1
  fi

  REGISTRY_DIR="$OUTPUT_DIR/v3/$REGISTRY"
  LOCAL_UNTIL="$(jq --raw-output '.until // empty' \
    "$REGISTRY_DIR/full_dataset/checkpoint.json" 2>/dev/null || true)"

  # Take the whole snapshot unless the output directory already holds one this
  # run can continue from. A delta cannot bootstrap a registry, and `since` has
  # to be a 10-digit unix-seconds value or the service answers 400, so a
  # checkpoint that is missing, unreadable or in another unit starts over.
  if ! [[ "$LOCAL_UNTIL" =~ ^[0-9]{10}$ ]]; then
    download_snapshot "$REGISTRY" "$UNTIL"
    continue
  fi

  # Resume from the newest archive on disk, snapshot or delta, which is where
  # GitLab's own checkpoint ends up once it has imported them. Asking from an
  # older timestamp would download deltas that are already here. Names that are
  # not a bare timestamp are ignored, matching what the connector reads.
  SINCE="$(find "$REGISTRY_DIR/deltas" -type f -name '*.tar.zst' 2>/dev/null |
    sed -e 's#.*/##' -e 's#\.tar\.zst$##' | grep -E '^[0-9]{10}$' |
    sort -n | tail -1 || true)"

  if [ -z "$SINCE" ] || [ "$LOCAL_UNTIL" -gt "$SINCE" ]; then
    SINCE="$LOCAL_UNTIL"
  fi

  # With deltas disabled, the published snapshot decides everything.
  if [ "$MAX_DELTAS" -le 0 ]; then
    if [ "$UNTIL" -gt "$LOCAL_UNTIL" ]; then
      echo "Replacing $REGISTRY, the published snapshot moved to $UNTIL"
      download_snapshot "$REGISTRY" "$UNTIL"
    else
      echo "Skipping $REGISTRY, snapshot $LOCAL_UNTIL is already downloaded"
    fi
    continue
  fi

  # Page forward. The service caps a response at 20 archives per registry and
  # sends the oldest of the backlog first, so re-asking from the newest archive
  # received walks the whole backlog without gaps.
  : >"$DELTAS_FILE"
  DELTA_TOTAL=0
  CAPPED=""

  while :; do
    HTTP_STATUS="$(pds_request "$PDS_URL/v1/$DATASET_PATH/delta?since=$REGISTRY:$SINCE" "$RESPONSE_FILE")"

    if [ "$HTTP_STATUS" != "200" ]; then
      echo "Delta request for $REGISTRY failed with HTTP $HTTP_STATUS"
      head -c 500 "$RESPONSE_FILE"
      exit 1
    fi

    # Registries are keyed by the identifier /supported gave us, and one that is
    # up to date comes back as an empty array rather than being left out.
    PAGE_COUNT="$(jq --arg r "$REGISTRY" '.purl_types[$r] // [] | length' "$RESPONSE_FILE")"

    if [ "$PAGE_COUNT" -eq 0 ]; then
      break
    fi

    jq --raw-output --arg r "$REGISTRY" \
      '.purl_types[$r] | sort_by(.delta | tonumber) | .[] | [.delta, (.signed_url // .url)] | @tsv' \
      "$RESPONSE_FILE" >>"$DELTAS_FILE"

    DELTA_TOTAL=$((DELTA_TOTAL + PAGE_COUNT))
    SINCE="$(cut -f1 "$DELTAS_FILE" | tail -1)"

    # Past the ceiling, one snapshot is fewer bytes than the rest of the backlog.
    if [ "$DELTA_TOTAL" -gt "$MAX_DELTAS" ]; then
      CAPPED=yes
      break
    fi
  done

  if [ -n "$CAPPED" ]; then
    echo "Replacing $REGISTRY, it is more than $MAX_DELTAS deltas behind"
    download_snapshot "$REGISTRY" "$UNTIL"
    continue
  fi

  if [ "$DELTA_TOTAL" -eq 0 ]; then
    echo "Skipping $REGISTRY, it is up to date at $SINCE"
    continue
  fi

  # Deltas sit beside the snapshot rather than replacing it: GitLab reads the
  # snapshot on a first sync and the deltas on every sync after it.
  mkdir -p "$REGISTRY_DIR/deltas"

  while IFS=$'\t' read -r DELTA URL; do
    echo "Downloading $REGISTRY delta $DELTA"
    curl --fail --silent --show-error --location \
      --output "$REGISTRY_DIR/deltas/$DELTA.tar.zst.part" "$URL"
    mv "$REGISTRY_DIR/deltas/$DELTA.tar.zst.part" "$REGISTRY_DIR/deltas/$DELTA.tar.zst"
  done <"$DELTAS_FILE"

  echo "Downloaded $DELTA_TOTAL delta(s) for $REGISTRY"
done

set +f

if [ -n "$SKIPPED" ]; then
  echo "Warning: no snapshot is published yet for:$SKIPPED"
  echo "The downloaded registries are complete and safe to copy. Run the script again later to pick up the rest."
fi

echo "$DATASET_LABEL saved to $OUTPUT_DIR"
```

다음과 같이 스크립트를 호출합니다:

```shell
./download_pmdb_data.sh <license_file> <gitlab_version> <dataset> <output_dir> <registry>
```

다음 표는 스크립트의 각 플래그가 나타내는 항목을 설명합니다:

| 인수         | 설명 |
|------------------|-------------|
| `license_file`   | 인스턴스의 라이선스 키를 보유하는 파일의 경로입니다. 이는 `sudo gitlab-rails runner 'puts License.current.data'`의 출력입니다. 활성화 코드는 라이선스 키가 아닙니다. |
| `gitlab_version` | 데이터를 가져오는 GitLab 인스턴스의 버전입니다. 이는 `sudo gitlab-rails runner 'puts Gitlab::VERSION'`의 출력입니다. 예를 들어, `19.4.0-ee`입니다. |
| `dataset`        | `licenses` 또는 `malware_advisories`. |
| `output_dir`     | 쓸 디렉터리입니다. 존재하지 않으면 생성됩니다. 모든 실행에서 동일한 디렉터리를 사용하면 변경되지 않은 스냅샷이 건너뜁니다. |
| `registry`   | 예를 들어 `npm` 또는 `pypi` 중 하나 이상의 패키지 레지스트리, 또는 지원되는 모든 레지스트리를 위해 `all`. [운영자 설정](../../administration/settings/security_and_compliance.md#choose-package-registry-metadata-to-sync)에서 활성화된 레지스트리 유형을 전달합니다. 여러 레지스트리는 공백으로 구분해야 합니다. 스크립트는 아무것도 다운로드하기 전에 지원되는 목록을 출력합니다. |

스크립트는 패키지 유형이 아닌 레지스트리 식별자로 명명된 패키지 레지스트리당 하나의 디렉터리를 만듭니다. 예:

```plaintext
licenses/
└── v3/
    └── npm/
        ├── full_dataset/
        │   ├── 00.tar.zst
        │   ├── 01.tar.zst
        │   ├── ...
        │   ├── 7f.tar.zst
        │   └── checkpoint.json
        └── deltas/
            ├── 1757520000.tar.zst
            └── 1757606400.tar.zst
```

각 스냅샷 아카이브는 16진수 분할 식별자 뒤에 명명됩니다. 레지스트리당 아카이브 수는 서비스에 의해 설정되며, 데이터가 없는 아카이브가 예상됩니다. 각 델타 아카이브는 해당 창을 종료하는 Unix 타임스탬프로 명명됩니다. GitLab이 이 폴더에서 읽는 내용은 [v3 라이선스 데이터 형식 버전](#v3-license-data-format-version)을 참고하세요.

레지스트리의 첫 실행은 전체 스냅샷을 다운로드하고, 이후 실행은 출력 디렉터리에 이미 있는 최신 아카이브 이후 서비스가 게시한 내용만 요청합니다.

> [!note]
> 모든 실행에서 동일한 출력 디렉터리를 재사용하거나, 스크립트가 재개할 것이 없으므로 전체 스냅샷을 다시 다운로드합니다.

스크립트는 스냅샷을 교체하고 레지스트리가 `MAX_DELTAS` 아카이브보다 더 많이 뒤쳐져 있을 때 `deltas/` 폴더 옆을 제거합니다. 스냅샷이 옆 델타보다 최신인 것이 예상됩니다. 서비스가 자체 일정에 따라 재구성하고 스크립트가 해당 스냅샷을 다시 다운로드하는 대신 델타를 계속 읽기 때문입니다. `MAX_DELTAS`은 100으로 기본 설정되며, 서비스는 요청당 최대 20개의 델타 아카이브를 제공합니다. 스냅샷을 모든 실행에서 교체하는 이전 동작을 복원하는 델타를 절대 다운로드하지 않으려면 `0`로 설정합니다.

스크립트는 또한 출력 디렉터리에 잠금을 만들므로, 첫 번째 통과가 여전히 데이터를 쓰는 동안 다시 실행하면 스크립트가 디렉터리를 손상시키지 않고 종료합니다. 출력 디렉터리가 이미 보유한 것보다 최신인 것이 없으면, 스크립트는 해당 레지스트리를 건너뛰므로 일정에 따라 실행하기에 안전합니다.

각 데이터 세트를 자신의 섹션의 단계로 적절한 위치에 복사합니다: [라이선스 데이터](#download-v3-license-data) 및 [악성 자문](#download-gitlab-v3-malware-advisories).

## GitLab v3 악성 자문 다운로드 {#download-gitlab-v3-malware-advisories}

{{< details >}}

- 티어: Ultimate

{{< /details >}}

{{< history >}}

- GitLab 19.3에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/20876)되었으며, `sync_malware_advisories` 및 `ingest_malware_advisories`로 명명된 [플래그](../../administration/feature_flags/_index.md)가 있습니다. 기본적으로 활성화되어 있습니다.
- [GitLab 19.5](https://gitlab.com/groups/gitlab-org/-/epics/20876)에서 일반적으로 사용할 수 있습니다. 기능 플래그 `sync_malware_advisories` 및 `ingest_malware_advisories`이 제거되었습니다.

{{< /history >}}

> [!note]
> Ultimate 외에도 이 기능은 종속성 방화벽 추가 기능이 있는 Premium 고객이 사용할 수 있습니다.

[GitLab 악성 자문](../../user/application_security/gitlab_advisory_database/_index.md#gitlab-advisories-for-malware)은 패키지 레지스트리에서 발견된 알려진 악성 패키지를 다룹니다. 패키지 메타데이터 데이터베이스 배포 서비스에 의해 배포되므로, 인터넷 액세스가 있는 머신에서 다운로드하고 오프라인 인스턴스로 복사합니다. 공유 스크립트 및 해당 필수 조건을 사용하여 다운로드합니다. 이는 [v3 패키지 메타데이터 데이터베이스 데이터 다운로드](#download-v3-package-metadata-database-data)에 설명되어 있습니다:

```shell
./download_pmdb_data.sh ./Gitlab.gitlab-license 19.3.0-ee malware_advisories ./malware_advisories npm pypi
```

자문을 오프라인 인스턴스로 복사하려면:

1. 출력 디렉터리를 오프라인 인스턴스로 전송합니다.
1. 오프라인 인스턴스에서 GitLab Rails 디렉터리의 루트를 찾은 다음, 자문을 제 위치에 복사하고 권한을 업데이트합니다.

   ```shell
   export GITLAB_RAILS_ROOT_DIR="$(sudo gitlab-rails runner 'puts Rails.root.to_s')"
   echo $GITLAB_RAILS_ROOT_DIR
   sudo mkdir -p "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/malware_advisories"
   sudo rsync --recursive --delete ./malware_advisories/ "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/malware_advisories/"
   sudo chmod -R 755 "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/"
   ```

`PackageMetadata::MalwareAdvisoriesSyncWorker` cron 작업은 5분마다 실행되고 다음 실행에서 자문을 가져옵니다. GitLab Self-Managed에서 작업은 인스턴스 전체에 부하를 분산하기 위해 최대 5분의 오프셋을 추가하므로, 파일을 복사한 후 최대 10분 후에 가져오기가 시작될 수 있습니다. [운영자 설정](../../administration/settings/security_and_compliance.md#choose-package-registry-metadata-to-sync)에서 활성화된 패키지 레지스트리 유형만 가져오므로, 인스턴스는 절대 가져오지 않을 레지스트리의 데이터를 보유할 수 있습니다.

이 절차를 반복하여 자문을 업데이트합니다. `rsync --delete`은 필요하므로 이전 스냅샷의 아카이브를 새로운 아카이브와 함께 가져오지 않습니다. 모든 실행에서 동일한 출력 디렉터리를 재사용합니다: `rsync --delete`는 스냅샷이 아직 게시되지 않았기 때문에 건너뛴 레지스트리를 포함하여 누락된 모든 레지스트리를 제거합니다.

## v3 라이선스 데이터 다운로드 {#download-v3-license-data}

{{< details >}}

- 티어: Ultimate

{{< /details >}}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/22880)되었으며, `sync_v3_license_expressions`로 명명된 플래그가 있습니다. 기본적으로 활성화되어 있습니다.

{{< /history >}}

> [!flag]
> 이 기능의 가용성은 기능 플래그로 제어됩니다. 자세한 내용은 기록을 참조하세요.
>
> 플래그를 끄면, 인스턴스는 v2 레이아웃으로 폴백되고 v3 체크포인트를 삭제합니다. 플래그를 다시 켜면, 인스턴스는 마지막 동기화된 스냅샷에서 재개하는 대신 처음부터 v3 데이터를 다시 가져옵니다.

v3 라이선스 데이터 레이아웃은 단일 라이선스 식별자 대신 Software Package Data Exchange (SPDX) 라이선스 표현식을 포함합니다. 예를 들어, `MIT OR Apache-2.0`입니다.

패키지 메타데이터 데이터베이스 배포 서비스는 v3 라이선스 데이터를 배포하므로, 인터넷 액세스가 있는 머신에서 다운로드하고 오프라인 인스턴스로 복사합니다. 라이선스 버킷이 보유한 모든 형식이 아닌 활성화된 레지스트리가 필요한 것만 다운로드합니다. `gsutil`이 필요하지 않습니다. 공유 스크립트 및 해당 필수 조건을 사용하여 다운로드합니다. 이는 [v3 패키지 메타데이터 데이터베이스 데이터 다운로드](#download-v3-package-metadata-database-data)에 설명되어 있습니다:

```shell
./download_pmdb_data.sh ./Gitlab.gitlab-license 19.4.0-ee licenses ./licenses npm pypi
```

`v3` 디렉터리가 `vendor/package_metadata/licenses` 아래에 존재하면, 인스턴스는 `v2` 디렉터리 대신 라이선스를 동기화합니다. 동기화 작업이 실행되기 전에 아래 복사 단계를 완료합니다.

라이선스 데이터를 오프라인 인스턴스로 복사하려면:

1. 출력 디렉터리를 오프라인 인스턴스로 전송합니다.
1. 오프라인 인스턴스에서 GitLab Rails 디렉터리의 루트를 찾은 다음, 라이선스 데이터를 제 위치에 복사하고 권한을 업데이트합니다.

   ```shell
   export GITLAB_RAILS_ROOT_DIR="$(sudo gitlab-rails runner 'puts Rails.root.to_s')"
   echo $GITLAB_RAILS_ROOT_DIR
   export LICENSES_DIR="$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses"
   sudo rm -rf "$LICENSES_DIR/v3.old" "$LICENSES_DIR/v3.incoming"
   sudo mkdir -p "$LICENSES_DIR/v3" "$LICENSES_DIR/v3.incoming"
   sudo rsync --recursive ./licenses/v3/ "$LICENSES_DIR/v3.incoming/"
   sudo mv "$LICENSES_DIR/v3" "$LICENSES_DIR/v3.old" && \
     sudo mv "$LICENSES_DIR/v3.incoming" "$LICENSES_DIR/v3" && \
     sudo rm -rf "$LICENSES_DIR/v3.old"
   sudo chmod -R 755 "$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/"
   ```

   명령은 `v3` 디렉터리에만 작성하므로, 기존 `v2` 디렉터리는 디스크에 남아있습니다.

   인스턴스는 해당 디렉터리가 존재하는 즉시 `v3` 디렉터리에서 라이선스를 읽습니다. 동기화 작업이 5분마다 실행되므로, `v3`에 직접 복사하면 동기화 작업이 여전히 작성 중인 디렉터리를 읽을 수 있으며 `v3`이 누락되거나 반쯤 작성될 수 있습니다. `v3.incoming`에 복사하고 대신 이름 바꾸기로 게시합니다.

`PackageMetadata::LicensesSyncWorker` cron 작업은 5분마다 실행되고 다음 실행에서 라이선스 데이터를 가져옵니다. 자문과 마찬가지로, 작업은 **운영자** 영역에서 활성화된 패키지 레지스트리 유형만 가져오므로, 인스턴스는 절대 가져오지 않을 레지스트리의 데이터를 보유할 수 있습니다.

라이선스 데이터를 업데이트하려면 이 절차를 반복합니다. 게시는 전체 `v3` 디렉터리를 교체하므로, 나중 실행에서 생략된 레지스트리는 업데이트 수신을 중단합니다. 해당 레지스트리에 대해 이미 가져온 라이선스 데이터는 데이터베이스에 남아있으며, 다시 실행에 포함할 때 업데이트가 재개됩니다.

## v3 라이선스 데이터 형식 버전 {#v3-license-data-format-version}

{{< history >}}

- GitLab 19.4에서 [도입](https://gitlab.com/groups/gitlab-org/-/epics/22880)되었습니다.

{{< /history >}}

`v2` 및 `v3`는 라이선스 내보내기의 형식 버전이며, 각각 자신의 폴더에 게시되고 다른 종류의 라이선스 데이터를 보유합니다:

| 형식 버전 | 폴더                                 | 라이선스 데이터                                      | 읽은 사람 |
|----------------|----------------------------------------|---------------------------------------------------|---------|
| v2             | `licenses/v2/<registry>/`              | `.ndjson` 파일의 단일 SPDX 식별자입니다.      | GitLab 19.3 이전 |
| v3             | `licenses/v3/<registry>/full_dataset/` | 압축된 아카이브의 SPDX 라이선스 표현식입니다. | GitLab 19.4 이상 |

형식 버전을 선택하지 않습니다. GitLab이 선택합니다. 인스턴스는 두 폴더를 모두 보유할 수 있지만, GitLab은 하나만 읽습니다.

GitLab 19.4 이상에서 `sync_v3_license_expressions` 플래그가 활성화되고 `vendor/package_metadata/licenses` 아래에 `v3/` 폴더가 존재할 때 GitLab이 v3를 읽습니다. 두 폴더가 모두 있으면 v3이 우선이고 `v2/`은 무시됩니다. 플래그를 끄면 대신 v2를 읽습니다. 이전 버전은 항상 v2를 읽습니다.

v3 폴더 구조 정보:

- GitLab은 `v3/<registry>` 아래에 데이터를 구성합니다. 여기서 `<registry>`는 `go`, `rubygem` 또는 `packagist`와 같은 이름입니다.
- 각 레지스트리 폴더는 `full_dataset/` 폴더를 보유하고 있으며, 선택적으로 `deltas/` 폴더도 보유합니다. `full_dataset/`은 완전한 스냅샷이며, 분할로 나뉩니다: 스냅샷 타임스탬프가 있는 `checkpoint.json` 및 분할 ID로 명명된 분할당 하나의 `.tar.zst` 아카이브. 예를 들어 `00.tar.zst`. `deltas/`은 증분 변경을 보유하며, 각 아카이브는 해당 창을 종료하는 Unix 타임스탬프로 명명됩니다.

  ```plaintext
  $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/rubygem/full_dataset/checkpoint.json
  $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/rubygem/full_dataset/00.tar.zst
  $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/rubygem/full_dataset/01.tar.zst
  $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/rubygem/full_dataset/...
  $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/rubygem/deltas/1757520000.tar.zst
  $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/rubygem/deltas/1757606400.tar.zst
  ```

- 레지스트리의 첫 번째 동기화는 `full_dataset/`을 읽고 `deltas/`은 무시합니다. 델타가 완전한 데이터 세트를 대신할 수 없기 때문입니다. 이후 동기화는 체크포인트보다 최신인 모든 것을 읽으며, 가장 오래된 것부터 읽습니다.

  > [!warning]
  > 델타 아카이브는 해당 창의 끝만 명명하므로, `deltas/` 폴더가 간격이 있으면 완전한 것과 같이 보이며 GitLab은 오류를 보고하지 않습니다. 다운로드 스크립트가 생성하는 전체 `deltas/` 폴더를 복사하거나 그것의 아카이브 선택을 복사합니다.

- 동기화 작업은 고정 기간 후 중지되므로, 큰 레지스트리는 여러 번 실행됩니다. 스냅샷은 분할별로 재개되며, 첫 번째에만이 아닌 모든 동기화에서 재개되므로 중단된 실행은 최대 하나의 분할을 다시 읽습니다. 델타 아카이브는 전체적으로 재개되므로 중단된 아카이브는 다음 실행에서 시작부터 다시 읽습니다. 스냅샷이 분할되는 방식의 큰 델타 분할은 [이슈 608196](https://gitlab.com/gitlab-org/gitlab/-/issues/608196)에서 추적됩니다.

## Helm 차트가 설치된 인스턴스 {#instances-installed-with-the-helm-chart}

이 절차는 Linux 패키지 설치의 Rails 디렉터리에 씁니다. 동기화 작업은 Sidekiq에서 실행됩니다. GitLab Helm 차트를 사용하는 설치에서 동일한 파일은 Sidekiq pod가 `/srv/gitlab/vendor/package_metadata`에서 읽는 볼륨에 있어야 합니다. 도구 상자 pod에만 마운트된 볼륨으로는 충분하지 않습니다. 동기화는 여전히 Sidekiq에서 실행되고, 여전히 디렉터리를 찾지 못하며, 모든 실행에서 네트워크 경로를 시도합니다.

`gitlab.sidekiq` 아래의 차트 값에서 볼륨을 선언합니다:

```yaml
gitlab:
  sidekiq:
    extraVolumes: |
      - name: package-metadata
        persistentVolumeClaim:
          claimName: gitlab-package-metadata
          readOnly: true
    extraVolumeMounts: |
      - name: package-metadata
        mountPath: /srv/gitlab/vendor/package_metadata
        readOnly: true
```

다른 설정은 필요하지 않습니다. GitLab은 디렉터리의 존재에서 오프라인 경로를 선택합니다. 변경은 다음 동기화 실행에서 효과가 발생하며, 재시작이나 Rake 작업은 필요하지 않습니다.

모든 Sidekiq pod가 클레임을 마운트하므로, `ReadOnlyMany`와 같이 허용하는 액세스 모드를 볼륨에 제공합니다. GitLab은 이 파일만 읽습니다.

값의 두 가지 실수를 조심합니다:

- `extraVolumes` 및 `extraVolumeMounts`를 [YAML 목록이 아닌 문자열](https://docs.gitlab.com/charts/charts/gitlab/sidekiq/)로 작성합니다. 목록은 템플릿의 이름을 지정하는 유형 오류로 렌더링할 때 실패합니다. 잘못된 레벨에 키를 배치하는 값 파일은 대신 조용히 실패합니다. Helm은 인식하지 못하는 키를 무시하고, Deployment는 마운트 없이 렌더링되며, 명령이 성공합니다. 성공적인 렌더링은 증거가 아닙니다. 마운트가 배포에 도달했는지 확인합니다:

  ```shell
  kubectl get deployment -l app=sidekiq -o yaml | grep -c 'vendor/package_metadata'
  ```

  차트는 이러한 문자열을 Helm 템플릿 엔진을 통해 전달하므로, 볼륨 이름이나 마운트 경로에서 `{{`을 이스케이프합니다.

- 마운트는 `kubectl set env` 또는 `kubectl patch`가 아닌 값에 속합니다. 다음 `helm upgrade`이 이를 덮어씁니다. 저장된 구성에서 조정하는 배포에서 다음 조정은 인스턴스를 네트워크 경로로 반환합니다. 오프라인 환경에서는 취약성 데이터가 없다는 것을 의미합니다.

가져오기를 따르려면 Webservice pod가 아닌 Sidekiq pod의 기록된 시퀀스 및 로그를 읽습니다. 이는 [문제 해결](#troubleshooting)에 설명되어 있습니다.

## 문제 해결 {#troubleshooting}

### 누락된 데이터베이스 데이터 {#missing-database-data}

라이선스 또는 자문 데이터가 종속성 목록, 취약성 보고서 또는 머지 리퀘스트 페이지에서 누락된 경우, 데이터베이스가 내보내기 데이터와 동기화되지 않았을 수 있습니다.

#### 활성화된 패키지 레지스트리 유형 확인 {#confirm-enabled-package-registry-types}

`package_metadata` 동기화는 cron 작업을 사용하여 트리거됩니다 ([자문 동기화](https://gitlab.com/gitlab-org/gitlab/-/blob/16-3-stable-ee/config/initializers/1_settings.rb#L864-866) 및 [라이선스 동기화](https://gitlab.com/gitlab-org/gitlab/-/blob/16-3-stable-ee/config/initializers/1_settings.rb#L855-857)). [운영자 설정](../../administration/settings/security_and_compliance.md#choose-package-registry-metadata-to-sync)에서 활성화된 패키지 레지스트리 유형만 가져옵니다.

예를 들어 `maven`이 선택되었지만 `golang`은 선택되지 않은 경우 Maven에 대한 자문 및 라이선스 정보만 표시됩니다.

#### 올바른 파일 구조 확인 {#confirm-correct-file-structure}

`vendor/package_metadata`의 파일 구조는 이전에 활성화된 패키지 레지스트리 유형과 일치해야 합니다. 예를 들어 `maven` 라이선스 또는 자문 데이터를 동기화하려면, Rails 디렉터리 아래의 패키지 메타데이터 디렉터리는 다음 구조를 가져야 합니다. 여기서 `$GITLAB_RAILS_ROOT_DIR`은 명령 `gitlab-rails runner 'puts Rails.root.to_s'`의 출력과 일치합니다:

- v2의 라이선스 (GitLab 19.3 이전):`$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v2/maven/**/*.ndjson`.
- v3의 라이선스 (GitLab 19.4 이상):`$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/licenses/v3/maven/full_dataset/*`. [v3 라이선스 데이터 형식 버전](#v3-license-data-format-version)을 참고하세요.
- v2의 자문:`$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/advisories/v2/maven/**/*.ndjson`.

CVE 보강은 패키지 레지스트리 유형으로 나뉘지 않습니다. GitLab 19.5 이상에서 GitLab은 그대로 만든 버킷의 복사본을 `$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/cve_enrichment/v2/cve_enrichment/*/*.ndjson`에서 읽습니다. 그 `cve_enrichment` 디렉터리가 존재하면 GitLab은 해당 디렉터리만 읽습니다. GitLab 19.4 이전 또는 그 디렉터리가 존재하지 않는 경우, CVE 보강 파일은 버전 디렉터리 아래 정확히 2개의 디렉터리 수준이어야 합니다:

- CVE 보강: `$GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/cve_enrichment/v2/*/*.ndjson`.

GitLab 19.4 이전에서 그대로 만든 CVE 보강 버킷의 복사본은 파일을 필요한 것보다 한 수준 깊게 배치하며, GitLab은 어떤 것도 읽지 않습니다. 이를 수정하려면 [다운로드 절차의 CVE 보강 단계](#download-v2-package-metadata-with-gsutil)를 참고하세요.

GitLab이 파일 경로를 인식하는지 [Rails 콘솔](../../administration/operations/rails_console.md)에서 확인할 수 있습니다:

- 라이선스: `sudo gitlab-rails runner "puts File.exist?(PackageMetadata::SyncConfiguration::Location::LICENSES_PATH)"`
- 자문: `sudo gitlab-rails runner "puts File.exist?(PackageMetadata::SyncConfiguration::Location::ADVISORIES_PATH)"`
- CVE 보강: `sudo gitlab-rails runner "puts File.exist?(PackageMetadata::SyncConfiguration::Location::CVE_ENRICHMENT_PATH)"`

위의 명령이 `false`을 반환하면, GitLab이 예상된 패키지 경로를 찾을 수 없습니다. 경로의 모든 폴더 및 파일은 `755` 권한을 가져야 합니다. 권한을 업데이트하려면:

`sudo chmod -R 755 $GITLAB_RAILS_ROOT_DIR/vendor/package_metadata/`

#### 데이터 확인 {#verify-data}

동기화 작업이 성공적으로 실행된 후 데이터베이스의 `pm_` 테이블 아래 데이터를 채워야 합니다.

[Rails 콘솔](../../administration/operations/rails_console.md)을 사용하여 벤더의 패키지 수를 확인하여 확인할 수 있습니다. 예를 들어 Maven 라이선스 및 자문 데이터가 로드되었는지 확인하려면 다음을 실행합니다:

- 라이선스: `sudo gitlab-rails runner "puts \"Package model has #{PackageMetadata::Package.where(purl_type: 'maven').size} packages\""`
- 자문: `sudo gitlab-rails runner "puts \"Advisory model has #{PackageMetadata::AffectedPackage.where(purl_type: 'maven').size} packages\""`

또한 체크포인트 데이터는 동기화되는 특정 패키지 레지스트리에 대해 존재해야 합니다. 예를 들어 Maven의 경우, 성공적인 동기화 실행 후 생성된 체크포인트가 있어야 합니다:

- 라이선스: `sudo gitlab-rails runner "puts \"maven data has been synced up to #{PackageMetadata::Checkpoint.where(data_type: 'licenses', purl_type: 'maven')}\""`
- 자문: `sudo gitlab-rails runner "puts \"maven data has been synced up to #{PackageMetadata::Checkpoint.where(data_type: 'advisories', purl_type: 'maven')}\""`

#### 로그 {#logs}

[`application_json.log`](../../administration/logs/_index.md#application_jsonlog) 파일은 동기화 작업이 실행되었고 오류가 없는지 확인하는 데 도움이 됩니다. 동기화와 관련된 이벤트는 `DEBUG` 심각도를 가지며, 클래스는 `PackageMetadata::SyncService`입니다. 예: `{"severity":"DEBUG","time":"2026-01-07T02:15:49.618Z","meta.caller_id":"PackageMetadata::AdvisoriesSyncWorker","correlation_id":"43008e30dd708eadbe1ab16ad7fa953f","meta.root_caller_id":"Cronjob","meta.feature_category":"software_composition_analysis","meta.client_id":"ip/","class":"PackageMetadata::SyncService","message":"Evaluating data for advisories:offline//opt/gitlab/embedded/service/gitlab-rails/vendor/package_metadata/advisories/v2/maven/1761761049/0.ndjson"}`

[`sidekiq`](../../administration/logs/_index.md#sidekiq-logs) 로그는 동기화 작업 중에 발생한 오류가 있는지 표시합니다. 동기화에 대해 로깅된 이벤트는 관련 클래스를 언급합니다:

- 라이선스: `PackageMetadata::LicensesSyncWorker`
- 자문: `PackageMetadata::AdvisoriesSyncWorker`

### 누락된 v3 라이선스 데이터 {#missing-v3-license-data}

라이선스 데이터를 인스턴스로 복사한 후 누락된 경우, 동기화 작업이 디렉터리를 찾지 못하거나 가져올 새로운 항목을 찾지 못했습니다. 두 결과 모두 조용하므로, 오류를 찾는 대신 다음 확인을 진행합니다.

시작하기 전에:

- [누락된 데이터베이스 데이터](#missing-database-data)에 대한 문제 해결 지침을 따르고, 특히 활성화된 패키지 레지스트리 유형 및 라이선스의 파일 구조를 확인합니다.
- v3 라이선스 파일 구조를 확인합니다. [악성 자문 파일 구조](#confirm-the-malware-advisory-file-structure)와 일치해야 합니다.

#### v3 라이선스 데이터 확인 {#verify-v3-license-data}

표현식은 라이선스 레코드에 저장됩니다. 동기화된 v3 스냅샷을 확인하려면, 표현식이 있는 최소 1개의 라이선스를 찾습니다. Rails 콘솔에서 확인할 수 있습니다:

- `sudo gitlab-rails runner "puts \"#{PackageMetadata::License.where.not(spdx_expression: nil).count} licenses have an expression\""`

패키지 및 체크포인트가 존재하지만 표현식이 있는 라이선스가 없으면, 인스턴스가 v3 대신 v2 레이아웃을 동기화했습니다. 디스크의 데이터가 `v3/` 아래에 있는지 확인합니다.

스냅샷은 기록된 체크포인트보다 최신인 경우에만 가져오므로, 동일한 스냅샷을 두 번째로 복사하면 아무 효과가 없습니다. 더 최신 라이선스 데이터를 얻으려면 다운로드 스크립트를 다시 실행합니다.

### 누락된 악성 자문 데이터 {#missing-malware-advisory-data}

악성 자문을 인스턴스로 복사한 후 누락된 경우, 동기화 작업이 디렉터리를 찾지 못하거나 가져올 새로운 항목을 찾지 못했습니다. 두 결과 모두 조용하므로, 오류를 찾는 대신 다음 확인을 진행합니다.

#### 악성 자문에 대한 활성화된 패키지 레지스트리 유형 확인 {#confirm-enabled-package-registry-types-for-malware-advisories}

[운영자 설정](../../administration/settings/security_and_compliance.md#choose-package-registry-metadata-to-sync)에서 활성화된 패키지 레지스트리 유형만 가져옵니다. 복사했지만 활성화하지 않은 레지스트리는 절대 읽지 않으며, 아무것도 로깅되지 않습니다.

#### GitLab이 오프라인 디렉터리를 감지하는지 확인 {#confirm-gitlab-detects-the-offline-directory}

GitLab은 벤더 디렉터리가 존재할 때 디스크에서 악성 자문을 읽으며, 존재하지 않을 때 배포 서비스에서 읽습니다. GitLab이 파일 경로를 인식하는지 [Rails 콘솔](../../administration/operations/rails_console.md)에서 확인할 수 있습니다:

- `sudo gitlab-rails runner "puts File.exist?(PackageMetadata::SyncConfiguration::Location::MALWARE_ADVISORIES_PATH)"`

명령이 `false`을 반환하면 GitLab이 예상된 경로를 찾을 수 없습니다. 경로의 모든 폴더 및 파일은 `755` 권한을 가져야 합니다. Kubernetes 설치에서는 Sidekiq과 동일한 볼륨을 마운트하는 pod에서 명령을 실행합니다. 그렇지 않으면 결과가 동기화 작업이 읽는 내용을 반영하지 않습니다.

#### 악성 자문 파일 구조 확인 {#confirm-the-malware-advisory-file-structure}

디렉터리는 패키지 유형이 아닌 패키지 레지스트리 식별자로 명명됩니다. 이러한 식별자는 항상 같지 않습니다: `gem` 자문은 `rubygem` 아래에 저장되고, `golang`은 `go` 아래에, `composer`은 `packagist` 아래에 저장됩니다. 패키지 유형으로 명명된 디렉터리는 무시되며, 오류가 로깅되지 않습니다.

각 `full_dataset` 디렉터리는 또한 `checkpoint.json`을 포함해야 합니다. GitLab은 체크포인트가 없는 디렉터리를 무시하므로, 중단된 다운로드가 가져오지는 것을 방지합니다.

#### 악성 자문 데이터 확인 {#verify-malware-advisory-data}

동기화 작업이 성공적으로 실행된 후 악성 자문을 채워야 합니다. [Rails 콘솔](../../administration/operations/rails_console.md)에서 자문을 계산하여 확인할 수 있습니다:

- `sudo gitlab-rails runner "puts \"Malware advisory model has #{PackageMetadata::MalwareAdvisory.count} advisories\""`

체크포인트 데이터도 복사한 패키지 레지스트리에 대해 존재해야 합니다:

- `sudo gitlab-rails runner "puts PackageMetadata::Checkpoint.where(data_type: 'malware_advisories').pluck(:purl_type, :sequence).to_h"`

스냅샷은 기록된 체크포인트보다 최신인 경우에만 가져오므로, 동일한 스냅샷을 두 번째로 복사하면 아무 효과가 없습니다.

#### 악성 자문 로그 {#malware-advisory-logs}

악성 자문 동기화와 관련된 이벤트는 [`application_json.log`](../../administration/logs/_index.md#application_jsonlog)에 `INFO` 심각도로 로깅됩니다. 클래스는 동기화 자체의 경우 `PackageMetadata::MalwareAdvisorySyncService`, 가져오기의 경우 `PackageMetadata::MalwareAdvisoryIngestionService`입니다. 동기화는 Sidekiq에서 실행되므로, Kubernetes 설치에서 이러한 이벤트는 `subcomponent="application_json"` 키 아래 Webservice pod가 아닌 Sidekiq pod에 있습니다.

[`sidekiq`](../../administration/logs/_index.md#sidekiq-logs) 로그는 `PackageMetadata::MalwareAdvisoriesSyncWorker` 클래스에 대해 로깅된 발생한 오류를 표시합니다.

각 레지스트리는 실행당 `started` 및 `completed` 이벤트를 로깅합니다. `completed` 이벤트가 `files_ingested: 0`인 경우 실행이 가져올 항목을 찾지 못했습니다. 해당 이벤트의 `storage_type` 필드는 다음을 알려줍니다: `offline`은 GitLab이 벤더 디렉터리를 읽었음을 의미하고, `pds`은 디렉터리를 찾지 못하고 배포 서비스를 시도했음을 의미합니다. Kubernetes에서 이 필드는 동기화를 실행하는 프로세스에서 나오므로 위의 `File.exist?` 확인보다 더 신뢰할 수 있습니다.

`PackageMetadata::MalwareAdvisorySyncService` 이벤트가 전혀 나타나지 않으면 `DEBUG` 심각도가 있는 `PackageMetadata::MalwareAdvisoriesSyncWorker` 이벤트를 찾습니다. 실행이 시작되지 않은 이유를 명명합니다. 예를 들어 `dependency_scanning` 라이선스도 종속성 방화벽도 사용할 수 없습니다.

큰 레지스트리의 첫 번째 가져오기는 몇 분 동안 실행될 수 있으며, cron은 이 동안 5분마다 다시 실행됩니다. 각 겹치는 실행은 `Cannot obtain an exclusive lease. There must be another instance already in execution.`을 `application_json.log`에 `ERROR` 심각도로 로깅하고 종료합니다. 임대는 두 개의 동기화가 한 번에 실행되지 않도록 하므로, 이러한 이벤트는 긴 가져오기 중에 예상되며 동기화 실패를 의미하지 않습니다.
