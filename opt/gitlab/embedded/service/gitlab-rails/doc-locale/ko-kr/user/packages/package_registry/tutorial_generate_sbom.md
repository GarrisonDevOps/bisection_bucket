---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: '튜토리얼: GitLab 패키지 레지스트리로 소프트웨어 자재 명세서 생성'
---

이 튜토리얼은 CI/CD 파이프라인으로 CycloneDX 형식의 소프트웨어 자재 명세서(SBOM)를 생성하는 방법을 보여줍니다. 구축할 파이프라인은 그룹의 여러 프로젝트에서 패키지를 수집하여 관련 프로젝트의 종속성에 대한 포괄적인 보기를 제공합니다.

이 튜토리얼을 완료하기 위해 가상 Python 환경을 만들지만 지원되는 다른 패키지 유형에도 동일한 접근 방식을 적용할 수 있습니다.

## 소프트웨어 자재 명세서란? {#what-is-a-software-bill-of-materials}

SBOM은 소프트웨어 제품을 구성하는 모든 소프트웨어 구성 요소의 머신 가독 인벤토리입니다. SBOM에 포함될 수 있는 항목은 다음과 같습니다:

- 직접 및 간접 종속성
- 오픈 소스 구성 요소 및 라이선스
- 패키지 버전 및 출처

소프트웨어 제품 사용에 관심이 있는 조직은 채택하기 전에 제품의 보안 수준을 파악하기 위해 SBOM을 요청할 수 있습니다.

GitLab 패키지 레지스트리에 익숙하다면 SBOM과 [종속성 목록](../../application_security/dependency_list/_index.md) 간의 차이점이 무엇인지 궁금할 수 있습니다. 다음 표는 주요 차이점을 강조합니다:

| 차이점   | 종속성 목록                                               | SBOM |
|---------------|---------------------------------------------------------------|------|
| 범위     | 개별 프로젝트 또는 그룹의 종속성을 표시합니다.         | 그룹 전체에 게시된 모든 패키지의 인벤토리를 만듭니다. |
| 방향 | 프로젝트가 의존하는 항목을 추적합니다(수신 종속성).  | 그룹이 게시하는 항목을 추적합니다(발신 패키지). |
| 범위  | `package.json` 또는 `pom.xml`와 같은 패키지 매니페스트를 기반으로 합니다. | 패키지 레지스트리에 실제로 게시된 아티팩트를 포함합니다. |

## CycloneDX란? {#what-is-cyclonedx}

CycloneDX는 SBOM을 만들기 위한 경량의 표준화된 형식입니다. CycloneDX는 조직을 지원하는 잘 정의된 스키마를 제공합니다:

- 소프트웨어 구성 요소 및 해당 관계를 문서화합니다.
- 소프트웨어 공급망 전체에서 취약점을 추적합니다.
- 오픈 소스 종속성에 대한 라이선스 준수를 확인합니다.
- 일관되고 머신 가독 가능한 SBOM 형식을 확립합니다.

CycloneDX는 JSON, XML 및 프로토콜 버퍼를 포함한 여러 출력 형식을 지원하므로 다양한 통합 요구 사항에 맞게 조정할 수 있습니다. 사양은 포괄적이면서도 효율적이도록 설계되어 기본 구성 요소 식별부터 소프트웨어 출처에 대한 상세한 메타데이터까지 모든 것을 다룹니다.

## 시작하기 전에 {#before-you-begin}

이 튜토리얼을 완료하려면 다음이 필요합니다:

- 유지 관리자 또는 소유자 역할이 있는 그룹입니다.
- GitLab CI/CD에 대한 액세스입니다.
- GitLab Self-Managed 인스턴스를 사용하는 경우 구성된 [러너](../../../ci/runners/_index.md#runner-categories)입니다. GitLab.com을 사용하는 경우 이 요구 사항을 건너뛸 수 있습니다.
- 선택 사항. 패키지 레지스트리에 대한 요청을 인증하기 위한 [그룹 배포 토큰](../../project/deploy_tokens/_index.md)입니다.

## 단계 {#steps}

이 튜토리얼은 완료할 두 가지 단계 세트를 포함합니다:

- CycloneDX 형식의 SBOM을 생성하는 CI/CD 파이프라인 구성
- 생성된 SBOM 및 패키지 통계 파일 액세스 및 작업

다음은 수행할 작업의 개요입니다:

1. [기본 파이프라인 구성 추가](#add-the-base-pipeline-configuration)입니다.
1. [`prepare` 스테이지 구성](#configure-the-prepare-stage)합니다.
1. [`collect` 스테이지 구성](#configure-the-collect-stage)합니다.
1. [`aggregate` 스테이지 구성](#configure-the-aggregate-stage)합니다.
1. [`publish` 스테이지 구성](#configure-the-publish-stage)합니다.
1. [생성된 SBOM 및 통계 파일 액세스](#access-the-generated-files)합니다.

> [!note]
> 이 솔루션을 구현하기 전에 다음을 알아두세요:
>
> - 패키지 종속성은 확인되지 않습니다(직접 패키지만 나열됨).
> - 패키지 버전은 포함되지만 취약점에 대해 분석되지 않습니다.

### 기본 파이프라인 구성 추가 {#add-the-base-pipeline-configuration}

먼저 파이프라인 전체에서 사용되는 변수 및 스테이지를 정의하는 기본 이미지를 설정합니다.

다음 섹션에서는 각 스테이지의 구성을 추가하여 파이프라인을 구축합니다.

프로젝트에서:

1. `.gitlab-ci.yml` 파일을 생성합니다.
1. 파일에 다음 기본 구성을 추가합니다:

   ```yaml
   # Base image for all jobs
   image: alpine:latest

   variables:
     SBOM_OUTPUT_DIR: "sbom-output"
     SBOM_FORMAT: "cyclonedx"
     OUTPUT_TYPE: "json"
     GROUP_PATH: ${CI_PROJECT_NAMESPACE}

   before_script:
     - apk add --no-cache curl jq ca-certificates

   stages:
     - prepare
     - collect
     - aggregate
     - publish
   ```

이 구성은,

- 작은 크기와 빠른 작업 시작을 위해 Alpine Linux를 사용합니다
- 인증을 위해 그룹 배포 토큰을 지원합니다
- API 요청을 위해 `curl`, JSON 처리를 위해 `jq`, 안전한 HTTPS 연결을 보장하기 위해 `ca-certificates`를 설치합니다
- 모든 출력을 `sbom-output` 디렉터리에 저장합니다
- CycloneDX JSON 형식의 SBOM을 생성합니다

### `prepare` 스테이지 구성 {#configure-the-prepare-stage}

`prepare` 스테이지는 Python 환경을 설정하고 필요한 종속성을 설치합니다.

`.gitlab-ci.yml` 파일에 다음 구성을 추가합니다:

```yaml
# Set up Python virtual environment and install required packages
prepare_environment:
  stage: prepare
  script: |
    mkdir -p ${SBOM_OUTPUT_DIR}
    apk add --no-cache python3 py3-pip py3-virtualenv
    python3 -m venv venv
    . venv/bin/activate
    pip3 install cyclonedx-bom
  artifacts:
    paths:
      - ${SBOM_OUTPUT_DIR}/
      - venv/
    expire_in: 1 week
```

이 스테이지:

- 격리를 위한 Python 가상 환경을 만듭니다
- SBOM 생성을 위해 CycloneDX 라이브러리를 설치합니다
- 아티팩트에 대한 출력 디렉터리를 만듭니다
- 나중의 스테이지를 위해 가상 환경을 유지합니다
- 저장소를 관리하기 위해 1주일 만료를 설정합니다

### `collect` 스테이지 구성 {#configure-the-collect-stage}

`collect` 스테이지는 그룹의 패키지 레지스트리에서 패키지 정보를 수집합니다.

`.gitlab-ci.yml` 파일에 다음 구성을 추가합니다:

```yaml
# Collect package information and versions from GitLab registry
collect_group_packages:
  stage: collect
  script: |
    mkdir -p "${SBOM_OUTPUT_DIR}"
    echo "[]" > "${SBOM_OUTPUT_DIR}/packages.json"

    # Resolve the auth header at runtime: use the group deploy token if set,
    # otherwise fall back to the CI job token.
    if [ -n "${GROUP_DEPLOY_TOKEN:-}" ]; then
      AUTH="Deploy-Token: ${GROUP_DEPLOY_TOKEN}"
    else
      AUTH="JOB-TOKEN: ${CI_JOB_TOKEN}"
    fi

    GROUP_PATH_ENCODED=$(echo "${GROUP_PATH}" | sed 's|/|%2F|g')
    PACKAGES_URL="${CI_API_V4_URL}/groups/${GROUP_PATH_ENCODED}/packages"

    # Optional exclusion list - you can add package types you want to exclude
    # EXCLUDE_TYPES="terraform npm"

    page=1
    while true; do
      # Fetch all packages without specifying type, with pagination
      http_status=$(curl --silent \
                      --output /tmp/api_response.json \
                      --write-out "%{http_code}" \
                      --header "$AUTH" \
                      "${PACKAGES_URL}?per_page=100&page=${page}")
      response=$(cat /tmp/api_response.json)

      if [ "$http_status" -lt 200 ] || [ "$http_status" -ge 300 ]; then
        echo "ERROR: HTTP ${http_status}"; echo "$response" | jq . 2>/dev/null || echo "$response"; exit 1
      fi

      response_type=$(echo "$response" | jq -r 'type' 2>/dev/null || echo "invalid")
      if [ "$response_type" != "array" ]; then
        echo "ERROR: Expected array, got ${response_type}"; echo "$response" | jq . 2>/dev/null || echo "$response"; exit 1
      fi

      count=$(echo "$response" | jq '. | length')
      [ "$count" -eq 0 ] && break

      # Filter packages if EXCLUDE_TYPES is set, using exact type matching
      if [ -n "${EXCLUDE_TYPES:-}" ]; then
        response=$(echo "$response" | jq --argjson types \
          "$(echo "${EXCLUDE_TYPES}" | tr ' ' '\n' | jq -R . | jq -s .)" \
          '[.[] | select(.package_type as $t | $types | any(. == $t) | not)]')
        count=$(echo "$response" | jq '. | length')
      fi

      # Merge this page of results with existing data
      jq -s '.[0] + .[1]' "${SBOM_OUTPUT_DIR}/packages.json" <(echo "$response") > "${SBOM_OUTPUT_DIR}/packages.tmp.json"
      mv "${SBOM_OUTPUT_DIR}/packages.tmp.json" "${SBOM_OUTPUT_DIR}/packages.json"

      # Move to next page if we got a full page of results
      [ "$count" -lt 100 ] && break
      page=$((page + 1))
    done
  artifacts:
    paths:
      - ${SBOM_OUTPUT_DIR}/
    expire_in: 1 week
  dependencies:
    - prepare_environment
```

이 스테이지:

- 사용 가능한 경우 그룹 배포 토큰을 사용하거나 그렇지 않으면 CI/CD 작업 토큰을 사용하여 런타임에 인증 헤더를 확인합니다
- 한 번에 모든 패키지 유형을 가져오기 위해 단일 API 호출을 수행합니다(유형당 별도 호출 대신)
- 패키지 유형을 정확히 일치시켜 필터링하는 선택적 제외 목록을 지원합니다
- 많은 패키지가 있는 그룹을 처리하기 위해 페이지 매김을 구현합니다(페이지당 100개)
- 하위 그룹을 올바르게 처리하기 위해 그룹 경로를 URL 인코딩합니다
- HTTP 상태 코드 및 응답 유형을 확인하고 오류 시 작업을 중지합니다

### `aggregate` 스테이지 구성 {#configure-the-aggregate-stage}

`aggregate` 스테이지는 수집된 데이터를 처리하고 SBOM을 생성합니다.

`.gitlab-ci.yml` 파일에 다음 구성을 추가합니다:

```yaml
# Generate SBOM by aggregating package data
aggregate_sboms:
  stage: aggregate
  before_script:
    - apk add --no-cache python3 py3-virtualenv
    - . venv/bin/activate
  script: |
    cat > process_sbom.py << 'EOL'
    import json
    import os
    from datetime import datetime
    from urllib.parse import quote

    # Map GitLab package types to valid PURL types. Defaults to "generic".
    PURL_TYPE_MAP = {
        "pypi": "pypi", "npm": "npm", "maven": "maven", "nuget": "nuget",
        "composer": "composer", "conan": "conan", "conda": "conda",
        "golang": "golang", "helm": "helm", "rubygems": "gem",
        "generic": "generic", "debian": "deb", "rpm": "rpm", "terraform": "terraform",
    }

    def make_purl(package_type, name, version):
        """Build a spec-compliant PURL with percent-encoded name and version."""
        purl_type = PURL_TYPE_MAP.get(package_type, "generic")
        # Maven names use a "/" namespace separator that the PURL spec requires,
        # so keep it unencoded for that type.
        safe_name = quote(name, safe='/') if purl_type == "maven" else quote(name, safe='')
        safe_version = quote(version, safe='')
        return f"pkg:{purl_type}/{safe_name}@{safe_version}"

    def analyze_version_history(packages_file):
        """Process version information by aggregating packages with same name and type"""
        version_history = {}
        package_versions = {}  # Dict to group packages by name and type

        try:
            with open(packages_file, 'r') as f:
                packages = json.load(f)
                if not isinstance(packages, list):
                    return version_history

                # First, group packages by name and type
                for package in packages:
                    key = f"{package.get('name')}:{package.get('package_type')}"
                    if key not in package_versions:
                        package_versions[key] = []

                    package_versions[key].append({
                        'id': package.get('id'),
                        'version': package.get('version', 'unknown'),
                        'created_at': package.get('created_at')
                    })

                # Then process each group to create version history
                for package_key, versions in package_versions.items():
                    # Sort versions by creation date, newest first
                    versions.sort(key=lambda x: x.get('created_at', ''), reverse=True)

                    # Use the first package's ID as the key (newest version)
                    if versions:
                        package_id = str(versions[0]['id'])
                        version_history[package_id] = {
                            'versions': [v['version'] for v in versions],
                            'latest_version': versions[0]['version'] if versions else None,
                            'version_count': len(versions),
                            'first_published': min((v.get('created_at') for v in versions if v.get('created_at')), default=None),
                            'last_updated': max((v.get('created_at') for v in versions if v.get('created_at')), default=None)
                        }
        except Exception as e:
            print(f"Error processing version history: {e}")
        return version_history

    def merge_package_data(package_file):
        """Combine package data and generate component list"""
        merged_components = {}
        package_stats = {
            'total_packages': 0,
            'package_types': {}
        }

        try:
            with open(package_file, 'r') as f:
                packages = json.load(f)
                if not isinstance(packages, list):
                    return [], package_stats

                for package in packages:
                    package_stats['total_packages'] += 1
                    pkg_type = package.get('package_type', 'unknown')
                    package_stats['package_types'][pkg_type] = package_stats['package_types'].get(pkg_type, 0) + 1

                    version = package.get('version', 'unknown')
                    component = {
                        'type': 'library',
                        'name': package['name'],
                        'version': version,
                        'purl': make_purl(pkg_type, package['name'], version),
                        'package_type': pkg_type,
                        'properties': [{
                            'name': 'registry_url',
                            'value': package.get('_links', {}).get('web_path', '')
                        }]
                    }

                    key = f"{component['name']}:{component['version']}"
                    if key not in merged_components:
                        merged_components[key] = component
        except Exception as e:
            print(f"Error merging package data: {e}")
            return [], package_stats

        return list(merged_components.values()), package_stats

    # Main processing
    version_history = analyze_version_history(f"{os.environ['SBOM_OUTPUT_DIR']}/packages.json")
    components, stats = merge_package_data(f"{os.environ['SBOM_OUTPUT_DIR']}/packages.json")
    stats['version_history'] = version_history

    # Create final SBOM document
    sbom = {
        "bomFormat": os.environ['SBOM_FORMAT'],
        "specVersion": "1.4",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat(),
            "tools": [{
                "vendor": "GitLab",
                "name": "Package Registry SBOM Generator",
                "version": "1.0.0"
            }],
            "properties": [{
                "name": "package_stats",
                "value": json.dumps(stats)
            }]
        },
        "components": components
    }

    # Write results to files
    with open(f"{os.environ['SBOM_OUTPUT_DIR']}/merged_sbom.{os.environ['OUTPUT_TYPE']}", 'w') as f:
        json.dump(sbom, f, indent=2)

    with open(f"{os.environ['SBOM_OUTPUT_DIR']}/package_stats.json", 'w') as f:
        json.dump(stats, f, indent=2)
    EOL

    python3 process_sbom.py
  artifacts:
    paths:
      - ${SBOM_OUTPUT_DIR}/
    expire_in: 1 week
  dependencies:
    - prepare_environment
    - collect_group_packages
```

이 스테이지:

- `packages.json` 파일과 직접 작동하는 최적화된 버전 기록 분석을 사용합니다
- 패키지를 이름 및 유형별로 그룹화하여 동일한 패키지의 다른 버전을 식별합니다
- JSON 형식의 CycloneDX 준수 SBOM을 만듭니다
- 다음을 포함하는 패키지 통계를 계산합니다:
  - 유형별 패키지의 총 수
  - 각 패키지의 버전 기록
  - 첫 게시 및 마지막 업데이트 날짜
- 새로 만드는 대신 `prepare` 스테이지의 가상 환경 아티팩트를 재사용합니다
- 각 구성 요소에 대해 사양 준수 패키지 URL(`purl`)을 생성하며, 패키지 유형이 유효한 PURL 유형으로 매핑되고 이름과 버전이 백분율 인코딩됩니다
- 적절한 예외 처리로 누락되거나 유효하지 않은 데이터를 정상적으로 처리합니다
- SBOM과 별도의 통계 파일을 모두 만듭니다

### `publish` 스테이지 구성 {#configure-the-publish-stage}

`publish` 스테이지는 생성된 SBOM 및 통계 파일을 GitLab에 업로드합니다.

`.gitlab-ci.yml` 파일에 다음 구성을 추가합니다:

```yaml
# Publish SBOM files to GitLab package registry
publish_sbom:
  stage: publish
  script: |
    # Resolve the auth header at runtime, as in the collect stage.
    if [ -n "${GROUP_DEPLOY_TOKEN:-}" ]; then
      AUTH="Deploy-Token: ${GROUP_DEPLOY_TOKEN}"
    else
      AUTH="JOB-TOKEN: ${CI_JOB_TOKEN}"
    fi

    # Upload generated files
    curl --header "$AUTH" \
         --upload-file "${SBOM_OUTPUT_DIR}/merged_sbom.${OUTPUT_TYPE}" \
         "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/sbom/${CI_COMMIT_SHA}/merged_sbom.${OUTPUT_TYPE}"

    curl --header "$AUTH" \
         --upload-file "${SBOM_OUTPUT_DIR}/package_stats.json" \
         "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/generic/sbom/${CI_COMMIT_SHA}/package_stats.json"
  dependencies:
    - aggregate_sboms
```

이 스테이지:

- SBOM 및 통계 파일을 프로젝트의 패키지 레지스트리에 게시합니다
- 저장소에 일반 패키지 유형을 사용합니다
- 추적을 위해 커밋 SHA를 패키지 버전으로 사용합니다

SBOM 파일은 이미 `metadata.timestamp`에 생성 타임스탬프를 기록하고 파이프라인은 `package_stats.json`에 패키지 통계를 저장합니다.

## 생성된 파일 액세스 {#access-the-generated-files}

파이프라인이 완료되면 이러한 파일을 생성합니다:

- `merged_sbom.json`: CycloneDX 형식의 완전한 SBOM
- `package_stats.json`: 패키지에 대한 통계

생성된 파일에 액세스하려면:

1. 프로젝트에서 **배포** > **패키지 레지스트리**를 선택합니다.
1. `sbom`이라는 패키지를 찾습니다.
1. SBOM 및 통계 파일을 다운로드합니다.

### SBOM 파일 사용 {#using-the-sbom-file}

SBOM 파일은 [CycloneDX 1.4 JSON 사양](https://cyclonedx.org/docs/1.4/json/)을 따르며 그룹의 패키지 레지스트리에 게시된 패키지, 패키지 버전 및 아티팩트에 대한 세부 정보를 제공합니다.

SBOM 파일을 규정 준수 및 감시 목적으로도 사용할 수 있습니다. 예를 들면 다음과 같습니다:

- 게시된 패키지의 보고서 생성
- 그룹의 패키지 레지스트리 콘텐츠 문서화
- 시간 경과에 따른 게시 활동 추적

CycloneDX 파일로 작업할 때 다음 도구를 사용하는 것을 고려하세요:

- [OWASP Dependency-Track](https://dependencytrack.org/)
- [CycloneDX CLI](https://github.com/CycloneDX/cyclonedx-cli)
- [OWASP CycloneDX Sunshine](https://cyclonedx.github.io/Sunshine/)
- [SBOM 분석 도구](https://cyclonedx.org/tool-center/)

### 통계 파일 사용 {#using-the-statistics-file}

통계 파일은 패키지 레지스트리 분석 및 활동 추적을 제공합니다.

예를 들어 패키지 레지스트리를 분석하려면 다음을 수행할 수 있습니다:

- 유형별로 게시된 패키지의 총 수를 봅니다.
- 각 패키지의 버전 수를 확인합니다.
- 첫 게시 및 마지막 업데이트 날짜를 추적합니다.

패키지 레지스트리 활동을 추적하려면 다음을 수행할 수 있습니다:

- 패키지 게시 패턴을 모니터링합니다.
- 가장 자주 업데이트되는 패키지를 식별합니다.
- 시간 경과에 따른 패키지 레지스트리 성장을 추적합니다.

통계 파일과 함께 `jq`과 같은 CLI 도구를 사용하여 읽을 수 있는 JSON 형식의 분석 또는 활동 정보를 생성할 수 있습니다.

다음 코드 블록은 일반 분석 또는 보고 목적으로 통계 파일에 대해 실행할 수 있는 여러 `jq` 명령 예제를 나열합니다:

```shell
# Get total package count in registry
jq '.total_packages' package_stats.json

# List package types and their counts
jq '.package_types' package_stats.json

# Find packages with most versions published
jq '.version_history | to_entries | sort_by(.value.version_count) | reverse | .[0:5]' package_stats.json
```

## 파이프라인 일정 {#pipeline-scheduling}

패키지 레지스트리를 자주 업데이트하는 경우 이에 따라 SBOM도 업데이트해야 합니다. 게시 활동에 따라 업데이트된 SBOM을 생성하도록 파이프라인 일정을 구성할 수 있습니다.

다음 권장 사항을 고려하세요:

- 일일 업데이트: 패키지를 자주 게시하거나 최신 보고서가 필요한 경우 권장됩니다
- 주간 업데이트: 중간 정도의 패키지 게시 활동이 있는 대부분의 팀에 적합합니다
- 월간 업데이트: 패키지를 거의 업데이트하지 않는 그룹에 충분합니다

파이프라인을 일정하려면:

1. 프로젝트에서 **빌드** > **파이프라인 일정**으로 이동합니다.
1. **새 파이프라인 일정 생성**을 선택하고 양식을 작성합니다:
   - **Cron 시간대** 드롭다운 목록에서 시간대를 선택합니다.
   - **간격 패턴**을 선택하거나 [cron 구문](../../../ci/pipelines/schedules.md)을 사용하여 **커스텀** 패턴을 추가합니다.
   - 파이프라인의 브랜치 또는 태그를 선택합니다.
   - **변수**에서 일정에 임의 개수의 CI/CD 변수를 입력합니다.
1. **파이프라인 일정 만들기**를 선택합니다.

## 문제 해결 {#troubleshooting}

이 튜토리얼을 완료하면서 다음 문제가 발생할 수 있습니다.

### 인증 오류 {#authentication-errors}

인증 오류가 발생하면:

- 그룹 배포 토큰 권한을 확인합니다.
- 토큰에 `read_package_registry` 및 `write_package_registry` 범위가 모두 있는지 확인합니다.
- 토큰이 만료되지 않았는지 확인합니다.

### 누락된 패키지 유형 {#missing-package-types}

패키지 유형이 누락된 경우:

- [배포 토큰이 모든 패키지 유형에 액세스](../../project/deploy_tokens/_index.md#pull-packages-from-a-package-registry)할 수 있는지 확인합니다.
- 패키지 유형이 그룹 설정에서 활성화되어 있는지 확인합니다.

### `aggregate` 스테이지의 메모리 문제 {#memory-issues-in-the-aggregate-stage}

메모리 문제가 발생하는 경우:

- 더 많은 메모리가 있는 러너를 사용합니다.
- 패키지 유형을 필터링하여 한 번에 더 적은 패키지를 처리합니다.

### 리소스 권장 사항 {#resource-recommendations}

최적의 성능을 위해:

- 최소 2GB의 RAM이 있는 러너를 사용합니다.
- 1,000개의 패키지당 5~10분을 허용합니다.
- 많은 패키지가 있는 그룹의 경우 작업 시간 초과를 늘립니다.

### 도움말 받기 {#getting-help}

다른 문제가 발생하면:

- 특정 오류 메시지에 대한 작업 로그를 확인합니다.
- `curl` 명령을 사용하여 API 액세스를 직접 확인합니다.
- 먼저 더 작은 패키지 유형 하위 집합으로 테스트합니다.
