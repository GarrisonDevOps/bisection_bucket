---
stage: Application Security Testing
group: Composition Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 프로젝트 종속성에 대해 CycloneDX 형식으로 소프트웨어 자재 명세서(SBOM)를 생성 및 내보내고 CI/CD 아티팩트로 저장하는 방법을 알아봅니다.
title: '자습서: SBOM 형식으로 종속성 목록 내보내기'
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

종속성 검사 출력을 CycloneDX JSON 형식으로 내보낼 수 있습니다.

이 자습서에서는 파이프라인에 대해 CycloneDX JSON SBOM을 생성한 후 CI 작업 아티팩트로 업로드하는 방법을 보여줍니다.

## 시작하기 전에 {#before-you-begin}

종속성 검사를 설정합니다. 자세한 지침은 [종속성 검사 자습서](dependency_scanning.md)를 따르세요.

## 구성 파일 생성 {#create-configuration-files}

1. `api` 범위와 `Developer` 역할로 개인 액세스 토큰을 생성합니다.
1. 토큰 값을 `PRIVATE_TOKEN`이라는 CI/CD 변수로 추가합니다.
1. 다음 코드를 포함하는 [스니펫](../api/snippets.md)을 생성합니다.

   파일 이름: `export.sh`

   ```shell
   #! /bin/sh

   function create_export {
     curl --silent \
     --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" \
     -X 'POST' --data "export_type=sbom" \
     "https://gitlab.com/api/v4/pipelines/$CI_PIPELINE_ID/dependency_list_exports" \
     | jq '.id'
   }

   function check_status {
     curl --silent \
       --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" \
       --write-out "%{http_code}" --output /dev/null \
       https://gitlab.com/api/v4/dependency_list_exports/$1
   }

   function download {
     curl --header "PRIVATE-TOKEN: $PRIVATE_TOKEN" \
       --output "gl-sbom-merged-$CI_PIPELINE_ID.cdx.json" \
       "https://gitlab.com/api/v4/dependency_list_exports/$1/download"
   }

   function export_sbom {
     local ID=$(create_export)

     for run in $(seq 0 3); do
       local STATUS=$(check_status $ID)
       # Status is 200 when JSON is generated.
       # Status is 202 when generate JSON job is running.
       if [ $STATUS -eq "200" ]; then
         download $ID

         exit 0
       elif [ $STATUS -ne "202" ]; then
         exit 1
       fi

       echo "Waiting for JSON to be generated"
       sleep 5
     done

     exit 1
   }

   export_sbom
   ```

   이 `export.sh` 스크립트는 다음 단계로 작동합니다:

   1. 현재 파이프라인에 대해 CycloneDX SBOM 내보내기를 생성합니다.
   1. 해당 내보내기의 상태를 확인하고 준비되었을 때 중지합니다.
   1. CycloneDX SBOM 파일을 다운로드합니다.

1. `.gitlab-ci.yml`을(를) 다음 코드로 업데이트합니다.

   ```yaml
   export-merged-sbom:
     image: alpine
     before_script:
       - apk add --update jq curl
     stage: .post
     script:
       - |
         curl --header "Authorization: Bearer $PRIVATE_TOKEN" --output export.sh --url "https://gitlab.com/api/v4/snippets/<SNIPPET_ID>/raw"
       - /bin/sh export.sh
     artifacts:
       paths:
         - "gl-sbom-merged-*.cdx.json"

   ```

1. **빌드** > **파이프라인**로 이동하여 최신 파이프라인이 성공적으로 완료되었는지 확인합니다.

작업 아티팩트에서 `gl-sbom-merged-<pipeline_id>.cdx.json` 파일이 있어야 합니다.
