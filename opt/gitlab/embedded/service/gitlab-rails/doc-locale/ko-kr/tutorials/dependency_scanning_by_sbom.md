---
stage: Application Security Testing
group: Composition Analysis
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: "SBOM을 사용하여 종속성 검사를 구성하는 방법, 프로젝트 종속성의 취약성을 감지하고, 코드에서 도달 가능한 취약성을 파악하는 방법을 알아봅니다."
title: '자습서: SBOM을 사용하여 종속성 검사 설정'
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab.com

{{< /details >}}

종속성 검사는 소프트웨어 종속성의 보안 취약성을 메인 브랜치로 커밋되기 전에 자동으로 감지할 수 있습니다. 애플리케이션을 개발하고 테스트하는 동안 워크플로 초반에 취약한 종속성을 파악하고 해결할 수 있습니다. 종속성 분석기는 애플리케이션 종속성의 SBOM(Software Bill of Materials)을 생성한 다음 권고사항과 비교하여 취약성을 파악합니다. 정적 도달가능성 분석은 애플리케이션이 가져오는 취약한 종속성을 파악하여 취약성 위험 평가 데이터를 강화합니다.

이 튜토리얼에서는 다음을 수행하는 방법을 보여줍니다:

- 예제 JavaScript 애플리케이션을 만듭니다.
- 정적 도달가능성 분석을 포함하여 새 SBOM 분석기를 사용하여 종속성 검사를 설정합니다.
- 애플리케이션 종속성의 취약성을 분류합니다.
- 종속성을 업데이트하여 취약성을 수정합니다.

> [!note]
> 이 튜토리얼은 감지를 시연하기 위해 알려진 취약성이 있는 오래된 종속성을 사용합니다.

## 시작하기 전에 {#before-you-begin}

이 튜토리얼을 시작하기 전에 다음을 준비했는지 확인하세요:

- GitLab.com 계정 및 새 프로젝트를 만들 수 있는 액세스
- Git
- Node.js(버전 14 이상)

## 예제 애플리케이션 파일 만들기 {#create-example-application-files}

이 튜토리얼의 첫 번째 작업은 예제 프로젝트를 설정하고(예제 취약 애플리케이션 포함), CI/CD를 구성하는 것입니다.

1. GitLab.com에서 기본값을 사용하여 빈 프로젝트를 만듭니다.
1. 프로젝트를 로컬 머신에 복제합니다:

   ```plaintext
   git clone https://gitlab.com/<your-username>/<project-name>.git
   cd <project-name>
   ```

1. 로컬 머신에서 프로젝트에 다음 파일을 만듭니다:

   - `.gitlab-ci.yml`
   - `package.json`
   - `app.js`

   파일 이름: `.gitlab-ci.yml`

   ```yaml
   stages:

   - build
   - test

   include:
   - template: Jobs/Dependency-Scanning.v2.gitlab-ci.yml
     inputs:
       enable_static_reachability: true
   ```

   파일 이름: `package.json`

   ```json
   {
      "name": "tutorial-ds-sbom-scanning-with-sra",
      "version": "1.0.0",
      "main": "index.js",
      "dependencies": {
         "axios": "0.21.1",
         "fastify": "2.14.1"
      }
   }
   ```

   파일 이름: `app.js`

   ```javascript
   const axios = require('axios');

   async function runDemo() {
     console.log("Starting Reachability Demo...");
     try {
       // This specific call creates the reachability link
       const response = await axios.get('<https://gitlab.com>');
       console.log("Request successful, status:", response.status);
     } catch (err) {
       console.log("Demo request finished.");
     }
   }

   runDemo();
   ```

1. 잠금 파일을 만듭니다.

   ```plaintext
   npm install
   ```

1. 이 파일들을 프로젝트에 커밋하고 푸시합니다:

   ```plaintext
   git add .gitlab-ci.yml app.js package.json package-lock.json
   git commit -m "Set up files for tutorial"
   git push
   ```

1. GitLab.com에서 **빌드** > **파이프라인**으로 이동하고 최근 파이프라인이 성공적으로 완료되었는지 확인합니다.

   파이프라인에서 종속성 검사가 실행되고 다음을 수행합니다:

   - 종속성에서 SBOM을 생성합니다. [SBOM을 다운로드](#optional-download-sbom)할 수 있습니다.
   - SBOM에 나열된 종속성을 알려진 취약성 권고사항과 비교하여 검사합니다.
   - 정적 도달가능성 분석으로 결과를 강화하여 코드에서 가져오는 종속성을 파악합니다.

## 취약성 분류 및 분석 {#triage-and-analyze-vulnerabilities}

종속성 검사는 애플리케이션 종속성의 취약성을 감지했어야 합니다. 다음 작업은 해당 취약성을 분류하고 분석하는 것입니다.

> [!note]
> 이 튜토리얼을 간소화하기 위해 모든 변경 사항은 `main` 브랜치로 커밋됩니다. 실제 환경에서는 브랜치가 병합되기 전에 취약성을 감지하기 위해 개발 브랜치에서 종속성 검사를 실행합니다.

이 튜토리얼에서는 하나의 취약성만 분류하고 분석합니다. 이 취약성을 선택한 이유는 도달 가능하며 명확한 수정 경로가 있기 때문입니다.

1. GitLab.com에서 **안전함** > **취약점 보고서**로 이동합니다.

   보고서에 여러 취약성이 나열되어 있어야 합니다. 작성 당시 12개의 취약성이 감지되었습니다.

   > 이 튜토리얼의 목적상 하나의 취약성만 살펴봅니다. 실제 환경에서는 모든 [위험 평가 데이터](../user/application_security/vulnerabilities/risk_assessment_data.md)를 분석하고 조직의 위험 관리 프레임워크를 적용합니다.
1. 검색 필터를 선택하고 드롭다운 목록에서 **도달가능성**을 선택한 다음 **예**를 선택합니다.

   취약성 보고서는 이제 도달 가능한 취약성만 나열합니다. 심각도별 취약성 수는 새 필터와 일치하도록 업데이트됩니다.

   > 이 예제에서는 `package.json`에서 다음 직접 종속성을 선언했습니다:
   >
   > - `axios` - 버전 0.21.1
   > - `fastify` - 버전 2.14.1
   >
   > 종속성 검사는 `fastify`과 `axios` 및 해당 전이 종속성에서 취약성을 감지했습니다. 그러나 `axios`만 예제 애플리케이션에서 가져오므로 `fastify`의 취약성은 도달 가능하지 않습니다. 도달가능성 필터를 적용하면 `fastify`의 취약성은 취약성 보고서에서 제외됩니다.

1. CVE-2026-25223의 설명 "Fastify의 Content-Type 헤더 탭 문자가 본문 유효성 검사 우회를 허용"을 선택합니다.

   1. 이 취약성의 세부 정보를 봅니다.

      취약성의 심각도는 높으며 **도달가능** 값은 **예**입니다. 즉, 종속성이 애플리케이션에서 가져옵니다. 이로 인해 도달 가능하지 않은 다른 높은 심각도의 취약성보다 더 위험합니다.

   1. **교정** 섹션을 봅니다.

      이 취약성의 경우 해결책은 이 종속성의 버전을 업그레이드하는 것입니다.

이 튜토리얼을 간소화하기 위해 명시된 해결책을 적용합니다. 실제 환경에서는 회사의 취약성 분석 프로세스에 따라 이 해결책을 적용하기 전에 검증합니다.

## 취약성 수정 {#remediate-the-vulnerability}

해결책이 있으므로 `fastify` 종속성을 업그레이드합니다.

1. 로컬 머신에서 `package.json` 파일의 버전을 취약성의 세부 정보 페이지에 나열된 `fastify` 버전(5.7.2)으로 업데이트합니다.

   ```json
   {
      "name": "tutorial-ds-sbom-scanning-with-sra",
      "version": "1.0.0",
      "main": "index.js",
      "dependencies": {
         "axios": "0.21.1",
         "fastify": "5.7.2"
      }
   }
   ```

1. 잠금 파일을 업데이트합니다.

   ```plaintext
   npm install
   ```

   이는 `package-lock.json` 파일을 새 종속성 버전으로 업데이트합니다.
1. 새 브랜치를 만들고 이 변경 사항들을 커밋합니다:

   ```plaintext
   git checkout -b update-dependencies
   git add package.json package-lock.json
   git commit -m "Update version of fastify"
   git push -u origin update-dependencies
   ```

1. GitLab.com에서 **코드** > **머지 리퀘스트**로 이동하고 **머지 리퀘스트 생성**를 선택합니다.
1. **새 머지 리퀘스트** 페이지에서 아래로 스크롤하고 **머지 리퀘스트 생성**를 선택합니다.

   머지 리퀘스트 파이프라인이 완료된 후 보안 스캐닝 보고서가 **리포트** 탭에 나타날 때까지 기다립니다. 보안 보고서 처리는 일반적으로 1~2분 정도 걸립니다.
1. **리포트** 탭을 선택한 다음 **보안 스캐닝**을 선택합니다.

   보안 스캐닝 보고서는 머지 리퀘스트의 변경 사항이 7개의 취약성을 수정한다고 명시합니다(분류하고 분석한 취약성 포함).
1. **머지**를 선택합니다.

   머지 리퀘스트가 병합될 때까지 기다립니다.
1. **보안** > **취약점 보고서**로 이동합니다.

   취약성 보고서가 기본적으로 **아직 감지됨**인 취약성만 나열하기 때문에 CVE-2026-25223은 더 이상 나열되지 않습니다. 취약성 세부 정보를 보려면 상태 필터를 변경할 수 있습니다.

이 튜토리얼에서는 다음을 수행하는 방법을 배웠습니다:

- SBOM 및 정적 도달가능성 분석으로 종속성 검사 설정
- 종속성의 취약성 감지 및 분류
- 종속성을 업데이트하여 취약성 수정
- 취약성이 수정되었는지 확인

## 선택 사항:  SBOM 다운로드 {#optional-download-sbom}

종속성 검사 분석기에서 생성한 SBOM을 다운로드하려면:

1. **빌드** > **파이프라인**으로 이동합니다.
1. 가장 최근의 파이프라인을 선택합니다.
1. **dependency-scanning** 작업을 선택합니다.
1. **작업 아티팩트** 섹션에서 **다운로드**를 선택합니다.

작업의 아티팩트가 `artifacts.zip` 파일로 다운로드됩니다. 압축을 해제하여 SBOM 파일 `gl-sbom-npm-npm.cdx.json`에 액세스합니다.
