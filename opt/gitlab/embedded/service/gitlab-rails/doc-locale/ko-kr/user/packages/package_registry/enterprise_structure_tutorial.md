---
stage: Package
group: Package Registry
info: For assistance with this tutorial, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments-to-other-projects-and-subjects>.
title: '튜토리얼: 엔터프라이즈 규모를 위한 패키지 레지스트리 구조화'
---

조직이 성장함에 따라 패키지 관리가 점점 복잡해질 수 있습니다. GitLab 패키지 레지스트리 모델은 엔터프라이즈 패키지 관리를 위한 강력한 솔루션을 제공합니다. 패키지 레지스트리를 활용하는 방법을 이해하는 것은 패키지를 안전하고 간단하며 대규모로 작업하는 데 중요합니다.

이 튜토리얼에서는 GitLab 패키지 레지스트리 모델을 엔터프라이즈 그룹 구조에 통합하는 방법을 배웁니다. 여기에 제공된 예제는 Maven 및 npm 패키지에 특정되지만, GitLab 패키지 레지스트리에서 지원하는 모든 패키지에 이 튜토리얼의 개념을 확장할 수 있습니다.

이 튜토리얼을 완료하면 다음을 수행하는 방법을 알게 됩니다:

1. [작업을 구조화하기 위해 단일 루트 또는 최상위 그룹을 설정](#create-an-enterprise-structure)합니다.
1. [명확한 소유권으로 패키지 게시를 위한 프로젝트를 구성](#set-up-a-top-level-group)합니다.
1. [간소화된 액세스를 위해 최상위 그룹 패키지 사용량을 설정](#publish-packages)합니다.
1. [팀이 조직의 패키지에 액세스할 수 있도록 배포 토큰을 추가](#add-deploy-tokens)합니다.
1. [CI/CD를 구성하여 패키지를 안전하게 작업](#use-packages-with-cicd)합니다.

## 시작하기 전에 {#before-you-begin}

이 튜토리얼을 완료하기 위해 다음이 필요합니다:

- npm 또는 Maven 패키지입니다.
- GitLab 패키지 레지스트리에 대한 숙련도입니다.
- 테스트 프로젝트입니다. 기존 프로젝트를 사용하거나 이 튜토리얼을 위해 새 프로젝트를 만들 수 있습니다.

## GitLab 패키지 레지스트리 이해 {#understand-the-gitlab-package-registry}

JFrog Artifactory 및 Sonatype Nexus와 같은 기존 패키지 관리자는 단일 중앙 집중식 리포지토리를 사용하여 패키지를 저장하고 업데이트합니다. GitLab을 사용하면 그룹 또는 프로젝트에서 패키지를 직접 관리할 수 있습니다. 이는 다음을 의미합니다.

- 팀이 코드를 저장하는 프로젝트에 패키지를 게시합니다.
- 팀이 아래의 모든 패키지를 집계하는 루트 그룹 레지스트리에서 패키지를 사용합니다.
- 액세스 제어는 기존 GitLab 권한에서 상속됩니다.

패키지가 코드처럼 저장되고 관리되므로 기존 프로젝트 또는 그룹에 패키지 관리를 추가할 수 있습니다. 이 모델은 여러 이점을 제공합니다:

- 소스 코드와 함께 패키지의 명확한 소유권
- 추가 구성 없이 세분화된 액세스 제어
- 간소화된 CI/CD 통합
- 팀 구조와의 자연스러운 조화
- 루트 그룹 사용을 통해 모든 회사 패키지에 액세스하기 위한 단일 URL

## 엔터프라이즈 구조 생성 {#create-an-enterprise-structure}

코드를 단일 최상위 그룹으로 구성하는 것을 고려합니다. 예를 들어:

```plaintext
company/ (top-level group)
├── retail-division/
│   ├── shared-libraries/    # Division-specific shared code
│   └── teams/
│       ├── checkout/        # Team publishes packages here
│       └── inventory/       # Team publishes packages here
├── banking-division/
│   ├── shared-libraries/    # Division-specific shared code
│   └── teams/
│       ├── payments/        # Team publishes packages here
│       └── fraud/           # Team publishes packages here
└── shared-platform/         # Enterprise-wide shared code
    ├── java-commons/        # Shared Java libraries
    └── ui-components/       # Shared UI components
```

이 구조에서 회사의 모든 팀이 자신의 프로젝트에 코드와 패키지를 게시하면서 최상위 `company/` 그룹의 구성을 상속합니다.

## 최상위 그룹 설정 {#set-up-a-top-level-group}

최상위 그룹이 있고 소유자 역할이 있으면 기존 최상위 그룹을 사용할 수 있습니다.

그룹이 없으면 하나를 만듭니다:

1. 오른쪽 위 모서리에서 **새로 만들기**({{< icon name="plus" >}}) 및 **새 그룹**을 선택합니다.
1. **그룹 이름**에서 그룹의 이름을 입력합니다.
1. **그룹 URL**에서 네임스페이스로 사용되는 그룹의 경로를 입력합니다.
1. [표시 수준](../../public_access.md)을 선택합니다.
1. 선택 사항. 경험을 개인화할 정보를 입력합니다.
1. **그룹 생성**를 선택합니다.

이 그룹은 조직의 다른 그룹 및 프로젝트를 저장합니다. 다른 프로젝트 및 그룹이 있으면 [관리를 위해 새 최상위 그룹으로 전송](../../group/manage.md#transfer-a-group)할 수 있습니다.

계속 진행하기 전에 최소한 다음이 있는지 확인하세요:

- 최상위 그룹입니다.
- 최상위 그룹 또는 하위 그룹 중 하나에 속하는 프로젝트입니다.

## 패키지 게시 {#publish-packages}

명확한 소유권을 유지하려면 팀이 자신의 패키지 레지스트리에 패키지를 게시해야 합니다. 이렇게 하면 패키지가 소스 코드와 함께 유지되고 버전 기록이 프로젝트 활동에 연결됩니다.

{{< tabs >}}

{{< tab title="Maven 프로젝트" >}}

Maven 패키지를 게시하려면:

- `pom.xml` 파일을 구성하여 프로젝트의 패키지 레지스트리에 게시합니다:

  ```xml
  <!-- checkout/pom.xml -->
  <distributionManagement>
      <repository>
          <id>gitlab-maven</id>
          <url>${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/maven</url>
      </repository>
  </distributionManagement>
  ```

{{< /tab >}}

{{< tab title="npm 프로젝트" >}}

npm 패키지를 게시하려면:

- `package.json` 파일을 구성합니다:

  ```json
  // ui-components/package.json
  {
    "name": "@company/ui-components",
    "publishConfig": {
      "registry": "${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/npm/"
    }
  }
  ```

{{< /tab >}}

{{< /tabs >}}

## 패키지 사용 {#consume-packages}

프로젝트가 단일 최상위 그룹으로 구성되어 있으므로 패키지는 여전히 조직에서 액세스할 수 있습니다. 팀이 패키지를 사용할 수 있도록 단일 API 엔드포인트를 구성해 봅시다.

{{< tabs >}}

{{< tab title="Maven 프로젝트" >}}

- `pom.xml`을 구성하여 최상위 그룹에서 패키지에 액세스합니다:

  ```xml
  <!-- Any project's pom.xml -->
  <repositories>
      <repository>
          <id>gitlab-maven</id>
          <url>https://gitlab.example.com/api/v4/groups/company/-/packages/maven</url>
      </repository>
  </repositories>
  ```

{{< /tab >}}

{{< tab title="npm 프로젝트" >}}

- `.npmrc` 파일을 구성합니다:

  ```shell
  # Any project's .npmrc
  @company:registry=https://gitlab.example.com/api/v4/groups/company/-/packages/npm/
  ```

{{< /tab >}}

{{< /tabs >}}

이 구성은 프로젝트 기반 게시의 이점을 유지하면서 조직 전체의 모든 패키지에 대한 액세스를 자동으로 제공합니다.

## 배포 토큰 추가 {#add-deploy-tokens}

다음으로 읽기 전용 배포 토큰을 추가합니다. 이 토큰은 조직의 하위 그룹 및 프로젝트에 저장된 패키지에 액세스할 수 있으므로 팀이 개발에 사용할 수 있습니다.

1. 최상위 그룹의 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **배포 토큰**을 확장합니다.
1. **토큰 추가**를 선택합니다.
1. 필드를 작성하고 범위를 `read_repository`로 설정합니다.
1. **배포 토큰 만들기**를 선택합니다.

최상위 그룹에 필요한 만큼 많은 배포 토큰을 추가할 수 있습니다. 정기적으로 토큰을 교체하는 것을 기억합니다. 토큰이 노출되었을 것으로 의심되면 즉시 회수하고 교체합니다.

## CI/CD를 사용하여 패키지 사용 {#use-packages-with-cicd}

CI/CD 작업이 패키지 레지스트리에 액세스해야 할 때 사전 정의된 CI/CD 변수 `CI_JOB_TOKEN`로 인증합니다. 이 인증은 자동으로 발생하므로 추가 구성을 수행할 필요가 없습니다:

```yaml
publish:
  script:
    - mvn deploy  # For Maven packages
    # or
    - npm publish # For npm packages
  # CI_JOB_TOKEN provides automatic authentication
```

## 요약 및 다음 단계 {#summary-and-next-steps}

GitLab 프로젝트를 단일 최상위 그룹으로 구성하면 여러 이점이 있습니다:

- 간소화된 구성:
  - 모든 패키지 액세스를 위한 단일 URL
  - 팀 간의 일관된 설정
  - 쉬운 토큰 교체
- 명확한 소유권:
  - 패키지가 소스 코드와 함께 유지됩니다
  - 팀이 게시에 대한 제어를 유지합니다
  - 버전 기록이 프로젝트 활동에 연결됩니다
- 자연스러운 조직:
  - 그룹이 회사 구조와 일치합니다
  - 팀이 자율성을 유지하면서 협업할 수 있습니다

GitLab 패키지 레지스트리 모델은 엔터프라이즈 패키지 관리를 위한 강력한 솔루션을 제공합니다. 프로젝트 기반 게시와 최상위 그룹 사용을 결합하면 명확한 소유권과 간소화된 액세스라는 두 가지 장점을 모두 얻을 수 있습니다.

이 방법은 조직과 함께 자연스럽게 확장되면서 보안과 사용 편의성을 유지합니다. 단일 팀 또는 부서로 이 모델을 구현하여 시작하고 이 통합 방법의 이점을 보면서 확장합니다. 이 튜토리얼이 Maven과 npm에 중점을 두었지만 GitLab에서 지원하는 모든 패키지 유형에 동일한 원칙이 적용됩니다.
