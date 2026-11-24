---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 전용 유형별 레지스트리로 패키지 관리
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

최상위 그룹 내의 전용 프로젝트에서 패키지를 유형별로 구성합니다. 이 방식은 명확한 소유권과 유형별 정책을 제공합니다.

다음의 경우 이 방식을 사용하세요:

- 전용 정책 및 설정으로 패키지를 유형별로 구성합니다.
- 모든 조직 패키지를 위한 단일 소비 엔드포인트를 제공합니다.
- 타사 레지스트리의 패키지를 구조화된 GitLab 설정으로 마이그레이션합니다.
- 패키지 관리 문제를 애플리케이션 소스 코드와 분리합니다.
- 다양한 패키지 유형에 다양한 거버넌스 정책을 적용합니다.
- 명확한 소유권을 유지하면서 조직 전체 액세스를 지원합니다.

## 예제 연습 {#example-walkthrough}

이 방식으로 패키지를 효과적으로 정리하고 관리하려면 다음을 수행해야 합니다:

- 패키지 유형별로 정리된 프로젝트를 포함하는 아티팩트 관리용 최상위 그룹을 전용으로 생성합니다.
- 최상위 그룹을 아티팩트가 포함된 프로젝트만으로 제한하여 패키지 사용 시 성능을 개선합니다.

### 권장 구조 {#recommended-structure}

다음 예제는 최상위 그룹과 프로젝트를 구조화하는 방식에 대한 개요를 제공합니다:

```plaintext
company_namespace/artifact_management/ # top-level group
├── java-packages/           # Maven packages
├── node-packages/           # npm packages
├── python-packages/         # PyPI packages
├── docker-images/           # Container registry
├── terraform-modules/       # Terraform modules
├── nuget-packages/          # NuGet packages
└── generic-packages/        # Generic file packages
```

> [!note]
> 일부 조직에서는 패키지 수명 주기 또는 안정성을 기반으로 추가 분리를 선호합니다. 예를 들어 `java-releases/`및 `java-snapshots/`에 대한 별도의 프로젝트를 생성할 수 있습니다. 이렇게 하면 안정적인 패키지와 개발 패키지에 대해 다양한 정리 정책, 액세스 제어 또는 승인 워크플로를 적용할 수 있습니다.

### 그룹 및 프로젝트 생성 {#create-the-group-and-projects}

아티팩트 관리용 새 최상위 그룹을 생성합니다:

1. 상단 표시줄에서 **새로 만들기** ({{< icon name="plus" >}}) 및 **새 그룹**을 선택합니다.
1. **그룹 생성**를 선택합니다.
1. **그룹 이름** 텍스트 상자에 `Artifact Management` 또는 유사한 이름을 입력합니다.
1. **그룹 URL**에서 생성된 경로를 유지합니다.
1. 그룹의 [**공개 수준**](../../public_access.md)을 선택합니다.
1. **그룹 생성**를 선택합니다.

필요한 각 패키지 유형에 대한 프로젝트를 생성합니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 아티팩트 관리 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **새로 만들기** ({{< icon name="plus" >}}) 및 **새 프로젝트/리포지토리**를 선택합니다.
1. **빈 프로젝트 생성**을 선택합니다.
1. 원하는 패키지 유형에 대해 **프로젝트 이름**을 입력합니다. 예를 들어 `java-packages` 또는 `node-packages`입니다.
1. 적절한 공개 수준을 설정합니다.
1. **프로젝트 생성**을 선택합니다.

조직에서 가장 많이 사용하는 패키지 유형으로 시작한 후 추가 패키지 형식을 도입하면서 구조를 확장합니다. 이 방식은 보안과 사용 편의성을 유지하면서 자연스럽게 확장됩니다.

그룹 설정 구성:

1. 아티팩트 관리 그룹의 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **중복 패키지** 또는 **패키지 전달**과 같은 필요한 그룹 정책을 구성합니다.
1. 필요에 따라 그룹 액세스 제어를 설정합니다.

## 인증 및 액세스 구성 {#configure-authentication-and-access}

인증은 사용 사례에 따라 다릅니다. 아래의 제안을 참조하세요. 인증에 대한 자세한 내용은 [레지스트리로 인증](../package_registry/supported_functionality.md#authenticate-with-the-registry)을 참조하세요.

로컬 개발(개발자):

- 개별 개발자를 위한 개인 액세스 토큰
- 공유 팀 자격 증명을 위한 그룹 액세스 토큰

CI/CD 파이프라인:

- CI/CD 작업 토큰(권장) - 자동 인증
- 특수한 경우를 위한 프로젝트 액세스 토큰

외부 시스템:

- 읽기 전용 사용을 위한 배포 토큰
- 더 세밀한 제어를 위한 프로젝트 및 그룹 액세스 토큰

### 최상위 그룹 액세스 설정 {#set-up-top-level-group-access}

조직 전체 패키지 사용을 위한 그룹 배포 토큰을 생성합니다:

1. 아티팩트 관리 그룹의 왼쪽 사이드바에서 **설정** > **리포지토리**를 선택합니다.
1. **배포 토큰**을 확장합니다.
1. **토큰 추가**를 선택하고 필드를 작성합니다:
   - **이름**에 `package-consumption`을(를) 입력합니다.
   - **범위**에서 `read_package_registry`를 선택합니다.
1. **배포 토큰 만들기**를 선택합니다.

토큰을 안전하게 저장합니다.

CI/CD 작업 토큰을 게시에 사용하려는 경우 작업 토큰 허용 목록을 구성합니다:

1. 각 패키지별 프로젝트의 왼쪽 사이드바에서 **설정** > **CI/CD**를 선택합니다.
1. **토큰 액세스**를 확장합니다.
1. 이 패키지 레지스트리에 패키지를 게시할 수 있어야 하는 프로젝트를 추가합니다.

### 프로젝트 설정 구성 {#configure-project-settings}

각 패키지 유형 프로젝트에 대해 다음을 구성합니다:

- 해당 패키지 유형에 적합한 **수명 주기 정책**
- 필요한 경우 **보호된 패키지** 규칙
- 필요한 경우 **보호된 컨테이너 태그** 규칙
- 특정 사용 사례를 위한 **프로젝트 액세스 토큰**

## 패키지 게시 {#publish-packages}

팀은 적절한 유형별 프로젝트 레지스트리에 패키지를 게시해야 합니다. 지원되는 각 패키지 형식에 대한 다음 예제를 참조하세요.

{{< tabs >}}

{{< tab title="Maven" >}}

프로젝트의 `pom.xml`을 `java-packages` 프로젝트에 게시하도록 구성합니다:

```xml
<distributionManagement>
    <repository>
        <id>gitlab-maven</id>
        <url>${CI_API_V4_URL}/projects/JAVA_PACKAGES_PROJECT_ID/packages/maven</url>
    </repository>
    <snapshotRepository>
        <id>gitlab-maven</id>
        <url>${CI_API_V4_URL}/projects/JAVA_PACKAGES_PROJECT_ID/packages/maven</url>
    </snapshotRepository>
</distributionManagement>
```

`settings.xml`에서 인증을 구성합니다:

```xml
<servers>
    <server>
        <id>gitlab-maven</id>
        <configuration>
            <httpHeaders>
                <property>
                    <name>Job-Token</name>
                    <value>${CI_JOB_TOKEN}</value>
                </property>
            </httpHeaders>
        </configuration>
    </server>
</servers>
```

다음을 사용하여 게시합니다:

```shell
mvn deploy
```

{{< /tab >}}

{{< tab title="npm" >}}

프로젝트의 `package.json`을 구성합니다:

```json
{
  "name": "@company/my-package",
  "publishConfig": {
    "registry": "${CI_API_V4_URL}/projects/NODE_PACKAGES_PROJECT_ID/packages/npm/"
  }
}
```

CI/CD 게시의 경우 작업 토큰이 자동으로 사용됩니다:

```yaml
publish:
  script:
    - npm publish
```

로컬 게시의 경우 인증을 구성합니다:

```shell
npm config set @company:registry https://gitlab.example.com/api/v4/projects/NODE_PACKAGES_PROJECT_ID/packages/npm/
npm config set //gitlab.example.com/api/v4/projects/NODE_PACKAGES_PROJECT_ID/packages/npm/:_authToken ${PERSONAL_ACCESS_TOKEN}
```

{{< /tab >}}

{{< tab title="PyPI" >}}

CI/CD 파이프라인에서 게시를 구성합니다:

```yaml
publish:
  script:
    - pip install build twine
    - python -m build
    - TWINE_PASSWORD=${CI_JOB_TOKEN} TWINE_USERNAME=gitlab-ci-token twine upload --repository-url ${CI_API_V4_URL}/projects/PYTHON_PACKAGES_PROJECT_ID/packages/pypi dist/*
```

로컬 게시의 경우:

```shell
twine upload --repository-url https://gitlab.example.com/api/v4/projects/PYTHON_PACKAGES_PROJECT_ID/packages/pypi --username __token__ --password ${PERSONAL_ACCESS_TOKEN} dist/*
```

{{< /tab >}}

{{< tab title="컨테이너 레지스트리" >}}

Docker 이미지를 빌드하고 푸시합니다:

```yaml
build-image:
  script:
    - docker build -t $CI_REGISTRY/artifact-management/docker-images/my-app:$CI_COMMIT_SHA .
    - docker push $CI_REGISTRY/artifact-management/docker-images/my-app:$CI_COMMIT_SHA
```

로컬 개발의 경우:

```shell
docker login gitlab.example.com -u ${USERNAME} -p ${PERSONAL_ACCESS_TOKEN}
docker push gitlab.example.com/artifact-management/docker-images/my-app:latest
```

{{< /tab >}}

{{< tab title="Terraform" >}}

Terraform 모듈을 게시합니다:

```yaml
publish-module:
  script:
    - tar -czf module.tar.gz *.tf
    - 'curl --header "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file module.tar.gz "${CI_API_V4_URL}/projects/TERRAFORM_PACKAGES_PROJECT_ID/packages/terraform/modules/my-module/my-provider/1.0.0/file"'
```

{{< /tab >}}

{{< tab title="NuGet" >}}

프로젝트 파일 또는 CI/CD 파이프라인에서 게시를 구성합니다:

```yaml
publish:
  script:
    - dotnet pack
    - dotnet nuget push "bin/Release/*.nupkg" --source ${CI_API_V4_URL}/projects/NUGET_PACKAGES_PROJECT_ID/packages/nuget/index.json --api-key ${CI_JOB_TOKEN}
```

로컬 게시의 경우:

```shell
dotnet nuget push package.nupkg --source https://gitlab.example.com/api/v4/projects/NUGET_PACKAGES_PROJECT_ID/packages/nuget/index.json --api-key ${PERSONAL_ACCESS_TOKEN}
```

{{< /tab >}}

{{< tab title="일반" >}}

일반 패키지를 업로드합니다:

```yaml
upload-package:
  script:
    - 'curl --header "JOB-TOKEN: $CI_JOB_TOKEN" --upload-file my-package.zip "${CI_API_V4_URL}/projects/GENERIC_PACKAGES_PROJECT_ID/packages/generic/my-package/1.0.0/my-package.zip"'
```

{{< /tab >}}

{{< /tabs >}}

## 패키지 사용 {#consume-packages}

패키지 사용을 위해 다음 중 하나를 수행할 수 있습니다:

- Maven 가상 레지스트리를 사용합니다.
- 최상위 그룹 엔드포인트를 사용합니다.

### Maven 가상 레지스트리 사용(베타) {#using-the-maven-virtual-registry-beta}

Maven 가상 레지스트리는 여러 소스에서 패키지를 집계하여 아티팩트 관리 설정을 향상시킬 수 있습니다. 다음과 같이 수행할 수 있습니다.

- 최상위 그룹 엔드포인트를 Maven 업스트림으로 사용하여 내부 패키지를 추가합니다. 예를 들어, `https://gitlab.example.com/api/v4/groups/artifact-management/-/packages/maven`입니다.
- Maven Central 또는 프라이빗 레지스트리와 같은 외부 업스트림 레지스트리를 추가합니다.
- 다른 GitLab 프로젝트 또는 그룹을 추가합니다.

이 방식은 지능형 캐싱 및 업스트림 우선순위 지정으로 내부 및 외부 종속성을 결합하는 단일 엔드포인트를 제공합니다.

다음과 같은 경우에 Maven 가상 레지스트리를 사용합니다:

- 외부 업스트림 레지스트리와 내부 GitLab 패키지를 집계해야 합니다.
- 외부 종속성을 캐시하여 안정성을 개선하려고 합니다.
- 프라이빗 레지스트리를 공개 레지스트리보다 우선시해야 합니다.
- 내부 및 외부 종속성을 모두 처리하는 단일 엔드포인트를 원합니다.

Maven 가상 레지스트리에서는 게시가 지원되지 않습니다.

자세한 내용은 [Maven 가상 레지스트리](../virtual_registry/maven/_index.md)를 참조하세요.

#### 최상위 아티팩트 관리 그룹 내에서 Maven 가상 레지스트리 구성 {#configure-the-maven-virtual-registry-within-a-top-level-artifact-management-group}

1. 최상위 그룹에서 가상 레지스트리를 생성합니다:
   - `artifact-management` 그룹에서 **배포** > **가상 레지스트리**로 이동합니다.
   - Maven 가상 레지스트리를 생성합니다(예: "Company Maven Registry").
1. 업스트림 레지스트리를 구성합니다:
   - 내부 `java-packages` 프로젝트를 업스트림으로 추가합니다.
   - Maven Central 또는 프라이빗 리포지토리와 같은 외부 레지스트리를 추가합니다.
   - 프라이빗 레지스트리를 먼저, 공개 레지스트리를 마지막으로 배치하여 업스트림을 정렬합니다.
1. Maven 클라이언트를 가상 레지스트리를 사용하도록 구성합니다:

```xml
   <mirrors>
     <mirror>
       <id>central-proxy</id>
       <name>GitLab virtual registry</name>
       <url>https://gitlab.example.com/api/v4/virtual_registries/packages/maven/<registry_id></url>
       <mirrorOf>central</mirrorOf>
     </mirror>
   </mirrors>
```

가상 레지스트리는 개인 액세스 토큰, 그룹 배포 토큰, 그룹 액세스 토큰 및 CI/CD 작업 토큰을 포함한 여러 토큰 유형을 지원합니다. 각 토큰 유형은 다른 HTTP 헤더 이름을 사용합니다. 자세한 내용은 [가상 레지스트리로 인증](../virtual_registry/_index.md#authenticate-to-the-virtual-registry)을 참조하세요.

다음 예제는 개인 액세스 토큰을 구현합니다:

```xml
   <servers>
     <server>
       <id>gitlab-maven</id>
       <configuration>
         <httpHeaders>
           <property>
             <name>Private-Token</name>
             <value>${PERSONAL_ACCESS_TOKEN}</value>
           </property>
         </httpHeaders>
       </configuration>
     </server>
   </servers>
```

### 최상위 그룹 엔드포인트 구성 {#configure-a-top-level-group-endpoint}

최상위 그룹 엔드포인트에서 패키지를 사용하도록 프로젝트를 구성합니다. 이 방식은 단일 구성을 통해 모든 패키지 유형에 액세스할 수 있게 해줍니다:

{{< tabs >}}

{{< tab title="Maven" >}}

`pom.xml`을 그룹 레지스트리에서 사용하도록 구성합니다:

```xml
<repositories>
    <repository>
        <id>gitlab-maven</id>
        <url>https://gitlab.example.com/api/v4/groups/artifact-management/-/packages/maven</url>
    </repository>
</repositories>
```

`settings.xml`에서 인증을 구성합니다:

```xml
<settings>
    <servers>
        <server>
            <id>gitlab-maven</id>
            <username>deploy-token-username</username>
            <password>deploy-token-password</password>
        </server>
    </servers>
</settings>
```

{{< /tab >}}

{{< tab title="npm" >}}

`.npmrc` 파일을 구성합니다:

```ini
@company:registry=https://gitlab.example.com/api/v4/groups/artifact-management/-/packages/npm/
//gitlab.example.com/api/v4/groups/artifact-management/-/packages/npm/:_authToken=${DEPLOY_TOKEN}
```

{{< /tab >}}

{{< tab title="PyPI" >}}

`pip`을 그룹 레지스트리를 사용하도록 구성합니다:

```ini
# pip.conf or ~/.pip/pip.conf
[global]
extra-index-url = https://deploy-token-username:deploy-token-password@gitlab.example.com/api/v4/groups/artifact-management/-/packages/pypi/simple/
```

또는 환경 변수를 사용합니다:

```shell
pip install --index-url https://deploy-token-username:deploy-token-password@gitlab.example.com/api/v4/groups/artifact-management/-/packages/pypi/simple/ --no-index my-package
```

{{< /tab >}}

{{< tab title="컨테이너 레지스트리" >}}

그룹 레지스트리에서 이미지를 가져옵니다:

```shell
docker login gitlab.example.com -u deploy-token-username -p deploy-token-password
docker pull gitlab.example.com/artifact-management/docker-images/my-app:latest
```

{{< /tab >}}

{{< tab title="Terraform" >}}

환경 변수를 사용하여 GitLab 자격 증명을 사용하도록 Terraform을 구성합니다:

```shell
export TF_TOKEN_gitlab_example_com="deploy-token-password"
```

그런 다음 Terraform 구성에서 모듈을 참조합니다:

```hcl
module "example" {
  source = "gitlab.example.com/artifact-management/terraform-modules//my-module"
  version = "1.0.0"
}
```

또는 프로젝트별 URL을 사용합니다:

```hcl
module "example" {
  source = "https://gitlab.example.com/api/v4/projects/TERRAFORM_PACKAGES_PROJECT_ID/packages/terraform/modules/my-module/my-provider/1.0.0"
}
```

{{< /tab >}}

{{< tab title="NuGet" >}}

그룹 레지스트리를 사용하도록 NuGet을 구성합니다:

```xml
<!-- nuget.config -->
<configuration>
  <packageSources>
    <add key="GitLab" value="https://gitlab.example.com/api/v4/groups/artifact-management/-/packages/nuget/index.json" />
  </packageSources>
  <packageSourceCredentials>
    <GitLab>
      <add key="Username" value="deploy-token-username" />
      <add key="ClearTextPassword" value="deploy-token-password" />
    </GitLab>
  </packageSourceCredentials>
</configuration>
```

{{< /tab >}}

{{< tab title="일반" >}}

일반 패키지를 다운로드합니다:

```shell
curl --header "DEPLOY-TOKEN: ${DEPLOY_TOKEN}" "https://gitlab.example.com/api/v4/groups/artifact-management/-/packages/generic/my-package/1.0.0/my-package.zip" --output my-package.zip
```

{{< /tab >}}

{{< /tabs >}}

## CI/CD 구성 예제 {#example-cicd-configuration}

다음 예제는 프로젝트에서 여러 패키지 유형의 패키지를 사용할 수 있는 방법을 보여줍니다:

```yaml
stages:
  - build
  - test

variables:
  MAVEN_OPTS: "-Dmaven.repo.local=${CI_PROJECT_DIR}/.m2/repository"

before_script:
  # Configure npm registry
  - echo "@company:registry=${CI_API_V4_URL}/groups/artifact-management/-/packages/npm/" >> .npmrc
  - echo "//${CI_SERVER_HOST}/api/v4/groups/artifact-management/-/packages/npm/:_authToken=${CI_JOB_TOKEN}" >> .npmrc

build:
  stage: build
  script:
    # Install npm dependencies from group registry
    - npm install
    # Build with Maven dependencies from group registry
    - mvn compile
  cache:
    paths:
      - .m2/repository/
      - node_modules/
```

## 소스 코드와 함께 게시 {#publish-alongside-source-code}

일부 조직에서는 [엔터프라이즈 규모 자습서](../package_registry/enterprise_structure_tutorial.md)에 설명된 대로 애플리케이션 소스 코드와 함께 패키지를 게시하는 것을 선호합니다. 이 방식은 다음과 같은 경우에 효과적입니다:

- 패키지가 특정 애플리케이션과 밀접하게 결합되어 있습니다.
- 패키지 소유권이 소스 코드 소유권과 일치하기를 원합니다.
- 팀에서 코드와 패키지를 함께 관리합니다.

아티팩트 관리 방식은 다음과 같은 경우에 더 효과적입니다:

- 패키지 거버넌스를 간소화하려고 합니다.
- 패키지가 여러 프로젝트 전체에서 공유됩니다.
- 유형별 정책 및 제어가 필요합니다.
- 기존 아티팩트 리포지토리에서 마이그레이션하고 있습니다.

조직에서 가장 많이 사용하는 패키지 유형으로 시작한 후 추가 패키지 형식을 도입하면서 구조를 확장합니다. 이 방식은 보안과 사용 편의성을 유지하면서 자연스럽게 확장됩니다.
