---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 패키지에 대한 종속성 프록시
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  베타

{{< /details >}}

> [!warning]
> 종속성 프록시는 [베타](../../../../policy/development_stages_support.md#beta) 상태입니다. 이 기능을 사용하기 전에 설명서를 주의 깊게 검토하세요.

GitLab 종속성 프록시는 패키지를 다운로드하고 복사본을 저장하는 로컬 프록시 서버입니다.

패키지를 처음 요청하면 GitLab이 업스트림 패키지 레지스트리에서 가져와 프로젝트에 복사본을 저장합니다. 동일한 패키지를 다시 요청하면 GitLab이 프로젝트의 패키지 레지스트리에 저장된 복사본을 제공합니다.

이 방식은 외부 소스에서의 다운로드 수를 줄이고 패키지 빌드를 더 빠르게 합니다.

## 종속성 프록시 활성화 {#enable-the-dependency-proxy}

패키지에 종속성 프록시를 사용하려면 프로젝트가 올바르게 구성되었는지, 캐시에서 끌어오는 사용자가 필요한 인증을 갖추었는지 확인하세요:

1. 전역 구성에서 다음 기능이 비활성화되어 있으면 활성화하세요:
   - [`package` 기능](../../../../administration/packages/_index.md#enable-or-disable-the-package-registry). 기본적으로 활성화됩니다.
   - [`dependency_proxy` 기능](../../../../administration/packages/dependency_proxy.md#turn-on-the-dependency-proxy). 기본적으로 활성화됩니다.
1. 프로젝트 설정에서 [`package` 기능](../_index.md#turn-off-the-package-registry)이 비활성화되어 있으면 활성화하세요. 기본적으로 활성화되어 있습니다.
1. [인증 방법 추가](#configure-a-client). 종속성 프록시는 패키지 레지스트리와 동일한 [인증 방법](../supported_functionality.md#authenticate-with-the-registry)을 지원합니다:
   - [개인 액세스 토큰](../../../profile/personal_access_tokens.md)
   - [프로젝트 배포 토큰](../../../project/deploy_tokens/_index.md)
   - [그룹 배포 토큰](../../../project/deploy_tokens/_index.md)
   - [작업 토큰](../../../../ci/jobs/ci_job_token.md)

## 고급 캐싱 {#advanced-caching}

가능하면 패키지에 대한 종속성 프록시는 고급 캐싱을 사용하여 프로젝트의 패키지 레지스트리에 패키지를 저장합니다.

고급 캐싱은 프로젝트의 패키지 레지스트리와 업스트림 패키지 레지스트리 간의 일관성을 확인합니다. 업스트림 레지스트리에 업데이트된 파일이 있으면 종속성 프록시가 이를 사용하여 캐시된 파일을 업데이트합니다.

고급 캐싱이 지원되지 않으면 종속성 프록시는 기본 동작으로 폴백합니다:

- 요청된 파일이 프로젝트의 패키지 레지스트리에 있으면 반환됩니다.
- 파일을 찾을 수 없으면 업스트림 패키지 레지스트리에서 가져옵니다.

고급 캐싱 지원은 업스트림 패키지 레지스트리가 종속성 프록시 요청에 응답하는 방식과 사용 중인 패키지 형식에 따라 달라집니다.

Maven 패키지의 경우:

| 패키지 레지스트리                                                                                                                      | 고급 캐싱이 지원됩니까? |
|---------------------------------------------------------------------------------------------------------------------------------------|-----------------------------|
| [GitLab](../../maven_repository/_index.md)                                                                                            | {{< yes >}} |
| [Maven Central](https://mvnrepository.com/repos/central)                                                                              | {{< yes >}} |
| [Artifactory](https://jfrog.com/integrations/maven-repository/)                                                                        | {{< yes >}} |
| [Sonatype Nexus](https://help.sonatype.com/en/maven-repositories.html)                                                                | {{< yes >}} |
| [GitHub Packages](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-apache-maven-registry) | {{< no >}} |

### 권한 {#permissions}

종속성 프록시가 파일을 끌어올 때 다음이 발생합니다:

1. 종속성 프록시는 프로젝트의 패키지 레지스트리에서 파일을 검색합니다. 읽기 작업입니다.
1. 종속성 프록시는 패키지 파일을 프로젝트의 패키지 레지스트리에 게시할 수 있습니다. 쓰기 작업입니다.

두 단계를 모두 실행하는지 여부는 사용자 권한에 따라 달라집니다. 종속성 프록시는 [패키지 레지스트리와 동일한 권한](../_index.md#package-registry-visibility-permissions)을 사용합니다.

| 프로젝트 가시성 | 최소 [역할](../../../permissions.md#roles) | 패키지 파일을 읽을 수 있습니까? | 패키지 파일을 쓸 수 있습니까? | 동작 |
|--------------------|-----------------------------------------------|-------------------------|--------------------------|----------|
| 공개             | 익명                                     | {{< no >}}              | {{< no >}}               | 요청이 거부되었습니다. |
| 공개             | Guest                                         | {{< yes >}}             | {{< no >}}               | 패키지 파일이 캐시 또는 원격 레지스트리에서 반환됩니다. |
| 공개             | Developer                                     | {{< yes >}}             | {{< yes >}}              | 패키지 파일이 캐시 또는 원격 레지스트리에서 반환됩니다. 파일이 캐시에 게시됩니다. |
| 내부           | 익명                                     | {{< no >}}              | {{< no >}}               | 요청이 거부되었습니다. |
| 내부           | Guest                                         | {{< yes >}}             | {{< no >}}               | 패키지 파일이 캐시 또는 원격 레지스트리에서 반환됩니다. |
| 내부           | Developer                                     | {{< yes >}}             | {{< yes >}}              | 패키지 파일이 캐시 또는 원격 레지스트리에서 반환됩니다. 파일이 캐시에 게시됩니다. |
| 비공개            | 익명                                     | {{< no >}}              | {{< no >}}               | 요청이 거부되었습니다. |
| 비공개            | 보고자                                      | {{< yes >}}             | {{< no >}}               | 패키지 파일이 캐시 또는 원격 레지스트리에서 반환됩니다. |
| 비공개            | Developer                                     | {{< yes >}}             | {{< yes >}}              | 패키지 파일이 캐시 또는 원격 레지스트리에서 반환됩니다. 파일이 캐시에 게시됩니다. |

최소한 종속성 프록시를 사용할 수 있는 모든 사용자도 프로젝트의 패키지 레지스트리를 사용할 수 있습니다.

캐시가 시간이 지남에 따라 제대로 채워지도록 하려면 개발자, 유지 관리자 또는 소유자 역할이 있는 사용자가 종속성 프록시로 패키지를 끌어오는지 확인하세요.

## 클라이언트 구성 {#configure-a-client}

종속성 프록시용 클라이언트 구성은 [패키지 레지스트리](../supported_functionality.md#pulling-packages)용 클라이언트 구성과 유사합니다.

### Maven 패키지 {#for-maven-packages}

Maven 패키지의 경우 [패키지 레지스트리에서 지원하는 모든 클라이언트](../../maven_repository/_index.md)가 종속성 프록시에서 지원됩니다:

- `mvn`
- `gradle`
- `sbt`

인증을 위해 [Maven 패키지 레지스트리](../../maven_repository/_index.md#edit-the-client-configuration)에서 허용하는 모든 방법을 사용할 수 있습니다. [기본 HTTP 인증](../../maven_repository/_index.md#basic-http-authentication) 방법을 사용해야 합니다. 복잡성이 낮기 때문입니다.

클라이언트를 구성하려면:

1. [기본 HTTP 인증](../../maven_repository/_index.md#basic-http-authentication)의 지침을 따르세요.

   엔드포인트 URL `https://gitlab.example.com/api/v4/projects/<project_id>/dependency_proxy/packages/maven`을 사용하는지 확인하세요.

1. 클라이언트에 대한 구성을 완료합니다:

{{< tabs >}}

{{< tab title="mvn" >}}

[기본 HTTP 인증](../../maven_repository/_index.md#basic-http-authentication)이 허용됩니다. 그러나 [사용자 지정 HTTP 헤더 인증](../../maven_repository/_index.md#custom-http-header)을 사용해야 하므로 `mvn`이 더 적은 네트워크 요청을 사용합니다.

`pom.xml` 파일에 `repository` 요소를 추가합니다:

```xml
<repositories>
  <repository>
    <id>gitlab-maven</id>
    <url>https://gitlab.example.com/api/v4/projects/<project_id>/dependency_proxy/packages/maven</url>
  </repository>
</repositories>
```

위치:

- `<project_id>`은 종속성 프록시로 사용할 프로젝트의 ID입니다.
- `<id>`은 [인증 구성](../../maven_repository/_index.md#basic-http-authentication)에서 사용된 `<server>`의 이름을 포함합니다.

기본적으로 Maven Central은 [Super POM](https://maven.apache.org/guides/introduction/introduction-to-the-pom.html#Super_POM)을 통해 먼저 확인됩니다. 그러나 `mvn`이 GitLab 엔드포인트를 먼저 확인하도록 강제할 수도 있습니다. 이를 위해 [요청 전달](../../maven_repository/_index.md#additional-configuration-for-mvn)의 지침을 따르세요.

{{< /tab >}}

{{< tab title="gradle" >}}

`repositories` 섹션을 [`build.gradle`](https://docs.gradle.org/current/userguide/tutorial_using_tasks.html) 파일에 추가합니다.

- Groovy DSL에서:

  ```groovy
  repositories {
      maven {
          url "https://gitlab.example.com/api/v4/projects/<project_id>/dependency_proxy/packages/maven"
          name "GitLab"
          credentials(PasswordCredentials) {
              username = 'REPLACE_WITH_NAME'
              password = gitLabPrivateToken
          }
          authentication {
              basic(BasicAuthentication)
          }
      }
  }
  ```

- Kotlin DSL에서:

  ```kotlin
  repositories {
      maven {
          url = uri("https://gitlab.example.com/api/v4/projects/<project_id>/dependency_proxy/packages/maven")
          name = "GitLab"
          credentials(BasicAuthentication::class) {
              username = "REPLACE_WITH_NAME"
              password = findProperty("gitLabPrivateToken") as String?
          }
          authentication {
              create("basic", BasicAuthentication::class)
          }
      }
  }
  ```

이 예에서:

- `<project_id>`은 종속성 프록시로 사용할 프로젝트의 ID입니다.
- `REPLACE_WITH_NAME`은 [기본 HTTP 인증](../../maven_repository/_index.md#basic-http-authentication) 섹션에서 설명되어 있습니다.

{{< /tab >}}

{{< tab title="sbt" >}}

[`build.sbt`](https://www.scala-sbt.org/1.x/docs/Directories.html#sbt+build+definition+files)에서 다음 줄을 추가합니다:

```scala
resolvers += ("gitlab" at "https://gitlab.example.com/api/v4/projects/<project_id>/dependency_proxy/packages/maven")

credentials += Credentials("GitLab Packages Registry", "<host>", "<name>", "<token>")
```

이 예에서:

- `<project_id>`은 종속성 프록시로 사용할 프로젝트의 ID입니다.
- `<host>`은 `<endpoint url>`에 있는 프로토콜 체계나 포트 없는 호스트입니다. 예: `gitlab.example.com`.
- `<name>`과 `<token>`은 [기본 HTTP 인증](../../maven_repository/_index.md#basic-http-authentication) 섹션에서 설명되어 있습니다.

{{< /tab >}}

{{< /tabs >}}

## 원격 레지스트리 구성 {#configure-the-remote-registry}

종속성 프록시는 다음과 같이 구성해야 합니다:

- 원격 패키지 레지스트리의 URL입니다.
- 선택 사항. 필요한 자격 증명입니다.

이러한 매개 변수를 설정하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **패키지 레지스트리**를 확장합니다.
1. **의존성 프록시** 아래에서 패키지 형식에 대한 양식을 작성하세요:

{{< tabs >}}

{{< tab title="Maven" >}}

모든 Maven 패키지 레지스트리를 종속성 프록시에 연결할 수 있습니다. Maven 패키지 레지스트리 사용자 이름과 비밀번호로 연결을 승인할 수 있습니다.

원격 Maven 패키지 레지스트리를 설정하거나 업데이트하려면 양식의 다음 필드를 업데이트하세요:

- `URL` - 원격 레지스트리의 URL입니다.
- `Username` - 선택 사항입니다. 원격 레지스트리에서 사용할 사용자 이름입니다.
- `Password` - 선택 사항입니다. 원격 레지스트리에서 사용할 비밀번호입니다.

사용자 이름과 비밀번호를 모두 설정하거나 두 필드를 모두 비워두어야 합니다.

{{< /tab >}}

{{< /tabs >}}

## 문제 해결 {#troubleshooting}

### 수동 파일 끌어오기 오류 {#manual-file-pull-errors}

cURL로 파일을 수동으로 끌어올 수 있습니다. 그러나 다음 응답 중 하나가 나타날 수 있습니다:

- `404 Not Found` - 종속성 프록시 설정 개체를 찾을 수 없습니다. 개체가 없거나 [요구 사항](#enable-the-dependency-proxy)이 충족되지 않았기 때문입니다.
- `401 Unauthorized` - 사용자는 제대로 인증되었지만 종속성 프록시 개체에 액세스할 적절한 권한이 없습니다.
- `403 Forbidden` - [GitLab 라이선스 수준](#enable-the-dependency-proxy)에 문제가 있었습니다.
- `502 Bad Gateway` - 원격 패키지 레지스트리가 파일 요청을 완료할 수 없습니다. [종속성 프록시 설정](#configure-the-remote-registry)을 확인하세요.
- `504 Gateway Timeout` - 원격 패키지 레지스트리 시간이 초과되었습니다. [종속성 프록시 설정](#configure-the-remote-registry)을 확인하세요.

{{< tabs >}}

{{< tab title="Maven" >}}

```shell
curl --fail-with-body --verbose "https://<username>:<personal access token>@gitlab.example.com/api/v4/projects/<project_id>/dependency_proxy/packages/maven/<group id and artifact id>/<version>/<file_name>"
```

- `<username>`과 `<personal access token>`은 GitLab 인스턴스의 종속성 프록시에 액세스할 자격 증명입니다.
- `<project_id>`은 프로젝트 ID입니다.
- `<group id and artifact id>`은 슬래시로 연결된 [Maven 패키지 그룹 ID 및 아티팩트 ID](https://maven.apache.org/pom.html#Maven_Coordinates)입니다.
- `<version>`은(는) 패키지 버전입니다.
- `file_name`은 파일의 정확한 이름입니다.

예를 들어 다음과 같은 패키지가 주어진 경우:

- 그룹 ID: `com.my_company`.
- 아티팩트 ID: `my_package`.
- 버전: `1.2.3`.

패키지를 수동으로 끌어올 요청은 다음과 같습니다:

```shell
curl --fail-with-body --verbose "https://<username>:<personal access token>@gitlab.example.com/api/v4/projects/<project_id>/dependency_proxy/packages/maven/com/my_company/my_package/1.2.3/my_package-1.2.3.pom"
```

{{< /tab >}}

{{< /tabs >}}
