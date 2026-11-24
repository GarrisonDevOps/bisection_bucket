---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: 패키지 레지스트리의 Maven 패키지
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

[Maven](https://maven.apache.org) 아티팩트를 프로젝트의 패키지 레지스트리에 게시합니다. 그런 다음 필요할 때마다 종속성으로 사용할 패키지를 설치합니다.

Maven 패키지 관리자 클라이언트가 사용하는 특정 API 엔드포인트에 대한 설명서는 [Maven API 설명서](../../../api/packages/maven.md)를 참조하세요.

지원되는 클라이언트:

- `mvn`. [Maven](../workflows/build_packages.md#maven) 패키지를 빌드하는 방법을 알아봅니다.
- `gradle`. [Gradle](../workflows/build_packages.md#gradle) 패키지를 빌드하는 방법을 알아봅니다.
- `sbt`.

## GitLab 패키지 레지스트리에 게시 {#publish-to-the-gitlab-package-registry}

### 패키지 레지스트리에 인증 {#authenticate-to-the-package-registry}

패키지를 게시하려면 토큰이 필요합니다. 달성하려는 작업에 따라 다양한 토큰을 사용할 수 있습니다. 자세한 내용은 [토큰에 대한 지침](../package_registry/supported_functionality.md#authenticate-with-the-registry)을 검토하세요.

토큰을 만들고 프로세스의 뒷부분에서 사용할 수 있도록 저장합니다.

여기에 설명된 방법 이외의 인증 방법을 사용하지 마세요. 문서화되지 않은 인증 방법은 향후 제거될 수 있습니다.

#### 클라이언트 구성 편집 {#edit-the-client-configuration}

HTTP를 사용하여 Maven 리포지토리에 인증하도록 구성을 업데이트합니다.

##### 사용자 지정 HTTP 헤더 {#custom-http-header}

클라이언트에 대한 구성 파일에 인증 세부 정보를 추가해야 합니다.

{{< tabs >}}

{{< tab title="`mvn`" >}}

| 토큰 유형            | 이름은 다음이어야 합니다.    | 토큰                                                                  |
| --------------------- | --------------- | ---------------------------------------------------------------------- |
| 개인 액세스 토큰 | `Private-Token` | 토큰을 있는 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| 배포 토큰          | `Deploy-Token`  | 토큰을 있는 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| CI 작업 토큰          | `Job-Token`     | `${CI_JOB_TOKEN}`                                                      |
| OAuth 토큰           | `Authorization` | `Bearer` (예: `Bearer <oauth_token>`)로 토큰 앞에 붙입니다.  |

> [!note]
> `<name>` 필드는 선택한 토큰과 일치하도록 이름을 지정해야 합니다.

[`settings.xml`](https://maven.apache.org/settings.html) 파일에 다음 섹션을 추가합니다.

```xml
<settings>
  <servers>
    <server>
      <id>gitlab-maven</id>
      <configuration>
        <httpHeaders>
          <property>
            <name>REPLACE_WITH_NAME</name>
            <value>REPLACE_WITH_TOKEN</value>
          </property>
        </httpHeaders>
      </configuration>
    </server>
  </servers>
</settings>
```

{{< /tab >}}

{{< tab title="`gradle`" >}}

| 토큰 유형            | 이름은 다음이어야 합니다.    | 토큰                                                                  |
| --------------------- | --------------- | ---------------------------------------------------------------------- |
| 개인 액세스 토큰 | `Private-Token` | 토큰을 있는 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| 배포 토큰          | `Deploy-Token`  | 토큰을 있는 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| CI 작업 토큰          | `Job-Token`     | `System.getenv("CI_JOB_TOKEN")`                                        |
| OAuth 토큰           | `Authorization` | `Bearer` (예: `Bearer <oauth_token>`)로 토큰 앞에 붙입니다.  |

> [!note]
> `<name>` 필드는 선택한 토큰과 일치하도록 이름을 지정해야 합니다.

[`GRADLE_USER_HOME` 디렉터리](https://docs.gradle.org/current/userguide/directory_layout.html#dir:gradle_user_home)에서 다음 내용으로 `gradle.properties` 파일을 만듭니다:

```properties
gitLabPrivateToken=REPLACE_WITH_YOUR_TOKEN
```

`repositories` 섹션을 [`build.gradle`](https://docs.gradle.org/current/userguide/tutorial_using_tasks.html) 파일에 추가합니다:

- Groovy DSL:

  ```groovy
  repositories {
      maven {
          url "https://gitlab.example.com/api/v4/groups/<group>/-/packages/maven"
          name "GitLab"
          credentials(HttpHeaderCredentials) {
              name = 'REPLACE_WITH_NAME'
              value = gitLabPrivateToken
          }
          authentication {
              header(HttpHeaderAuthentication)
          }
      }
  }
  ```

- Kotlin DSL:

  ```kotlin
  repositories {
      maven {
          url = uri("https://gitlab.example.com/api/v4/groups/<group>/-/packages/maven")
          name = "GitLab"
          credentials(HttpHeaderCredentials::class) {
              name = "REPLACE_WITH_NAME"
              value = findProperty("gitLabPrivateToken") as String?
          }
          authentication {
              create("header", HttpHeaderAuthentication::class)
          }
      }
  }
  ```

{{< /tab >}}

{{< /tabs >}}

##### 기본 HTTP 인증 {#basic-http-authentication}

기본 HTTP 인증을 사용하여 Maven 패키지 레지스트리에 인증할 수도 있습니다.

{{< tabs >}}

{{< tab title="`mvn`" >}}

| 토큰 유형            | 이름은 다음이어야 합니다.                 | 토큰                                                                  |
| --------------------- | ---------------------------- | ---------------------------------------------------------------------- |
| 개인 액세스 토큰 | 사용자의 사용자 이름     | 토큰을 있는 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| 배포 토큰          | 배포 토큰의 사용자 이름 | 토큰을 있는 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| CI 작업 토큰          | `gitlab-ci-token`            | `${CI_JOB_TOKEN}`                                                      |

[`settings.xml`](https://maven.apache.org/settings.html) 파일에 다음 섹션을 추가합니다.

```xml
<settings>
  <servers>
    <server>
      <id>gitlab-maven</id>
      <username>REPLACE_WITH_NAME</username>
      <password>REPLACE_WITH_TOKEN</password>
      <configuration>
        <authenticationInfo>
          <userName>REPLACE_WITH_NAME</userName>
          <password>REPLACE_WITH_TOKEN</password>
        </authenticationInfo>
      </configuration>
    </server>
  </servers>
</settings>
```

{{< /tab >}}

{{< tab title="`gradle`" >}}

| 토큰 유형            | 이름은 다음이어야 합니다.                 | 토큰                                                                  |
| --------------------- | ---------------------------- | ---------------------------------------------------------------------- |
| 개인 액세스 토큰 | 사용자의 사용자 이름     | 토큰을 있는 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| 배포 토큰          | 배포 토큰의 사용자 이름 | 토큰을 있는 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| CI 작업 토큰          | `gitlab-ci-token`            | `System.getenv("CI_JOB_TOKEN")`                                        |

[`GRADLE_USER_HOME` 디렉터리](https://docs.gradle.org/current/userguide/directory_layout.html#dir:gradle_user_home)에서 다음 내용으로 `gradle.properties` 파일을 만듭니다:

```properties
gitLabPrivateToken=REPLACE_WITH_YOUR_TOKEN
```

`repositories` 섹션을 [`build.gradle`](https://docs.gradle.org/current/userguide/tutorial_using_tasks.html)에 추가합니다.

- Groovy DSL:

  ```groovy
  repositories {
      maven {
          url "https://gitlab.example.com/api/v4/groups/<group>/-/packages/maven"
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

- Kotlin DSL:

  ```kotlin
  repositories {
      maven {
          url = uri("https://gitlab.example.com/api/v4/groups/<group>/-/packages/maven")
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

{{< /tab >}}

{{< tab title="`sbt`" >}}

| 토큰 유형            | 이름은 다음이어야 합니다.                 | 토큰                                                                  |
|-----------------------|------------------------------|------------------------------------------------------------------------|
| 개인 액세스 토큰 | 사용자의 사용자 이름     | 토큰을 있는 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| 배포 토큰          | 배포 토큰의 사용자 이름 | 토큰을 있는 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| CI 작업 토큰          | `gitlab-ci-token`            | `sys.env.get("CI_JOB_TOKEN").get`                                      |

[SBT](https://www.scala-sbt.org/index.html)의 인증은 [기본 HTTP 인증](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication)을 기반으로 합니다. 이름과 비밀번호를 제공해야 합니다.

> [!note]
> 이름 필드는 선택한 토큰과 일치하도록 이름을 지정해야 합니다.

Maven GitLab 패키지 레지스트리에서 `sbt`를 사용하여 패키지를 설치하려면 [Maven 리졸버](https://www.scala-sbt.org/1.x/docs/Resolvers.html#Maven+resolvers)를 구성해야 합니다. 비공개 또는 내부 프로젝트나 그룹에 액세스하는 경우 [자격증명](https://www.scala-sbt.org/1.x/docs/Publishing.html#Credentials)을 설정해야 합니다. 리졸버와 인증을 구성한 후 프로젝트, 그룹 또는 네임스페이스에서 패키지를 설치할 수 있습니다.

[`build.sbt`](https://www.scala-sbt.org/1.x/docs/Directories.html#sbt+build+definition+files)에 다음 줄을 추가합니다:

```scala
resolvers += ("gitlab" at "<endpoint url>")

credentials += Credentials("GitLab Packages Registry", "<host>", "<name>", "<token>")
```

이 예에서:

- `<endpoint url>`는 [엔드포인트 URL](#endpoint-urls)입니다. 예: `https://gitlab.example.com/api/v4/projects/<project_id>/packages/maven`.
- `<host>`는 프로토콜 스킴이나 포트 없이 `<endpoint url>`에 있는 호스트입니다. 예: `gitlab.example.com`.
- `<name>` 및 `<token>`는 위의 표에서 설명됩니다.

{{< /tab >}}

{{< /tabs >}}

### 명명 규칙 {#naming-convention}

Maven 패키지를 설치하기 위해 3개의 엔드포인트 중 하나를 사용할 수 있습니다. 패키지를 프로젝트에 게시해야 하지만, 선택한 엔드포인트는 게시를 위해 `pom.xml` 파일에 추가하는 설정을 결정합니다.

세 엔드포인트는 다음과 같습니다:

- 프로젝트: 몇 개의 Maven 패키지가 있고 같은 GitLab 그룹에 없을 때 사용합니다.
- 그룹: 같은 GitLab 그룹의 여러 프로젝트에서 패키지를 설치하려는 경우 사용합니다. GitLab은 그룹 내에서 패키지 이름의 고유성을 보장하지 않습니다. 같은 패키지 이름과 패키지 버전을 가진 두 개의 프로젝트를 가질 수 있습니다. 그 결과 GitLab은 더 최근의 것을 제공합니다.
- 인스턴스: 다양한 GitLab 그룹 또는 자체 네임스페이스에 많은 패키지가 있을 때 사용합니다.

인스턴스 수준 엔드포인트의 경우 Maven의 `pom.xml`의 관련 섹션이 다음과 같은지 확인하세요:

```xml
  <groupId>group-slug.subgroup-slug</groupId>
  <artifactId>project-slug</artifactId>
```

인스턴스 수준 엔드포인트에서는 프로젝트와 동일한 경로를 가진 패키지만 노출됩니다.

| 프로젝트             | 패키지                          | 인스턴스 수준 엔드포인트 사용 가능 |
| ------------------- | -------------------------------- | --------------------------------- |
| `foo/bar`           | `foo/bar/1.0-SNAPSHOT`           | 예                               |
| `gitlab-org/gitlab` | `foo/bar/1.0-SNAPSHOT`           | 아니요                                |
| `gitlab-org/gitlab` | `gitlab-org/gitlab/1.0-SNAPSHOT` | 예                               |

#### 엔드포인트 URL {#endpoint-urls}

| 엔드포인트 | `pom.xml`에 대한 엔드포인트 URL                                               | 추가 정보 |
|----------|--------------------------------------------------------------------------|------------------------|
| 프로젝트  | `https://gitlab.example.com/api/v4/projects/<project_id>/packages/maven` | `gitlab.example.com`를 도메인 이름으로 바꿉니다. `<project_id>`를 프로젝트 ID로 바꾸면 [프로젝트 개요 페이지](../../project/working_with_projects.md#find-the-project-id)에서 찾을 수 있습니다. |
| 그룹    | `https://gitlab.example.com/api/v4/groups/<group_id>/-/packages/maven`   | `gitlab.example.com`를 도메인 이름으로 바꿉니다. `<group_id>`를 그룹의 홈페이지에서 찾을 수 있는 그룹 ID로 바꿉니다. |
| 인스턴스 | `https://gitlab.example.com/api/v4/packages/maven`                       | `gitlab.example.com`를 도메인 이름으로 바꿉니다. |

### 게시를 위한 구성 파일 편집 {#edit-the-configuration-file-for-publishing}

클라이언트에 대한 구성 파일에 게시 세부 정보를 추가해야 합니다.

{{< tabs >}}

{{< tab title="`mvn`" >}}

선택한 엔드포인트에 관계없이 다음이 있어야 합니다:

- `distributionManagement` 섹션의 프로젝트별 URL
- `repository` 및 `distributionManagement` 섹션입니다.

Maven의 `pom.xml`에서 관련 `repository` 섹션은 다음과 같아야 합니다:

```xml
<repositories>
  <repository>
    <id>gitlab-maven</id>
    <url><your_endpoint_url></url>
  </repository>
</repositories>
<distributionManagement>
  <repository>
    <id>gitlab-maven</id>
    <url>https://gitlab.example.com/api/v4/projects/<project_id>/packages/maven</url>
  </repository>
  <snapshotRepository>
    <id>gitlab-maven</id>
    <url>https://gitlab.example.com/api/v4/projects/<project_id>/packages/maven</url>
  </snapshotRepository>
</distributionManagement>
```

- `id`는 [`settings.xml`](#edit-the-client-configuration)에서 정의한 것입니다.
- `<your_endpoint_url>`는 선택한 [엔드포인트](#endpoint-urls)에 따라 달라집니다.
- `gitlab.example.com`를 도메인 이름으로 바꿉니다.

{{< /tab >}}

{{< tab title="`gradle`" >}}

Gradle을 사용하여 패키지를 게시하려면:

1. Gradle 플러그인 [`maven-publish`](https://docs.gradle.org/current/userguide/publishing_maven.html)을(를) 플러그인 섹션에 추가합니다:

   - Groovy DSL:

     ```groovy
     plugins {
         id 'java'
         id 'maven-publish'
     }
     ```

   - Kotlin DSL:

     ```kotlin
     plugins {
         java
         `maven-publish`
     }
     ```

1. `publishing` 섹션을 추가합니다:

   - Groovy DSL:

     ```groovy
     publishing {
         publications {
             library(MavenPublication) {
                 from components.java
             }
         }
         repositories {
             maven {
                 url "https://gitlab.example.com/api/v4/projects/<PROJECT_ID>/packages/maven"
                 credentials(HttpHeaderCredentials) {
                     name = "REPLACE_WITH_TOKEN_NAME"
                     value = gitLabPrivateToken // the variable resides in $GRADLE_USER_HOME/gradle.properties
                 }
                 authentication {
                     header(HttpHeaderAuthentication)
                 }
             }
         }
     }
     ```

   - Kotlin DSL:

     ```kotlin
     publishing {
         publications {
             create<MavenPublication>("library") {
                 from(components["java"])
             }
         }
         repositories {
             maven {
                 url = uri("https://gitlab.example.com/api/v4/projects/<PROJECT_ID>/packages/maven")
                 credentials(HttpHeaderCredentials::class) {
                     name = "REPLACE_WITH_TOKEN_NAME"
                     value =
                         findProperty("gitLabPrivateToken") as String? // the variable resides in $GRADLE_USER_HOME/gradle.properties
                 }
                 authentication {
                     create("header", HttpHeaderAuthentication::class)
                 }
             }
         }
     }
     ```

{{< /tab >}}

{{< /tabs >}}

## 패키지 게시 {#publish-a-package}

> [!warning]
> `DeployAtEnd` 옵션을 사용하면 업로드가 `400 bad request {"message":"Validation failed: Name has already been taken"}`로 거부될 수 있습니다. 자세한 내용은 [문제 424238](https://gitlab.com/gitlab-org/gitlab/-/issues/424238)을 참조하세요.

[인증](#authenticate-to-the-package-registry)을 설정하고 [게시를 위한 엔드포인트를 선택](#naming-convention)한 후 Maven 패키지를 프로젝트에 게시합니다.

{{< tabs >}}

{{< tab title="`mvn`" >}}

Maven을 사용하여 패키지를 게시하려면:

```shell
mvn deploy
```

배포가 성공하면 빌드 성공 메시지가 표시됩니다:

```shell
...
[INFO] BUILD SUCCESS
...
```

메시지는 또한 패키지가 올바른 위치에 게시되었음을 표시해야 합니다:

```shell
Uploading to gitlab-maven: https://example.com/api/v4/projects/PROJECT_ID/packages/maven/com/mycompany/mydepartment/my-project/1.0-SNAPSHOT/my-project-1.0-20200128.120857-1.jar
```

{{< /tab >}}

{{< tab title="`gradle`" >}}

게시 작업을 실행합니다:

```shell
gradle publish
```

프로젝트의 **패키지 및 레지스트리** 페이지로 이동하여 게시된 패키지를 봅니다.

{{< /tab >}}

{{< tab title="`sbt`" >}}

`publishTo` 설정을 `build.sbt` 파일에서 구성합니다:

```scala
publishTo := Some("gitlab" at "<endpoint url>")
```

자격증명이 올바르게 참조되는지 확인합니다. [`sbt` 설명서](https://www.scala-sbt.org/1.x/docs/Publishing.html#Credentials)를 참조하세요.

`sbt`를 사용하여 패키지를 게시하려면:

```shell
sbt publish
```

배포가 성공하면 빌드 성공 메시지가 표시됩니다:

```shell
[success] Total time: 1 s, completed Jan 28, 2020 12:08:57 PM
```

성공 메시지를 확인하여 패키지가 올바른 위치에 게시되었는지 확인합니다:

```shell
[info]  published my-project_2.12 to https://gitlab.example.com/api/v4/projects/PROJECT_ID/packages/maven/com/mycompany/my-project_2.12/0.1.1-SNAPSHOT/my-project_2.12-0.1.1-SNAPSHOT.pom
```

{{< /tab >}}

{{< /tabs >}}

> [!note]
> Maven 패키지를 게시하기 전에 보호하면 `403 Forbidden` 오류 및 `Authorization failed` 오류 메시지로 거부됩니다. 게시할 때 Maven 패키지가 보호되지 않는지 확인합니다. 패키지 보호 규칙에 대한 자세한 내용은 [패키지 보호 방법](../package_registry/package_protection_rules.md#protect-a-package)을 참조하세요.

## 패키지 설치 {#install-a-package}

GitLab 패키지 레지스트리에서 패키지를 설치하려면 [리모트를 구성하고 인증](#authenticate-to-the-package-registry)해야 합니다. 이 작업이 완료되면 프로젝트, 그룹 또는 네임스페이스에서 패키지를 설치할 수 있습니다.

여러 패키지의 이름과 버전이 같으면 패키지를 설치할 때 가장 최근에 게시된 패키지가 검색됩니다.

{{< tabs >}}

{{< tab title="`mvn`" >}}

`mvn install`를 사용하여 패키지를 설치하려면:

1. 프로젝트 `pom.xml` 파일에 종속성을 수동으로 추가합니다. 앞에서 만든 예제를 추가하려면 XML은 다음과 같습니다:

   ```xml
   <dependency>
     <groupId>com.mycompany.mydepartment</groupId>
     <artifactId>my-project</artifactId>
     <version>1.0-SNAPSHOT</version>
   </dependency>
   ```

1. 프로젝트에서 다음을 실행합니다:

   ```shell
   mvn install
   ```

메시지는 패키지가 패키지 레지스트리에서 다운로드되고 있음을 표시해야 합니다:

```shell
Downloading from gitlab-maven: http://gitlab.example.com/api/v4/projects/PROJECT_ID/packages/maven/com/mycompany/mydepartment/my-project/1.0-SNAPSHOT/my-project-1.0-20200128.120857-1.pom
```

Maven [`dependency:get` 명령](https://maven.apache.org/plugins/maven-dependency-plugin/get-mojo.html)을 사용하여 패키지를 설치할 수도 있습니다.

1. 프로젝트 디렉터리에서 실행합니다:

   ```shell
   mvn dependency:get -Dartifact=com.nickkipling.app:nick-test-app:1.1-SNAPSHOT -DremoteRepositories=gitlab-maven::::<gitlab endpoint url>  -s <path to settings.xml>
   ```

   - `<gitlab endpoint url>`는 GitLab [엔드포인트](#endpoint-urls)의 URL입니다.
   - `<path to settings.xml>`는 [인증 세부 정보](#edit-the-client-configuration)를 포함하는 `settings.xml` 파일의 경로입니다.

> [!note]
> `gitlab-maven` 명령과 `settings.xml` 파일의 리포지토리 ID가 일치해야 합니다.

메시지는 패키지가 패키지 레지스트리에서 다운로드되고 있음을 표시해야 합니다:

```shell
Downloading from gitlab-maven: http://gitlab.example.com/api/v4/projects/PROJECT_ID/packages/maven/com/mycompany/mydepartment/my-project/1.0-SNAPSHOT/my-project-1.0-20200128.120857-1.pom
```

{{< /tab >}}

{{< tab title="`gradle`" >}}

`gradle`를 사용하여 패키지를 설치하려면:

1. [종속성](https://docs.gradle.org/current/userguide/declaring_dependencies.html)을 `build.gradle`의 종속성 섹션에 추가합니다:

   - Groovy DSL:

     ```groovy
     dependencies {
         implementation 'com.mycompany.mydepartment:my-project:1.0-SNAPSHOT'
     }
     ```

   - Kotlin DSL:

     ```kotlin
     dependencies {
         implementation("com.mycompany.mydepartment:my-project:1.0-SNAPSHOT")
     }
     ```

1. 프로젝트에서 다음을 실행합니다:

   ```shell
   gradle build
   ```

{{< /tab >}}

{{< tab title="`sbt`" >}}

`sbt`를 사용하여 패키지를 설치하려면:

1. [인라인 종속성](https://www.scala-sbt.org/1.x/docs/Library-Management.html#Dependencies)을 `build.sbt`에 추가합니다:

   ```scala
   libraryDependencies += "com.mycompany.mydepartment" % "my-project" % "8.4"
   ```

1. 프로젝트에서 다음을 실행합니다:

   ```shell
   sbt update
   ```

{{< /tab >}}

{{< /tabs >}}

### Maven 패키지의 프록시 다운로드 {#proxy-downloads-for-maven-packages}

{{< history >}}

- [도입됨](https://gitlab.com/gitlab-org/gitlab/-/issues/507768) GitLab 17.8에서.

{{< /history >}}

GitLab Maven 패키지 레지스트리는 [원격으로 포함된 체크섬](https://maven.apache.org/resolver/expected-checksums.html#remote-included-checksums)을 사용합니다. 파일을 다운로드하면 레지스트리는 파일을 프록시하고 파일과 관련 체크섬을 모두 단일 요청에서 Maven 클라이언트에 전송합니다.

최근 Maven 클라이언트를 사용하여 원격으로 포함된 체크섬을 사용합니다:

- GitLab Maven 패키지 레지스트리에 대한 클라이언트의 웹 요청 수를 줄입니다.
- GitLab 인스턴스의 부하를 줄입니다.
- 클라이언트 명령 실행 시간을 개선합니다.

기술적 제약으로 인해 객체 저장소를 사용하면 Maven 패키지 레지스트리는 `packages`에 대한 객체 저장소 구성에서 [프록시 다운로드](../../../administration/object_storage.md#proxy-download) 설정을 무시합니다. 대신 Maven 패키지 레지스트리 다운로드에 대해 프록시 다운로드가 항상 활성화됩니다.

> [!note]
> 객체 저장소를 사용하지 않으면 이 동작은 인스턴스에 영향을 미치지 않습니다.

## Maven 패키지에 대한 CI/CD 통합 {#cicd-integration-for-maven-packages}

CI/CD를 사용하여 Maven 패키지를 자동으로 빌드, 테스트 및 게시할 수 있습니다. 이 섹션의 예는 다음과 같은 시나리오를 다룹니다:

- 다중 모듈 프로젝트
- 버전 지정 릴리스
- 조건부 게시
- 코드 품질 및 보안 스캔과의 통합

특정 프로젝트 요구사항에 맞게 이러한 예제를 조정하고 결합할 수 있습니다.

프로젝트 요구사항에 따라 Maven 버전, Java 버전 및 기타 세부 사항을 조정해야 합니다. 또한 GitLab 패키지 레지스트리에 게시하기 위한 필요한 자격증명 및 설정이 올바르게 구성되었는지 확인합니다.

### 기본 Maven 패키지 빌드 및 게시 {#basic-maven-package-build-and-publish}

이 예제는 Maven 패키지를 빌드하고 게시하는 파이프라인을 구성합니다:

```yaml
default:
  image: maven:3.8.5-openjdk-17
  cache:
    paths:
      - .m2/repository/
      - target/

variables:
  MAVEN_CLI_OPTS: "-s .m2/settings.xml --batch-mode"
  MAVEN_OPTS: "-Dmaven.repo.local=.m2/repository"

stages:
  - build
  - test
  - publish

build:
  stage: build
  script:
    - mvn $MAVEN_CLI_OPTS compile

test:
  stage: test
  script:
    - mvn $MAVEN_CLI_OPTS test

publish:
  stage: publish
  script:
    - mvn $MAVEN_CLI_OPTS deploy
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

### 병렬 작업이 있는 다중 모듈 Maven 프로젝트 {#multi-module-maven-project-with-parallel-jobs}

여러 모듈이 있는 더 큰 프로젝트의 경우 병렬 작업을 사용하여 빌드 프로세스를 빠르게 할 수 있습니다:

```yaml
default:
  image: maven:3.8.5-openjdk-17
  cache:
    paths:
      - .m2/repository/
      - target/

variables:
  MAVEN_CLI_OPTS: "-s .m2/settings.xml --batch-mode"
  MAVEN_OPTS: "-Dmaven.repo.local=.m2/repository"

stages:
  - build
  - test
  - publish

build:
  stage: build
  script:
    - mvn $MAVEN_CLI_OPTS compile

test:
  stage: test
  parallel:
    matrix:
      - MODULE: [module1, module2, module3]
  script:
    - mvn $MAVEN_CLI_OPTS test -pl $MODULE

publish:
  stage: publish
  script:
    - mvn $MAVEN_CLI_OPTS deploy
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

### 태그를 사용한 버전 지정 릴리스 {#versioned-releases-with-tags}

이 예제는 태그가 푸시될 때 버전 지정된 릴리스를 만듭니다:

```yaml
default:
  image: maven:3.8.5-openjdk-17
  cache:
    paths:
      - .m2/repository/
      - target/

variables:
  MAVEN_CLI_OPTS: "-s .m2/settings.xml --batch-mode"
  MAVEN_OPTS: "-Dmaven.repo.local=.m2/repository"

stages:
  - build
  - test
  - publish
  - release

build:
  stage: build
  script:
    - mvn $MAVEN_CLI_OPTS compile

test:
  stage: test
  script:
    - mvn $MAVEN_CLI_OPTS test

publish:
  stage: publish
  script:
    - mvn $MAVEN_CLI_OPTS deploy
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH

release:
  stage: release
  script:
    - mvn versions:set -DnewVersion=${CI_COMMIT_TAG}
    - mvn $MAVEN_CLI_OPTS deploy
  rules:
    - if: $CI_COMMIT_TAG
```

### 변경 사항을 기반으로 한 조건부 게시 {#conditional-publishing-based-on-changes}

이 예제는 특정 파일이 변경될 때만 패키지를 게시합니다:

```yaml
default:
  image: maven:3.8.5-openjdk-17
  cache:
    paths:
      - .m2/repository/
      - target/

variables:
  MAVEN_CLI_OPTS: "-s .m2/settings.xml --batch-mode"
  MAVEN_OPTS: "-Dmaven.repo.local=.m2/repository"

stages:
  - build
  - test
  - publish

build:
  stage: build
  script:
    - mvn $MAVEN_CLI_OPTS compile

test:
  stage: test
  script:
    - mvn $MAVEN_CLI_OPTS test

publish:
  stage: publish
  script:
    - mvn $MAVEN_CLI_OPTS deploy
  rules:
    - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
      changes:
        - pom.xml
        - src/**/*
```

### 코드 품질 및 보안 스캔과의 통합 {#integration-with-code-quality-and-security-scans}

이 예제는 코드 품질 검사 및 보안 스캔을 파이프라인에 통합합니다:

```yaml
default:
  image: maven:3.8.5-openjdk-17
  cache:
    paths:
      - .m2/repository/
      - target/

variables:
  MAVEN_CLI_OPTS: "-s .m2/settings.xml --batch-mode"
  MAVEN_OPTS: "-Dmaven.repo.local=.m2/repository"

include:
  - template: Security/SAST.gitlab-ci.yml
  - template: Code-Quality.gitlab-ci.yml

stages:
  - build
  - test
  - quality
  - publish

build:
  stage: build
  script:
    - mvn $MAVEN_CLI_OPTS compile

test:
  stage: test
  script:
    - mvn $MAVEN_CLI_OPTS test

code_quality:
  stage: quality

sast:
  stage: quality

publish:
  stage: publish
  script:
    - mvn $MAVEN_CLI_OPTS deploy
  rules:
    - if: $CI_COMMIT_BRANCH == "main"
```

## 유용한 팁 {#helpful-hints}

### 같은 이름 또는 버전의 패키지 게시 {#publishing-a-package-with-the-same-name-or-version}

기존 패키지와 같은 이름 및 버전의 패키지를 게시하면 새 패키지 파일이 기존 패키지에 추가됩니다. UI 또는 API를 사용하여 기존 패키지의 이전 자산에 계속 액세스하고 볼 수 있습니다.

이전 패키지 버전을 삭제하려면 Packages API 또는 UI 사용을 고려합니다.

### 중복 Maven 패키지 허용 안 함 {#do-not-allow-duplicate-maven-packages}

{{< history >}}

- 필수 역할이 GitLab 15.0에서 Developer에서 유지 관리자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/350682)됨.
- 필수 역할이 GitLab 17.0에서 유지 관리자에서 소유자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/370471)되었습니다.

{{< /history >}}

사용자가 중복 Maven 패키지를 게시하지 못하도록 하려면 [GraphQL API](../../../api/graphql/reference/_index.md#packagesettings) 또는 UI를 사용할 수 있습니다.

UI에서:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **패키지 및 레지스트리**를 선택합니다.
1. **Maven** 행의 **중복 패키지** 표에서 **중복 허용** 토글을 끕니다.
1. 선택 사항. **예외** 텍스트 상자에 허용할 패키지의 이름 및 버전과 일치하는 정규식을 입력합니다.

> [!note]
> **중복 허용**이 켜져 있으면 **예외** 텍스트 상자에서 중복이 아니어야 하는 패키지 이름 및 버전을 지정할 수 있습니다.

변경 사항이 자동으로 저장됩니다.

### Maven Central로 요청 전달 {#request-forwarding-to-maven-central}

{{< history >}}

- GitLab 15.4에서 [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/85299) [기능 플래그](../../../administration/feature_flags/_index.md) `maven_central_request_forwarding` (이름). 기본적으로 비활성화되었습니다.
- 필수 역할이 GitLab 17.0에서 유지 관리자에서 소유자로 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/370471)되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요.

Maven 패키지가 패키지 레지스트리에서 발견되지 않으면 요청이 [Maven Central](https://search.maven.org/)로 전달됩니다.

기능 플래그가 활성화되면 관리자는 [지속적 통합 설정](../../../administration/settings/continuous_integration.md)에서 이 동작을 비활성화할 수 있습니다.

Maven 전달은 프로젝트 수준 및 그룹 수준 [엔드포인트](#naming-convention)에만 제한됩니다. 인스턴스 수준 엔드포인트는 해당 규칙을 따르지 않는 패키지에 사용되지 않도록 하는 명명 제한이 있으며 공급망 스타일 공격에 대한 보안 위험도 너무 많이 초래합니다.

#### `mvn`에 대한 추가 구성 {#additional-configuration-for-mvn}

`mvn`를 사용할 때 Maven이 GitLab에서 Maven Central의 패키지를 요청하도록 Maven 프로젝트를 구성하는 방법은 많습니다. Maven 리포지토리는 [특정 순서](https://maven.apache.org/guides/mini/guide-multiple-repositories.html#repository-order)로 쿼리됩니다. 기본적으로 Maven Central은 [Super POM](https://maven.apache.org/guides/introduction/introduction-to-the-pom.html#Super_POM)을 통해 먼저 확인되므로 GitLab을 maven-central 전에 쿼리되도록 구성해야 합니다.

모든 패키지 요청이 Maven Central 대신 GitLab으로 전송되도록 하려면 `settings.xml`에 `<mirror>` 섹션을 추가하여 Maven Central을 중앙 리포지토리로 재정의할 수 있습니다:

```xml
<settings>
  <servers>
    <server>
      <id>central-proxy</id>
      <configuration>
        <httpHeaders>
          <property>
            <name>Private-Token</name>
            <value><personal_access_token></value>
          </property>
        </httpHeaders>
      </configuration>
    </server>
  </servers>
  <mirrors>
    <mirror>
      <id>central-proxy</id>
      <name>GitLab proxy of central repo</name>
      <url>https://gitlab.example.com/api/v4/projects/<project_id>/packages/maven</url>
      <mirrorOf>central</mirrorOf>
    </mirror>
  </mirrors>
</settings>
```

### GitLab CI/CD로 Maven 패키지 생성 {#create-maven-packages-with-gitlab-cicd}

Maven용 패키지 리포지토리를 사용하도록 리포지토리를 구성한 후 GitLab CI/CD를 구성하여 새 패키지를 자동으로 빌드할 수 있습니다.

{{< tabs >}}

{{< tab title="`mvn`" >}}

기본 브랜치가 업데이트될 때마다 새 패키지를 만들 수 있습니다.

1. Maven의 `settings.xml` 파일로 사용되는 `ci_settings.xml` 파일을 만듭니다.
1. `server` 섹션을 `pom.xml` 파일에서 정의한 것과 같은 ID로 추가합니다. 예를 들어 `gitlab-maven`을(를) ID로 사용합니다:

   ```xml
   <settings xmlns="http://maven.apache.org/SETTINGS/1.1.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
     xsi:schemaLocation="http://maven.apache.org/SETTINGS/1.1.0 http://maven.apache.org/xsd/settings-1.1.0.xsd">
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
   </settings>
   ```

1. `pom.xml` 파일이 다음을 포함하는지 확인합니다. Maven이 이 예제에서와 같이 [미리 정의된 CI/CD 변수](../../../ci/variables/predefined_variables.md)를 사용하도록 하거나 서버의 호스트 이름과 프로젝트 ID를 하드 코딩할 수 있습니다.

   ```xml
   <repositories>
     <repository>
       <id>gitlab-maven</id>
       <url>${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/maven</url>
     </repository>
   </repositories>
   <distributionManagement>
     <repository>
       <id>gitlab-maven</id>
       <url>${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/maven</url>
     </repository>
     <snapshotRepository>
       <id>gitlab-maven</id>
       <url>${CI_API_V4_URL}/projects/${CI_PROJECT_ID}/packages/maven</url>
     </snapshotRepository>
   </distributionManagement>
   ```

1. `deploy` 작업을 `.gitlab-ci.yml` 파일에 추가합니다:

   ```yaml
   deploy:
     image: maven:3.6-jdk-11
     script:
       - 'mvn deploy -s ci_settings.xml'
     rules:
       - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
   ```

1. 이러한 파일을 리포지토리에 푸시합니다.

다음 번에 `deploy` 작업이 실행되면 `ci_settings.xml`를 사용자의 홈 위치로 복사합니다. 이 예에서:

- 작업이 Docker 컨테이너에서 실행되므로 사용자는 `root`입니다.
- Maven이 구성된 CI/CD 변수를 사용합니다.

{{< /tab >}}

{{< tab title="`gradle`" >}}

기본 브랜치가 업데이트될 때마다 패키지를 만들 수 있습니다.

1. [Gradle의 CI 작업 토큰](#edit-the-client-configuration)을 사용하여 인증합니다.
1. `deploy` 작업을 `.gitlab-ci.yml` 파일에 추가합니다:

   ```yaml
   deploy:
     image: gradle:6.5-jdk11
     script:
       - 'gradle publish'
     rules:
       - if: $CI_COMMIT_BRANCH == $CI_DEFAULT_BRANCH
   ```

1. 파일을 리포지토리에 커밋합니다.

파이프라인이 성공하면 Maven 패키지가 생성됩니다.

{{< /tab >}}

{{< /tabs >}}

### 버전 유효성 검사 {#version-validation}

버전 문자열은 다음 정규식을 사용하여 유효성이 검사됩니다.

```ruby
\A(?!.*\.\.)[\w+.-]+\z
```

[이 정규식 편집기](https://rubular.com/r/rrLQqUXjfKEoL6)에서 정규식을 실험하고 버전 문자열을 시도할 수 있습니다.

### 스냅샷 및 릴리스 배포를 위해 다양한 설정 사용 {#use-different-settings-for-snapshot-and-release-deployments}

스냅샷 및 릴리스에 다양한 URL이나 설정을 사용하려면:

- `<distributionManagement>` 섹션의 `pom.xml` 파일에서 별도의 `<repository>` 및 `<snapshotRepository>` 요소를 정의합니다.

### 유용한 Maven 명령줄 옵션 {#useful-maven-command-line-options}

GitLab CI/CD로 작업을 수행할 때 사용할 수 있는 [Maven 명령줄 옵션](https://maven.apache.org/ref/current/maven-embedder/cli.html)이 있습니다.

- 파일 전송 진행률은 CI 로그를 읽기 어렵게 만들 수 있습니다. 옵션 `-ntp,--no-transfer-progress`은(는) [3.6.1](https://maven.apache.org/docs/3.6.1/release-notes.html#User_visible_Changes)에서 추가되었습니다. 대신 `-B,--batch-mode` [또는 더 낮은 수준의 로깅 변경](https://stackoverflow.com/questions/21638697/disable-maven-download-progress-indication)을(를) 참조하세요.

- `pom.xml` 파일을 찾을 위치 지정 (`-f,--file`):

  ```yaml
  package:
    script:
      - 'mvn --no-transfer-progress -f helloworld/pom.xml package'
  ```

- 사용자 설정을 찾을 위치를 지정합니다 (`-s,--settings`) ([기본 위치](https://maven.apache.org/settings.html) 대신). `-gs,--global-settings` 옵션도 있습니다:

  ```yaml
  package:
    script:
      - 'mvn -s settings/ci.xml package'
  ```

### 지원되는 CLI 명령 {#supported-cli-commands}

GitLab Maven 리포지토리는 다음 CLI 명령을 지원합니다:

{{< tabs >}}

{{< tab title="`mvn`" >}}

- `mvn deploy`: 패키지를 패키지 레지스트리에 게시합니다.
- `mvn install`: Maven 프로젝트에서 지정한 패키지를 설치합니다.
- `mvn dependency:get`: 특정 패키지를 설치합니다.

{{< /tab >}}

{{< tab title="`gradle`" >}}

- `gradle publish`: 패키지를 패키지 레지스트리에 게시합니다.
- `gradle build`: 이 프로젝트를 어셈블하고 테스트합니다.

{{< /tab >}}

{{< /tabs >}}

## 문제 해결 {#troubleshooting}

GitLab에서 Maven 패키지로 작업할 때 문제가 발생할 수 있습니다. 많은 일반적인 문제를 해결하려면 다음 단계를 시도합니다:

- 인증 확인 - 인증 토큰이 올바르고 만료되지 않았는지 확인합니다.
- 권한 확인 - 패키지를 게시하거나 설치할 권한이 있는지 확인합니다.
- Maven 설정 유효성 검사 - `settings.xml` 파일의 올바른 구성을 다시 확인합니다.
- GitLab CI/CD 로그 검토 - CI/CD 문제의 경우 작업 로그에서 오류 메시지를 주의하여 검토합니다.
- 올바른 엔드포인트 URL 확인 - 프로젝트 또는 그룹에 올바른 엔드포인트 URL을 사용하고 있는지 확인합니다.
- `mvn` 명령으로 -s 옵션 사용 - 항상 `-s` 옵션으로 Maven 명령을 실행하세요(예: `mvn package -s settings.xml`). 이 옵션이 없으면 인증 설정이 적용되지 않으며 Maven이 패키지를 찾지 못할 수 있습니다.

### 캐시 지우기 {#clear-the-cache}

성능을 개선하기 위해 클라이언트는 패키지와 관련된 파일을 캐시합니다. 문제가 발생하면 다음 명령으로 캐시를 지웁니다:

{{< tabs >}}

{{< tab title="`mvn`" >}}

```shell
rm -rf ~/.m2/repository
```

{{< /tab >}}

{{< tab title="`gradle`" >}}

```shell
rm -rf ~/.gradle/caches # Or replace ~/.gradle with your custom GRADLE_USER_HOME
```

{{< /tab >}}

{{< /tabs >}}

### 네트워크 추적 로그 검토 {#review-network-trace-logs}

Maven 리포지토리 문제가 발생하면 네트워크 추적 로그를 검토하려 할 수 있습니다. 네트워크 추적 로그를 검토하면 Maven 클라이언트가 기본적으로 포함하지 않는 더 자세한 오류 메시지가 제공됩니다.

예를 들어 `mvn deploy`를 PAT 토큰으로 로컬에서 실행하고 이러한 옵션을 사용해 봅니다:

```shell
mvn deploy \
-Dorg.slf4j.simpleLogger.log.org.apache.maven.wagon.providers.http.httpclient=trace \
-Dorg.slf4j.simpleLogger.log.org.apache.maven.wagon.providers.http.httpclient.wire=trace
```

> [!warning]
> 이러한 옵션을 설정하면 모든 네트워크 요청이 로깅되고 많은 양의 출력이 생성됩니다.

### Maven 설정 확인 {#verify-your-maven-settings}

CI/CD 내에서 `settings.xml` 파일과 관련된 문제가 발생하면 추가 스크립트 작업이나 작업을 추가하여 [유효한 설정 확인](https://maven.apache.org/plugins/maven-help-plugin/effective-settings-mojo.html)을 시도합니다.

도움말 플러그인은 [시스템 속성](https://maven.apache.org/plugins/maven-help-plugin/system-mojo.html)도 제공할 수 있습니다(환경 변수 포함):

```yaml
mvn-settings:
  script:
    - 'mvn help:effective-settings'

package:
  script:
    - 'mvn help:system'
    - 'mvn package'
```

### `401 Unauthorized` 패키지 게시 시 오류 {#401-unauthorized-error-when-trying-to-publish-a-package}

이것은 일반적으로 인증 문제를 나타냅니다. 확인:

- 인증 토큰이 유효하고 만료되지 않았습니다.
- 올바른 토큰 유형(개인 액세스 토큰, 배포 토큰 또는 CI 작업 토큰)을 사용하고 있습니다.
- 토큰에 필요한 권한이 있습니다 (`api`, `read_api` 또는 `read_repository`).
- Maven 프로젝트의 경우 mvn 명령과 함께 `-s` 옵션을 사용하고 있습니다(예: `mvn deploy -s settings.xml`). 이 옵션이 없으면 Maven이 `settings.xml` 파일에서 인증 설정을 적용하지 않아 승인 안 됨 오류가 발생합니다.

### `400 Bad Request` 메시지가 있는 오류 "유효성 검사 실패: 버전이 유효하지 않음" {#400-bad-request-error-with-message-validation-failed-version-is-invalid}

GitLab은 버전 문자열에 대한 특정 요구사항을 가지고 있습니다. 버전이 형식을 따르는지 확인합니다:

```plaintext
^(?!.*\.\.)(?!.*\.$)[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*(\+[0-9A-Za-z-]+)?$
```

예를 들어 "1.0.0", "1.0-SNAPSHOT" 및 "1.0.0-alpha"는 유효하지만 "1..0" 또는 "1.0."은(는) 그렇지 않습니다.

### `403 Forbidden` 패키지 게시 시 오류 {#403-forbidden-error-when-trying-to-publish-a-package}

`Authorization failed` 메시지와 함께 `403 Forbidden` 오류는 일반적으로 인증 또는 권한 문제를 나타냅니다. 확인:

- 올바른 토큰 유형(개인 액세스 토큰, 배포 토큰 또는 CI/CD 작업 토큰)을 사용하고 있습니다. 자세한 내용은 [패키지 레지스트리에 인증](#authenticate-to-the-package-registry)을 참조하세요.
- 토큰에 필요한 권한이 있습니다. 개발자, 유지 관리자 또는 소유자 역할이 있는 사용자만 패키지를 게시할 수 있습니다. 자세한 내용은 [GitLab 권한](../../permissions.md#project-packages-and-registries)을 참조하세요.
- 게시하는 패키지는 푸시 보호 규칙으로 보호되지 않습니다. 패키지 보호 규칙에 대한 자세한 내용은 [패키지 보호 방법](../package_registry/package_protection_rules.md#protect-a-package)을 참조하세요.

### `Artifact already exists` 게시 시 오류 {#artifact-already-exists-errors-when-publishing}

이 오류는 이미 존재하는 패키지 버전을 게시하려고 할 때 발생합니다. 해결하려면:

- 게시하기 전에 패키지 버전을 증가시킵니다.
- SNAPSHOT 버전을 사용하는 경우 구성에서 SNAPSHOT 덮어쓰기를 허용하도록 해야 합니다.

### UI에 나타나지 않는 게시된 패키지 {#published-package-not-appearing-in-the-ui}

방금 패키지를 게시한 경우 나타나는 데 몇 분이 걸릴 수 있습니다. 여전히 표시되지 않으면:

- 패키지를 볼 권한이 있는지 확인합니다.
- CI/CD 로그 또는 Maven 출력을 검토하여 패키지가 성공적으로 게시되었는지 확인합니다.
- 올바른 프로젝트 또는 그룹을 찾고 있는지 확인합니다.

### Maven 리포지토리 종속성 충돌 {#maven-repository-dependency-conflicts}

종속성 충돌은 다음을 통해 해결할 수 있습니다:

- `pom.xml`에서 명시적으로 버전을 정의합니다.
- Maven의 종속성 관리 섹션을 사용하여 버전을 제어합니다.
- `<exclusions>` 태그를 사용하여 충돌하는 전이 종속성을 제외합니다.

### `Unable to find valid certification path to requested target` 오류 {#unable-to-find-valid-certification-path-to-requested-target-error}

이것은 일반적으로 SSL 인증서 문제입니다. 해결하려면:

- JDK가 GitLab 서버의 SSL 인증서를 신뢰하는지 확인합니다.
- 자체 서명된 인증서를 사용하는 경우 JDK의 신뢰 저장소에 추가합니다.
- 마지막 수단으로 Maven 설정에서 SSL 확인을 비활성화할 수 있습니다. 프로덕션에는 권장되지 않습니다.

### `No plugin found for prefix` 파이프라인 오류 {#no-plugin-found-for-prefix-pipeline-errors}

이것은 일반적으로 Maven이 플러그인을 찾을 수 없음을 의미합니다. 수정하려면:

- 플러그인이 `pom.xml`에 올바르게 정의되어 있는지 확인합니다.
- CI/CD 구성이 올바른 Maven 설정 파일을 사용하고 있는지 확인합니다.
- 파이프라인이 필요한 모든 리포지토리에 액세스할 수 있는지 확인합니다.
