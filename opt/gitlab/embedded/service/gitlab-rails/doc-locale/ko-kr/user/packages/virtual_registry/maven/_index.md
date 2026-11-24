---
stage: Package
group: Package Registry
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Maven 가상 레지스트리
description: Maven 가상 레지스트리를 사용하여 여러 개인 및 공개 업스트림 레지스트리를 구성하고 관리합니다.
---

{{< details >}}

- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated
- 상태:  베타

{{< /details >}}

{{< history >}}

- GitLab 18.0에서 `virtual_registry_maven` [기능 플래그](../../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/14137)되었습니다. 기본적으로 비활성화되었습니다.
- 기능 플래그가 GitLab 18.1에서 `maven_virtual_registry`로 [이름 변경](https://gitlab.com/gitlab-org/gitlab/-/issues/540276)되었습니다.
- GitLab 18.1에서 실험에서 베타로 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/540276)되었습니다.
- GitLab 18.2에서 [GitLab.com, GitLab Self-Managed 및 GitLab Dedicated에서 활성화](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/197432)되었습니다.

{{< /history >}}

> [!flag]
> 이 기능의 사용 가능성은 기능 플래그로 제어합니다. 자세한 내용은 기록을 참조하세요. 이 기능은 [베타](../../../../policy/development_stages_support.md#beta)에서 사용할 수 있습니다. 이 기능을 사용하기 전에 설명서를 주의 깊게 검토하세요.

Maven 가상 레지스트리는 단일의 잘 알려진 URL을 사용하여 GitLab의 여러 외부 레지스트리에서 패키지를 관리하고 배포합니다.

Maven 가상 레지스트리를 사용하여 다음을 수행할 수 있습니다:

- 가상 레지스트리를 생성합니다.
- 가상 레지스트리를 공개 및 개인 업스트림 레지스트리에 연결합니다.
- 구성된 업스트림에서 패키지를 가져오도록 Maven 클라이언트를 구성합니다.
- 사용 가능한 업스트림에 대한 캐시 항목을 관리합니다.

이 방식은 시간이 지남에 따라 더 나은 패키지 성능을 제공하며, Maven 패키지를 관리하기가 더 쉬워집니다.

가상 레지스트리 및 업스트림 레지스트리 관리에 대한 일반 정보는 [가상 레지스트리](../_index.md)를 참조하세요.

## 사전 요구 사항 {#prerequisites}

Maven 가상 레지스트리를 사용하기 전에 다음을 수행합니다:

- [전제 조건](../_index.md#prerequisites)을 검토하여 가상 레지스트리를 사용합니다.
- 가상 레지스트리에 대한 인증을 구성합니다. 자세한 내용은 [가상 레지스트리에 인증](../_index.md#authenticate-to-the-virtual-registry)을 참조하세요.
- GitLab Self-Managed:  로컬 네트워크에 대한 아웃바운드 요청을 허용합니다. 자세한 내용은 [로컬 네트워크에 대한 요청 허용](../../../../security/webhooks.md#allow-requests-to-the-local-network-from-webhooks-and-integrations)을 참조하세요.

Maven 가상 레지스트리를 사용할 때 다음 제한 사항을 기억하세요:

- 최상위 그룹당 최대 `20` Maven 가상 레지스트리를 생성할 수 있습니다.
- 지정된 Maven 가상 레지스트리에만 `20` 업스트림을 설정할 수 있습니다.
- 기술적 이유로 `proxy_download` 설정은 강제로 활성화되어 있으며, [객체 저장소 구성](../../../../administration/object_storage.md#proxy-download)에서 구성된 값이 무엇이든 관계없이 활성화됩니다.
- Geo 지원은 구현되지 않았습니다. [이슈 473033](https://gitlab.com/gitlab-org/gitlab/-/issues/473033)에서 개발을 추적할 수 있습니다.

## 가상 레지스트리 관리 {#manage-virtual-registries}

{{< history >}}

- GitLab 18.5에서 `ui_for_virtual_registries`라는 [기능 플래그](../../../../administration/feature_flags/_index.md)로 [도입](https://gitlab.com/groups/gitlab-org/-/epics/15090)되었습니다. 기본적으로 활성화됩니다.
- GitLab 18.6에서 `maven_virtual_registry` 이름의 플래그로 [변경](https://gitlab.com/gitlab-org/gitlab/-/issues/525934)되었습니다. 기본적으로 활성화됩니다. 기능 플래그 `ui_for_virtual_registries`이 제거되었습니다.

{{< /history >}}

그룹의 Maven 가상 레지스트리를 관리합니다.

[API 사용](../../../../api/maven_virtual_registries.md#manage-maven-virtual-registries)을 할 수도 있습니다.

### Maven 가상 레지스트리 생성 {#create-a-maven-virtual-registry}

Maven 가상 레지스트리를 생성하려면 다음을 수행합니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 레벨에 있어야 합니다.
1. **배포** > **가상 레지스트리**를 선택합니다.
1. 다음 조건에 해당하는 경우:
   - 기존 레지스트리가 있으면 **레지스트리 생성**을 선택합니다. 드롭다운 목록에서 **Maven**을 선택합니다.
   - 기존 레지스트리가 없으면 드롭다운 목록에서 **Maven**을 선택합니다. 그런 다음 **레지스트리 생성**을 선택합니다.
1. **이름**과 선택적 **설명**을 입력합니다.
1. **레지스트리 생성**을 선택합니다.

## 업스트림 레지스트리 관리 {#manage-upstream-registries}

가상 레지스트리에서 업스트림 Maven 레지스트리를 관리합니다.

### Maven 업스트림 레지스트리 생성 {#create-a-maven-upstream-registry}

가상 레지스트리에 연결할 Maven 업스트림 레지스트리를 생성합니다.

사전 요구 사항:

- Maven 가상 레지스트리가 있어야 합니다. 자세한 내용은 [가상 레지스트리 생성](#create-a-maven-virtual-registry)을 참조하세요.

Maven 업스트림 레지스트리를 생성하려면 다음을 수행합니다:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 그룹을 찾습니다. 이 그룹은 최상위 레벨에 있어야 합니다.
1. **배포** > **가상 레지스트리**를 선택합니다.
1. **레지스트리 유형**에서 **레지스트리 보기**를 선택합니다.
1. **레지스트리** 탭에서 레지스트리를 선택합니다.
1. **업스트림 추가**를 선택합니다. 가상 레지스트리에 기존 업스트림이 있으면 드롭다운 목록에서 다음 중 하나를 선택합니다:
   - **새 업스트림 생성**을 클릭하여 업스트림을 구성합니다.
   - **기존 업스트림 링크** > **기존 업스트림 선택**.
     1. 드롭다운 목록에서 업스트림을 선택합니다.
     1. 선택 사항. **업스트림 테스트**를 선택하여 업스트림을 생성하기 전에 업스트림 연결을 테스트합니다.
     1. **업스트림 추가**를 선택합니다.
1. 필드를 완성하세요.
   - **사용자명**과 **암호**를 모두 포함하거나 둘 다 포함하지 않습니다. 설정하지 않으면 공개(익명) 요청을 사용하여 업스트림에 액세스합니다.
   - 업스트림을 Maven Central에 연결하려면 **업스트림 URL**로 다음을 사용합니다:

      ```plaintext
      https://repo1.maven.org/maven2
      ```

   - **아티팩트 캐싱 기간**과 **메타데이터 캐싱 기간**은 기본값이 24시간입니다. `0`로 설정하여 캐시 항목 검사를 비활성화하거나 Maven Central을 사용 중인 경우입니다.
   - 업스트림을 생성하기 전에 업스트림 연결을 테스트하려면 **업스트림 테스트**를 선택합니다.

1. **업스트림 생성**을 선택합니다.

캐시 유효성 설정에 대한 자세한 내용은 [캐시 유효성 기간 설정](../_index.md#set-the-cache-validity-period)을 참조하세요.

## Maven 가상 레지스트리 사용 {#use-the-maven-virtual-registry}

가상 레지스트리를 생성한 후 가상 레지스트리를 통해 종속성을 가져오도록 Maven 클라이언트를 구성해야 합니다.

### Maven 클라이언트 구성 {#configure-maven-clients}

Maven 가상 레지스트리는 다음 Maven 클라이언트를 지원합니다:

- [`mvn`](https://maven.apache.org/index.html)
- [`gradle`](https://gradle.org/)
- [`sbt`](https://www.scala-sbt.org/)

Maven 클라이언트 구성에서 가상 레지스트리를 선언해야 합니다.

모든 클라이언트는 인증해야 합니다. 클라이언트 인증의 경우 사용자 지정 HTTP 헤더 또는 기본 인증을 사용할 수 있습니다. 각 클라이언트에 대해 아래의 구성 중 하나를 사용해야 합니다.

{{< tabs >}}

{{< tab title="mvn" >}}

| 토큰 유형            | 이름은 다음이어야 합니다    | 토큰                                                                   |
| --------------------- | --------------- | ----------------------------------------------------------------------- |
| 개인 액세스 토큰 | `Private-Token` | 토큰을 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| 그룹 배포 토큰    | `Deploy-Token`  | 토큰을 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| 그룹 액세스 토큰    | `Private-Token` | 토큰을 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| CI/CD 작업 토큰          | `Job-Token`     | `${CI_JOB_TOKEN}`                                                       |
| OAuth 2.0 토큰       | `Authorization` | `Bearer <your_oauth_token>`                                             |

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

`mvn` 애플리케이션에서 가상 레지스트리를 다음 두 가지 방법 중 하나로 구성할 수 있습니다:

- 기본 레지스트리(Maven central) 위에 추가 레지스트리로 사용합니다. 이 구성에서는 가상 레지스트리와 기본 레지스트리에 모두 있는 프로젝트 종속성을 선언된 레지스트리 중 하나에서 가져올 수 있습니다.
- 기본 레지스트리(Maven central)의 대체로 사용합니다. 이 구성에서는 종속성이 가상 레지스트리를 통해 가져와집니다. 필수 공개 종속성을 누락하지 않도록 Maven central을 가상 레지스트리의 마지막 업스트림으로 구성해야 합니다.

Maven 가상 레지스트리를 추가 레지스트리로 구성하려면 `pom.xml` 파일에 `repository` 요소를 추가합니다:

```xml
<repositories>
  <repository>
    <id>gitlab-maven</id>
    <url>https://gitlab.example.com/api/v4/virtual_registries/packages/maven/<registry_id></url>
  </repository>
</repositories>
```

- `<id>`: `settings.xml`에서 사용되는 `<server>`와 동일한 ID입니다.
- `<registry_id>`: Maven 가상 레지스트리의 ID입니다.

Maven 가상 레지스트리를 기본 레지스트리의 대체로 구성하려면 `settings.xml`에서 `mirrors` 요소를 추가합니다:

```xml
<settings>
  <servers>
    ...
  </servers>
  <mirrors>
    <mirror>
      <id>central-proxy</id>
      <name>GitLab proxy of central repo</name>
      <url>https://gitlab.example.com/api/v4/virtual_registries/packages/maven/<registry_id></url>
      <mirrorOf>central</mirrorOf>
    </mirror>
  </mirrors>
</settings>
```

- `<registry_id>`: Maven 가상 레지스트리의 ID입니다.

{{< /tab >}}

{{< tab title="gradle" >}}

| 토큰 유형            | 이름은 다음이어야 합니다    | 토큰                                                                   |
| --------------------- | --------------- | ----------------------------------------------------------------------- |
| 개인 액세스 토큰 | `Private-Token` | 토큰을 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| 그룹 배포 토큰    | `Deploy-Token`  | 토큰을 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| 그룹 액세스 토큰    | `Private-Token` | 토큰을 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| CI/CD 작업 토큰          | `Job-Token`     | `${CI_JOB_TOKEN}`                                                       |
| OAuth 2.0 토큰       | `Authorization` | `Bearer <your_oauth_token>`                                             |

[`GRADLE_USER_HOME` 디렉터리](https://docs.gradle.org/current/userguide/directory_layout.html#dir:gradle_user_home)에서 `gradle.properties` 파일을 다음 내용으로 생성합니다:

```properties
gitLabPrivateToken=REPLACE_WITH_YOUR_TOKEN
```

`repositories` 섹션을 [`build.gradle`](https://docs.gradle.org/current/userguide/tutorial_using_tasks.html)에 추가합니다.

- Groovy DSL:

  ```groovy
  repositories {
      maven {
          url "https://gitlab.example.com/api/v4/virtual_registries/packages/maven/<registry_id>"
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
          url = uri("https://gitlab.example.com/api/v4/virtual_registries/packages/maven/<registry_id>")
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

- `<registry_id>`: Maven 가상 레지스트리의 ID입니다.

{{< /tab >}}

{{< tab title="sbt" >}}

| 토큰 유형            | 사용자명은 다음이어야 합니다                                        | 토큰                                                                   |
| --------------------- | ------------------------------------------------------- | ----------------------------------------------------------------------- |
| 개인 액세스 토큰 | 사용자의 사용자명                                | 토큰을 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| 그룹 배포 토큰    | 배포 토큰의 사용자명                            | 토큰을 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| 그룹 액세스 토큰    | 액세스 토큰에 연결된 사용자의 사용자명     | 토큰을 그대로 붙여넣거나 토큰을 보관할 환경 변수를 정의합니다. |
| CI/CD 작업 토큰          | `gitlab-ci-token`                                       | `sys.env.get("CI_JOB_TOKEN").get`                                       |

[SBT](https://www.scala-sbt.org/index.html) 인증은 [기본 HTTP 인증](https://developer.mozilla.org/en-US/docs/Web/HTTP/Authentication)을 기반으로 합니다. 이름과 암호를 제공해야 합니다.

[`build.sbt`](https://www.scala-sbt.org/1.x/docs/Directories.html#sbt+build+definition+files)에서 다음 줄을 추가합니다:

```scala
resolvers += ("gitlab" at "<endpoint_url>")

credentials += Credentials("GitLab Virtual Registry", "<host>", "<username>", "<token>")
```

- `<endpoint_url>`: Maven 가상 레지스트리 URL입니다. 예를 들어 `https://gitlab.example.com/api/v4/virtual_registries/packages/maven/<registry_id>`, 여기서 `<registry_id>`은 Maven 가상 레지스트리의 ID입니다.
- `<host>`: `<endpoint_url>`에 있는 프로토콜 체계나 포트 없이 호스트입니다. 예를 들어, `gitlab.example.com`입니다.
- `<username>`: 사용자명입니다.
- `<token>`: 구성된 토큰입니다.

`Credentials`의 첫 번째 인수가 `"GitLab Virtual Registry"`인지 확인합니다. 이 영역 이름은 Maven 가상 레지스트리에서 보낸 [기본 인증 영역](https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Authentication#www-authenticate_and_proxy-authenticate_headers)과 정확히 일치해야 합니다.

{{< /tab >}}

{{< /tabs >}}

## 문제 해결 {#troubleshooting}

Maven 가상 레지스트리로 작업할 때 다음 문제가 발생할 수 있습니다.

### 오류: `Connect to gitlab.example.com:443 failed: Connection timed out` {#error-connect-to-gitlabexamplecom443-failed-connection-timed-out}

가상 레지스트리를 통해 Maven 종속성을 가져올 때 간헐적인 연결 시간 초과 오류가 발생할 수 있습니다:

```plaintext
Connect to gitlab.example.com:443 failed: Connect timed out
```

이 문제는 업스트림 레지스트리 URL이 로컬 네트워크 주소로 확인되는 GitLab Self-Managed 인스턴스에서 발생할 수 있습니다. 기본적으로 GitLab은 보안상의 이유로 로컬 네트워크 주소에 대한 아웃바운드 요청을 차단합니다.

이 이슈를 해결하려면:

1. 오른쪽 위 모서리에서 **Admin**을 선택합니다.
1. 왼쪽 사이드바에서 **설정 > 네트워크**를 선택합니다.
1. **아웃바운드 요청**을 확장합니다.
1. **Webhook 및 통합에서 로컬 네트워크에 대한 요청 허용** 확인란을 선택합니다.
1. 선택 사항. 모든 로컬 네트워크 요청 대신 특정 주소만 허용하려면 **후크 및 통합이 액세스할 수 있는 로컬 IP 주소 및 도메인 이름**에서 업스트림 레지스트리의 호스트명 또는 IP 주소를 추가합니다.
1. **변경 사항 저장**을 선택합니다.

자세한 내용은 [로컬 네트워크에 대한 요청 허용](../../../../security/webhooks.md#allow-requests-to-the-local-network-from-webhooks-and-integrations)을 참조하세요.
