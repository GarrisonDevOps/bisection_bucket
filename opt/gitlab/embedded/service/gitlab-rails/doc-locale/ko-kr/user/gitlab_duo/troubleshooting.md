---
stage: AI Platform
group: AI Model Services
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: GitLab Duo 문제 해결
---

GitLab Duo로 작업할 때 문제가 발생할 수 있습니다.

[상태 점검 실행](../../administration/gitlab_duo/configure/_index.md#run-a-health-check-for-gitlab-duo)으로 시작하여 인스턴스가 GitLab Duo를 사용하기 위한 요구 사항을 충족하는지 확인합니다.

GitLab Duo 문제 해결에 대한 자세한 내용을 보려면 다음을 참조하세요:

- [코드 제안 문제 해결](../project/repository/code_suggestions/troubleshooting.md).
- [GitLab Duo Chat 문제 해결](../gitlab_duo_chat/troubleshooting.md).
- [GitLab Duo 자체 호스팅 문제 해결](../../administration/gitlab_duo_self_hosted/troubleshooting.md).

상태 점검으로 문제가 해결되지 않으면 다음 문제 해결 단계를 검토합니다.

## GitLab Duo 기능이 자체 관리 인스턴스에서 작동하지 않음 {#gitlab-duo-features-do-not-work-on-self-managed}

[GitLab Duo 기능이 켜져 있는지](turn_on_off.md) 확인하는 것 외에도 다음을 수행할 수 있습니다:

1. 관리자로서 GitLab Duo의 상태 점검을 실행합니다.

   {{< tabs >}}

   {{< tab title="17.5 이상" >}}

   GitLab 17.5 이상에서는 UI를 사용하여 상태 점검을 실행하고 문제를 파악하고 해결하는 데 도움이 되는 자세한 보고서를 다운로드할 수 있습니다.

   {{< /tab >}}

   {{< tab title="17.4" >}}

   GitLab 17.4에서는 상태 점검 Rake 작업을 실행하여 문제를 파악하고 해결하는 데 도움이 되는 자세한 보고서를 생성할 수 있습니다.

   ```shell
   sudo gitlab-rails 'cloud_connector:health_check(root,report.json)'
   ```

   {{< /tab >}}

   {{< tab title="17.3 이전" >}}

   GitLab 17.3 이하에서는 `health_check` 스크립트를 다운로드하고 실행하여 문제를 파악하고 해결하는 데 도움이 되는 자세한 보고서를 생성할 수 있습니다.

   1. 상태 점검 스크립트를 다운로드합니다:

      ```shell
      wget https://gitlab.com/gitlab-org/gitlab/-/snippets/3734617/raw/main/health_check.rb
      ```

   1. Rails Runner를 사용하여 스크립트를 실행합니다:

      ```shell
      gitlab-rails runner [full_path/to/health_check.rb] --debug --username [username] --output-file [report.txt]
      ```

      ```shell
      Usage: gitlab-rails runner full_path/to/health_check.rb
             --debug                Enable debug mode
             --output-file FILE     Write a report to FILE
             --username USERNAME    Provide a username to test seat assignments
             --skip [CHECK]         Skip specific check (options: access_data, token, license, host, features, end_to_end)
      ```

   {{< /tab >}}

   {{< /tabs >}}

1. GitLab 인스턴스가 [필요한 GitLab.com 끝점](../../administration/gitlab_duo/configure/_index.md)에 도달할 수 있는지 확인합니다. `curl`과 같은 명령줄 도구를 사용하여 연결을 확인할 수 있습니다.

   ```shell
   curl --verbose "https://cloud.gitlab.com"

   curl --verbose "https://customers.gitlab.com"
   ```

   HTTP/S 프록시가 GitLab 인스턴스에 대해 구성된 경우 `proxy` 매개 변수를 `curl` 명령에 포함합니다.

   ```shell
   # https proxy for curl
   curl --verbose --proxy "http://USERNAME:PASSWORD@example.com:8080" "https://cloud.gitlab.com"
   curl --verbose --proxy "http://USERNAME:PASSWORD@example.com:8080" "https://customers.gitlab.com"
   ```

1. 선택 사항. GitLab 애플리케이션과 공용 인터넷 사이에 [프록시 서버](../../administration/gitlab_duo/configure/_index.md#allow-outbound-connections-from-the-gitlab-instance-to-gitlab-duo)를 사용하는 경우 [DNS 리바인딩 보호를 비활성화합니다](../../security/webhooks.md#enforce-dns-rebinding-attack-protection).

1. [구독 데이터를 수동으로 동기화합니다](../../subscriptions/manage_subscription.md#manually-synchronize-subscription-data).
   - GitLab 인스턴스가 [구독 데이터를 GitLab과 동기화](https://about.gitlab.com/pricing/licensing-faq/cloud-licensing/)하는지 확인합니다.

## 오류: `Webview didn't initialize in 10000ms` {#error-webview-didnt-initialize-in-10000ms}

VS Code Remote SSH 또는 WSL 세션에서 GitLab Duo Chat을 사용할 때 이 오류가 발생할 수 있습니다. 확장이 `127.0.0.1` 주소에 잘못 연결되려고 시도할 수도 있습니다.

이 문제는 원격 환경이 GitLab VS Code Extension 6.8.0 이상에서 하드코딩된 10초 제한 시간을 초과하는 지연을 도입할 때 발생합니다.

이 이슈를 해결하려면:

1. VS Code에서 설정 편집기를 엽니다.
   - macOS의 경우 <kbd>Command</kbd>+<kbd>,</kbd>를 누릅니다.
   - Windows 또는 Linux의 경우 <kbd>Control</kbd>+<kbd>,</kbd>를 누릅니다.
1. **설정 열기(JSON)**을 선택하여 `settings.json` 파일을 편집합니다. 또는 <kbd>F1</kbd> 키를 누르고 **기본 설정: 설정 열기(JSON)**을 선택합니다.
1. 이 설정을 추가합니다:

   ```json
   "gitlab.featureFlags.languageServerWebviews": false
   ```

1. VS Code를 저장하고 다시 로드합니다.

## GitLab Dedicated에서 GitLab Duo 문제 해결 {#troubleshooting-gitlab-duo-on-gitlab-dedicated}

GitLab Duo Core는 Premium 및 Ultimate 고객을 위해 GitLab 18.3 이상에서 기본적으로 작동해야 하며, GitLab Duo Non-Agentic Chat을 제외한 모든 GitLab Duo 기능에 대해 작동합니다.

사전 프로덕션 GitLab Dedicated 인스턴스는 설계상 GitLab Duo Core를 지원하지 않습니다.

### GitLab Duo 설정이 관리자 영역에 표시되지 않음 {#gitlab-duo-settings-not-visible-in-admin-area}

하나 이상의 다음 문제가 발생할 수 있습니다:

- **GitLab Duo** 섹션이 관리자 영역에 나타나지 않습니다.
- 구성 옵션이 없습니다.
- API 호출이 `"addOnPurchases": []`을 반환합니다.

이러한 문제는 라이선스가 인스턴스와 제대로 동기화되지 않을 때 발생합니다.

이 문제를 해결하려면 지원 티켓을 만들어 라이선스 동기화를 확인합니다. 지원팀이 동기화 상태를 확인하고 필요한 경우 새 라이선스를 생성하도록 요청할 수 있습니다.

### 오류: `GitLab-workflow failed: the GitLab Language server failed to start in 10 seconds` {#error-gitlab-workflow-failed-the-gitlab-language-server-failed-to-start-in-10-seconds}

Web IDE가 로드되지 않을 때 이 오류가 발생할 수 있습니다. `Platform is missing!`에 대한 콘솔 오류도 표시될 수 있습니다

이 문제는 `cloud.gitlab.com` 및 `customers.gitlab.com`에 대한 네트워크 연결이 네트워크 구성에 의해 차단될 때 발생합니다.

이 이슈를 해결하려면:

1. `cloud.gitlab.com:443` 및 `customers.gitlab.com:443`에 대한 아웃바운드 연결을 확인합니다.
1. [Cloudflare IP 범위](https://www.cloudflare.com/ips/)를 필요한 경우 허용 목록에 추가합니다.
1. [개인 링크](../../administration/dedicated/configure_instance/network_security.md#aws-privatelink-connectivity)를 사용하여 허용 목록 또는 방화벽 제한을 확인합니다.
1. [아웃바운드 요청 필터링](../../security/webhooks.md#gitlab-duo-functionality-is-blocked)을 따라 연결 문제를 해결합니다.
1. 인스턴스에서 연결을 테스트합니다.

### 오류: `Unable to resolve resource` {#error-unable-to-resolve-resource}

Web IDE가 로드되지 않을 때 이 오류가 발생할 수 있습니다. CORS 오류에 대한 브라우저 로그를 확인합니다: `failed to load because it violates the following Content Security policy`.

이 문제는 CORS 정책이 필요한 리소스를 차단할 때 발생합니다.

이 이슈를 해결하려면:

1. GitLab for VS Code 버전 6.35.1 이상으로 업데이트합니다.
1. `https://*.cdn.web-ide.gitlab-static.net`을 CORS 정책에 추가합니다.
1. 추가 문제 해결을 위해 로그에 대한 HAR 파일을 확인합니다. 자세한 내용은 [HAR 파일 생성](../application_security/api_fuzzing/create_har_files.md)을 참조하세요.

자세한 내용은 [CORS 문제](../project/web_ide/_index.md#cors-issues)를 참조하세요.

## 사용자가 GitLab Duo 기능을 사용할 수 없음 {#gitlab-duo-features-not-available-for-users}

[GitLab Duo 기능을 켜는 것](turn_on_off.md) 외에도 다음을 수행할 수 있습니다:

- GitLab Duo Core가 있으면 다음을 확인합니다:
  - Premium 또는 Ultimate 구독.
  - [IDE 기능을 켰습니다](turn_on_off.md#turn-gitlab-duo-core-on-or-off).
  > [!note]
  > GitLab Duo Non-Agentic Chat은 GitLab Duo Core 사용자가 사용할 수 없습니다.
- GitLab Duo Pro 또는 Enterprise가 있으면:
  - [구독 추가 기능이 구매되었는지](../../subscriptions/subscription-add-ons.md#purchase-gitlab-duo) 확인합니다.
  - [사용자에게 좌석을 할당했는지](../../subscriptions/subscription-add-ons.md#assign-gitlab-duo-seats) 확인합니다.
- IDE의 경우:
  - [확장](../project/repository/code_suggestions/set_up.md#configure-an-editor-extension) 또는 플러그인이 최신 상태인지 확인합니다.
  - 상태 점검을 실행하고 인증을 테스트합니다.
