---
stage: GitLab Dedicated
group: Import
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: 사용자 정의 HTTP 콜백으로 이벤트를 전송하는 데 사용됩니다.
title: 웹후크 문제 해결
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab 웹후크의 일반적인 문제를 해결하고 해결합니다.

## 웹후크 디버깅 {#debug-webhooks}

다음 방법을 사용하여 GitLab 웹후크를 디버깅하고 페이로드를 캡처합니다:

- [공개 웹후크 검사 도구](#use-public-webhook-inspection-tools)
- [웹후크 요청 및 응답 세부 정보](webhooks.md#inspect-request-and-response-details)
- [GitLab Development Kit (GDK)](#use-the-gitlab-development-kit-gdk)
- [비공개 웹후크 수신기](#create-a-private-webhook-receiver)

웹후크 이벤트 및 JSON 페이로드에 대한 자세한 내용은 [웹후크 이벤트](webhook_events.md)를 참조하세요.

### 공개 웹후크 검사 도구 사용 {#use-public-webhook-inspection-tools}

공개 도구를 사용하여 웹후크 페이로드를 검사하고 테스트합니다. 이러한 도구는 HTTP 요청에 대한 catch-all 엔드포인트를 제공하고 `200 OK` 상태 코드로 응답합니다.

> [!warning]
> 공개 도구를 사용할 때는 주의하세요. 외부 서비스에 민감한 데이터를 전송할 수 있습니다. 테스트 토큰을 사용하고 실수로 제3자에게 전송된 모든 암호를 순환시킵니다. 향상된 개인 정보 보호를 위해 [비공개 웹후크 수신기를 만듭니다](#create-a-private-webhook-receiver).

공개 웹후크 검사 도구는 다음과 같습니다:

<!-- vale gitlab_base.Spelling = NO -->
- [Beeceptor](https://beeceptor.com): 임시 HTTPS 엔드포인트를 만들고 수신 페이로드를 검사합니다.
<!-- vale gitlab_base.Spelling = YES -->
- [Webhook.site](https://webhook.site): 수신 페이로드를 검토합니다.
- [Webhook Tester](https://webhook-test.com): 수신 페이로드를 검사하고 디버깅합니다.

### GitLab Development Kit (GDK) 사용 {#use-the-gitlab-development-kit-gdk}

더 안전한 개발 환경을 위해 [GitLab Development Kit (GDK)](https://gitlab.com/gitlab-org/gitlab-development-kit)를 사용하여 GitLab 웹후크를 로컬에서 작업합니다. GDK를 사용하여 로컬 GitLab 인스턴스에서 웹후크를 머신의 웹후크 수신기로 전송합니다.

이 방법을 사용하려면 GDK를 설치 및 구성합니다.

### 비공개 웹후크 수신기 만들기 {#create-a-private-webhook-receiver}

웹후크 페이로드를 [공개 수신기](#use-public-webhook-inspection-tools)로 전송할 수 없는 경우 고유한 비공개 웹후크 수신기를 만듭니다.

사전 요구 사항:

- 시스템에 Ruby가 설치되어 있습니다.

비공개 웹후크 수신기를 만들려면:

1. 이 스크립트를 `print_http_body.rb`로 저장합니다:

   ```ruby
   require 'webrick'

   server = WEBrick::HTTPServer.new(:Port => ARGV.first)
   server.mount_proc '/' do |req, res|
     puts req.body
   end

   trap 'INT' do
     server.shutdown
   end
   server.start
   ```

1. 사용하지 않는 포트(예: `8000`)를 선택하고 스크립트를 시작합니다:

   ```shell
   ruby print_http_body.rb 8000
   ```

1. GitLab에서 [웹후크를 구성](webhooks.md#configure-webhooks)하고 수신기의 URL(예: `http://receiver.example.com:8000/`)을 입력합니다.
1. **테스트**를 선택합니다. 다음과 유사한 출력이 표시됩니다:

   ```plaintext
   {"before":"077a85dd266e6f3573ef7e9ef8ce3343ad659c4e","after":"95cd4a99e93bc4bbabacfa2cd10e6725b1403c60",<SNIP>}
   example.com - - [14/May/2014:07:45:26 EDT] "POST / HTTP/1.1" 200 0
   - -> /
   ```

> [!note]
> 이 수신기를 추가하려면 [로컬 네트워크에 대한 요청을 허용](../../../security/webhooks.md)해야 할 수도 있습니다.

## SSL 인증서 검증 오류 해결 {#resolve-ssl-certificate-verification-errors}

SSL 검증을 사용하면 GitLab이 웹후크 엔드포인트의 SSL 인증서 검증을 실패할 수 있습니다. 다음 오류가 표시됩니다:

```plaintext
unable to get local issuer certificate
```

이 오류는 일반적으로 루트 인증서가 [CAcert.org](http://www.cacert.org/)에서 결정한 신뢰할 수 있는 인증 기관에서 발급되지 않았을 때 발생합니다.

이 이슈를 해결하려면:

1. [SSL Checker](https://www.sslshopper.com/ssl-checker.html)를 사용하여 특정 오류를 식별합니다.
1. 누락된 중간 인증서를 확인하는 것이 검증 실패의 일반적인 원인입니다.

## 웹후크가 트리거되지 않음 {#webhook-not-triggered}

웹후크가 트리거되지 않으면 다음을 확인합니다:

- 웹후크가 [자동으로 비활성화](webhooks.md#auto-disabled-webhooks)되지 않았습니다.
- GitLab 인스턴스가 [Silent Mode](../../../administration/silent_mode/_index.md)에 없습니다.
- **Push 이벤트 활동 제한** 및 **Push 이벤트 훅 제한** 설정이 [**운영자** 영역](../../../administration/settings/push_event_activities_limit.md)에서 `0`보다 큰 값으로 설정되어 있습니다.

## 오류: `Webhook rate limit exceeded` {#error-webhook-rate-limit-exceeded}

웹후크는 속도 제한으로 인해 실패할 수 있습니다. GitLab.com은 각 최상위 네임스페이스에 대해 분당 웹후크 호출의 총 수를 제한합니다. 자세한 내용은 [속도 제한](../../gitlab_com/_index.md#rate-limits)을 참조하세요.

속도 제한이 문제인지 확인하려면:

1. GitLab 로그에서 메시지 `Webhook rate limit exceeded`을 확인합니다.
1. 웹후크를 트리거하는 이벤트의 수를 줄이거나 GitLab 지원 팀에 문의하여 속도 제한 요구 사항을 논의합니다.

## 따옴표가 없는 자리 표시자가 있는 사용자 정의 웹후크 템플릿을 저장할 수 없음 {#custom-webhook-template-with-unquoted-placeholders-cannot-be-saved}

GitLab 18.8~18.10에서 [사용자 정의 웹후크 템플릿](webhooks.md#custom-webhook-template)에 따옴표가 없는 페이로드 필드를 저장할 수 없습니다. 이 문제는 GitLab 18.11에서 해결되었습니다. 해결 방법으로 필드를 따옴표로 묶거나 GitLab 18.11 이상으로 업그레이드합니다. 예를 들어 `{"value": {{id}}}`은 `{"value": "{{id}}"}`이 됩니다.

따옴표가 붙은 필드는 숫자 값 대신 문자열 값을 생성합니다. 이것이 웹후크와 호환되지 않고 변경해야 하는 경우 업그레이드하는 것이 좋습니다.

## 거부 후 중복 배포 실패 경고 {#duplicate-deployment-failure-alerts-after-a-rejection}

[보호 환경](../../../ci/environments/deployment_approvals.md)에 대한 배포가 거부되면 GitLab은 `status: "rejected"` 웹후크를 전송하고, 배포 작업이 중단될 때 동일한 `deployment_id`에 대해 `status: "failed"` 웹후크를 전송합니다. `failed` 이벤트는 기존 수명 주기 이벤트이며 승인 필드를 포함하지 않으므로, `status: "failed"`에 경고를 보내는 수신기는 의도적으로 거부된 배포에 대해 중복 경고를 발생시킬 수 있습니다.

중복 경고를 방지하려면:

1. `deployment_id`별로 이벤트를 상관 관계를 만들고 동일한 배포에 대해 `status: "rejected"` 이벤트 다음에 오는 `status: "failed"` 이벤트를 동일한 이벤트로 처리합니다.
1. 거부 기인 실패와 실제 실패를 구별하려면 `status: "rejected"` 이벤트를 수신 대기하고 거부된 배포 ID를 저장합니다. `status: "failed"` 이벤트가 도착하면 해당 `deployment_id`이 해당 집합에 있으면 경고를 표시하지 않습니다.
