---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Slack 알림(더 이상 사용 안 함)
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

> [!warning]
> 이 기능은 GitLab 15.9에서 [더 이상 지원되지 않습니다](https://gitlab.com/gitlab-org/gitlab/-/issues/435909). 대신 [GitLab for Slack 앱](gitlab_slack_application.md)을 사용하세요.

Slack 알림 연동을 통해 GitLab 프로젝트에서 이슈 생성과 같은 이벤트를 기존 Slack 팀으로 알림으로 보낼 수 있습니다. Slack 알림을 설정하려면 Slack과 GitLab 모두에 대한 구성 변경이 필요합니다.

## Slack 구성 {#configure-slack}

1. Slack 팀에 로그인하고 [새로운 수신 WebHook 구성을 시작](https://my.slack.com/services/new/incoming-webhook)하세요.
1. 기본적으로 알림을 보낼 Slack 채널을 확인하세요. **수신 WebHook 연동 추가**를 선택하여 구성을 추가합니다.
1. **Webhook URL**을 복사하여 나중에 GitLab을 구성할 때 사용합니다.

## GitLab 구성 {#configure-gitlab}

{{< history >}}

- GitLab 15.9에서 Slack 채널을 이벤트당 10개로 제한하도록 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/106760)되었습니다.
- GitLab 19.5에서 사용하지 않은 프로젝트의 연동을 숨기도록 [변경](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/254341)되었습니다.

{{< /history >}}

**Slack 알림** 연동은 다음이 모두 참일 때 프로젝트의 **설정** > **연동** 목록에서 숨겨집니다:

- GitLab for Slack 앱이 인스턴스에 대해 활성화되어 있어서 대체 연동이 있습니다.
- 프로젝트 자체에 Slack 알림 연동이 없습니다.
- 프로젝트가 인스턴스 수준의 Slack 알림 연동을 상속하지 않습니다.

이미 Slack 알림이 구성된 프로젝트는 목록에서 계속 볼 수 있습니다. 인스턴스 수준 연동을 상속하는 프로젝트도 마찬가지입니다. 두 경우 모두 GitLab은 이전과 같이 알림을 계속 보냅니다.

Slack 알림을 구성하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **Slack 알림**을 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. **트리거** 섹션에서 Slack으로 알림으로 보낼 각 GitLab 이벤트 유형의 체크박스를 선택합니다. 전체 목록을 보려면 [Slack 알림 트리거](#triggers-for-slack-notifications)를 참고하세요. 기본적으로 메시지는 [Slack 구성](#configure-slack) 중에 구성한 채널로 전송됩니다.
1. 선택 사항. 메시지를 다른 채널, 여러 채널 또는 직접 메시지로 보내려면:
   - *채널에 메시지를 보내려면,* Slack 채널 이름을 쉼표로 구분하여 입력합니다.
   - *직접 메시지를 보내려면,* 사용자의 Slack 프로필에서 찾은 멤버 ID를 사용합니다.
1. **Webhook**에 [Slack 구성](#configure-slack) 단계에서 복사한 웹훅 URL을 입력합니다.
1. 선택 사항. **사용자명**에 알림을 보내는 Slack 봇의 사용자명을 입력합니다.
1. **잘못된 파이프라인만 알림 받기** 체크박스를 선택하여 실패 시에만 알림을 받습니다.
1. **상태 변경 시에만 알림** 체크박스를 선택하여 ref의 파이프라인 상태가 변경될 때만 알림을 보냅니다.
1. **알림을 보내야 할 브랜치** 드롭다운 목록에서 알림을 보낼 브랜치 유형을 선택합니다.
1. **알림할 레이블** 필드를 비워두면 모든 알림을 받거나, 알림을 트리거하기 위해 이슈 또는 병합 요청이 가져야 할 레이블을 추가합니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

Slack 팀이 구성된 대로 GitLab 이벤트 알림을 받기 시작합니다.

## Slack 알림 트리거 {#triggers-for-slack-notifications}

Slack 알림에 사용할 수 있는 트리거는 다음과 같습니다:

| 트리거 이름                                                              | 트리거 이벤트 |
| ------------------------------------------------------------------------- | ------------- |
| **푸시**                                                                  | 리포지토리에 푸시합니다. |
| **이슈**                                                                 | 작업 항목이 생성, 종료 또는 다시 열립니다. |
| **인시던트**                                                              | 인시던트가 생성, 종료 또는 다시 열립니다. |
| **비공개 이슈**                                                    | 기밀 작업 항목이 생성, 종료 또는 다시 열립니다. |
| **병합 요청**                                                         | 병합 요청이 생성, 병합, 승인, 종료 또는 다시 열립니다. |
| **노트**                                                                  | 댓글이 추가됩니다. |
| **비공개 메모**                                                     | 기밀 작업 항목에 대한 내부 메모 또는 댓글이 추가됩니다. |
| **태그 푸시**                                                              | 새 태그가 리포지토리에 푸시되거나 제거됩니다. |
| **파이프라인**                                                              | 파이프라인 상태가 변경되었습니다. |
| **위키 페이지**                                                             | 위키 페이지가 생성 또는 업데이트됩니다. |
| **배포**                                                            | 배포가 시작되거나 완료됩니다. |
| **경고**                                                                 | 새로운 고유 알림이 기록됩니다. |
| **[그룹 언급](#trigger-notifications-for-group-mentions) (공개)**  | 그룹이 공개 컨텍스트에서 언급됩니다. |
| **[그룹 언급](#trigger-notifications-for-group-mentions) (비공개)** | 그룹이 기밀 컨텍스트에서 언급됩니다. |
| [**취약점**](../../application_security/vulnerabilities/_index.md) | 새로운 고유 취약성이 기록됩니다. |

## 그룹 언급에 대한 트리거 알림 {#trigger-notifications-for-group-mentions}

{{< history >}}

- GitLab 16.4에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/issues/417751)되었습니다.
- 알림 트리거에 대한 제한 사항이 GitLab 18.3에서 [도입](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/134677)되었으며 [기능 플래그](../../../administration/feature_flags/_index.md)를 사용합니다. `group_mention_access_check` 기본적으로 비활성화되었습니다.

{{< /history >}}

그룹 언급에 대해 [알림 이벤트](#triggers-for-slack-notifications)를 트리거하려면 다음에서 `@<group_name>`을 사용합니다:

- 이슈 및 병합 요청 설명
- 이슈, 병합 요청 및 커밋에 대한 댓글

알림은 모든 직접 그룹 멤버가 언급된 리소스(예: 병합 요청)를 볼 수 있는 권한이 있을 때만 트리거됩니다. 알림은 이벤트당 최대 3개 그룹으로만 전송됩니다.

## 문제 해결 {#troubleshooting}

Slack 연동이 작동하지 않으면 [Sidekiq 로그](../../../administration/logs/_index.md#sidekiqlog)를 검색하여 Slack 서비스와 관련된 오류를 찾아 문제 해결을 시작합니다.

### 오류: `Something went wrong on our end` {#error-something-went-wrong-on-our-end}

GitLab UI에서 이 일반적인 오류 메시지가 표시될 수 있습니다. [로그](../../../administration/logs/_index.md#productionlog)를 검토하여 오류 메시지를 찾고 거기서부터 문제 해결을 계속합니다.

### 오류: `certificate verify failed` {#error-certificate-verify-failed}

Sidekiq 로그에서 다음과 같은 항목을 볼 수 있습니다:

```plaintext
2019-01-10_13:22:08.42572 2019-01-10T13:22:08.425Z 6877 TID-abcdefg Integrations::ExecuteWorker JID-3bade5fb3dd47a85db6d78c5 ERROR: {:class=>"Integrations::ExecuteWorker :integration_class=>"SlackService", :message=>"SSL_connect returned=1 errno=0 state=error: certificate verify failed"}
```

이 문제는 GitLab과 Slack 간 통신 또는 GitLab과 자체 간 통신에 문제가 있을 때 발생합니다. 전자는 가능성이 낮습니다. Slack 보안 인증서는 항상 신뢰되어야 하기 때문입니다.

어떤 문제가 원인인지 확인하려면:

1. Rails 콘솔을 시작합니다:

   ```shell
   sudo gitlab-rails console -e production

   # for source installs:
   bundle exec rails console -e production
   ```

1. 다음 명령을 실행합니다:

   ```ruby
   # replace <SLACK URL> with your actual Slack URL
   result = Net::HTTP.get(URI('https://<SLACK URL>'));0

   # replace <GITLAB URL> with your actual GitLab URL
   result = Net::HTTP.get(URI('https://<GITLAB URL>'));0
   ```

GitLab이 자체에 대한 HTTPS 연결을 신뢰하지 않으면 [GitLab 신뢰 인증서에 인증서 추가](https://docs.gitlab.com/omnibus/settings/ssl/#install-custom-public-certificates)를 참고합니다.

GitLab이 Slack 연결을 신뢰하지 않으면 GitLab OpenSSL 신뢰 저장소가 잘못된 것입니다. 일반적인 원인은 다음과 같습니다:

- `gitlab_rails['env'] = {"SSL_CERT_FILE" => "/path/to/file.pem"}`로 신뢰 저장소를 재정의합니다.
- 기본 CA 번들 `/opt/gitlab/embedded/ssl/certs/cacert.pem`을 실수로 수정합니다.

### Slack 알림 연동 비활성화를 위한 일괄 업데이트 {#bulk-update-to-disable-the-slack-notification-integration}

Slack 연동이 활성화된 모든 프로젝트의 알림을 비활성화하려면 [Rails 콘솔 세션을 시작](../../../administration/operations/rails_console.md#starting-a-rails-console-session)하고 다음과 유사한 스크립트를 사용합니다:

> [!warning]
> 데이터를 변경하는 명령은 올바르게 실행되지 않거나 올바른 조건 하에서 실행되지 않으면 손상을 야기할 수 있습니다. 항상 테스트 환경에서 먼저 명령을 실행하고 복원할 준비가 된 백업 인스턴스가 있어야 합니다.

```ruby
# Grab all projects that have the Slack notifications enabled
p = Project.find_by_sql("SELECT p.id FROM projects p LEFT JOIN integrations s ON p.id = s.project_id WHERE s.type_new = 'Integrations::Slack' AND s.active = true")

# Disable the integration on each of the projects that were found.
p.each do |project|
  project.slack_integration.update!(:active, false)
end
```
