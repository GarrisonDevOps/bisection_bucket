---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: Service Desk
description: "Service Desk를 사용하여 고객 버그 보고서, 기능 요청 및 피드백을 이메일로 GitLab 티켓으로 받을 수 있으며, 고객이 GitLab 계정을 보유할 필요가 없습니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

> [!note]
> 이 기능은 적극적으로 개발 중이지 않지만 [커뮤니티 기여](https://about.gitlab.com/community/contribute/)를 환영합니다. 기존 설명서를 확인하거나 [Service Desk 카테고리 열린 이슈](https://gitlab.com/gitlab-org/gitlab/-/issues/?sort=updated_desc&state=opened&label_name%5B%5D=Category%3AService%20Desk&first_page_size=100)를 참조하여 아직 수행되지 않은 작업에 대해 자세히 알아보세요. Service Desk의 우선순위를 낮추기로 결정했습니다. 이는 Service Desk 카테고리도 장기적으로 이점을 얻는 작업 항목 프레임워크를 구축하고 확장하는 데 집중하기 위함입니다.
>
> Service Desk를 작업 항목 프레임워크로 이동하는 방법에 대한 자세한 내용은 [에픽 10772](https://gitlab.com/groups/gitlab-org/-/epics/10772)를 참조하세요.

Service Desk를 사용하면 고객이 버그 보고서, 기능 요청 또는 일반 피드백을 이메일로 보낼 수 있습니다. Service Desk는 고유한 이메일 주소를 제공하므로 고객이 자체 GitLab 계정을 보유할 필요가 없습니다.

Service Desk 이메일은 GitLab 프로젝트에서 새 티켓으로 생성됩니다. 팀은 프로젝트에서 직접 응답할 수 있으며, 고객은 이메일을 통해서만 스레드와 상호작용합니다.

<i class="fa-youtube-play" aria-hidden="true"></i> 비디오 개요를 보려면 [GitLab Service Desk 소개](https://www.youtube.com/watch?v=LDVQXv3I5rI)를 참조하세요.
<!-- Video published on 2023-12-19 -->

## Service Desk 워크플로우 {#service-desk-workflow}

예를 들어 iOS 또는 Android용 게임을 개발한다고 가정해봅시다. 코드베이스는 GitLab 인스턴스에서 호스팅되며 GitLab CI/CD로 빌드 및 배포됩니다.

Service Desk가 작동하는 방식은 다음과 같습니다:

1. 프로젝트별 이메일 주소를 지불 고객에게 제공하면 고객이 애플리케이션에서 직접 이메일을 보낼 수 있습니다.
1. 고객이 보내는 각 이메일은 적절한 프로젝트에 티켓을 생성합니다.
1. 팀 구성원은 Service Desk 티켓 추적기로 이동하여 새 지원 요청을 확인하고 관련 티켓 내에서 응답할 수 있습니다.
1. 팀은 고객과 소통하여 요청을 파악합니다.
1. 팀은 고객의 문제를 해결하기 위해 코드를 구현하기 시작합니다.
1. 팀이 구현을 완료하면 병합 요청이 병합되고 티켓이 자동으로 닫힙니다.

한편:

- 고객은 GitLab 인스턴스에 대한 액세스가 필요 없이 이메일을 통해서만 팀과 상호작용합니다.
- 팀은 GitLab을 떠나거나 통합을 설정할 필요 없이 고객과 후속 조치할 수 있으므로 시간을 절약합니다.

## 관련 항목 {#related-topics}

- [Service Desk 구성](configure.md)
  - [프로젝트 보안 개선](configure.md#improve-your-projects-security)
  - [외부 참여자에게 보낸 이메일 사용자 지정](configure.md#customize-emails-sent-to-external-participants)
  - [Service Desk 티켓용 사용자 지정 템플릿 사용](configure.md#use-a-custom-template-for-service-desk-tickets)
  - [Support Bot 사용자](configure.md#support-bot-user)
  - [기본 티켓 표시 여부](configure.md#default-ticket-visibility)
  - [외부 참여자가 댓글을 달 때 티켓 다시 열기](configure.md#reopen-tickets-when-an-external-participant-comments)
  - [사용자 지정 이메일 주소](configure.md#custom-email-address)
  - [추가 Service Desk 별칭 이메일 사용](configure.md#use-an-additional-service-desk-alias-email)
  - [다중 노드 환경에서 이메일 수집 구성](configure.md#configure-email-ingestion-in-multi-node-environments)
- [Service Desk 사용](using_service_desk.md)
  - [최종 사용자(티켓 작성자)로서](using_service_desk.md#as-an-end-user-ticket-creator)
  - [티켓 응답자로서](using_service_desk.md#as-a-responder-to-the-ticket)
  - [이메일 내용 및 서식](using_service_desk.md#email-contents-and-formatting)
  - [일반 이슈를 Service Desk 티켓으로 변환](using_service_desk.md#convert-a-regular-issue-to-a-service-desk-ticket)
  - [개인정보 보호 고려 사항](using_service_desk.md#privacy-considerations)
- [외부 참여자](external_participants.md)
  - [Service Desk 티켓](external_participants.md#service-desk-tickets)
  - [외부 참여자로서](external_participants.md#as-an-external-participant)
  - [GitLab 사용자로서](external_participants.md#as-a-gitlab-user)

## Service Desk 문제 해결 {#troubleshooting-service-desk}

### Service Desk에 대한 이메일이 티켓을 생성하지 않음 {#emails-to-service-desk-do-not-create-tickets}

- 이메일에 [GitLab이 무시하는 이메일 헤더](../../../administration/incoming_email.md#rejected-headers) 중 하나가 포함되어 있으면 무시될 수 있습니다.
- 프로젝트별 Service Desk 주소로 이메일을 전달할 때 발신자 이메일 도메인이 엄격한 DKIM 규칙을 사용하고 확인 실패가 발생하면 이메일이 삭제될 수 있습니다. 이메일 헤더에서 찾을 수 있는 일반적인 DKIM 오류 메시지는 다음과 같을 수 있습니다:

  ```plaintext
  dkim=fail (signature did not verify) ... arc=fail
  ```

  사용 중인 특정 이메일 시스템이나 도구에 따라 오류 메시지의 정확한 표현이 달라질 수 있습니다. [DKIM 오류에 대한 이 문서](https://automatedemailwarmup.com/blog/dkim-fail/)를 참조하여 자세한 내용 및 가능한 해결책을 확인하세요.

### 16.6.0에서 이메일 수집이 작동하지 않음 {#email-ingestion-doesnt-work-in-1660}

GitLab Self-Managed `16.6.0`에서는 `mail_room`(이메일 수집)가 시작되는 것을 방지하는 회귀가 발생했습니다. Service Desk 및 기타 이메일 회신 기능이 작동하지 않습니다. [이슈 432257](https://gitlab.com/gitlab-org/gitlab/-/issues/432257)이 이 문제 해결을 추적합니다.

해결 방법은 GitLab 설치에서 다음 명령을 실행하여 영향을 받는 파일을 패치하는 것입니다:

{{< tabs >}}

{{< tab title="Linux 패키지(Omnibus)" >}}

```shell
curl --output /tmp/mailroom.patch --url "https://gitlab.com/gitlab-org/gitlab/-/merge_requests/137279.diff"
patch -p1 -d /opt/gitlab/embedded/service/gitlab-rails < /tmp/mailroom.patch
gitlab-ctl restart mailroom
```

{{< /tab >}}

{{< tab title="Docker" >}}

```shell
curl --output /tmp/mailroom.patch --url "https://gitlab.com/gitlab-org/gitlab/-/merge_requests/137279.diff"
cd /opt/gitlab/embedded/service/gitlab-rails
patch -p1 < /tmp/mailroom.patch
gitlab-ctl restart mailroom
```

{{< /tab >}}

{{< /tabs >}}
