---
stage: Plan
group: Work Items
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
title: irker (IRC 게이트웨이)
description: "irker 통합을 구성하여 GitLab 푸시 알림을 IRC 채널로 보냅니다."
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab은 irker 서버에 업데이트 메시지를 푸시하는 방법을 제공합니다. 통합을 구성한 후 프로젝트에 푸시할 때마다 통합이 irker 서버에 데이터를 직접 전송합니다.

[irker 통합 API 문서](../../../api/project_integrations.md)도 참조하세요.

자세한 내용은 [irker 프로젝트 홈페이지](https://gitlab.com/esr/irker)를 참조하세요.

## irker 데몬 설정 {#set-up-an-irker-daemon}

irker 데몬을 설정해야 합니다. 다음을 수행합니다:

1. irker 코드를 [리포지토리에서](https://gitlab.com/esr/irker) 다운로드합니다:

   ```shell
   git clone https://gitlab.com/esr/irker.git
   ```

1. `irkerd`라는 Python 스크립트를 실행합니다. 스크립트는 게이트웨이입니다. IRC 서버로 메시지를 보내기 위한 IRC 클라이언트로, GitLab 서비스에서 메시지를 수신하기 위한 TCP 서버로 모두 작동합니다.

irker 서버가 같은 머신에서 실행 중이면 완료된 것입니다. 그렇지 않으면 다음 섹션의 첫 번째 단계를 따라야 합니다.

> [!warning]
> irker에는 내장된 인증이 없으므로 방화벽 외부에서 호스팅될 경우 IRC 채널 스팸에 취약합니다. 악용을 방지하려면 보안 네트워크에서 데몬을 실행하십시오. 자세한 내용은 [irker 보안 분석](http://www.catb.org/~esr/irker/security.html)을 읽으세요.

## GitLab에서 다음 단계를 완료합니다 {#complete-these-steps-in-gitlab}

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **연동**을 선택합니다.
1. **irker (IRC 게이트웨이)**를 선택합니다.
1. **통합 활성화** 아래에서 **활성** 체크박스를 선택합니다.
1. 선택 사항. **서버 호스트**에서 `irkerd`가 실행 중인 서버 호스트 주소를 입력합니다. 비워두면 `localhost`으로 기본 설정됩니다.
1. 선택 사항. **서버 포트**에서 `irkerd`의 서버 포트를 입력합니다. 비워두면 `6659`으로 기본 설정됩니다.
1. 선택 사항. **기본 IRC URI**에서 기본 IRC URI를 `irc[s]://domain.name` 형식으로 입력합니다. **수신자**에서 제공하는 모든 채널 또는 사용자 앞에 추가되며, 이는 전체 URI가 아닙니다.
1. **수신자**에서 업데이트를 수신할 사용자 또는 채널을 공백으로 구분하여 입력합니다(예: `#channel1 user1`). 자세한 내용은 [irker 수신자 입력](#enter-irker-recipients)을 참조하세요.
1. 선택 사항. 메시지를 강조하려면 **메시지 색상 지정** 체크박스를 선택합니다.
1. 선택 사항. **테스트 설정**을 선택합니다.
1. **변경 사항 저장**을 선택합니다.

## irker 수신자 입력 {#enter-irker-recipients}

**기본 IRC URI** 텍스트 상자를 비워두면 전체 URI로 수신자를 입력합니다: `irc[s]://irc.network.net[:port]/#channel`. 기본 IRC URI를 입력했으면 채널 또는 사용자 이름만 사용할 수 있습니다.

메시지를 보내려면:

- 채널로 보낼 경우(예: `#chan`), irker는 `chan` 및 `#chan` 형식의 채널 이름을 허용합니다.
- 암호로 보호된 채널의 경우 채널 이름에 `?key=thesecretpassword`을 추가하고 `thesecretpassword` 대신 채널 암호를 입력합니다. 예를 들어, `chan?key=hunter2`입니다. 채널 이름 앞에 `#` 기호를 붙이지 마세요. 그렇게 하면 irker는 `#chan?key=password`라는 채널에 들어가려고 시도하며 `/whois` IRC 명령어를 통해 채널 암호가 유출될 수 있습니다. 오래된 irker 버그로 인해 이러한 동작이 발생합니다.
- 사용자 쿼리에서 사용자 이름 다음에 `,isnick`을 추가합니다. 예를 들어, `UserSmith,isnick`입니다.
