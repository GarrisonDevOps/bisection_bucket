---
stage: Plan
group: Planner Intelligence
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: "GitLab Pages를 위한 자동 Let's Encrypt SSL 인증서입니다."
title: "GitLab Pages Let's Encrypt 인증서"
---

{{< details >}}

- 티어: Free, Premium, Ultimate
- 제공 서비스: GitLab.com, GitLab Self-Managed

{{< /details >}}

GitLab Pages와 Let's Encrypt(LE)의 통합을 통해 사용자 정의 도메인으로 Pages 웹사이트에 LE 인증서를 사용할 수 있으며, 직접 인증서를 발급하고 업데이트해야 하는 번거로움이 없습니다. GitLab이 모든 작업을 자동으로 처리합니다.

[Let's Encrypt](https://letsencrypt.org)는 무료이고 자동화된 오픈 소스 인증 기관입니다.

> [!warning]
> 이 기능은 사용자 정의 도메인의 인증서만 포함하며, [Pages daemon](../../../../administration/pages/_index.md) 실행에 필요한 와일드카드 인증서는 포함하지 않습니다(GitLab Self-Managed, Free, Premium 및 Ultimate만 해당). 와일드카드 인증서 생성은 [이 이슈](https://gitlab.com/gitlab-org/omnibus-gitlab/-/issues/3342)에서 추적됩니다.

## 사전 요구 사항 {#prerequisites}

도메인의 SSL 인증서 자동 프로비저닝을 활성화하기 전에 다음을 확인하세요:

- 웹사이트 소스 코드를 포함하는 GitLab에 [프로젝트](../_index.md#getting-started)를 생성했습니다.
- 도메인(`example.com`)을 획득하고 Pages 웹사이트를 가리키는 [DNS 항목](_index.md)을 추가했습니다. 최상위 도메인(`.com`)은 [public suffix](https://publicsuffix.org/)이어야 합니다.
- [Pages 프로젝트에 도메인을 추가](_index.md#step-1-add-a-custom-domain)하고 소유권을 확인했습니다.
- 웹사이트가 실행 중이며 사용자 정의 도메인을 통해 액세스할 수 있는지 확인했습니다.

GitLab과 Let's Encrypt의 통합이 활성화되어 있으며 GitLab.com에서 사용할 수 있습니다. **GitLab Self-Managed** 인스턴스의 경우 관리자가 [활성화했는지](../../../../administration/pages/_index.md#lets-encrypt-integration) 확인하세요.

## 사용자 정의 도메인에 대한 Let's Encrypt 통합 활성화 {#enabling-lets-encrypt-integration-for-your-custom-domain}

요구 사항을 충족한 후 Let's Encrypt 통합을 활성화하세요:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Pages**를 선택합니다.
1. 도메인 이름 옆에서 **편집** ({{< icon name="pencil" >}})을 선택합니다.
1. **Let's Encrypt를 사용하여 인증서를 자동으로 관리** 토글을 활성화합니다.

   ![사용자 정의 도메인 설정에서 Let's Encrypt 토글입니다.](img/lets_encrypt_integration_v12_1.png)

1. **변경 사항 저장**을 선택합니다.

활성화한 후 GitLab은 Let's Encrypt 인증서를 획득하여 관련 Pages 도메인에 추가합니다. GitLab은 또한 자동으로 인증서를 갱신합니다.

> [!note]
> 인증서 발급 및 Pages 구성 업데이트는 최대 1시간이 소요될 수 있습니다. 도메인 설정에 이미 SSL 인증서가 있는 경우 Let's Encrypt 인증서로 교체될 때까지 계속 작동합니다.

## 문제 해결 {#troubleshooting}

### Let's Encrypt 인증서를 획득하는 중 오류가 발생했습니다 {#something-went-wrong-while-obtaining-the-lets-encrypt-certificate}

**Let's Encrypt 인증서를 획득하는 중 오류가 발생했습니다**라는 오류 메시지가 표시될 수 있습니다.

Let's Encrypt가 도메인에 도달하거나 유효성을 검사할 수 없을 때 이 문제가 발생합니다.

이 이슈를 해결하려면:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **설정** > **일반**을 선택합니다.
1. **표시 여부, 프로젝트 기능, 권한**을 확장합니다.
1. **Pages** 아래에서 드롭다운 목록으로부터 **액세스 권한이 있는 모든 사용자**를 선택합니다.
1. **배포** > **Pages** > **도메인 & 설정**을 선택합니다.
1. 도메인 이름 옆에서 **편집** ({{< icon name="pencil" >}})을 선택합니다.
1. **검증 상태**에서 **검증 재시도** ({{< icon name="retry" >}})를 선택합니다.

같은 오류가 발생하면 다음을 확인하세요:

- 도메인에 대해 `CNAME` 또는 `A` DNS 레코드 중 하나만 설정했는지 확인하세요.
- 도메인에 `AAAA` DNS 레코드가 없는지 확인하세요.
- 도메인 또는 상위 수준의 도메인에 `CAA` DNS 레코드가 있는 경우 [`letsencrypt.org`](https://letsencrypt.org/docs/caa/)를 포함하는지 확인하세요.
- 사용자 [도메인이 검증되었는지](_index.md#step-1-add-a-custom-domain) 확인하세요.
- [병렬 배포](../parallel_deployments.md)를 사용하는 경우 기본 배포에 빈 `path_prefix`이 있는지 확인하세요. 비어 있지 않은 `path_prefix`(예: `latest`)은 `/.well-known/acme-challenge` 경로가 제공되지 않도록 합니다.

**배포** > **Pages** 설정으로 돌아가 검증을 다시 시도하세요.

### 인증서 획득이 1시간 이상 지연됨 {#obtaining-a-certificate-hangs-for-more-than-an-hour}

Let's Encrypt 통합을 활성화했지만 1시간 후에도 인증서가 없고 다음 메시지가 표시되는 경우:

```plaintext
GitLab is obtaining a Let's Encrypt SSL certificate for this domain.
This process can take some time. Please try again later.
```

다음 단계를 따라 GitLab Pages의 도메인을 다시 제거하고 추가하세요:

1. 상단 표시줄에서 **검색 또는 이동**을 선택하고 프로젝트를 찾습니다.
1. 왼쪽 사이드바에서 **배포** > **Pages**를 선택합니다.
1. 도메인 이름 옆에서 **삭제**를 선택합니다.
1. [도메인을 다시 추가하고 검증합니다](_index.md#step-1-add-a-custom-domain).
1. [도메인에 대한 Let's Encrypt 통합을 활성화합니다](#enabling-lets-encrypt-integration-for-your-custom-domain).
1. 여전히 같은 오류가 발생하는 경우:
   1. 도메인에 대해 `CNAME` 또는 `A` DNS 레코드 중 하나만 올바르게 설정했는지 확인하세요.
   1. 도메인에 `AAAA` DNS 레코드가 없는지 확인하세요.
   1. 도메인 또는 상위 수준의 도메인에 `CAA` DNS 레코드가 있는 경우 [`letsencrypt.org`](https://letsencrypt.org/docs/caa/)를 포함하는지 확인하세요.
   1. 1단계로 이동합니다.

<!-- Include any troubleshooting steps that you can foresee. If you know beforehand what issues
one might have when setting this up, or when something is changed, or on upgrading, it's
important to describe those, too. Think of things that may go wrong and include them here.
This is important to minimize requests for support, and to avoid doc comments with
questions that you know someone might ask.

Each scenario can be a third-level heading, for example, `### Getting error message X`.
If you have none to add when creating a doc, leave this section in place
but commented out to help encourage others to add to it in the future. -->
