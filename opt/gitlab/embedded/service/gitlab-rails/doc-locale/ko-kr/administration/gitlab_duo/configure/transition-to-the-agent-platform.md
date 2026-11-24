---
stage: Tutorial
group: Tutorial
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab Duo Pro 또는 Enterprise에서 GitLab Duo Agent Platform으로 전환합니다.
title: GitLab Duo Agent Platform으로 전환
---

{{< details >}}

- 티어: Premium, Ultimate
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated

{{< /details >}}

GitLab Duo(비에이전트)에서 Agent Platform으로 전환할 때 소프트웨어 개발 생애 주기 전반에서 여러 어시스턴트(에이전트라고 함)에 접근할 수 있습니다.

인스턴스를 Agent Platform으로 전환하려면 다음 단계를 완료하세요:

1. 환경 설정
1. 구성 검증
1. Agent Platform 설정 구성
1. 사용량 검증

## 전환 후 사용 가능한 기능 {#features-available-after-transition}

다음 표는 GitLab Duo 비에이전트 기능과 Agent Platform으로 전환한 후 사용자가 접근할 수 있는 에이전트 버전을 나열합니다. Agent Platform의 기능 전체 목록은 [일반적으로 사용 가능한 기능](../../../user/duo_agent_platform/_index.md#generally-available-features) 및 [베타 및 실험 기능](../../../user/duo_agent_platform/_index.md#beta-and-experimental-features-that-dont-consume-credits)을 참조하세요.

| 비에이전트 기능 | Agent Platform |
|---------------------|----------------|
| GitLab Duo Non-Agentic Chat | [에이전트 채팅](../../../user/gitlab_duo_chat/agentic_chat.md) <br /> 복잡한 질문에 답하고 자율적으로 파일을 생성 및 편집합니다. 플래너 및 Security Analyst 에이전트와 연결합니다. 머지 리퀘스트 요약, 토론 요약, 코드 리팩토링 및 테스트 생성이 이제 에이전트 채팅의 일부입니다. |
| GitLab Duo 코드 검토 | [Code Review 플로우](../../../user/duo_agent_platform/flows/foundational_flows/code_review/_index.md)[^runner-configured-execute]  <br /> 코드 검토 작업을 자동화하고 팀 전체에 걸쳐 코딩 표준을 적용합니다. |
| 근본 원인 분석 | [Fix CI/CD Pipeline 플로우](../../../ci/pipelines/fix_pipeline.md)[^runner-configured-execute] <br /> 실패한 CI/CD 파이프라인을 진단하고 자동으로 수정합니다. |
| 취약성 설명 및 해결 | [SAST 취약성 해결 플로우](../../../user/duo_agent_platform/flows/foundational_flows/agentic_sast_vulnerability_resolution.md)[^runner-configured-execute] <br /> SAST 취약점에 대한 수정 사항 및 수정 단계를 자동으로 생성합니다. |

[^runner-configured-execute]: [플로우를 실행하도록 구성된](#set-up-your-environment) 러너가 필요합니다. 러너를 구성하지 않으면 Agent Platform으로 전환한 후 GitLab Duo(비에이전트)에서 이러한 기능을 사용했던 사용자에게 이 기능들이 사용 불가능하게 표시됩니다.

## 시작하기 전에 {#before-you-begin}

GitLab 19.0 이상이 필요합니다.

## 환경 설정 {#set-up-your-environment}

GitLab Duo(비에이전트)와 달리 Agent Platform은 러너에서 플로우를 실행하고 커밋 및 파이프라인을 만들기 위해 서비스 계정을 사용합니다. 이를 위해서는 비에이전트 기능에 없던 구성이 필요합니다.

Agent Platform의 환경을 설정하려면 다음을 수행하세요:

1. [인스턴스 구성](_index.md).
1. [네트워크 구성](_index.md#allow-outbound-connections-from-the-gitlab-instance-to-gitlab-duo)에서 GitLab 인스턴스로부터의 아웃바운드 연결을 허용합니다.
1. [인스턴스 또는 그룹 러너 구성](../../../user/duo_agent_platform/flows/execution/_index.md#configure-runners-to-execute-flows)하여 플로우를 사용합니다. CI/CD를 사용하는 플로우는 러너에서 실행됩니다. 에이전트 채팅은 러너가 필요하지 않습니다.
1. 러너에서 GitLab 인스턴스로의 [연결 허용](_index.md#allow-connections-from-the-runner).
1. 온라인 라이선스가 있는 경우 [구독 데이터 동기화](../../../subscriptions/manage_subscription.md#manually-synchronize-subscription-data).

## 구성 검증 {#validate-your-configuration}

환경을 설정한 후 다음 진단 검사를 실행하세요:

- [GitLab Duo 상태 확인](_index.md#run-a-health-check-for-gitlab-duo)
- [구성 진단 스크립트](../../../user/duo_agent_platform/troubleshooting.md#run-the-configuration-diagnostic-script)

## Agent Platform 설정 구성 {#configure-agent-platform-settings}

환경을 설정한 후 다음 설정을 구성하세요:

1. [Agent Platform 켜기](../../../user/duo_agent_platform/turn_on_off.md#turn-gitlab-duo-agent-platform-on-or-off).
1. [기본 플로우 켜기](../../../user/duo_agent_platform/flows/foundational_flows/_index.md).
1. 기본 플로우에서 사용하는 서비스 계정의 [푸시 규칙 구성](../../../user/duo_agent_platform/troubleshooting.md#configure-push-rules-to-allow-a-service-account).
1. [기본 GitLab Duo 네임스페이스 설정](../../../user/profile/preferences.md#set-a-default-gitlab-duo-namespace).
1. 선택사항. 일관성을 위해 비용을 제어하려면 [기능의 모델 선택](../../../user/duo_agent_platform/model_selection.md#select-a-model-for-a-feature)을 수행하여 모든 사용자가 해당 모델을 사용하도록 합니다. 요구 사항에 맞는 모델이 확실하지 않으면 [올바른 모델 선택](../../../user/duo_agent_platform/model_selection.md#select-a-model-for-a-feature)을 참조하세요.

## 사용량 검증 {#validate-usage}

Agent Platform을 대다수의 사용자에게 롤아웃하기 전에 소규모의 사용자 그룹에게 다음 결과를 확인하도록 요청하세요:

- GitLab UI에서 에이전트 채팅에 접근하여 사용할 수 있습니다.
- IDE에서 Agent Platform을 인증할 수 있습니다.
- 테스트 머지 리퀘스트에서 Code Review 플로우를 실행할 수 있습니다.
- 구독에서 사용 가능한 다른 기본 플로우를 실행할 수 있습니다.

이러한 사용자가 일부 플로우를 실행한 후 [크레딧 대시보드](../../../subscriptions/gitlab_credits_dashboard.md)를 확인하여 크레딧 사용량을 확인하세요.

## 청구 {#billing}

GitLab Duo Pro 또는 Enterprise에서 사용량 기반 청구로 구독을 변경한 후 자리 대신 [크레딧 사용량](../../../subscriptions/gitlab_credits.md)을 기준으로 요금이 청구됩니다.

팀의 크레딧 사용량을 추적하고 사용량 한도를 설정하려면 [크레딧 대시보드](../../../subscriptions/gitlab_credits_dashboard.md)를 사용하세요.

## 전환 중 일반적인 문제 {#common-issues-during-transition}

인스턴스를 Agent Platform으로 처음 전환할 때 다음과 같은 문제가 발생할 수 있습니다.

| 이슈 | 가능한 원인 | 해결 방법 |
|---------|--------------|------------|
| UI에서 플로우가 표시되지 않음 | GitLab Duo 또는 플로우 실행이 켜져 있지 않거나, 그룹이 플로우 사용 권한이 없거나, 플로우가 프로젝트 수준에서 활성화되지 않았습니다. | [UI에서 플로우가 표시되지 않음](../../../user/duo_agent_platform/troubleshooting.md#flows-not-visible-in-the-ui) |
| 러너가 작업을 선택하지 않아 플로우가 실행되지 않음 | 러너에 `gitlab--duo` 태그가 없거나 플로우를 위해 러너가 구성되지 않았습니다. | [러너 구성](../../../user/duo_agent_platform/flows/execution/_index.md#configure-runners-to-execute-flows) |
| 세션이 `created` 상태로 고정됨 | 푸시 규칙이 서비스 계정을 차단합니다. 커밋 작성자 이메일 또는 `duo/feature/` 브랜치 접두사가 허용되지 않습니다. | [서비스 계정을 허용하도록 푸시 규칙 구성](../../../user/duo_agent_platform/troubleshooting.md#configure-push-rules-to-allow-a-service-account) |
| `Error in creating workload: Insufficient permissions to create a new pipeline` | 기본 플로우 서비스 계정은 가져오거나 템플릿된 프로젝트가 존재하기 전에 설정되었습니다. | [가져온 프로젝트의 새 파이프라인을 만들 수 있는 권한 부족](../../../user/duo_agent_platform/troubleshooting.md#insufficient-permissions-to-create-a-new-pipeline-for-imported-projects) |
| 기본 플로우가 켜져 있지만 아무것도 하지 않음 | 서비스 계정이 만들어지지 않았거나 그룹 멤버십 잠금이 프로젝트에 추가되지 않도록 방지합니다. | [기본 플로우 서비스 계정이 만들어지지 않음](../../../user/duo_agent_platform/troubleshooting.md#foundational-flow-service-account-not-created) 및 [그룹 멤버십 잠김](../../../user/duo_agent_platform/troubleshooting.md#group-membership-locked) |
| Agent Platform이 꺼져 있거나 `Something went wrong while requesting a review from GitLab Duo` | 사용자가 여러 GitLab Duo 네임스페이스에 속하고 기본 네임스페이스가 설정되지 않았습니다. | [기본 GitLab Duo 네임스페이스가 설정되지 않음](../../../user/duo_agent_platform/troubleshooting.md#default-gitlab-duo-namespace-not-set) |
| `Your request was valid but Workflow failed to complete it` | 리포지토리에 커밋이 없으므로 플로우가 기본 브랜치를 찾을 수 없습니다. | [오류: 요청은 유효했지만 Workflow가 완료하지 못했습니다](../../../user/duo_agent_platform/troubleshooting.md#error-your-request-was-valid-but-workflow-failed-to-complete-it) |
| `SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)` | GitLab Self-Managed(사용자 지정 또는 자체 서명된 CA 포함)에서 샌드박스 강화는 `git clone` 중에 러너의 CA 삽입을 차단합니다. | [오류: SSL 인증서 OpenSSL 확인 결과](../../../user/duo_agent_platform/troubleshooting.md#error-ssl-certificate-openssl-verify-result-unable-to-get-local-issuer-certificate-20) |
| 모든 GitLab Duo 기능이 전환 직후 모든 사용자에 대해 실패 | Silent Mode가 켜져 있어 GitLab이 AI 게이트웨이에 도달할 수 없습니다. | [Silent Mode 끄기](../../silent_mode/_index.md#turn-off-silent-mode) |
| 상태 확인 네트워크 테스트 실패 또는 GitLab Duo 기능이 전환 후 사용 불가능 | `cloud.gitlab.com`, `customers.gitlab.com` 또는 `duo-workflow-svc.runway.gitlab.net`으로의 아웃바운드 HTTPS가 방화벽이나 프록시에 의해 차단됩니다. | [GitLab 인스턴스에서 GitLab Duo로의 아웃바운드 연결 허용](_index.md#allow-outbound-connections-from-the-gitlab-instance-to-gitlab-duo) |
| 변환 직후 모든 사용자에 대해 Agent Platform 기능을 사용할 수 없음 | 사용량 기반 청구 약관이 수락되지 않았거나 풀에 사용 가능한 크레딧이 없습니다. | [온디맨드 크레딧](../../../subscriptions/gitlab_credits.md#on-demand-credits) |

## 관련 항목 {#related-topics}

- [GitLab Duo Agent Platform](_index.md)
- [GitLab Duo Agent Platform 문제 해결](../../../user/duo_agent_platform/troubleshooting.md)
- [사용량 한도](../../../subscriptions/gitlab_credits_dashboard.md#usage-caps)
- [자체 호스팅 모델](../../gitlab_duo_self_hosted/_index.md)
- [GitLab University: 관리자용 GitLab Duo Agent Platform](https://university.gitlab.com/learning-paths/gitlab-duo-agent-platform-for-admins)
- [GitLab University: GitLab Duo Agent Platform 설정](https://university.gitlab.com/courses/gitlab-duo-agent-platform-setup)
- [GitLab University: GitLab Duo Pro 또는 Enterprise에서 Agent Platform으로 전환](https://university.gitlab.com/courses/gitlab-duo-agent-platform-setup)
