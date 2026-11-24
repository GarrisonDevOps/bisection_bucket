---
stage: AI Platform
group: AI Core Infra
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: GitLab Duo가 GitLab Dedicated for Government에서 올바르게 구성되고 작동 중인지 확인합니다.
title: GitLab Dedicated for Government에서 GitLab Duo 구성
gitlab_dedicated: yes
---

{{< details >}}

- 제공 서비스: GitLab Dedicated for Government

{{< /details >}}

GitLab Dedicated for Government의 경우 GitLab Duo Self-Hosted 아키텍처를 사용해야 합니다. GitLab에서 관리하는 AI Gateway 및 모델은 사용할 수 없습니다.

> [!note]
> GitLab Duo Agent Platform 기능은 기능별 기준으로 GitLab Dedicated for Government에서 사용할 수 있도록 승인되었습니다. 자세한 내용은 [GitLab Dedicated for Government](../../../subscriptions/gitlab_dedicated_for_government/_index.md#gitlab-duo)를 참조하세요.

GitLab Duo Self-Hosted를 설정하려면:

1. [Silent Mode가 꺼져 있는지](../../silent_mode/_index.md#turn-off-silent-mode) 확인합니다.
1. [GitLab AI Gateway를 설치](../../../install/install_ai_gateway.md)하고 AWS GovCloud (US-West)에 배포합니다. 최적의 성능을 위해 [AI Gateway와 인스턴스를 같은 위치에 배치](../../../install/install_ai_gateway.md#co-locate-your-ai-gateway-and-instance)합니다.
   - [FIPS 검증 AI Gateway 이미지](../../../install/install_ai_gateway.md#fips-validated-images)를 사용합니다. FIPS 검증 이미지는 [컨테이너 레지스트리](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/container_registry/9518478?orderBy=PUBLISHED_AT&sort=desc&search%5B%5D=self-hosted)에 게시됩니다. 인스턴스가 실행 중인 GitLab 버전과 동일한 태그가 지정된 최신 이미지를 선택합니다.
   - [Docker](../../../install/install_ai_gateway.md#install-by-using-docker) 또는 [GitLab Helm chart](../../../install/install_ai_gateway.md#install-by-using-helm-chart)를 사용하여 AI Gateway를 배포할 수 있습니다. 각 배포 방법에 대한 자세한 내용은 [보안 업데이트 및 이미지 확인](../../../install/install_ai_gateway.md#security-updates-and-image-verification)을 참조하세요.
1. AI Gateway를 설치한 환경에서 [네트워크 설정을 구성](../../../install/install_ai_gateway.md#restrict-network-access)하여 인스턴스 및 선택한 LLM에 대한 액세스를 활성화합니다.
1. [로컬 AI Gateway에 대한 액세스 구성](../../gitlab_duo_self_hosted/configure_duo_features.md#configure-access-to-the-local-ai-gateway)합니다.
1. [Self-Hosted 모델을 추가](../../gitlab_duo_self_hosted/configure_duo_features.md#add-a-self-hosted-model)하여 GitLab Duo 기능과 함께 사용합니다.
1. GitLab이 인스턴스에서 Self-Hosted AI Gateway 및 선택한 LLM으로의 네트워크 연결을 활성화하도록 [지원 티켓을 생성](https://support.gitlab.com/hc/en-us/requests/new?ticket_form_id=4414917877650)하여 요청합니다.
1. [GitLab Duo 및 SDLC 동향 보기](../../../user/analytics/duo_and_sdlc_trends.md#view-gitlab-duo-and-sdlc-trends)를 통해 GitLab Duo가 팀의 생산성에 미치는 영향을 측정합니다.

## 관련 항목 {#related-topics}

- [지원되는 모델 및 하드웨어 요구 사항](../../gitlab_duo_self_hosted/supported_models_and_hardware_requirements.md)
- [GitLab Duo Self-Hosted 문제 해결](../../gitlab_duo_self_hosted/troubleshooting.md)
- [GitLab Duo 상태 확인 실행](_index.md#run-a-health-check-for-gitlab-duo)
