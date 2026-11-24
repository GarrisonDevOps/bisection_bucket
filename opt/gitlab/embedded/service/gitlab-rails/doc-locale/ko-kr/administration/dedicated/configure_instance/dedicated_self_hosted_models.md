---
stage: GitLab Dedicated
group: AI Model Services
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/product/ux/technical-writing/#assignments>
description: GitLab Dedicated용 자체 AI 모델을 호스팅합니다.
title: GitLab Dedicated용 자체 호스팅 모델 구성
---

{{< details >}}

- 티어: Ultimate
- 제공 서비스: GitLab Dedicated

{{< /details >}}

GitLab Dedicated용 AI 게이트웨이를 사용하여 자체 호스팅 모델을 연결합니다. GitLab Duo Agent Platform을 사용하면 AI 게이트웨이를 Amazon Bedrock에 연결하여 AWS 리전에서 추론을 유지할 수 있습니다. 또는 선호하는 제공자를 사용할 수 있습니다.

## 하이브리드 AI 게이트웨이 및 모델 구성 {#hybrid-ai-gateway-and-model-configuration}

GitLab Dedicated용 AI 게이트웨이는 GitLab Dedicated 인스턴스와 동일한 AWS 환경 및 리전에서 실행됩니다. GitLab이 사용자를 위해 게이트웨이를 호스팅하고 구성합니다. **운영자** 영역에서 AI 게이트웨이를 설치하거나 로컬 AI 게이트웨이 URL을 입력할 필요가 없습니다.

GitLab Dedicated용 AI 게이트웨이를 사용하면 인스턴스가 [하이브리드 AI 게이트웨이 및 모델 구성](../../gitlab_duo_self_hosted/_index.md#hybrid-ai-gateway-and-model-configuration)을 사용합니다. 각 GitLab Duo 기능에 대해 다음 중 하나를 사용할 수 있습니다:

- 자체 호스팅 모델: 이 기능은 GitLab Dedicated용 AI 게이트웨이를 통해 구성한 모델 엔드포인트로 요청을 전송합니다.
- GitLab 관리형 모델: 이 기능은 GitLab.com AI 게이트웨이로 요청을 전송합니다. GitLab Dedicated용 AI 게이트웨이는 GitLab 관리형 모델로 라우팅할 수 없습니다.

GitLab Dedicated용 AI 게이트웨이는 인스턴스의 기본 동작을 변경하지 않습니다. 기본적으로 모든 GitLab Duo 기능은 GitLab.com AI 게이트웨이를 통해 GitLab 관리형 모델을 사용합니다. 인스턴스는 자체 호스팅 모델을 사용하도록 구성한 기능에 대해서만 GitLab Dedicated용 AI 게이트웨이를 통해 요청을 전송합니다.

## 자체 호스팅 모델 추가 {#add-a-self-hosted-model}

GitLab 인스턴스에서 사용할 자체 호스팅 모델을 추가할 수 있습니다.

자체 호스팅 모델을 추가하려면:

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **GitLab Duo**를 선택합니다.
1. **모델 관리**를 선택합니다.
1. **자체 호스팅 모델 추가**를 선택합니다.
1. 필드를 완성합니다:
   - **배포 이름**: 모델 배포를 고유하게 식별할 수 있는 이름을 입력합니다(예: `Mixtral-8x7B-it-v0.1 on GCP`).
   - **모델 패밀리**: 배포가 속한 모델 패밀리를 선택합니다. 지원되거나 호환되는 모델을 선택할 수 있습니다.
   - **엔드포인트**: 모델이 호스팅된 URL을 입력합니다.
   - **API 키**: 선택사항. 모델에 액세스할 API 키를 추가합니다.
   - **모델 식별자**: 배포 방법에 따라 모델 ID를 입력합니다. 모델 ID는 다음 형식과 일치해야 합니다:

     | 배포 방법 | 형식 | 예제 |
     |-------------------|--------|---------|
     | Amazon Bedrock(모델 ID) | `bedrock/<model ID>` | `bedrock/mistral.mixtral-8x7b-instruct-v0:1` |
     | Amazon Bedrock(애플리케이션 추론 프로필 ARN) | `bedrock/converse/<application inference profile ARN>` | `bedrock/converse/arn:aws:bedrock:us-east-1:123456789012:application-inference-profile/abcd1234efgh` |
     | Gemini Enterprise Agent Platform | `vertex_ai/<model ID>` | `vertex_ai/claude-sonnet-4-6@default` |
     | Anthropic                                                            | `anthropic/<model ID>`                     | `anthropic/claude-opus-4-6` |
     | OpenAI                                                              | `openai/<model ID>`                        | `openai/gpt-5` |
     | Azure OpenAI                                                          | `azure/<model ID>`                         | `azure/gpt-35-turbo` |

1. **자체 호스팅 모델 추가**를 선택합니다.

자체 호스팅 모델을 추가하면 사용할 수 있게 되지만 GitLab Duo 기능에 할당되지 않습니다. 사용하려면 [기능에 대한 자체 호스팅 모델을 선택](../../gitlab_duo_self_hosted/configure_duo_features.md#select-a-self-hosted-model-for-a-feature)해야 합니다. 자체 호스팅 모델을 선택하지 않은 기능은 GitLab.com AI 게이트웨이를 통해 GitLab 관리형 모델을 계속 사용합니다.
