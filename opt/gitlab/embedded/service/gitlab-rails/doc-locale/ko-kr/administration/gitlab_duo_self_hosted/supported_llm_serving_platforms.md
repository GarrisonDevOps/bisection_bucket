---
stage: AI Platform
group: AI Model Services
info: To determine the technical writer assigned to the Stage/Group associated with this page, see <https://handbook.gitlab.com/handbook/marketing/product-and-technical-marketing/technical-writing/#assignments>
description: 지원되는 LLM 서비스 제공 플랫폼입니다.
title: LLM 플랫폼 구성
---

{{< details >}}

- 티어:  Premium, Ultimate
- 추가 기능: GitLab Duo Enterprise
- 제공 서비스: GitLab Self-Managed, GitLab Dedicated, GitLab Dedicated for Government

{{< /details >}}

{{< history >}}

- GitLab 17.1에서 `ai_custom_model`이라는 [기능 플래그](../feature_flags/_index.md)로 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/12972)되었습니다. 기본적으로 비활성화되었습니다.
- GitLab 17.5에서 [GitLab Self-Managed 인스턴스용으로 사용으로 설정](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/168171)되었습니다.
- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/171692) \- GitLab 17.6에서 GitLab Duo Enterprise 애드온이 필요하도록 변경되었습니다.
- 기능 플래그 `ai_custom_model` [제거됨](https://gitlab.com/gitlab-org/gitlab/-/work_items/498194) - GitLab 17.8에서 제거되었습니다.
- GitLab 17.9에서 [일반적으로 사용 가능](https://gitlab.com/groups/gitlab-org/-/work_items/15176)합니다.
- [변경됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/188263) \- GitLab 18.0에서 GitLab Premium을 포함하도록 변경되었습니다.

{{< /history >}}

AI Gateway는 [LiteLLM](https://docs.litellm.ai/docs/providers)을 통해 여러 LLM 공급자를 지원합니다. GitLab이 검증 및 테스트한 플랫폼은 다음과 같습니다.

사용하려는 플랫폼이 목록에 없으면 [이슈 526144](https://gitlab.com/gitlab-org/gitlab/-/work_items/526144)에서 피드백을 공유하세요.

## 여러 모델 및 플랫폼 사용 {#use-multiple-models-and-platforms}

동일한 GitLab 인스턴스에서 여러 모델 및 플랫폼을 사용할 수 있습니다.

예를 들어 한 기능은 Azure OpenAI를 사용하도록 구성하고 다른 기능은 AWS Bedrock 또는 vLLM으로 제공되는 자체 호스팅 모델을 사용하도록 구성할 수 있습니다.

이 설정으로 각 사용 사례에 최적의 모델과 플랫폼을 선택할 수 있는 유연성을 얻을 수 있습니다. 모델은 호환되는 플랫폼을 통해 지원되고 제공되어야 합니다.

## 자체 호스팅 모델 배포 {#self-hosted-model-deployments}

### vLLM {#vllm}

[vLLM](https://docs.vllm.ai/en/latest/index.html)은 메모리 효율성을 위해 최적화된 높은 성능의 추론 서버입니다. 모델 병렬화를 지원하며 기존 워크플로우와 쉽게 통합됩니다.

vLLM을 설치하려면 [vLLM 설치 가이드](https://docs.vllm.ai/en/latest/getting_started/installation/)를 참조하세요. [v0.18.1 버전](https://github.com/vllm-project/vllm/releases/tag/v0.18.1) 이상을 설치해야 합니다.

vLLM으로 GPT OSS 120B를 제공하는 규정적 설정 가이드는 [vLLM으로 GPT OSS 120B 제공](vllm_gpt_oss_120b.md)을 참조하세요.

#### 엔드포인트 URL 구성 {#configuring-the-endpoint-url}

GitLab에서 OpenAI API 호환 플랫폼(예: vLLM)의 엔드포인트 URL을 구성할 때:

- URL은 `/v1`로 접미사가 붙어야 합니다.
- 기본 vLLM 구성을 사용하는 경우 엔드포인트 URL은 `https://<hostname>:8000/v1`입니다.
- 서버가 프록시 또는 로드 밸런서 뒤에 구성되어 있으면 포트를 지정할 필요가 없을 수 있습니다. 이 경우 URL은 `https://<hostname>/v1`입니다.

#### 모델 이름 찾기 {#find-the-model-name}

모델이 배포된 후 GitLab의 모델 식별자 필드에 대한 모델 이름을 가져오려면 vLLM 서버의 `/v1/models` 엔드포인트를 쿼리하세요.

```shell
curl \
  --header "Authorization: Bearer API_KEY" \
  --header "Content-Type: application/json" \
  http://your-vllm-server:8000/v1/models
```

모델 이름은 응답의 `data.id` 필드의 값입니다.

응답 예시:

```json
{
  "object": "list",
  "data": [
    {
      "id": "Mixtral-8x22B-Instruct-v0.1",
      "object": "model",
      "created": 1739421415,
      "owned_by": "vllm",
      "root": "mistralai/Mixtral-8x22B-Instruct-v0.1",
      // Additional fields removed for readability
    }
  ]
}
```

이 예시에서 모델의 `id`이 `Mixtral-8x22B-Instruct-v0.1`이면 GitLab에서 모델 식별자를 `custom_openai/Mixtral-8x22B-Instruct-v0.1`으로 설정합니다.

자세한 내용은 다음 설명서를 참조하세요.

- vLLM 지원 모델은 [vLLM 지원 모델 설명서](https://docs.vllm.ai/en/latest/models/supported_models/)를 참조합니다.
- vLLM을 사용하여 모델을 실행할 때 사용 가능한 옵션은 [vLLM 엔진 인수 설명서](https://docs.vllm.ai/en/stable/configuration/engine_args/)를 참조합니다.

#### Mistral-7B-Instruct-v0.2 {#mistral-7b-instruct-v02}

1. HuggingFace에서 모델을 다운로드합니다.

   ```shell
   git clone https://<your-hugging-face-username>:<your-hugging-face-token>@huggingface.co/mistralai/Mistral-7B-Instruct-v0.3
   ```

1. 서버를 실행합니다.

   ```shell
   vllm serve <path-to-model>/Mistral-7B-Instruct-v0.3 \
      --served_model_name <choose-a-name-for-the-model>  \
      --tokenizer_mode mistral \
      --tensor_parallel_size <number-of-gpus> \
      --load_format mistral \
      --config_format mistral \
      --tokenizer <path-to-model>/Mistral-7B-Instruct-v0.3
   ```

#### Mixtral-8x7B-Instruct-v0.1 {#mixtral-8x7b-instruct-v01}

1. HuggingFace에서 모델을 다운로드합니다.

   ```shell
   git clone https://<your-hugging-face-username>:<your-hugging-face-token>@huggingface.co/mistralai/Mixtral-8x7B-Instruct-v0.1
   ```

1. 토큰 구성의 이름을 변경합니다.

   ```shell
   cd <path-to-model>/Mixtral-8x7B-Instruct-v0.1
   cp tokenizer.model tokenizer.model.v3
   ```

1. 모델을 실행합니다.

   ```shell
   vllm serve <path-to-model>/Mixtral-8x7B-Instruct-v0.1 \
     --tensor_parallel_size 4 \
     --served_model_name <choose-a-name-for-the-model> \
     --tokenizer_mode mistral \
     --load_format safetensors \
     --tokenizer <path-to-model>/Mixtral-8x7B-Instruct-v0.1
   ```

#### 지연 시간을 줄이기 위해 요청 로깅을 사용 중지 {#disable-request-logging-to-reduce-latency}

프로덕션에서 vLLM을 실행하는 경우 요청 로깅을 사용 중지하기 위해 `--disable-log-requests` 플래그를 사용하여 지연 시간을 크게 줄일 수 있습니다.

> [!note]
> 상세한 요청 로깅이 필요하지 않을 때만 이 플래그를 사용하세요.

요청 로깅을 사용 중지하면 특히 높은 부하에서 상세한 로그로 인한 오버헤드가 최소화되므로 성능 수준을 향상하는 데 도움이 됩니다.

```shell
vllm serve <path-to-model>/<model-version> \
--served_model_name <choose-a-name-for-the-model>  \
--disable-log-requests
```

이러한 변경으로 인해 내부 벤치마크에서 응답 시간이 눈에 띄게 향상되었습니다.

## 클라우드 호스팅 모델 배포 {#cloud-hosted-model-deployments}

GitLab은 다음 공급자를 확인하고 테스트했습니다. AI Gateway는 [LiteLLM](https://docs.litellm.ai/docs/providers)과 호환되는 LLM 공급자를 지원합니다.

- [AWS Bedrock](https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html)
- [Amazon Bedrock Mantle](#configure-amazon-bedrock-mantle)
- [Gemini Enterprise Agent Platform](https://cloud.google.com/products/gemini-enterprise-agent-platform)
- [Azure OpenAI](#configure-azure-openai)
- [Anthropic](https://platform.claude.com/docs/en/about-claude/models/overview)
- [OpenAI](https://developers.openai.com/api/docs/models)

### AWS Bedrock으로 인증 구성 {#configure-authentication-with-aws-bedrock}

AI Gateway를 사용하여 AWS Bedrock을 인증하는 여러 가지 방법을 사용할 수 있습니다.

전제 조건:

- 모델은 Bedrock에서 처음 호출될 때 자동으로 사용으로 설정됩니다. 자세한 내용은 [Bedrock 모델 액세스](https://docs.aws.amazon.com/bedrock/latest/userguide/model-access.html)를 참조하세요.
- 적절한 IAM 권한으로 구성된 AWS 자격 증명이 필요합니다.

#### Amazon EKS with Helm Chart(권장) {#amazon-eks-with-helm-chart-recommended}

AI Gateway 포드에 IRSA(IAM Roles for Service Accounts)를 사용하여 정적 자격 증명을 저장하지 않고 AWS Bedrock에 인증합니다.

Amazon EKS를 IRSA로 인증한 후 AI Gateway는 IRSA 역할에서 자동으로 임시 자격 증명을 가져옵니다.

IRSA를 사용하여 Amazon EKS를 인증하려면 다음을 수행합니다.

1. Bedrock 모델에 대한 액세스를 허용하는 IAM 정책을 만듭니다. 보안을 강화하려면 이를 특정 모델로 범위를 지정할 수 있습니다.

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "bedrock:InvokeModel",
           "bedrock:InvokeModelWithResponseStream"
         ],
         "Resource": "arn:aws:bedrock:*::foundation-model/*"
       }
     ]
   }
   ```

   ```shell
   aws iam create-policy \
     --policy-name bedrock-ai-gateway-access \
     --policy-document file://bedrock-policy.json \
     --description "Bedrock access for AI Gateway"
   ```

1. 선택사항. 더 엄격한 액세스 제어를 위해 와일드카드 리소스를 특정 모델 Amazon Resource Name(ARN)으로 바꿉니다. GitLab 구성이 변경되더라도 승인된 모델만 액세스할 수 있도록 보장합니다. 사용 가능한 모델 ARN의 경우 [Amazon Bedrock 모델 ID](https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html)를 참조하세요.

   ```json
   "Resource": [
     "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-5-sonnet-20241022-v2:0",
     "arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0"
   ]
   ```

   > [!note]
   > 일부 모델은 다른 ARN 형식을 사용할 수 있습니다. 예를 들어 최신 모델은 기초 모델 ARN 외에 추론 프로필 ARN이 필요할 수 있습니다. 특정 모델의 ARN 형식을 확인하려면 [Amazon Bedrock 모델 ID](https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html)를 참조하세요.

1. Amazon EKS 서비스 계정에서 사용할 신뢰 정책을 포함한 IAM 역할을 만듭니다. 다음 값을 바꿉니다.

   - `YOUR_ACCOUNT_ID`: AWS 계정 ID입니다.
   - `REGION`: Amazon EKS 클러스터 리전(예: `us-east-1`)입니다.
   - `YOUR_OIDC_ID`: Amazon EKS 클러스터의 OIDC 공급자 ID입니다.
   - `NAMESPACE`: AI Gateway가 배포된 Kubernetes 네임스페이스입니다.

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "Federated": "arn:aws:iam::YOUR_ACCOUNT_ID:oidc-provider/oidc.eks.REGION.amazonaws.com/id/YOUR_OIDC_ID"
         },
         "Action": "sts:AssumeRoleWithWebIdentity",
         "Condition": {
           "StringEquals": {
             "oidc.eks.REGION.amazonaws.com/id/YOUR_OIDC_ID:sub": "system:serviceaccount:NAMESPACE:ai-gateway",
             "oidc.eks.REGION.amazonaws.com/id/YOUR_OIDC_ID:aud": "sts.amazonaws.com"
           }
         }
       }
     ]
   }
   ```

   ```shell
   # Create the role
   aws iam create-role \
     --role-name eks-ai-gateway-bedrock \
     --assume-role-policy-document file://trust-policy.json \
     --description "EKS IRSA role for AI Gateway to access Bedrock"
   ```

1. Bedrock IAM 정책을 이 역할에 연결합니다.

   ```shell
   # Attach the role
   aws iam attach-role-policy \
     --role-name eks-ai-gateway-bedrock \
     --policy-arn arn:aws:iam::YOUR_ACCOUNT_ID:policy/bedrock-ai-gateway-access
   ```

1. Helm 차트를 구성하려면 IAM 역할 주석을 포함하여 AI Gateway를 설치합니다.

   ```yaml
   serviceAccount:
     create: true
     name: ai-gateway
     annotations:
       eks.amazonaws.com/role-arn: arn:aws:iam::YOUR_ACCOUNT_ID:role/YOUR_ROLE_NAME
   extraEnvironmentVariables:
     - name: AWS_REGION
       value: us-east-1
   ```

자세한 내용은 [서비스 계정의 IAM 역할](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)을 참조하세요.

#### Docker 배포 {#docker-deployments}

AI Gateway 컨테이너를 시작할 때 환경 변수를 통해 IAM 자격 증명을 구성합니다.

```shell
docker run -d \
  -e AWS_ACCESS_KEY_ID=your-access-key \
  -e AWS_SECRET_ACCESS_KEY=your-secret-key \
  -e AWS_REGION=us-east-1 \
  -p 5052:5052 \
  registry.gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/model-gateway:self-hosted-vX.Y.Z-ee
```

IAM 사용자 또는 역할은 Amazon EKS with Helm Chart에서 설정할 정책과 유사한 정책을 가져야 합니다.

#### Kubernetes 배포 {#kubernetes-deployments}

Amazon EKS가 아닌 다른 Kubernetes 클러스터의 경우 Kubernetes 보안을 사용하여 AWS 자격 증명을 저장할 수 있습니다.

1. Kubernetes 보안을 만듭니다.

   ```shell
   kubectl create secret generic aws-credentials \
     --from-literal=access-key-id=YOUR_ACCESS_KEY_ID \
     --from-literal=secret-access-key=YOUR_SECRET_ACCESS_KEY \
     -n YOUR_NAMESPACE
   ```

1. Helm 차트를 구성하여 보안을 참조합니다.

   ```yaml
   extraEnvironmentVariables:
     - name: AWS_ACCESS_KEY_ID
       valueFrom:
         secretKeyRef:
           name: aws-credentials
           key: access-key-id
     - name: AWS_SECRET_ACCESS_KEY
       valueFrom:
         secretKeyRef:
           name: aws-credentials
           key: secret-access-key
     - name: AWS_REGION
       value: us-east-1
   ```

#### AWS Bedrock으로 IAM 역할 가정 {#assume-an-iam-role-with-aws-bedrock}

{{< history >}}

- [도입됨](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/259000) \- GitLab 19.5에서 도입되었습니다.

{{< /history >}}

기본적으로 AI Gateway는 이미 가지고 있는 자격 증명(예: IRSA 역할 또는 환경 변수)으로 Bedrock을 호출합니다. 다른 역할(예: 다른 AWS 계정의 역할)로 Bedrock을 호출하려면 각 자체 호스팅 모델에 대해 IAM 역할을 제공합니다. AI Gateway는 자신의 자격 증명을 사용하여 AWS 보안 토큰 서비스(STS) [`AssumeRole`](https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html) 작업을 통해 그 역할을 가정합니다. 그런 다음 AI Gateway는 임시 자격 증명을 사용하여 Bedrock을 호출합니다.

전제 조건:

- 관리자 액세스 권한이 있어야 합니다.
- [AWS로 인증된 AI Gateway](#configure-authentication-with-aws-bedrock)입니다. AI Gateway가 실행되는 AWS 자격 증명은 역할에 대해 `sts:AssumeRole`를 호출할 수 있습니다.

Bedrock을 호출할 때 IAM 역할을 가정하려면:

1. 대상 AWS 계정에서 다음 신뢰 관계 정책을 사용하여 IAM 역할을 만듭니다. 다음을 바꿉니다:

   - `AI_GATEWAY_PRINCIPAL_ARN` - AI Gateway가 실행되는 AWS 자격 증명의 ARN(예: `arn:aws:iam::AI_GATEWAY_ACCOUNT_ID:role/eks-ai-gateway-bedrock` IRSA 역할)으로 바꿉니다.
   - `GITLAB_INSTANCE_ID` - **IAM 역할 가정** 텍스트 상자에 표시되는 GitLab 인스턴스의 ID로 바꿉니다.

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Principal": {
           "AWS": "AI_GATEWAY_PRINCIPAL_ARN"
         },
         "Action": "sts:AssumeRole",
         "Condition": {
           "StringEquals": {
             "sts:ExternalId": "GITLAB_INSTANCE_ID"
           }
         }
       }
     ]
   }
   ```

   AI Gateway는 역할을 가정할 때 STS 외부 ID로 인스턴스 ID를 전송합니다. 이 조건은 역할 ARN을 알고 있는 다른 AI Gateway 고객이 AI Gateway의 자격 증명을 사용하여 귀하의 역할을 가정하는 것을 방지합니다(혼동된 대리자 문제). 인스턴스 ID는 비밀이 아닙니다.

1. Bedrock 모델을 호출하려면 역할에 권한 정책을 연결합니다. `Resource`의 범위를 특정 모델로 지정할 수 있습니다:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "bedrock:InvokeModel",
           "bedrock:InvokeModelWithResponseStream"
         ],
         "Resource": "arn:aws:bedrock:*::foundation-model/*"
       }
     ]
   }
   ```

1. AI Gateway가 역할과 다른 계정에서 실행되는 경우 AI Gateway 자격 증명이 ID 기반 정책으로 역할에 대해 `sts:AssumeRole`를 호출하도록 허용합니다:

   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "sts:AssumeRole",
         "Resource": "arn:aws:iam::ROLE_ACCOUNT_ID:role/YOUR_ROLE_NAME"
       }
     ]
   }
   ```

1. 오른쪽 위 모서리에서 **관리자**를 선택합니다.
1. 왼쪽 사이드바에서 **GitLab Duo**를 선택합니다.
1. **GitLab Duo용 모델 구성**을 선택합니다.
1. **Amazon Bedrock** 플랫폼의 경우 자체 호스팅 모델을 추가하거나 편집합니다.
1. 선택사항. **IAM 역할 가정** 텍스트 상자에 역할의 ARN(예: `arn:aws:iam::123456789012:role/YOUR_ROLE_NAME`)을 입력합니다. 비어 있으면 AI Gateway는 자신의 자격 증명을 사용합니다.
1. 선택사항. **연결 테스트**를 선택합니다.
1. **자체 호스팅 모델 추가**를 선택합니다.

IAM 역할과 API 키(베어러 토큰)는 상호 배타적입니다. GitLab은 API 키가 있는 모델에 대해 IAM 역할을 수락하지 않으며, AI Gateway는 둘 다 포함하는 요청을 거부합니다.

> [!note]
> STS 외부 ID를 전송하려면 AI Gateway 버전에 [Amazon Bedrock 모델에 대한 `AssumeRole` 지원](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/merge_requests/7210)이 포함되어야 합니다. 이전 AI Gateway 버전에서는 AI Gateway가 STS 외부 ID를 전송하지 않으며, 신뢰 정책에 `sts:ExternalId`이 필요한 경우 역할 가정이 실패합니다.

#### AWS Bedrock API 키 {#aws-bedrock-api-keys}

IAM 자격 증명의 대안으로 AWS Bedrock API 키를 사용하려면 다음을 수행합니다.

1. [Bedrock API 키 만들기](https://docs.aws.amazon.com/bedrock/latest/userguide/api-keys-generate.html)
1. API 키를 사용하여 Kubernetes 보안을 만듭니다.

   ```shell
   kubectl create secret generic bedrock-api-key \
     --from-literal=token=YOUR_BEDROCK_API_KEY \
     -n YOUR_NAMESPACE
   ```

1. AI Gateway를 구성합니다(`values.yaml`에 추가):

   ```yaml
   extraEnvironmentVariables:
     - name: AWS_BEARER_TOKEN_BEDROCK
       valueFrom:
         secretKeyRef:
           name: bedrock-api-key
           key: token
     - name: AWS_REGION
       value: us-east-1
   ```

#### Private VPC 엔드포인트 {#private-vpc-endpoints}

VPC에서 개인 Bedrock 엔드포인트를 사용하려면 `AWS_BEDROCK_RUNTIME_ENDPOINT` 환경 변수를 설정합니다.

Helm 배포의 경우:

```yaml
extraEnvironmentVariables:
  - name: AWS_BEDROCK_RUNTIME_ENDPOINT
    value: https://bedrock-runtime.us-east-1.amazonaws.com
```

Docker 배포의 경우:

```shell
docker run -d \
  -e AWS_BEDROCK_RUNTIME_ENDPOINT=https://bedrock-runtime.us-east-1.amazonaws.com \
  -e AWS_REGION=us-east-1 \
  # ... other configuration
```

VPC 엔드포인트의 경우 형식을 사용하세요: `https://vpce-{vpc-endpoint-id}-{service-name}.{region}.vpce.amazonaws.com`

#### Bedrock 가드레일 {#bedrock-guardrails}

{{< history >}}

- GitLab 19.0에서 [도입](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/merge_requests/4715)되었습니다.

{{< /history >}}

Amazon Bedrock 가드레일을 사용하여 Bedrock 모델 요청에 대한 안전 및 개인 정보 보호 제어를 제공할 수 있습니다.

`AIGW_BEDROCK_GUARDRAIL_CONFIG` 환경 변수 값을 다음 필드를 포함하는 JSON 개체로 설정하여 이러한 가드레일을 적용합니다.

| 필드                 | 설명 |
|-----------------------|-------------|
| `guardrailIdentifier` | AWS 계정의 가드레일 ID입니다. 간단한 ID(`abc123`) 또는 전체 ARN(`arn:aws:bedrock:us-east-1:123456789012:guardrail/abc123`)일 수 있습니다. |
| `guardrailVersion`    | 적용할 가드레일의 버전입니다. `1`로 설정합니다. |
| `trace`               | 응답에 추적 정보를 포함할지 여부입니다. `enabled` 또는 `disabled`로 설정할 수 있습니다. |

> [!note]
> 가드레일이 요청을 차단하면 사용자에게 반환되는 메시지는 GitLab에서 제공한 메시지가 아니라 AWS Bedrock 가드레일에 구성된 사용자 지정 차단 메시지입니다. 사용자가 적절한 안내를 받도록 AWS 콘솔에서 가드레일의 차단된 메시징을 구성합니다.

Helm 배포의 경우 다음과 같이 환경 변수를 설정합니다.

```yaml
extraEnvironmentVariables:
  - name: AIGW_BEDROCK_GUARDRAIL_CONFIG
    value: '{"guardrailIdentifier": "<guardrail_id>", "guardrailVersion": "1", "trace": "disabled"}'
```

Docker 배포의 경우:

```shell
docker run -d \
  -e AIGW_BEDROCK_GUARDRAIL_CONFIG='{"guardrailIdentifier": "<guardrail_id>", "guardrailVersion": "1", "trace": "disabled"}' \
  # ... other configuration
```

자세한 내용은 [Amazon Bedrock 가드레일](https://docs.aws.amazon.com/bedrock/latest/userguide/guardrails.html)을 참조하세요.

### Amazon Bedrock Mantle 구성 {#configure-amazon-bedrock-mantle}

{{< details >}}

- 상태:  베타

{{< /details >}}

{{< history >}}

- GitLab 19.3에서 [베타](../../policy/development_stages_support.md#beta)로 [도입](https://gitlab.com/groups/gitlab-org/-/work_items/22787)되었습니다.
- GPT-5 이상 모델이 2026년 9월 16일에 지원되는 모델로 [추가](https://gitlab.com/gitlab-org/modelops/applied-ml/code-suggestions/ai-assist/-/merge_requests/6956)되었습니다.

{{< /history >}}

[Amazon Bedrock Mantle](https://docs.aws.amazon.com/bedrock/latest/userguide/bedrock-mantle.html)은 AWS의 OpenAI API 호환 추론 서비스입니다. Amazon Bedrock Mantle을 다른 OpenAI 호환 엔드포인트처럼 API 플랫폼과 구성합니다.

Amazon Bedrock Mantle에서 검증 및 지원되는 모델은 다음과 같습니다:

| 모델 | 모델 식별자 |
|-------|------------------|
| GPT-5.4 | `bedrock_mantle/openai.gpt-5.4` |
| GPT-5.5 | `bedrock_mantle/openai.gpt-5.5` |
| GPT-5.6 Luna | `bedrock_mantle/openai.gpt-5.6-luna` |
| GPT-5.6 Sol | `bedrock_mantle/openai.gpt-5.6-sol` |
| GPT-5.6 Terra | `bedrock_mantle/openai.gpt-5.6-terra` |
| GPT-6 Astra | `bedrock_mantle/openai.gpt-6-astra` |
| GPT-6 Luna | `bedrock_mantle/openai.gpt-6-luna` |
| GPT-6 Sol | `bedrock_mantle/openai.gpt-6-sol` |
| GPT-6.1 Sol | `bedrock_mantle/openai.gpt-6.1-sol` |
| GPT OSS 120B | `bedrock_mantle/openai.gpt-oss-120b` |

AI Gateway는 GPT-5 이상 모델에 대한 요청을 Amazon Bedrock Mantle의 응답 API로 전송합니다. 모든 모델에 동일한 `bedrock_mantle/` 접두사를 사용합니다.

Anthropic 모델은 Amazon Bedrock Mantle에서 지원되지 않습니다. Amazon Bedrock Mantle은 이러한 모델을 Anthropic Messages API를 통해서만 제공하며, AI Gateway는 이 플랫폼에 대해 해당 API를 사용하지 않습니다. AWS에서 Anthropic 모델을 사용하려면 [Amazon Bedrock 모델 추가](configure_duo_features.md#add-an-amazon-bedrock-model)를 사용하세요.

Amazon Bedrock Mantle 모델을 구성하려면 다음 값을 사용하여 [자체 호스팅 모델 추가](configure_duo_features.md#add-a-self-hosted-model)합니다.

- **모델 패밀리**에 대해 모델과 일치하는 패밀리를 선택합니다. OpenAI 모델의 경우 **GPT**를 선택합니다.
- **엔드포인트**의 경우 `https://bedrock-mantle.<region>.api.aws/v1` 형식의 리전 엔드포인트를 입력합니다 (예: `https://bedrock-mantle.us-east-1.api.aws/v1`).
- **모델 식별자**의 경우 `bedrock_mantle/` 접두사를 사용합니다 (예: `bedrock_mantle/openai.gpt-oss-120b`).
- **API 키**의 경우 Amazon Bedrock Mantle API 키를 입력합니다. 자세한 내용은 [AWS Bedrock API 키](#aws-bedrock-api-keys)를 참조하세요.

### Azure OpenAI 구성 {#configure-azure-openai}

[Azure OpenAI](https://learn.microsoft.com/en-us/azure/foundry/foundry-models/concepts/models-sold-directly-by-azure?tabs=global-standard&pivots=azure-openai)는 Chat Completions API와 [Responses API](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/responses)를 통해 모델을 제공합니다. 대부분의 모델은 Chat Completions API를 지원합니다. 일부 최신 모델은 Responses API를 통해서만 사용할 수 있습니다.

Azure OpenAI 모델을 구성하려면 [자체 호스팅 모델 추가](configure_duo_features.md#add-a-self-hosted-model)를 수행하고 다음 값을 입력합니다:

- **모델 패밀리**에 대해 모델과 일치하는 패밀리를 선택합니다. GPT-5의 경우 **GPT**를 선택합니다.
- **엔드포인트**에 대해 Azure OpenAI 리소스의 엔드포인트를 `https://<resource-name>.openai.azure.com` 형식으로 입력합니다. 경로나 API 버전을 추가하지 마세요.
- **모델 식별자**에 대해 `azure/` 접두사를 사용한 후 배포의 이름을 입력합니다(예: `azure/gpt-4o`). 이 식별자는 Chat Completions API로 요청을 전송합니다. 대신 Responses API로 요청을 전송하려면 [Responses API 사용](#use-the-responses-api)을 참조하세요.
- **API 키**에 대해 Azure OpenAI 리소스에 대한 API 키를 입력합니다.

#### Responses API 사용 {#use-the-responses-api}

Responses API를 통해서만 사용 가능한 배포의 경우 `azure/responses/` 접두사를 사용합니다. **모델 식별자**에 대해 접두사를 입력한 후 배포의 이름을 입력합니다(예: `azure/responses/gpt-5`).

AI Gateway는 리소스의 `/openai/responses` 경로로 요청을 전송합니다. AI Gateway는 각 요청을 Responses API 형식으로 변환하고 응답을 다시 변환합니다. 변환은 스트리밍된 응답 및 도구 호출을 지원합니다. 두 API 간을 변환하기 위해 프록시가 필요하지 않습니다.

### Gemini Enterprise Agent Platform을 사용한 인증 구성 {#configure-authentication-with-gemini-enterprise-agent-platform}

Gemini Enterprise Agent Platform의 모델을 사용하려면 AI Gateway 인스턴스를 인증해야 합니다. 다음 메커니즘 중 하나를 사용할 수 있습니다.

- Docker 컨테이너를 시작할 때 환경 변수를 내보냅니다. AI Gateway 컨테이너를 실행할 때 다음 환경 변수를 설정합니다.

  ```shell
  GOOGLE_APPLICATION_CREDENTIALS=/path/to/application_default_credentials.json
  VERTEXAI_PROJECT=<gcp-project-id>
  VERTEXAI_LOCATION=global # or any specific location, e.g., "europe-west1"
  ```

- Google Cloud Run에서 AI Gateway 컨테이너를 실행하고 Gemini Enterprise Agent Platform 액세스를 위해 [Cloud Run 서비스 계정](https://docs.litellm.ai/docs/providers/vertex#using-gcp-service-account)을 사용합니다.

## 관련 항목 {#related-topics}

- [지원되는 모델 및 하드웨어 요구 사항 설명서](supported_models_and_hardware_requirements.md).
- [Amazon Bedrock 지원 기초 모델](https://docs.aws.amazon.com/bedrock/latest/userguide/models-supported.html)
- [AWS IAM 모범 사례](https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html)
- [Amazon Bedrock 보안](https://docs.aws.amazon.com/bedrock/latest/userguide/security.html)
- 구성 정보는 다음 설명서를 참조하세요:
  - [Anthropic API 개요](https://platform.claude.com/docs/en/api/overview)
  - [OpenAI API 개요](https://developers.openai.com/api/docs)
  - [Azure OpenAI 모델 작업](https://learn.microsoft.com/en-us/azure/foundry/openai/how-to/working-with-models?tabs=powershell)
