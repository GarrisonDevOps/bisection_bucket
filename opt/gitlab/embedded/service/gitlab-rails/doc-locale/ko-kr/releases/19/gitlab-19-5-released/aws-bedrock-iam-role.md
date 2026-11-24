---
title: Amazon Bedrock 자체 호스팅 모델을 위한 IAM 역할
tier: [ Premium, Ultimate ]
offering: [ self_managed, gitlab_dedicated ]
stage: ai_platform
documentation_link: "../../../administration/gitlab_duo_self_hosted/supported_llm_serving_platforms/#assume-an-iam-role-with-aws-bedrock"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/542393
categories: [ Model Selection ]
level: secondary
weight: 50
---

이전에는 AI Gateway가 Amazon Bedrock 모델에 사용할 AWS 자격 증명을 제어할 수 없었습니다. 단일 AWS 신원이 이 모든 모델에 대한 액세스 권한이 필요했습니다.

이번 릴리스에서는 각 모델에 대해 IAM 역할을 지정할 수 있으며, AI Gateway가 모델을 호출할 때 해당 역할을 가정합니다. 이렇게 하면 역할이 다른 AWS 계정에 있더라도 각 모델은 필요한 AWS 액세스 권한만 얻을 수 있습니다.
