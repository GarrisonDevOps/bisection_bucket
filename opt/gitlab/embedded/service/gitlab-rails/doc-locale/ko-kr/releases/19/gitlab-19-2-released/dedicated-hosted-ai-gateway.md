---
title: GitLab Dedicated AI 게이트웨이
tier: [ Ultimate ]
offering: [ gitlab_dedicated ]
stage: gitlab_dedicated
documentation_link: "../../../administration/gitlab_duo_self_hosted/supported_llm_serving_platforms/#configure-authentication-with-aws-bedrock"
work_item: https://gitlab.com/gitlab-com/gl-infra/gitlab-dedicated/team/-/work_items/13486
categories: [ GitLab Dedicated ]
level: secondary
---

GitLab Dedicated AI 게이트웨이는 AWS 환경에서 GitLab Dedicated 인스턴스와 같은 지역에서 실행됩니다. 추론 요청(코드 입력, 프롬프트 및 모델 응답 포함)은 네트워크와 지역 내에 머물러 있습니다. 모든 GitLab Duo Agent Platform 추론 요청은 GitLab Dedicated 인스턴스와 동일한 감시 범위에 머물러 있습니다. GitLab Dedicated AI 게이트웨이는 기본적으로 활성화되어 있으며 설정이 필요하지 않습니다.

선택적으로 BYOM(Bring Your Own Model)을 사용하여 자신의 클라우드 호스팅 모델에 연결할 수 있습니다. GitLab Duo Agent Platform 기능을 선택한 모델로 자신의 지역에서 액세스 제어 하에 활성화할 수 있습니다.
