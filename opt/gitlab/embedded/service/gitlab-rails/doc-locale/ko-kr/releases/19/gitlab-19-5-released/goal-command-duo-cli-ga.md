---
title: "GitLab Duo CLI의 `/goal` 명령어가 일반 공개되었습니다."
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/gitlab_duo_cli/use/#slash-commands"
work_item: https://gitlab.com/groups/gitlab-org/ai-powered/-/work_items/10
categories: [ Duo CLI ]
level: secondary
weight: 50
---


GitLab Duo CLI의 `/goal` 슬래시 명령어는 이제 GitLab Duo CLI 9.27.0에서 일반 공개됩니다.

개방형 목표를 설명하면 GitLab Duo가 이를 로컬에서 실행되는 관리형 목표 기반 플로우로 위임하고 구현 및 검증을 모두 처리합니다.

시작하려면 `/goal <task>`을 실행하세요. 예를 들어:

```plaintext
/goal Fix the failing tests in spec/models/user_spec.rb
```

GitLab 19.5(GitLab Duo CLI 9.24.0)에서 `/settings`의 **제안된 프롬프트를 /goal 세션으로 실행** 설정은 제안된 프롬프트를 채팅 메시지 대신 `/goal` 세션으로 실행합니다.

`/goal`은 GitLab 19.3 이상 및 GitLab Duo CLI 9.17.0 이상이 필요합니다.
