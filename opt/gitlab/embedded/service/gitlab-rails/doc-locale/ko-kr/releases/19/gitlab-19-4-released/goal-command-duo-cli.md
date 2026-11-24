---
title: "GitLab Duo CLI의 /goal 명령어"
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_clients
documentation_link: "../../../user/gitlab_duo_cli/use/#slash-commands"
work_item: https://gitlab.com/groups/gitlab-org/ai-powered/-/work_items/10
categories: [ Duo CLI ]
level: secondary
weight: 50
---

GitLab Duo CLI은 이제 개방형 목표를 로컬에서 실행되는 목표 중심의 플로우에 위임하는 `/goal` 슬래시 명령을 포함합니다.

목표를 설명하면 GitLab Duo가 구현과 검증을 처리하며, 독립적인 판사를 사용하여 목표를 달성했는지 또는 반복 제한에 도달했는지를 결정합니다. 시작부터 끝까지 제어 상태를 유지할 수 있습니다. 언제든지 일시 중지하거나, 목표를 업데이트하거나, 에이전트를 리디렉션할 수 있습니다.

`/goal` 슬래시 명령은 GitLab 19.3 이상 및 GitLab Duo CLI 9.17.0 이상이 필요합니다.

시작하려면 `/goal <task>`을 실행합니다.

예를 들어:

```plaintext
/goal Fix the failing tests in spec/models/user_spec.rb
```
