---
title: Code Review 플로우의 후속 검토
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
documentation_link: "../../../user/duo_agent_platform/flows/foundational_flows/code_review/#follow-up-reviews"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/21620
categories: [ DAP Code Review ]
level: secondary
weight: 50
---

GitLab의 이전 버전에서는 GitLab Duo에 머지 리퀘스트를 다시 검토해 달라고 요청하면 검토를 처음부터 새로 진행했습니다. 이미 해결한 내용을 포함하여 이전 스레드의 발견 사항을 반복할 수 있었습니다.

이제 Code Review 플로우는 이전 GitLab Duo 검토의 댓글 스레드를 사용하여 새로운 변경 사항을 평가하고 사용자의 답글도 함께 검토합니다. GitLab Duo는 마지막 검토 이후 추가된 라인에 집중하고, 이미 제시한 내용을 반복하지 않으며, 요약에 해결되지 않은 발견 사항을 나열합니다. 코드가 정확한 이유를 설명하기 위해 스레드에 답글을 남기면 GitLab Duo는 같은 내용을 다시 제시하지 않습니다.

후속 검토를 시작하려면 GitLab Duo에 머지 리퀘스트를 다시 검토해 달라고 요청합니다. **푸시 시 새로운 검토 시작**이 켜져 있으면 변경 사항을 푸시할 때 GitLab Duo가 자동으로 후속 검토를 시작합니다.
