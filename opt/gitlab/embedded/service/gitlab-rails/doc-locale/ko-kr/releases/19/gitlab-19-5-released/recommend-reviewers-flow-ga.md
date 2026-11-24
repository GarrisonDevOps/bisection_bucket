---
title: GitLab Duo로 검토자 추천하기
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: ai_coding
documentation_link: "../../../user/project/merge_requests/reviews/automatic_reviewer_assignment/#recommend-reviewers-flow"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/20711
categories: [ DAP Code Review ]
level: secondary
weight: 50
---

이전 버전의 GitLab에서는 각 승인 규칙을 확인하고 누가 머지 리퀘스트를 검토할 시간이 있는지 추측해야 했습니다. 또는 전체 그룹을 할당하고 누군가 이를 처리하기를 바라야 했습니다.

이제 권장 검토자 플로우를 사용하여 검토자를 대신 제안할 수 있습니다. 이 플로우는 일반적으로 사용 가능합니다.

각 승인 규칙에 대해 가용성, 작업량, 시간대 및 최근 활동을 기반으로 필요한 최소 검토자 수를 권장합니다.

권장 사항은 머지 리퀘스트 사이드바의 **권장** 섹션에 나타납니다. 사용자 위에 마우스를 가져가면 권장된 이유를 확인할 수 있습니다.

시작하려면 최상위 그룹의 플로우를 켜세요. 머지 리퀘스트가 생성될 때 실행되거나, 초안이 준비 완료로 표시될 때 실행할 트리거를 생성할 수 있습니다. 새 권장 사항을 얻으려면 **새로 고침**을 선택하세요.
