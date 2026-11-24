---
title: GitLab Duo Enterprise 사용자용 Code Review 플로우
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
tier: [ Premium, Ultimate ]
stage: ai_coding
documentation_link: "../../../user/project/merge_requests/duo_in_merge_requests/#turn-on-code-review-flow-for-gitlab-duo-enterprise-seats"
work_item: https://gitlab.com/groups/gitlab-org/-/work_items/22247
categories: [ DAP Code Review ]
---

이전 버전의 GitLab에서 GitLab Duo Enterprise 사용자가 GitLab Duo에 코드 검토를 요청하면 GitLab Duo 코드 검토가 검토를 완료했습니다. 이는 그룹에 대해 Code Review 플로우를 켠 경우에도 발생했습니다. 모든 사용자에 대해 에이전트 플로우를 켤 수 있는 방법이 없었습니다.

이제 최상위 그룹 소유자는 이 기본값을 변경하고 사용자의 사용자 여부에 관계없이 모든 코드 검토에서 Code Review 플로우를 대신 사용하도록 구성할 수 있습니다. 모든 검토는 GitLab Credits를 소비합니다.

이 변경은 GitLab Duo Enterprise 사용자에게 다른 모든 사용자와 동일한 리포지토리 전체 컨텍스트 인식, 다단계 추론 및 검토 세션을 제공합니다.
