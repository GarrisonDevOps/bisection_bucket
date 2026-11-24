---
title: GitLab Duo를 위한 그룹 수준 사용자 지정 검토 지침
stage: ai-powered
level: primary
tier: [ Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
documentation_link: "../../../user/gitlab_duo/customize_duo/review_instructions/#configure-custom-review-instructions-for-a-group"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/21504"
categories: [ Duo Code Review ]
add_ons: [ GitLab Duo Enterprise ]
weight: 10
---

이전 버전의 GitLab에서는 프로젝트 수준에서만 GitLab Duo를 위한 맞춤형 검토 지침을 정의할 수 있었습니다. 동일한 그룹의 여러 프로젝트에서 작업하는 팀은 모든 프로젝트에서 동일한 지침을 복제해야 했습니다.

이제 전체 그룹 및 하위 그룹에 대한 공유 맞춤형 검토 지침을 구성할 수 있습니다.

템플릿으로 사용할 그룹의 프로젝트를 선택하세요. GitLab Duo가 코드 검토를 수행할 때 그룹 수준 `.gitlab/duo/mr-review-instructions.yaml` 파일과 개별 프로젝트에서 정의된 모든 지침을 결합합니다.

Code Review 플로우와 GitLab Duo Code Review는 모두 그룹 수준 맞춤형 지침을 지원합니다.
