---
title: 머지 트레인의 병렬 파이프라인 제한 구성
stage: verify
level: secondary
tier: [ Premium, Ultimate ]
offering: [ self_managed, gitlab_dedicated ]
documentation_link: "../../../administration/cicd/limits/#merge-train-parallel-pipeline-limit"
work_item: "https://gitlab.com/gitlab-org/gitlab/-/work_items/374188"
categories: [ Continuous Integration (CI) ]
weight: 90
---

이전 버전의 GitLab에서는 머지 트레인의 최대 20개 병렬 파이프라인을 변경할 수 없었으므로 러너를 과부하시키거나 머지 트레인을 완전히 건너뛰어야 했습니다. 이제 머지 트레인당 병렬 파이프라인 제한을 구성하여 러너 부하와 머지 처리량을 균형 있게 조정할 수 있습니다. 프로젝트당 또는 인스턴스 전체에서 제한을 설정할 수 있습니다. 제한을 1로 설정하면 각 머지 리퀘스트가 한 번에 하나씩 깨끗한 대상 브랜치에 대해 실행됩니다.

이 커뮤니티 기여에 대해 [Norman Debald(@Modjo85)](https://gitlab.com/Modjo85)에게 감사합니다.
