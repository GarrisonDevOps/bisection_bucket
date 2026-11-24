---
title: 취약한 종속성에 대한 자동 수정 (실험)
stage: software_supply_chain_security
level: secondary
tier: [ Ultimate ]
offering: [ gitlab_com ]
documentation_link: "../../../user/application_security/remediate/auto_remediation/"
work_item: "https://gitlab.com/groups/gitlab-org/-/work_items/17403"
categories: [ Software Composition Analysis ]
weight: 10
---

종속성에 대한 자동 수정은 이제 GitLab 19.0에서 실험으로 사용 가능합니다. 종속성 검사에서 알려진 수정이 있는 취약한 Ruby 종속성을 감지하면 GitLab은 자동으로 머지 리퀘스트를 열어 사람의 개입 없이 안전한 버전으로 업데이트합니다. 실험에서는 Ruby 프로젝트만 지원됩니다.

각 파이프라인 후 GitLab은 사용 가능한 패치 또는 부 버전 업그레이드가 있는 최고 심각도 취약성을 식별합니다. GitLab은 매니페스트 파일 변경을 생성하고 서비스 계정을 통해 머지 리퀘스트를 엽니다. 머지 리퀘스트는 프로젝트의 표준 검토 및 승인 워크플로우를 거칩니다.

실험 중에 프로젝트당 최대 3개의 자동 수정 머지 리퀘스트를 한 번에 열 수 있습니다.

피드백을 공유하거나 실험을 시도하도록 요청하려면 [에픽 600511](https://gitlab.com/gitlab-org/gitlab/-/work_items/600511)에 댓글을 남기세요. 프로젝트에서 실험을 활성화하려면 GitLab 팀 구성원이 프로젝트에 대해 `dependency_management_auto_remediation` 기능 플래그를 활성화해야 합니다.
