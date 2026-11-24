---
title: 자식 파이프라인이 부모 작업에 선택적으로 의존할 수 있음
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated ]
stage: verify
co_create: false
documentation_link: "../../../ci/yaml/#needspipelinejob"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/349538
categories: [ Continuous Integration (CI) ]
level: secondary
weight: 20
---

많은 개발팀이 대규모 CI/CD 설정을 부모 파이프라인과 자식 파이프라인으로 분할하여 각 부분을 더 쉽게 관리합니다. 지금까지 자식 파이프라인 작업은 특정 파일이 변경될 때만 실행되는 테스트와 같이 특정 조건 하에서만 실행되는 부모 작업에 안전하게 의존할 수 없었습니다. 부모 작업을 건너뛸 경우 자식 작업이 중단되어 팀이 중복 작업이나 불안정한 스크립트로 해결해야 했습니다.

이제 이러한 종속성을 선택사항으로 표시할 수 있습니다. 부모 작업이 실행되면 자식은 평소처럼 기다립니다. 실행되지 않으면 자식 작업은 이를 기다리지 않고 진행됩니다. 파이프라인은 해결책 없이도 빠르고 안정적으로 유지되며, 실행되는 작업의 실패는 여전히 파이프라인을 중지하므로 품질 검사가 약해지지 않습니다.

이 기여를 주신 [Jimmy Spagnola](https://gitlab.com/jspagnola)님께 감사합니다!
