---
title: 작업 로그 업데이트 빈도 설정
tier: [ Free, Premium, Ultimate ]
offering: [ self_managed, gitlab_dedicated ]
stage: verify
co_create: true
documentation_link: "../../../administration/settings/continuous_integration/#configure-the-frequency-of-job-log-updates"
work_item: https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251401
categories: [ Continuous Integration (CI) ]
level: secondary
weight: 30
---

관리자는 이제 **운영자 영역** > **설정** > **CI/CD** 또는 설정 API를 통해 작업 로그가 업데이트되는 빈도를 설정할 수 있습니다. 3초에서 3600초 사이를 선택할 수 있습니다. 이전 GitLab 버전에서는 이러한 간격이 상수였으므로 인스턴스에 패치를 적용하지 않고 단시간 작업의 초기 라이브 로그 지연을 단축할 수 없었습니다.

[Aleksandr Kotlyar](https://gitlab.com/aleksandr-kotlyar)에게 이 기여에 대해 감사합니다([머지 리퀘스트](https://gitlab.com/gitlab-org/gitlab/-/merge_requests/251401))!
