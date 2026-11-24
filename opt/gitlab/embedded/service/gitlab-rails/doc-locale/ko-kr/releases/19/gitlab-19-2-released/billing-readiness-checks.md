---
title: GitLab Duo Agent Platform Self-Hosted 사용량 청구 확인
offering: [ self_managed, gitlab_dedicated_for_government ]
tier: [ Premium, Ultimate ]
stage: ai-powered
documentation_link: "../../../administration/gitlab_duo/configure/#run-a-health-check-for-gitlab-duo"
work_item: https://gitlab.com/gitlab-org/gitlab/-/work_items/603196
categories: [ Health & Connectivity ]
level: secondary
---

<!-- categories: Health & Connectivity  -->

온라인 라이선스를 사용하는 자체 호스팅 모델을 사용하는 GitLab Self-Managed 고객의 경우, GitLab Duo Health는 이제 GitLab 인스턴스가 다음 엔드포인트에 연결할 수 있는지 확인합니다:

- 고객 포털
- AI Gateway
- Duo Workflow Service

이 엔드포인트에 대한 연결은 사용량 청구에 필요합니다.

이전에는 방화벽이 이러한 구성 요소 중 하나를 차단한 경우 관리자는 사용자가 기능을 사용할 수 없을 때까지 연결 문제를 알 수 없었습니다. 관리자는 이제 이 새로운 유효성 검사를 사용하여 문제를 진단하고 사용자에게 어떤 중단이 발생하기 전에 방화벽 허용 목록을 검토할 수 있습니다.
