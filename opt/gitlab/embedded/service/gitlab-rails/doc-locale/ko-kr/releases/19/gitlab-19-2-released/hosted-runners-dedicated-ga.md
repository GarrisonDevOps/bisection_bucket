---
title: GitLab Dedicated용 호스팅 러너가 일반적으로 사용 가능함
tier: [ Ultimate ]
offering: [ gitlab_dedicated ]
stage: production_engineering
documentation_link: "../../../administration/dedicated/hosted_runners"
work_item: https://gitlab.com/gitlab-com/gl-infra/gitlab-dedicated/transistor/-/merge_requests/834
categories: [ GitLab Hosted Runners ]
level: secondary
weight: 50
---

GitLab Dedicated용 호스팅 러너가 이제 일반적으로 사용 가능합니다. GitLab은 GitLab Dedicated 인스턴스와 동일한 보안 및 규정 준수 경계 내에서 러너를 프로비저닝, 패치 적용 및 확장합니다.

주요 기능은 다음을 포함합니다.

- GitLab Dedicated 인스턴스와 동일한 리전에 있는 AWS EC2 인스턴스로, 각 작업 후 삭제되는 단일 테넌트, 임시 VM에서 실행
- GitLab 인스턴스에 대한 보안 아웃바운드 PrivateLink 연결
- 소형부터 2X-대형까지 5가지 크기의 Linux x86-64 및 Arm64 러너
- 99.9% 가동 시간 SLA로, GitLab Dedicated 인스턴스 SLA와 별도로 계산되어 워크플로우가 안정적이고 복원력 있으며 온라인 상태로 유지되도록 보장

Switchboard에서 호스팅 러너를 직접 만들고 관리하며, 사용한 것에 대해서만 비용을 지불하며, 사용량은 GitLab Credits 대시보드에서 추적됩니다. 시작하려면 고객 성공 관리자 또는 계정 담당자에게 문의하세요.
