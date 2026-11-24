---
title: GitLab Runner 19.2
tier: [ Free, Premium, Ultimate ]
offering: [ gitlab_com, self_managed, gitlab_dedicated, gitlab_dedicated_for_government ]
stage: verify
documentation_link: https://docs.gitlab.com/runner
work_item: https://gitlab.com/gitlab-org/gitlab-runner/-/issues/?milestone_title=19.2&state=closed
categories: [ GitLab Runner Core ]
level: secondary
---

저희는 오늘 GitLab Runner 19.2를 출시합니다! GitLab Runner는 CI/CD 작업을 실행하고 결과를 GitLab 인스턴스로 보내는 높은 확장성의 빌드 에이전트입니다. GitLab Runner는 GitLab에 포함된 오픈 소스 지속적 통합 서비스인 GitLab CI/CD와 함께 작동합니다.

**새로운 기능**

- [GitLab Runner는 이제 작업 완료 PUT 요청 중에 환경 키를 내보냅니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39463)
- [GitLab Runner는 이제 KAS 작업 요청이 연속으로 실패할 때 Rails로 자동으로 폴백하는 서킷 브레이커를 포함합니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39389)

**버그 수정**

- [암호 해결 실패가 `runner_system_failure`로 잘못 분류됩니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39573)
- [GitLab Runner를 19.1.0으로 업데이트할 때 작업이 `context deadline exceeded`와 함께 실패합니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39556)
- [Docker 실행기에서 작업이 `context deadline exceeded`로 간헐적으로 실패합니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39555)
- [`FF_CONCRETE`가 활성화되면 아티팩트 다운로드가 실패합니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39475)
- [KAS Job Router `GetJob` 지연 시간 히스토그램이 스테이징에서 데이터를 표시하지 않습니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39388)
- [자동 러너 토큰 회전으로 인해 Docker Autoscaler 실행기가 활성 인스턴스를 정리하고 실행 중인 작업이 실패합니다](https://gitlab.com/gitlab-org/gitlab-runner/-/work_items/39380)

모든 변경 사항 목록은 GitLab Runner [CHANGELOG](https://gitlab.com/gitlab-org/gitlab-runner/blob/19-2-stable/CHANGELOG.md)에 있습니다.
